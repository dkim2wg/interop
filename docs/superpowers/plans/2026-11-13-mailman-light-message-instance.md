# Mailman light Message-Instance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mailman adds DKIM2 Message-Instances without keeping the received octets: header Recipes from a change log in `Message`, body Recipes from decorate's wrap structure, every Recipe checked by hash.

**Architecture:** Port the existing 7-commit DKIM2 series onto `decorate-always-wrap`, then replace its octet machinery piece by piece: change log in `mailman/email/message.py`; LMTP keeps two digests + an arrival status instead of `original_bytes`; decorate records what it did; egress rebuilds the previous instance from log + structure and checks it against the digests. Finally rewrite the history into an upstream series and replace the `dkim2*` branches.

**Tech Stack:** Python 3 (local `.venv` is 3.14; box tests 3.13), compat32 `email` package, nose2, Mailman 3 handlers/runners.

**Spec:** `docs/superpowers/specs/2026-11-13-mailman-light-message-instance-design.md` (interop repo). Read it before any task.

## Global Constraints

- Repo for code: `~/src/mailman`. Dev branch `dkim2-light`, based on `decorate-always-wrap` (78f7d43df). TDD on this branch only.
- Local focused tests: `cd ~/src/mailman && .venv/bin/python -m nose2 -s src <dotted.module[.Class[.test]]>`. Full suite runs on the box once (Task 9), not locally.
- Lint: `uvx flake8 <files>` and `uvx isort --check-only --diff <files>` clean for every touched file.
- No `original_bytes`, no body line diff, no `message_instance_max_recipe_lines`, no `body-modified` flags, no `without_received_bytes`, no `_ReceivedPart` when done.
- A header Recipe is never null.
- Keep: `[mta] message_instance`, per-list `dkim2_message_instance` + migration, -09 constants (`DKIM2_DRAFT`, `DKIM2_DATE`), X-DKIM2-Info beside every instance, exploded hint, Bcc/Resent-Bcc removal, retry guard, originator `m=1`, ruling-17 single `m=1` for unsigned posts, DMARC From rewrite.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never push until Task 10.
- `dkim2-3.3.8` is cherry-pick only, never tested (feedback_mailman_develop_on_master_backport).

## Review Focus

1. Header edits made by stdlib methods that bypass `__setitem__` (`set_param` on Content-Type, `set_boundary`, `set_charset` via `set_payload(..., charset)`) — must be logged; covered in Task 2 tests.
2. A body line starting `From ` (smtplib turns it into `>From `) in an unchanged and in a wrapped body — Recipe must still rebuild the previous body; Task 6.
3. A post that is already multipart/mixed with both header and footer — two copy ranges, Task 6.
4. Personalised delivery (deepcopy per recipient) changing To — log must survive the copy; Task 2 (deepcopy) + Task 8 (pipeline).
5. A message pickled before the change log existed (no log attribute) reaching egress — must not crash; Task 2 (`__setstate__`) + Task 4 (mismatch path).

---

### Task 1: Port the existing series onto `decorate-always-wrap`

**Files:** whatever the 7 commits `cc78253ff..c575dc3bf` (`master..dkim2`) touch; conflict expected in `src/mailman/handlers/decorate.py`.

**Interfaces:** Produces the starting point every later task edits: `src/mailman/handlers/message_instance.py` (functions as on `dkim2`), `src/mailman/handlers/tests/{mi_support,test_message_instance,test_mi_roundtrip,test_mi_null_recipe}.py`.

- [ ] **Step 1:** `git switch -c dkim2-light decorate-always-wrap && git cherry-pick master..dkim2`
- [ ] **Step 2:** Resolve `decorate.py`: keep the `decorate_plain_text_in_place` condition and add the fork's `_dkim2_wrap` call above it, unchanged. Resolve any alembic `down_revision` to the head of current upstream (`.venv/bin/alembic -c src/mailman/config/alembic.cfg heads` must show one head).
- [ ] **Step 3:** Run `.venv/bin/python -m nose2 -s src mailman.handlers mailman.runners.tests.test_lmtp mailman.rest.tests.test_listconf` — expected OK.
- [ ] **Step 4:** Commits stay as cherry-picked (history is rewritten in Task 10).

### Task 2: Header change log in `Message`

**Files:**
- Modify: `src/mailman/email/message.py`
- Test: `src/mailman/email/tests/test_message.py` (new class `TestHeaderLog`)

**Interfaces — Produces:**
- `Message.start_header_log() -> None` — idempotent; never resets a running log.
- `Message.header_log` (property) `-> dict[str, list[str]] | None` — lower-case name → original raw values (`raw_items()` form) in document order; `[]` = absent originally; `None` = log not started.
- `Message._unlogged_prepend(name: str, value: str) -> None` — inserts at position 0 without logging (for Message-Instance / X-DKIM2-Info).
- Storage attribute `_header_log` (instance `__dict__`, so it pickles and deep-copies).

- [ ] **Step 1: Write failing tests** in `TestHeaderLog`:
  - `test_parser_does_not_log`: `message_from_string(..., Message).header_log is None`.
  - `test_setitem_logs_absent`: after start, `msg['X-New']='1'; msg['Reply-To']='a@b'` → `header_log == {'x-new': [], 'reply-to': []}` (if excluded names are skipped, drop `x-new` from the expectation and assert it absent — builder's call per spec, pick one and test it).
  - `test_delitem_logs_all_values`: two `Cc` fields `a`, `b`; `del msg['cc']` → `{'cc': ['a', 'b']}`.
  - `test_first_touch_only`: `msg.replace_header('Subject','x')` then `msg.replace_header('Subject','y')` → `{'subject': ['<original>']}`.
  - `test_add_header`, `test_set_raw`: each logs its name.
  - `test_set_param_logs_content_type`, `test_set_boundary_logs_content_type`, `test_set_payload_charset_logs`: `set_payload('é', 'utf-8')` logs `content-type`, `content-transfer-encoding`, `mime-version` with their originals.
  - `test_start_is_idempotent`: change, `start_header_log()` again → log unchanged.
  - `test_pickle_and_deepcopy_carry_log`, `test_unpickle_without_log`: a pickle made from a `Message` whose `__dict__` lacks `_header_log` loads with `header_log is None`.
  - `test_unlogged_prepend`: `_unlogged_prepend('Message-Instance','v=1')` → first item, nothing logged.
- [ ] **Step 2:** Run `.venv/bin/python -m nose2 -s src mailman.email.tests.test_message.TestHeaderLog` — FAIL (AttributeError).
- [ ] **Step 3:** Override exactly `__setitem__`, `__delitem__`, `add_header`, `replace_header`, `set_boundary`, `set_raw`; each calls `self._log_header(name)` before `super()`. `_log_header` records `[v for k, v in self.raw_items() if k.lower() == name]` only if the log is running and `name` not yet in it. `set_boundary` logs `content-type`.
- [ ] **Step 4:** Rerun — PASS. Also rerun `mailman.email` and `mailman.handlers` — OK.
- [ ] **Step 5:** Commit `Message: log the original values of header fields Mailman changes`.

### Task 3: Arrival digests and status instead of received octets

**Files:**
- Modify: `src/mailman/runners/lmtp.py`, `src/mailman/handlers/message_instance.py` (ingress, `_strip_stamped`, remove `_received_bytes` / `without_received_bytes`), `src/mailman/handlers/to_archive.py`, `src/mailman/handlers/to_usenet.py` (back to upstream), `src/mailman/config/schema.cfg` (`message_instance` comment no longer mentions octets)
- Test: `src/mailman/runners/tests/test_lmtp.py`, `src/mailman/handlers/tests/test_message_instance.py` (`TestMessageInstanceFlow`, `TestQueueCopiesWithoutReceivedOctets` deleted)

**Interfaces:**
- Consumes: `Message.start_header_log()` (Task 2); existing `compute_header_hash_raw(raw)`, `compute_body_hash_raw(raw)`, `get_max_mi_version`, `_parse_mi`, `MalformedInstance`.
- Produces: `arrival_record(raw: bytes) -> dict` in `message_instance.py` returning `{'header_hash': bytes, 'body_hash': bytes, 'version': int, 'status': str}`, status one of `'none' | 'match' | 'mismatch' | 'malformed'` (top `m=` instance's `h=`/`b=` vs the digests; unparseable or duplicate `m=` → `malformed`). Stored as `msg.mi_arrival` (dict attribute). Ingress sets `msgdata['mi_snapshot']` (same shape as today) and `msgdata['mi_arrival_status']`.

- [ ] **Step 1: Failing tests:**
  - `test_lmtp`: with `[mta] message_instance: yes`, a delivered message in the `in` queue has `mi_arrival` equal to `arrival_record(<sent bytes CRLF>)`, no `original_bytes`, `header_log` running and containing `message-id-hash` (stamped after) and, for a post without Message-ID, `message-id`. With the option off: no `mi_arrival`, `header_log is None`.
  - `arrival_record` unit tests: no instance → `none`; matching `m=1` → `match`, version 1; body edited after signing → `mismatch`; `m=1` twice → `malformed`.
  - Ingress: message with `mi_arrival` → `mi_snapshot` built from it (version 0 for unsigned, highest `m=` for signed); `status == 'mismatch'` logs a warning. Message without `mi_arrival` (inject path) → record computed from `_serialize_msg(_strip_stamped(msg))`, log started, Message-ID-Hash appears in the log as `[]`. List with `dkim2_message_instance` false → `mi_arrival` removed, log stopped (`_header_log` deleted).
- [ ] **Step 2:** Run those tests — FAIL.
- [ ] **Step 3:** LMTP: replace the `original_bytes` assignment with `msg.mi_arrival = arrival_record(_normalize_crlf(envelope.content)); msg.start_header_log()`, placed directly after `set_unixfrom`. Ingress: as the Interfaces block says; drop the `verify_mi_raw` call.
- [ ] **Step 4:** Rerun — PASS; `mailman.handlers mailman.runners` OK (tests that relied on `original_bytes` are updated or deleted in this task, except decorate/body ones handled in Tasks 5-6 — mark those `@unittest.skip('Task 6')` and remove the skip there).
- [ ] **Step 5:** Commit `DKIM2: hash and check a post on arrival instead of keeping its octets`.

### Task 4: Header Recipe from the change log

**Files:**
- Modify: `src/mailman/handlers/message_instance.py` (egress header part; `_prepend_header` → `msg._unlogged_prepend`)
- Test: `test_message_instance.py` (new class `TestHeaderRecipeFromLog`)

**Interfaces:**
- Consumes: `header_log` (Task 2), `mi_snapshot` (Task 3), existing `compute_header_recipe(current, previous)`, `_collect_headers`, `_hash_header_pairs`, `_should_exclude_header`.
- Produces: `previous_header_pairs(msg) -> list[tuple[str, str]] | None` — current hashed pairs with each logged name's values replaced by its originals (positions: originals placed where that name's first current field was, or appended when absent now; per-name order is all the hash depends on). `None` when the log is not running.

- [ ] **Step 1: Failing tests:**
  - Subject prefixed + Reply-To added + Cc removed → Recipe restores all three; `undo_message_instance` (mi_support) gives headers whose hash equals `mi_snapshot['header_hash']`.
  - Untouched long folded header → not in the Recipe.
  - Signed post, header changed behind the log's back (append to `msg._headers` directly) → error logged, **no** Message-Instance added.
  - Unsigned post (version 0), same tampering → `m=1` added with no `h` Recipe key, error logged.
  - Message with no log (pre-upgrade pickle) → treated as header mismatch (same two branches).
- [ ] **Step 2:** Run — FAIL.
- [ ] **Step 3:** In egress, when `h_hash != snapshot['header_hash']`: `prev = previous_header_pairs(msg)`; if `prev` is not None and `_hash_header_pairs(prev) == snapshot['header_hash']` → `compute_header_recipe(_collect_headers(msg), prev)`; else mismatch handling per the spec (signed: return without adding; version 0: omit header Recipe).
- [ ] **Step 4:** Rerun — PASS.
- [ ] **Step 5:** Commit `DKIM2: header Recipes from the change log`.

### Task 5: Decorate records its wrap

**Files:**
- Modify: `src/mailman/handlers/decorate.py`
- Test: `src/mailman/handlers/tests/test_decorate.py` (new class `TestDecorateDKIM2Record`), delete `TestReceivedPart` and `TestDKIM2Wrap` cases that need received octets from `test_message_instance.py`

**Interfaces:**
- Produces: `msgdata['dkim2-decoration'] = {'shape': 'wrapped' | 'mixed', 'boundary': str, 'header': bool, 'footer': bool}` — set only when `_mi_enabled(mlist)` and decoration happened. `'wrapped'`: upstream's encapsulation path (original is part index 1 if header else 0). `'mixed'`: header/footer parts added to an existing multipart/mixed.

- [ ] **Step 1: Failing tests:** MI list + `decorate_plain_text_in_place: yes` (site) + text/plain → still wrapped, record shape `wrapped`, boundary equals the outer Content-Type boundary after `msg.as_bytes()`; multipart/mixed post → shape `mixed`; MI off → no record and in-place behaviour.
- [ ] **Step 2:** Run — FAIL.
- [ ] **Step 3:** Remove `_ReceivedPart`, `_dkim2_wrap`, `_decoration_part` and the imports from `message_instance`; make the in-place condition also require `not _mi_enabled(mlist)`; on the wrap path set an explicit boundary (`msg.set_boundary(...)` after setting Content-Type, using a uuid like the fork's `_new_boundary`) so it is known before serialisation; set the record.
- [ ] **Step 4:** Rerun — PASS; whole `test_decorate` OK.
- [ ] **Step 5:** Commit `decorate: on a DKIM2 list always wrap, and record how`.

### Task 6: Structural body Recipe with hash check

**Files:**
- Modify: `src/mailman/handlers/message_instance.py` (egress body part), `src/mailman/handlers/mime_delete.py`, `src/mailman/handlers/dmarc.py` (remove `body-modified`), `src/mailman/config/schema.cfg` (remove `message_instance_max_recipe_lines`)
- Test: `test_message_instance.py` (`TestBodyRecipeStructural`; delete `TestBodyDiff`, `TestBodyRecipeLimit`, octet-based `TestNullBodyRecipe` cases; un-skip Task 3 skips or delete them)

**Interfaces:**
- Consumes: `msgdata['dkim2-decoration']` (Task 5), `mi_snapshot['body_hash']`, `_wire_bytes(msg)`, `compute_body_hash_raw`.
- Produces: `structural_body_recipe(msg: Message, wire: bytes, record: dict | None, body_hash: bytes) -> list | None` — `None` means emit `NULL_BODY_RECIPE`.

- [ ] **Step 1: Failing tests** (each asserts `undo_message_instance` rebuilds a body whose hash is the snapshot's):
  - wrapped text/plain with header and footer → `[{'c': [k, k+n-1]}]`-shaped, no literals;
  - wrapped body containing a line `From me` → one literal `From me` amid copy ranges;
  - unchanged-body post with a `From ` line (no decoration, version 0) → Recipe with that literal;
  - multipart/mixed + header + footer → two copy ranges;
  - mime-delete stripped a part → `"b": null`, and no `body-modified` key anywhere in msgdata;
  - DMARC wrap → `"b": null`.
- [ ] **Step 2:** Run — FAIL.
- [ ] **Step 3:** Locate the original region by `record` (boundary delimiters in `wire`), or the whole body when `record` is None. Previous-body candidate: that region's message object serialised with `BytesGenerator(..., mangle_from_=False, policy=compat32.clone(linesep='\r\n'))` (for `'mixed'`: the outer body with the inserted parts' line spans removed). If candidate and wire region have equal line counts, emit copy ranges, with `{"d": [...]}` / `{"b": [...]}` literals (existing `_literal_steps`) only for lines that differ; hash the rebuilt previous body; return `None` on any count or hash mismatch. Delete `_body_diff`, `compute_body_recipe`, `_wrapped_body_recipe` and their constants.
- [ ] **Step 4:** Rerun `mailman.handlers` — OK.
- [ ] **Step 5:** Commit `DKIM2: body Recipes from the wrap's structure, checked by hash`.

### Task 7: Arrival status in X-DKIM2-Info

**Files:** Modify `message_instance.py` (egress `_dkim2_info` calls); test in `test_message_instance.py`.

**Interfaces:** Consumes `msgdata['mi_arrival_status']` (Task 3). Tag name `arrival`, value the status string; omitted when the key is absent (virgin pipeline).

- [ ] **Step 1:** Failing test: signed post whose top instance matched → X-DKIM2-Info contains `arrival=match;`; tampered → `arrival=mismatch;`; originator `m=1` → no `arrival=`.
- [ ] **Step 2:** Run — FAIL. **Step 3:** pass `arrival=msgdata.get('mi_arrival_status')` to `_dkim2_info`. **Step 4:** PASS.
- [ ] **Step 5:** Commit `DKIM2: report the arrival check in X-DKIM2-Info`.

### Task 8: Full-pipeline test, docs, tidy

**Files:**
- Test: `src/mailman/handlers/tests/test_mi_roundtrip.py` (new `TestEveryHeaderFeature`)
- Modify: `DKIM2-MESSAGE-INSTANCE.md` (design, resource impact: no octet copy; queue growth = log + 64 bytes), remove dead helpers (`verify_mi_raw` if unused, `_SEND_MESSAGE_DROPS` stays)

- [ ] **Step 1:** Failing/at-risk test: list with `subject_prefix`, `reply_goes_to_list` (explicit Reply-To), `dmarc_mitigate_action: munge_from` + unconditional, `filter_content` off, header + footer templates, `personalize: full`; run the posting pipeline then `Deliver` for two members; for each copy `verify_message_instance` passes and undo reaches `mi_snapshot`'s hashes. Repeat with a signed `m=1` post.
- [ ] **Step 2:** Run — fix any unlogged header path found (add the override or route the code through the class), rerun until PASS.
- [ ] **Step 3:** `git grep -n "original_bytes\|body-modified\|dkim2-wrap\|max_recipe_lines\|_ReceivedPart\|without_received_bytes" src/ DKIM2-MESSAGE-INSTANCE.md` → no output. flake8 + isort clean on all touched files.
- [ ] **Step 4:** Commit `DKIM2: whole-pipeline round trip; docs for the light form`.

### Task 9: Box verification (once)

- [ ] **Step 1:** Push nothing; bundle `dkim2-light` to the box (`git bundle create`, scp, fetch into `/opt/mailman/src-test`; check `git status` there first — memory: stray migrations break the REST layer).
- [ ] **Step 2:** Full Mailman suite in `/opt/mailman/test-venv` per SERVER.md — expected OK (count ≥ previous 150 minus deleted tests; report).
The charset corpus needs the deployed install, so it runs in Task 10 Step 6.

### Task 10: Upstream series, replace branches, deploy

- [ ] **Step 1:** Rewrite `dkim2-light` into a reviewable series on `decorate-always-wrap` (suggested: header log; per-list flag + migration; arrival digests; Message-Instance handlers; docs). Each commit passes `mailman.handlers mailman.email mailman.runners` locally.
- [ ] **Step 2:** Replace branches: tag old heads `dkim2-history-2026-11-13` on `dkim2`, `dkim2-3.3.10`, `dkim2-3.3.8`; reset `dkim2` to the new series (it now includes the `decorate-always-wrap` commit); cherry-pick the series onto `v3.3.10` + the two py3.13 fixes for `dkim2-3.3.10` (one box suite run) and onto `3.3.8` for `dkim2-3.3.8` (no tests). Adjust migration `down_revision` per branch as before.
- [ ] **Step 3:** `util/export-list-patches.sh` then `--check` (interop) — all series apply. Update the README in `interop/mailman/` if counts changed.
- [ ] **Step 4:** Ask Bron before force-pushing the `brong` remote branches and tags.
- [ ] **Step 5:** Deploy ("Updating Code on the Server" in SERVER.md): hold Postfix delivery to Mailman (`postsuper -h` on mail for the list transport, or stop the transport), wait for `out`/`retry` queues to empty, `pip install --force-reinstall --no-deps 'git+https://github.com/brong/mailman@dkim2-3.3.10'`, `mailman info` (migrations), start.
- [ ] **Step 6:** Prod checks: `deploy/dkim2-list-smoke.sh` PASS; `util/charset-corpus.sh` against the Mailman corpus list — report verify count (target ≥ 85/88) and `"b": null` count; queue file size for a sample post vs stock (short run, feedback_short_benchmarks).
- [ ] **Step 7:** Update memory (project_mailman_sympa_deploy_from_branch, project_mailman_always_wrap) and interop docs that describe `original_bytes`.
