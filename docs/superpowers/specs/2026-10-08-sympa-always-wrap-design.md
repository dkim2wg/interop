# Sympa DKIM2: rebuild as always-wrap, null body Recipe, and a performance harness

Date: 2026-10-08

## Why

The Sympa series (`dkim2` on brong/sympa, three commits on 6.2.78) predates
the Mailman always-wrap rework. Before rebuilding it we ran two adversarial
reviews of it (correctness and performance) against the tag
`dkim2-cte-preserve-6.2.78` (`bc6d4413b`). Both said rebuild.

Correctness, confirmed by running the code:

- **Breaks lists with DKIM2 off** (commit 1, "Preserve the body encoding"):
  - QP posts on `footer_type append` lists are double-encoded
    (`Caf=C3=A9` reaches readers) and the footer lands above the body;
  - non-ASCII footer and personalisation text becomes `?` (`body_encode`
    substitutes instead of dying, so the UTF-8 fallback never runs);
  - opaque S/MIME and message/rfc822-first multiparts gain a footer part;
  - `decorate()` dies when Algorithm::Diff is missing.
- **Leaks private data:**
  - anonymous lists carry the real From/Organization in the header Recipe,
    because the snapshot is taken before anonymisation;
  - S/MIME lists put the decrypted plaintext in the body Recipe (snapshot
    after `smime_decrypt`).
- **Breaks the chain:**
  - moderated, held and auth messages lose the in-memory snapshot
    (`mi_original`) and go out with a stale m=1;
  - resend-from-archive does the same;
  - MDN tracking rewrites `Disposition-Notification-To` after the instance
    is built.
- **Unbounded Recipes:** `"b": null` is never used. Notice mode on a post
  with a 300 KB attachment gives a 572 KB Message-Instance header per
  recipient, which Postfix truncates at `header_size_limit` (102400).
- **No switch:** it is on wherever `Mail::DKIM2::MessageInstance` loads.

Performance, from reading the code and timing it (micro-timings of the same
functions):

- **The base64 re-wrap** (`_restore_b64_wrapping`) is a character-level
  Algorithm::Diff that also runs with DKIM2 off:
  - about 500 MB RSS per MB of body in the best case;
  - quadratic when an edit shifts base64 alignment: a 30 KB body takes 33 s,
    and a 40 KB post with a list header 47 s;
  - txt mode diffs the attachments too: 75 s for a 1 MB attachment.
- **`_fold_mi_header` is quadratic:** a 1.9 MB header takes 26 s. Any body
  Sympa re-encodes differently from the sender hits it, for example
  attachments wrapped at 72 columns, or any multipart.
- **Egress work is repeated:** it is redone per packet, or per recipient
  under merge, VERP or tracking. Each pass does five Email::MIME parses and
  about seven SHA-256 passes, peaking around 45× the message size.
- **Spool:** `.mi_orig` doubles the spool, is re-read per packet and leaks on
  some error paths.

The parts worth keeping: the ProcessIncoming/ProcessOutgoing hook points,
`as_rfc822_string`, verify-before-build, Bcc/Resent-Bcc removal recorded in
the Recipe, and numbering from max(m)+1. Commit 3 (X-DKIM2-Info) stays as is.

## Decisions

- **Keep the old series:** tag `dkim2-cte-preserve-6.2.78` (local; never
  delete). The rebuilt `dkim2` branch replaces commits 1 and 2.
- **Always-wrap:** same policy as Mailman. On a DKIM2 list every decorated
  post is a raw-splice MIME wrap, and a body changed for any reason gets a
  null body Recipe (`"b": null`).
- **Carry original headers in a pseudo-header:** the received header block
  travels in an `X-Sympa-*` pseudo-header through every spool. The body hash
  is not stored again; it is already in the top Message-Instance's `h=`.
- **Diff the headers at egress** rather than account for each change along
  the way. It costs little and catches every change. Accounting was
  rejected because Sympa edits `$entity->head` from too many places to hook
  reliably.
- **Anonymous lists and resend-from-archive** strip the upstream chain. The
  outbound signer then originates m=1.
- **S/MIME-encrypted lists** get a null body Recipe.
- **`remove_headers`:** removed fields that are hashed (not `X-`, not trace)
  stay in the header Recipe, as spec §5.1 requires. This is documented, not
  special-cased.
- **Sympa never originates an instance:** mail it composes or sends directly
  gets m=1 from the outbound signer (`dkim2-milter` adds one when absent).

## §1 Sympa change

### Switch

A new list parameter `dkim2_message_instance` (`on`/`off`), with robot and
site defaults, default `off`. With it off, Sympa behaves exactly like stock
6.2.78: no pseudo-header, no wrap, no Message-Instance, no X-DKIM2-Info. A
missing `Mail::DKIM2` with the switch on logs once per message at `err` and
behaves as off.

### Ingress (`Spindle::ProcessIncoming`, once per message)

This runs before `smime_decrypt` and before any header change. Anonymous
lists skip it.

1. If the message has no Message-Instance, add m=1 describing it as
   received. If it has one (inbound milter or signing sender), keep it.
2. Store the received header block, base64, as a pseudo-header (working
   name `X-Sympa-DKIM2-Headers:`).
   - `Sympa::Message::to_string` writes it and `new_from_file` reads it, so
     it travels through the msg, moderation, held, auth, topic, bulk and bad
     spools with no spool-specific code.
   - It is never part of the message proper: `as_string` doesn't emit it,
     and archive copies don't carry it.

### Egress (`Spindle::ProcessOutgoing`, last step before DKIM/ARC signing)

Moved ahead of this step:

- the MDN `Disposition-Notification-To` rewrite;
- the DomainKey-Signature removal;
- anything else that edits hashed headers after the current MI call. The
  review found these two; the plan must audit for more.

Once per packet:

1. Decode the saved header block. If there is none (for example, the
   switch was turned on while the message sat in a spool), add no instance
   and log at `info`. Otherwise check the top instance's header hash
   against it. On a mismatch, log and add no instance (as now: never build
   on a broken chain).
2. Hash the current body (canonicalised as the spec requires) and compare
   it with the top instance's `h=` body hash.
   - **Equal (body unchanged):** decoration on a DKIM2 list is a MIME wrap
     (next section). The body Recipe is literal / one copy range / literal,
     built from the layout. A post with no decoration is not wrapped, and
     its body Recipe is a single copy range.
   - **Different:** `"b": null`. Covered: S/MIME, the txt, html, urlize and
     notice reception modes, body merge, content filters, and anything not
     yet thought of.
3. Build the header Recipe from the saved header block against the outgoing
   header block. Bcc/Resent-Bcc removal is recorded as now.
4. Add the next `m=` (max+1), with X-DKIM2-Info above it, folded with the
   linear folder from `Mail::DKIM2::Common`.

Per recipient (inside `__twist_one`, used for merge, VERP and tracking):

- VERP and DSN tracking change only the envelope, so the packet's instance
  is reused as is.
- Footer-only personalisation changes only the trailing footer. Each
  recipient's body hash is a full pass at first. Reusing the SHA-256 state
  of everything before the footer is done only if the benchmark shows the
  per-recipient hash matters (plan Task 12).
- Body merge (`mail_apply_on: all`) means `"b": null` for each recipient.

Failure handling: the whole DKIM2 step runs in an `eval`. On any exception
it logs (a valid Sympa level) and the message goes out without the new
instance. List mail is never blocked or lost because of DKIM2.

### Wrap (`Sympa::Message::decorate` on a DKIM2 list, body unchanged)

- Output: `multipart/mixed`, containing:
  1. an optional `message_header` part, `text/plain` in UTF-8;
  2. the original part: the original `Content-*` fields from the saved
     headers, a blank line, then the raw `_body` octets byte for byte;
  3. the footer part(s), personalised per recipient where configured.

  It uses a fresh boundary that is checked not to occur in the body. The
  preamble is a one-line note for readers without MIME support, as in
  Mailman.
- `footer_type append` is ignored on DKIM2 lists.
- Built by string assembly, not through MIME::Entity, so the original part
  is never re-encoded. The Recipe's copy range is computed from the line
  offsets of the assembled pieces.
- Where stock Sympa skips decoration, we skip too. Stock `decorate()`
  returns early for `multipart/signed` and `multipart/encrypted`. On DKIM2
  lists opaque `application/pkcs7-mime` is skipped as well, so the body
  Recipe is a copy.

### Special cases

| Case | Behaviour |
|---|---|
| S/MIME encrypted list | headers saved before decrypt; re-encrypted body differs, so `"b": null`; no plaintext in any header |
| `multipart/signed`, `multipart/encrypted` (stock skips), opaque `application/pkcs7-mime` | untouched; no body Recipe |
| txt, html, urlize, notice reception modes | `"b": null`; instance built per mode's packets |
| Body merge | `"b": null` per recipient |
| Footer-only merge | wrap; per-recipient trailing literal |
| Anonymous list | no pseudo-header at ingress; egress strips DKIM2-Signature, Message-Instance and X-DKIM2-Info; signer adds m=1 |
| Resend from archive | strip the chain as for anonymous lists |
| digest, digestplain, summary | new message: Sympa adds nothing; embedded messages' instances are content, left alone |
| Notifications, auto-replies, ToMailer direct sends, bounces | Sympa adds nothing (removes today's originating m=1 in ToList, ToMailer, ResendArchive) |
| VERP, DSN tracking | envelope only; no effect on the instance |
| MDN tracking | header rewrite moved before the DKIM2 step |
| DMARC From rewrite, subject tag, custom headers, topics, `remove_headers` | header changes, captured by the egress diff |
| Requeued from `bad/` | pseudo-header is in the spooled text, so the chain survives |
| Archive copies | stored without the pseudo-header |

### Removed

- Commit 1 in full: the re-encode skip, charset preference, separate-part
  fallback, QP encoded-level append, base64 re-wrap and Algorithm::Diff.
- `.mi_orig` and `Spool::Outgoing`'s link/read/cleanup code.
- `mi_original` on the message object, and the diff and flat Recipe builders
  on the egress path.
- `_fold_mi_header`'s use of TextWrap.
- Originating m=1 in ToList, ToMailer and ResendArchive.

### Series

Rebuilt `dkim2` on 6.2.78, upstream-review sized:

1. Add the `dkim2_message_instance` list parameter (off by default).
2. Message-Instance at ingress and egress, with the header pseudo-header,
   always-wrap decoration and the null body Recipe.
3. The X-DKIM2-Info debug header (today's commit 3, rebased).

Exported to `interop/sympa/patches-6.2.78/`, replacing the three current
patches. `DKIM2-MESSAGE-INSTANCE.md` is rewritten to match: spec-06 wire
format, real resource figures from §2, and the `remove_headers` note.

### Tests (Sympa)

`t/Message_DKIM2.t` is rewritten. It runs in CI without `skip_all`; the test
finds Mail::DKIM2 through PERL5LIB, documented in the test's header. It
drives the real `decorate()`, not helper return values, and checks with
`chain_verifies` and Mail::DKIM2 undo. Cases:

- the 19 real-decorate cases from the review, which must keep passing:
  7bit, CRLF, no final newline, latin1 8bit, html-only, empty body, long
  line, multipart/alternative, mixed with PDF, PGP/MIME, header-only
  changes, odd folding, `Keywords:abc`, Bcc, image-only, dot lines, trailing
  blanks, bare CR;
- the review's failure reproductions, which must now pass or be inert:
  - the QP append and non-ASCII footer render correctly, with DKIM2 on and
    with it off;
  - the anonymous list carries no original From anywhere;
  - S/MIME gives `"b": null` and no plaintext;
  - moderated and held mail goes through `to_string`/`new_from_file` and
    still verifies;
  - resend from archive strips the chain;
  - MDN tracking verifies;
  - notice and txt modes give `"b": null` with a small header;
- switch off: output byte-identical to stock 6.2.78 for the whole
  real-decorate set;
- personalisation, footer-only and body merge, across several recipients.

## §2 Performance harness

Location: `util/sympa-bench/` in interop, following `util/mailman-bench/`.
It runs on dkim2-dev under `/opt/sympa-bench/`, never touching production
Sympa, its spools or its database. Raw results are gitignored. The summary
goes in `docs/sympa-dkim2-performance.md`, plus an HTML report page.

### Builds

| id | build | DKIM2 |
|---|---|---|
| `up` | 6.2.78 | n/a |
| `cte` | tag `dkim2-cte-preserve-6.2.78`, Mail::DKIM2 installed | on (no switch exists) |
| `cte-nomod` | same, Mail::DKIM2 not on `@INC` | the old series' only "off" |
| `wrap` | rebuilt `dkim2` | list switch on |
| `wrap-off` | same | list switch off |

Each build is a separate install prefix. `cte-nomod` and `wrap-off` reuse
the `cte` and `wrap` installs.

### Corpus

Shared with the Mailman harness where possible:

- the 317 charset-corpus samples;
- single-part base64 text and HTML at 10 KB, 30 KB, 100 KB, 1 MB and 5 MB;
- single-part QP;
- multipart/alternative with a QP HTML part;
- 1, 10, 25 and 50 MB attachments, each base64-wrapped at both 76 and 72
  columns;
- latin1 and ISO-2022-JP bodies with a UTF-8 footer;
- posts that already carry a Message-Instance.

Each message is run unsigned and DKIM2-signed.

The `cte` build's known pathological cases (quadratic re-wrap and fold) run
under a timeout. A timeout is recorded as a result, and the run continues.

### In-process driver (`bench_inproc.pl`)

It loads each build's Sympa libraries with a throwaway config (SQLite list
database, temporary spool directories) and drives, per message:

1. ProcessIncoming;
2. ToList, including `_test_personalize`;
3. the spool round trip through `to_string`/`new_from_file`;
4. ProcessOutgoing per packet and per recipient, against a capturing mailer.

It runs under `systemd-run --scope -p MemoryMax=700M`, so an OOM is a
recorded result.

List configurations:

- footer only, and `message_header` plus footer;
- `footer_type` mime and append;
- personalisation off, footer-only and all (with `[% user.email %]` near the
  top and in the middle of the body);
- `verp_rate` 0% and 100%;
- reception modes mail, txt, notice and digest;
- 25 and 1000 members, over many domains (many packets) and few domains.

Recorded per stage:

- CPU time and peak RSS, for ingress, ToList, decorate, egress and fold;
- spool bytes and inodes;
- wire bytes per recipient;
- Message-Instance header length, flagged when over 100 KB;
- whether the output verifies and undoes (Mail::DKIM2).

Median of 5 runs, as JSON lines.

### Soak (`soak.sh`)

One build at a time runs as a real Sympa instance with its own prefix,
spools, SQLite database and ports:

- sympa_msg plus several bulk children;
- an SMTP sink that discards everything;
- a 700M cgroup cap;
- 1000 members.

The corpus subset under 2 MB is injected 3×. Every second it samples
per-process VmRSS/VmHWM and CPU from `/proc`, and `du` of every spool.
Reported: peak and mean RSS, total CPU, peak spool disk and drain time.

### Report (`bench_report.pl` or `.py`)

Compares each build with `up`: median, p95 and max, by size class, list
configuration and signed/unsigned. Writes the markdown summary and the HTML
page.

### Success criteria

- `wrap-off` matches `up` within noise.
- `wrap` is linear in message size and in recipients. No
  Message-Instance header exceeds a few KB except for header-Recipe-heavy
  cases.
- Numbers that answer the review's claims for `cte`, so the rebuild's gain
  is measured, not asserted.

## Acceptance (definition of done)

- Sympa's test suite and the new `t/Message_DKIM2.t` pass, locally and on
  the box.
- Interop Perl tests pass; the shared harnesses stay green
  (negative-vectors, signer-gate, hash-matrix, interop-fold-mi).
- Deployed to dkim2-dev from the rebuilt `dkim2`, with production lists set
  `dkim2_message_instance: on` (dkim2corpus, dkim2test and the smoke lists).
- Charset corpus replay: 317/317 through the Sympa corpus list, verified by
  all five verifiers. The smoke list round-trips.
- Captured checks on the box:
  - a QP post on an append-footer list renders correctly;
  - a notice/txt-mode delivery arrives signed with `"b": null`;
  - an anonymous-list post carries no original From;
  - a moderated post verifies after approval.
- Benchmark run complete; report published.
- `sympa/README.md`, `sympa/patches-6.2.78/` and
  `docs/dkim2-postfix-list-host-guide.md` (Sympa parts) updated.

## Interim (needs Bron's yes)

Production on dkim2-dev runs the old series now, including commit 1's QP
and charset breakage for every list. Option: revert commit 1 alone on the
box before the rebuild lands. Not done until approved.

## Out of scope

- Upstreaming to sympa-community (the series is sized for it; submission is
  separate).
- "Queue only the bytes" style spool changes beyond dropping `.mi_orig`.
- Sympa versions other than 6.2.78.
