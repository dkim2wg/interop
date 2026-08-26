# DKIM2 draft-05 Spec Upgrade — Design

**Date:** 2026-08-25
**Status:** Approved (design); implementation plan to follow
**Precedent:** `docs/superpowers/specs/2026-07-05-dkim2-spec-04-upgrade-design.md` (executed to completion)
**Authoritative spec:** `spec/draft-ietf-dkim-dkim2-spec-05.txt` — SHA-256 verified against the
published copy on ietf.org, 2520 lines.

> **The published `.txt` is the only source of truth for this delta.** The `-05` markdown
> source is *not* in git. Every ref on `dkim2wg/spec` — `main`, `v04`, `03version`, PRs 1–7 —
> was checked and none contains `sha512`, the duplicate-Selector text, or the lower-case-keys
> rule; `main` still says `docname: draft-ietf-dkim-dkim2-spec-04`. `-05` was submitted from an
> author's local tree. Do not try to regenerate from the repo, and do not assume a later
> `main` supersedes this document without re-checking.

## Goal

Bring all seven DKIM2 implementations into conformance with `draft-ietf-dkim-dkim2-spec-05`,
bump every embedded spec-version string to `-05` / `2026-08-25`, and deploy through to
production acceptance on the box.

| Codebase | Path | Role |
|---|---|---|
| Perl `Mail::DKIM2` | `interop/perl` | **Deployed** — backs the milter, reflector, validator; Sympa's dependency |
| C | `interop/c` | interop reference (lib + milter) |
| Go | `interop/go` | interop reference |
| Python | `interop/python` | interop reference (sign/verify/undo/dsn) |
| Browser JS | `interop/deploy/www/verify` | client-side verifier, live at https://dkim2.com/verify/ |
| Mailman | `mailman` (branch `dkim2`) | list manager — embedded Message-Instance handler |
| Sympa | `sympa` (branch `dkim2`) | list manager — depends on Perl `Mail::DKIM2` |

Out of scope: `interop/hs/` and `interop/rnc1/` are third-party sample data, not our
implementations. `interop/deploy/www/validate` is a thin UI over the Perl validator and needs
only its displayed hash-name to stop being hardcoded.

## The -04 → -05 delta

Derived from a paragraph-level normalized diff of the two published `.txt` files, cross-checked
against §17 "Changes from Earlier Versions".

| # | Change | Section | Wire-affecting |
|---|---|---|---|
| A | `sha512` added: `hash-name = "sha256" / "sha512" / x-hash-name`. Signers MAY implement either or both hashes and either or both signature algorithms; **Verifiers MUST implement all four algorithms** | §3, §3.1, §7.3 | yes |
| B | An algorithm MUST NOT repeat within one Message-Instance `h=` | §7.3 | yes |
| C | A Selector MUST NOT repeat within one DKIM2-Signature `s=`; the same signing algorithm may appear at most twice, and only with distinct Selectors | §8.9 | yes |
| D | Recipe JSON keys MUST be lower case (was: any case, provided no two differ only by case). Matching against the message stays case-insensitive | §5.1 | yes |
| E | Unsigned header list expanded; `ARC-` prefix narrowed to three exact names; `Received-*` prefix rule added | §4, §4.1 | yes |
| F | Four new PERMERROR strings | §11.2 | no |
| G | §9.1: dropped the SHOULD NOT on pointless Message-Instance fields; "currently highest" → "previously highest numbered"; "All other MI fields SHOULD contain at least one recipe" → "will contain" | §9.1 | no |
| H | Editorial capitalisation sweep: Recipes / Selector / Chain of Custody | throughout | no |
| I | Version strings → `-05`, date → `2026-08-25` | — | yes (provenance headers) |

## Current conformance state (audited 2026-08-25)

### Hash-set parsing — the bulk of the work

| | parses `h=` as a list? | checks the alg name? | sha512-ready |
|---|---|---|---|
| C | ✅ `parse_hsets` (`c/dkim2_header.c:20`) | ❌ **ignores `alg` entirely** | ❌ |
| Browser JS | ✅ `parseHashSets` | ✅ `sets.find(s => s.alg === 'sha256')` | ❌ |
| Python | ❌ `h_tag.split(":")`, requires `len == 3` (`dkim2verify.py:317`) | ✅ rejects non-`sha256` | ❌ |
| Go | ❌ `strings.SplitN(h, ":", 3)` (`go/dkim2/mi.go:42`) | ✅ `parts[0] != "sha256"` | ❌ |
| Perl | ❌ regex `/\bh=sha256:(…):(…)/` (`Verifier.pm:24`) | implicit in the regex | ❌ |

**C carries a live bug, independent of -05.** It loops every hash-set but never reads
`hsets[hi].alg`, b64-decoding each into a fixed `DKIM2_HASH_LEN` (32-byte) buffer. A message
carrying `h=sha256:…,sha512:…` fails today with `PERMERROR: bad body hash` — which also
violates *-04's* §3.4 ("Verifiers MUST ignore any hashes or signatures using algorithms that
they do not implement"). This must be fixed regardless of the rest of this work.

### Everything else

| Item | C | Go | Python | Perl | JS | Mailman | Sympa |
|---|---|---|---|---|---|---|---|
| A sha512 verify | ❌ | ❌ | ❌ | ❌ | ❌ | — | — |
| A sha512 sign (`--hash`) | ❌ | ❌ | ❌ | ❌ | — | — | — |
| B duplicate hash alg | ❌ | ❌ | ❌ | ❌ | ❌ | — | — |
| C duplicate Selector / ≤2 per alg | ❌ | ❌ | ❌ | ❌ | ❌ | — | — |
| D lower-case Recipe keys (emit) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | delegated |
| D invalid-JSON PERMERROR | ❌ | ❌ | ❌ | ❌ | ❌ | — | — |
| E unsigned header list | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | inherited |
| F error strings | ❌ | ❌ | ❌ | ❌ | ❌ | — | — |
| I version strings | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

**Item D is already done everywhere — it is a comment fix, not a code change.** All seven force
lower case on emit: Perl `MessageInstance.pm:120`, Go `recipe.go:38`, Python
`dkim2sign.py:239`, C `dkim2_recipe.c:332` (lowercases before `cJSON_AddItemToObject`), JS
`recipes.js:45`, Mailman `message_instance.py:350` (collects by lowercase name), Sympa
delegated. Three carry a now-false comment — *"not yet mandated by the draft, but we do it"*
(Perl:120, Go:38) and *"Not yet mandated by the draft, but we always do it"*
(Python:243) — plus two test files echoing it (`go/dkim2/recipe_test.go:8`,
`python/tests/test_recipe_case.py:2`). All five now cite §5.1 instead.

## Design

### 1. Hash agility

Approach: **a hash-set list plus a per-language supported-algorithm table.** Each
implementation parses `h=` into an ordered list of `{alg, headerHash, bodyHash}` and looks each
`alg` up in a small registry mapping name → digest function and length.

Rejected alternatives:

- *Minimal patch* (`if alg == "sha512"` beside the existing single-hash-set code). A mixed
  `h=sha256:…,sha512:…` is precisely what -05 invites other implementations to send, and three
  of our five verifiers cannot parse a list at all. Rejected.
- *Pluggable agility layer* with `x-hash-name` dispatch. §3.4 says ignore what you don't
  implement, which a fixed table already handles. YAGNI.

**Verification semantics.** -05 does not spell out multi-hash-set verification the way §11.6
does for multi-signature. Settled reading, approved:

> Verify every hash-set whose algorithm we implement, and require **all** of them to pass.
> If **no** hash-set names an implemented algorithm, **fail closed**.

This mirrors §11.6's all-signatures-must-pass reasoning and the existing browser-JS
fail-closed comment (`verify.js:237`). Hash-sets naming unimplemented algorithms are skipped
per §3.4.

**Signing.** A `--hash sha256|sha512|both` option on the Python, Go, C and Perl signing CLIs,
**defaulting to `sha256`**. sha256-only signing stays conformant under -05 (§3: "Signers MAY
implement either or both"), so the default keeps every fixture, golden vector and the live box
byte-identical, while `--hash both` gives us a way to generate dexterity probes for other
implementations — the stated purpose of adding sha512. Mailman and Sympa keep sha256 with no
new flag surface.

### 2. Duplicate and limit checks

Verifier-side only; our signers never emit more than one of anything.

| Condition | Error |
|---|---|
| an algorithm repeats within one `h=` | `PERMERROR Message-Instance m=<x> has a duplicate hash algorithm` |
| a Selector repeats within one `s=` | `PERMERROR DKIM2-Signature i=<x> has a duplicate selector` |
| any signing algorithm appears 3+ times in one `s=` | `PERMERROR DKIM2-Signature i=<x> has too many signatures` |

These are independent checks: two signatures sharing an algorithm *and* a Selector is a
duplicate-Selector error but not a too-many-signatures error (the count is 2, not 3+).

**Case handling — a deliberate reading past the literal text.** RFC 5234 makes ABNF quoted
strings case-insensitive, so `SHA256` is a syntactically valid `hash-name`. Hash-name
recognition and duplicate detection are therefore done case-insensitively, replacing today's
exact `strcmp`/`==` comparisons. Selector is `Domain` (§3.5), and DNS names are
case-insensitive, so duplicate-Selector detection is likewise case-insensitive. Both choices
are strictly more permissive than current behaviour and cannot reject anything we accept today.

### 3. Unsigned header fields (§4)

Add to every exclusion list: `apparently-to`, `auto-submitted`, `dl-expansion-history`,
`original-recipient`, `sio-label-history`, `vbr-info`, `x400-received`, `x400-trace`; add a
`received-` **prefix** rule; narrow the `arc-` prefix to exactly `arc-authentication-results`,
`arc-message-signature`, `arc-seal`.

Six lists to change — `go/dkim2/canon.go:51`, `python/dkim2sign.py:104`,
`deploy/www/verify/canon.js:3`, `perl/lib/Mail/DKIM2/Common.pm:45`, `c/dkim2_hash.c:125`,
`mailman/src/mailman/handlers/message_instance.py:127`. Sympa delegates to
`Mail::DKIM2::Common::should_skip` and inherits.

**The ARC narrowing is a no-op in practice.** RFC 8617 defines exactly three ARC header fields,
and a sweep of every fixture, vector and captured message across all three trees finds only
those three. It matters only if a deployment invents a non-standard `ARC-`-prefixed field,
which would now be signed. Implement it precisely and test it, but it carries no regression
risk.

**The `Received-*` rule does carry regression risk, and it has already landed on us.** These
committed Perl fixtures carry `Received-SPF: pass`:

- `perl/tests/expected/chain-hop6-unchanged-re-sign.eml` — 6 DKIM2-Signatures, 5 Message-Instances
- `perl/tests/expected/chain-hop5-final-delivery.eml` — 5 DKIM2-Signatures, 5 Message-Instances
- `perl/tests/emails/spam.eml`, `perl/tests/emails/brong-final.eml` — unsigned inputs

Under -04 `Received-SPF` is signed (it is not `received`, and does not start with `x-`/`arc-`).
Under -05 it becomes unsigned, so **every header hash in those golden fixtures changes** and all
signatures and Message-Instances in them must be regenerated. The equivalents in the other
languages must be swept for the same pattern before regenerating anything.

Also: `deploy/www/verify/canon.js` omits `message-instance` and `dkim2-signature` from
`UNSIGNED_EXACT` — they are filtered upstream in `signedFields`, so behaviour is correct, but
the list reads as incomplete next to the other five. Add them for parity.

### 4. Recipes (§5.1)

Lower-case emission is already correct in all seven (see the audit above). The only work is
updating the three stale *"not yet mandated by the draft"* comments and the two test files
echoing them to cite §5.1.

Add `PERMERROR Message-Instance m=<x> contains invalid JSON` as a distinct outcome from a
generic syntax error, per §11.2's "To assist debugging, errors in a JSON object specifying
Recipes should be called out specifically."

Matching against the message stays case-insensitive (§5.1 is explicit). **Keep** the existing
keys-differing-only-in-case rejection: -05 dropped that MUST NOT, but under mandatory
lower-case such a pair is non-conformant anyway, and matching it case-insensitively is
ambiguous. Retaining the check cannot reject any conformant Recipe.

### 5. §9.1 and editorial

Remove any encoded SHOULD-NOT-add-a-pointless-Message-Instance enforcement; adding one is now
merely "pointless", not forbidden. Update wording to "previously highest numbered". Apply the
Recipes / Selector / Chain of Custody capitalisation to comments, docstrings and docs.

### 6. Version strings

`ietf-dkim-dkim2-spec-04` → `-05`, `2026-07-05` → `2026-08-25`:

- `perl/lib/Mail/DKIM2/Common.pm:41,43` — feeds the live `X-DKIM2-Info` provenance header
- `sympa/src/lib/Sympa/Message.pm:464,466`
- `mailman/src/mailman/handlers/message_instance.py` (`DKIM2_DRAFT`, `DKIM2_DATE`)

Two tests pin these and will fail until bumped: `perl/t/version.t:4-5` and
`mailman/src/mailman/handlers/tests/test_message_instance.py`. Roughly 233 further
`spec-04`/`draft-04`/`2026-07-05` references across comments and docs get swept.

## Testing

1. Each language's own suite green.
2. `./util/turscar-all.sh` — the Turscar `dkim2tests` vectors against all five verifiers.
   Check upstream for new -05 vectors before running.
3. **Cross-implementation matrix:** sign with each of the four signing CLIs at `--hash sha256`,
   `--hash sha512` and `--hash both`; verify each output with all five verifiers. This is the
   only thing that actually proves hash agility works, and it is new coverage — no existing
   test exercises a non-sha256 hash.
4. Negative vectors, hand-built, one per new PERMERROR: duplicate hash algorithm, duplicate
   Selector, three same-algorithm signatures, malformed Recipe JSON.
5. Regenerated Perl chain fixtures verify clean end-to-end.

## Deployment

Per the standing definition of done: deploy everything to the box — Mailman and Sympa from
their `dkim2` branches, not master/main — then run `deploy/dkim2-list-smoke.sh` and acceptance-
test on prod. The `X-DKIM2-Info` provenance header should read `draft=ietf-dkim-dkim2-spec-05;
date=2026-08-25` on live mail afterwards.

## Risks

| Risk | Mitigation |
|---|---|
| Regenerated Perl fixtures bake in a *wrong* hash, turning a broken implementation green | Regenerate only after the §4 list change is reviewed; cross-verify each regenerated fixture with a second implementation, not just the one that produced it |
| The `Received-*` sweep misses a fixture in another language | Grep every tree for `^Received-[A-Za-z0-9-]+:` before regenerating, not just the Perl tree |
| C's fixed 32-byte hash buffers overflow on sha512 | The registry carries digest length; audit every `DKIM2_HASH_LEN` use on the hash path |
| Prod regression from the unsigned-list change | Smoke test on the box before declaring done; `X-DKIM2-Info` gives a quick visual confirmation of which build is live |
