# DKIM2 draft-04 Spec Upgrade — Design

**Date:** 2026-07-05
**Status:** Approved (design); implementation plan to follow
**Supersedes:** `docs/superpowers/plans/2026-06-24-dkim2-spec-03-upgrade.md` (never executed to completion; its still-open items are absorbed here)
**Authoritative spec:** `/Users/brong/src/spec/draft-ietf-dkim-dkim2-spec.mkd` (`docname: draft-ietf-dkim-dkim2-spec-04`, v04 dated 2026-07-05)

## Goal

Bring all six DKIM2 codebases into full conformance with `draft-ietf-dkim-dkim2-spec-04`,
bump every embedded spec-version string to `-04`, refresh the interop repo's stale
committed spec copy, and deploy the Perl stack to `mail.dkim2.com`.

The six codebases (one shared spec):

| Codebase | Path | Role |
|---|---|---|
| Perl `Mail::DKIM2` | `/Users/brong/src/interop/brong` | **Deployed** — backs the milter, reflector, validator; Sympa's dependency |
| C | `/Users/brong/src/interop/c` | interop reference (lib + milter) |
| Go | `/Users/brong/src/interop/go` | interop reference |
| Python | `/Users/brong/src/interop/python` | interop reference (sign/verify/undo/dsn) |
| Mailman | `/Users/brong/src/mailman` | list manager — embedded Message-Instance handler |
| Sympa | `/Users/brong/src/sympa` | list manager — depends on Perl `Mail::DKIM2` |

## Background: the -02 → -04 spec delta

The spec advanced `-02 → -03 → -04`. Most *normative* change landed in **-03**; **-04**
is mostly clarifying text plus a few small normative additions. The
implementation-relevant items:

| # | Change | Landed | Notes |
|---|---|---|---|
| A | Bump all version strings to `-04` | -04 | includes live provenance headers |
| B | `Delivered-To:` (RFC 9228) added to the unsigned-header list | -03 | |
| C | Null header recipe removed — `"h":null` no longer allowed; body `"b":null` stays | -03 | |
| D | `nd=` tag — alternative to `mf=`/`rt=` for imaginary hops; required-tag rule `i,m,t,d,s` + (`nd=` XOR `mf=`+`rt=`); verifier matches `nd=` to next-higher `d=` | -03 (+ -04 top-sig text) | |
| E | `feedhere` feedback flag added to `f=` | -03 | |
| F | Authentication-Results **no longer** counts as a modification (flipped) | -04 | |
| G | DSN rewrite — RFC 3462; 3 MIME parts; propagated DSN is a *new* message (one sig + one MI); `text/rfc822-headers` fallback | -03/-04 | |
| H | Verifier error strings gain `i=<x>` prefixes; new `nd=` / "tag was unexpected" forms | -04 | |

## Current conformance state (audited 2026-07-05)

Six parallel per-codebase audits produced this matrix.
Legend: ✅ done · ⚠️ partial · ❌ missing · — N/A

| Item | C | Go | Python | Perl | Mailman | Sympa |
|---|---|---|---|---|---|---|
| A version strings | ⚠️ docs only | ❌ 14 refs | ❌ all `-01/-03` | ❌ `-03` (live) | ⚠️ | ❌ |
| B `delivered-to` | ✅ | ✅ | ✅ | ✅ | ✅ (test gap) | ✅ inherited |
| C null `h` removed | ✅ | ✅ | ✅ (verify nit) | ✅ | ✅ | ✅ delegated |
| D1–D3 `nd=` | ✅ | ✅ | ✅ (emit not on CLI) | ✅ | — | — |
| D4 top-`nd=` semantics | ❌ | ❌ | ❌ | ❌ | — | — |
| E `feedhere` | ✅ | ✅ | ✅ (not on CLI) | ✅ | — | — |
| F A-R not a modification | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| G DSN RFC 3462 | — none | ✅ (nit) | ⚠️ | ⚠️ | — | — |
| H error strings | ⚠️ | ⚠️ | ⚠️/❌ | ⚠️ | — | — |

**Key observation:** the work is lopsided — ~80% is trivial version-string/comment
bumps; the genuinely-open behavioral items are D4 and H, plus a Python functional gap
and DSN grounding. B/C/E/F are already correct everywhere.

## Scope decisions (agreed)

1. **D4 — reject top `nd=` (stricter than spec).** Spec-04 SHOULD-tolerates a
   highest-numbered signature carrying `nd=` via out-of-band arrangements. We do **not**
   accept this: our verifiers **MUST reject** a message whose highest-`i=`
   DKIM2-Signature carries `nd=`. Rationale: the only legitimate `nd=` producer in our
   ecosystem is the **reflector-brand-nd** path, which always emits the `nd=` signature
   *together with* its matching higher-`i=` signature — so `nd=` never legitimately
   appears on top. The real functional requirement is that the verifier can **undo /
   verify across an `nd=` imaginary hop, including multiple consecutive `nd=`
   signatures.**
2. **H — canonicalize error strings exactly** to the spec-04 forms across all four
   verifiers and the web validator.
3. **Python envelope check — in scope.** Add delivered MAIL FROM / RCPT TO checks
   against the top signature plus the relaxed d↔mf match to the Python verifier, even
   though the gap likely predates -04.

## Design — tiered by risk/value

The plan is organized into tiers (not per-codebase), because the work is lopsided:
land the trivial, deploy-critical version bumps first; isolate the one real behavioral
change; then canonicalize; then the smaller functional items; then test + deploy.

### Tier 1 — version strings (all six + artifacts)

Single source of truth per codebase, then cosmetic references, then committed artifacts.

- **Deployed-critical constants:**
  - Perl `brong/lib/Mail/DKIM2/Common.pm:41` `DKIM2_DRAFT => 'ietf-dkim-dkim2-spec-04'`
    and `:43` `DKIM2_DATE => '2026-07-05'`. Feeds the live `X-DKIM2-Info` header emitted
    by the milter and reflector.
  - Mailman `src/mailman/handlers/message_instance.py:49` `DKIM2_DRAFT` → `-04`, `:51`
    `DKIM2_DATE` → `2026-07-05`, `:21` docstring `-02` → `-04`.
  - Sympa `src/lib/Sympa/Message.pm:463` `DKIM2_DRAFT` → `-04`, `:465` `DKIM2_DATE`.
  - Go `dkim2/recipe.go:26` — a *user-visible* error string carrying `draft-03`.
- **Cosmetic POD/comment refs** (`spec-02`/`spec-03`/`draft-03` → `-04`):
  - Perl: `Common.pm` (45/60/83/301/343/416), `Signature.pm`, `Signer.pm`, `Verifier.pm`,
    `MessageInstance.pm`, `Validate.pm`, `Reflector.pm`, `DSN.pm`, `TagValueList.pm`,
    `HeaderParser.pm`, `MessageStore.pm`, `Handler/DKIM2Sign.pm`, `Handler/DKIM2Verify.pm`,
    `bin/dkim2-milter.pl:721` (still `-02`), `bin/dkim2-reflector.pl:66`.
  - Python: `dkim2sign.py` (3/310/482), `dkim2verify.py` (3/87/533/679),
    `dkim2undo.py` (3/440), `dkim2dsn.py:2`, plus stale `draft-03 §N` comments.
  - Go: 14 `draft-03 §…` comments across `signature.go`, `verify.go:412`, `dsn.go:22`,
    `cmd/dkim2dsn/main.go:1`, `recipe.go:21`, tests.
  - C: section-reference comments in `dkim2_header.c`, `dkim2_hash.c`, `dkim2_verify.c`,
    `TODO-dsn.md:1`.
- **Artifacts:** refresh the interop repo's committed spec copy — replace/augment
  `spec/draft-ietf-dkim-dkim2-spec-*.txt` with a `-04` `.txt` generated from
  `/Users/brong/src/spec`; refresh `c/dkim2-spec.txt` (currently an entire `-01` copy);
  update references in `docs/` and `c/INTEROP-NOTES.md:381`.

### Tier 2 — `nd=` chain semantics (C / Go / Python / Perl + validator)

- **Reject top `nd=`:** if the highest-`i=` DKIM2-Signature carries `nd=`, fail
  verification with `DKIM2-Signature i=<x> unexpected nd= tag`. Applies to all four
  verifiers and the web validator (`Validate.pm` + UI).
- **Undo/verify across `nd=` hops:** chain verification and the undo path must correctly
  traverse one or more consecutive `nd=` (imaginary-hop) signatures — a signature with
  `nd=` and no `mf=`/`rt=`, whose `nd=` equals the next-higher signature's `d=`, as
  produced by reflector-brand-nd. This includes a run of ≥2 consecutive `nd=` signatures.
  - Perl focus: `Verifier.pm` chain walk (`:403-460`) and any undo traversal; the
    existing adjacent-match check (`:414-425`) stays.
- **Perl D2 completeness:** add the missing check that `i,m,t,d,s` are all present
  (`Verifier.pm:266-278` currently enforces only the `nd=` XOR `mf=`+`rt=` rule). C, Go,
  Python already enforce presence.
- **Test fixtures:** signed messages exercising (a) a single `nd=` hop and (b) a doubled
  `nd=` run, both verifying/undoing cleanly; plus a top-`nd=` message that MUST be
  rejected.

### Tier 3 — canonical error strings (four verifiers + validator)

Rewrite verifier/validator messages to the exact spec-04 forms (§"Ensure … Valid",
§"Check the Chain-of-Custody"):

```
DKIM2-Signature i=<x> tag=<y> missing
DKIM2-Signature i=<x> tag=<y> was unexpected
DKIM2-Signature i=<x> MAIL FROM <value> did not match
DKIM2-Signature i=<x> RCPT TO <value> did not match
DKIM2-Signature i=<x> MAIL FROM and d= do not match
DKIM2-Signature i=<x> MAIL nd= does not match
DKIM2-Signature i=<x> unexpected nd= tag
```

Semantics to preserve:

- `tag=<y> was unexpected` applies to **disallowed combinations** (e.g. `nd=` alongside
  `mf=`/`rt=`), **not** to unknown extension tags, which MUST still be silently ignored.
- Spec line 1476 reads `... MAIL nd= does not match` — the leading "MAIL" is a probable
  spec typo (copy-paste artifact from the `MAIL FROM and d=` line above; the check has
  nothing to do with MAIL FROM). **Decision: match the spec byte-for-byte**, including the
  `MAIL` token, so our output/interop tests stay literally spec-conformant. Correct it
  when draft-05 fixes the typo. Do not file a nit now.
- Where verifiers already emit the Message-Instance (`Message-Instance m=<x> …`) and
  public-key (`public key <value> …`) error families, align those to spec-04 wording too
  as encountered; the primary target is the custody/`nd=` set above.

These strings surface in `Authentication-Results` comments and the validator UI, so
consistency across implementations matters for interop tests.

### Tier 4 — Python functional gap + DSN grounding

- **Python verifier envelope checks** (`dkim2verify.py`): add the delivered MAIL FROM /
  RCPT TO checks against the top signature's `mf=`/`rt=`, plus the relaxed d↔mf domain
  match, emitting the Tier-3 canonical strings. Also reject a present-null `h` recipe
  consistently (`:641`, matching `dkim2undo.py:325-329`).
- **Python signer CLI:** wire `--next-domain` and `--flag` through `sign_message`/`main`
  so `nd=` and `feedhere` are reachable from the command line.
- **DSN RFC 3462 grounding + structure validation (G):** in Perl `DSN.pm`, Python
  `dkim2dsn.py`, Go `dsn.go`, add the RFC 3462 reference and validate the 3-part DSN
  structure — human-readable text + `message/delivery-status` + (`message/rfc822` OR
  `text/rfc822-headers`) — rather than a bare part-count check. Behavior is already
  spec-04-shaped (one-MI/one-sig rebuild, `rfc822-headers` fallback); this hardens
  validation and updates references. C has no DSN implementation — out of scope (tracked
  in `c/TODO-dsn.md`).

### Tier 5 — tests + deploy

- Per-codebase test gates (Go `go test ./...`, Python `tests/run_tests.sh`, Perl
  `make test`, C `make`, Mailman tox handler tests).
- Add the missing `Delivered-To` assertion to Mailman `test_excluded_headers`
  (`test_message_instance.py:78-82`).
- Cross-impl interop check: the existing corpus of expected emails must still verify
  across C/Go/Python/Perl after the error-string and `nd=` changes.
- Deploy the Perl stack to `mail.dkim2.com` (git pull) + rsync Mailman/Sympa + service
  restart; live smoke test confirming `X-DKIM2-Info` on outbound mail advertises `-04`.

## Out of scope

- The DKIM2-DSN singleton-header experiment stays parked (removed from `lib/`; parked on
  `dkim2-dsn-header` branches pending in-person IETF ~mid/late July 2026).
- C DSN implementation (feature absent; tracked separately).
- Any spec-behavior change beyond the -04 delta.

## Testing strategy summary

- Unit/regression per codebase (existing suites, extended with the new fixtures).
- New `nd=` fixtures: single hop, doubled `nd=` run (both verify + undo), top-`nd=`
  (must reject).
- Error-string assertions updated to the canonical spec-04 forms.
- Full cross-implementation interop pass over the shared expected-email corpus.
- Post-deploy live smoke test on `mail.dkim2.com`.
