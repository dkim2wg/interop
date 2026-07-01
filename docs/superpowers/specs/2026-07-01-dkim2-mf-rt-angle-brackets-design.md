# Design: `mf=`/`rt=` angle-bracket conformance (all implementations)

**Date:** 2026-07-01
**Status:** approved, ready for implementation plan

## Purpose

Make the `mf=` and `rt=` tags of `DKIM2-Signature` conform to
draft-ietf-dkim-dkim2-spec-02 §7.5/§7.6, which require the base64-encoded value
to be the **full RFC5321 reverse-/forward-path _including angle brackets_**
(`<user@domain>`, or `<>` for the null sender). Today every implementation emits
the base64 of the **bare** address (no brackets) for normal senders — a spec
violation that is consistent across the ecosystem (the Perl↔Python interop
fixtures all decode to bare addresses). The null-sender case already emits `<>`.

Two things change:

1. **Emit** the bracketed form everywhere.
2. **Enforce** it: a present `mf=`/`rt=` whose decoded value is not bracketed is a
   spec violation that **fails** verification, and the failure is surfaced all the
   way to the web validator UI.

## Spec basis

- **§7.5 (`mf=`):** "recorded as the base64 encoding of the [RFC5321]
  reverse-path … **The angle brackets MUST be included**, but any 'Mail-parameters'
  … MUST NOT be included." `MAIL FROM` may be just `<>` (e.g. a DSN).
- **§7.6 (`rt=`):** same for the **Forward-path**: "**The angle brackets MUST be
  included**"; multiple recipients allowed (`base64string *("," base64string)`).
- **§8.2:** the receiver checks an **exact match (including local parts)** between
  the actual SMTP MAIL FROM / RCPT TO protocol values and the top signature's
  `mf=`/`rt=`. The SMTP protocol values are the bracketed RFC5321 paths, so the
  recorded values must be bracketed for this to hold.
- **§8.3 relaxed domain match** (chain-of-custody `mf`↔prev-`rt`, and `d=`↔`mf`
  domain): "only the domain part … is used; the local part and the @ are ignored."
  Brackets do not affect this match — but the recorded value must still be
  bracketed per §7.5/§7.6.

## The canonical rule (identical across every implementation)

- **Encode (signing):** the value placed in `mf=` (and each `rt=` entry) is
  `base64(path)`, where `path` is the RFC5321 path:
  - real address → `<localpart@domain>`
  - null sender  → `<>`
  Mail-/Rcpt-parameters are excluded (already the case). Normalize at the signing
  boundary: wrap a bare address in `<…>`, leave an already-bracketed value or `<>`
  unchanged — so existing call sites that pass bare addresses keep working.
- **Enforce (verifying):** decode base64 → `path`; `path` MUST match `^<.*>$`
  (`<>` satisfies this). A present `mf=`/`rt=` value that is not bracketed is a
  **spec violation → fail** (see Enforcement below). Applies to **every** `mf=`
  and `rt=` in **every** `DKIM2-Signature` in the message, not just the top one.
- **Relaxed domain match (§8.3) unchanged:** the domain is extracted from *inside*
  the brackets (strip `<`…`>` and the localpart), so all existing matching behaves
  exactly as before, now operating on bracketed inputs.

## Enforcement behaviour

A present-but-unbracketed `mf=` or `rt=` value is treated as a **hard failure**:
the affected signature level's result is `fail`/`permerror` with a clear reason
(e.g. `mf= is not a bracketed RFC5321 reverse-path (spec §7.5)`). This is
enforced in the **core verifier** of each tree, so both the operational verify
path (e.g. the Perl milter) and the diagnostic validator inherit it.

Consequence (accepted): once shipped, any message still carrying bracket-less
`mf=`/`rt=` (including previously-generated ones) fails verification until its
sender is updated. This is intended — we are conforming the whole ecosystem.

## Scope

Fix **all implementations we own**:

- **Perl** (`brong/`) — library, milter, reflector, DSN, CLI tools, **and the web
  validator**.
- **Python** (`python/`)
- **C** (`c/`)
- **Go** (`go/`)

Explicitly **out of scope:** `rnc1/` (not ours — an old example, not a
maintained implementation); `hs/` and `arobins/` (no source present).

### Perl touch points (pinned)

- **Encode:** `Mail::DKIM2::Signature` (`new`, the `encode_base64` of
  `MailFrom`/`RcptTo` at ~lines 39–43) — normalize to the bracketed path. This is
  the single choke point; `Signer.pm`, `DSN.pm`, `Reflector.pm`,
  `dkim2-milter.pl`, and CLI tools pass values through and need no per-caller
  change (verify they still pass bare/`<>` and let the choke point normalize).
- **Decode + domain extraction:** `Mail::DKIM2::Signature` `mail_from`/`rcpt_to`
  accessors and the domain-extraction used by `Mail::DKIM2::Verifier`
  (`extract_domain`/relaxed match, ~Verifier.pm:306–318) — strip surrounding
  brackets for the domain.
- **Enforcement check:** `Mail::DKIM2::Verifier` — new per-signature check that
  every present `mf=`/`rt=` decodes to a `^<.*>$` value; on violation, set the
  level result to fail with the §7.5/§7.6 reason.
- **Web validator:** `Mail::DKIM2::Validate` (report) carries the violation;
  `brong/bin/validate.cgi` returns it in JSON; the `deploy/www/validate/`
  front-end **displays** it as a failure/violation in the rendered report.

### Python / C / Go touch points (to be located in the plan)

Each has the same three logical sites — encoder, domain-extraction, and a new
enforcement check — plus any tree-local validator/report surface. The plan will
pin exact files/functions per tree during a short per-tree survey.

## Interop and fixture regeneration

`mf=`/`rt=` are inside the signed `DKIM2-Signature`, so **every signature's bytes
change** and **all interop/expected fixtures must be regenerated**:
`brong/tests/expected/`, `python/tests/expected/`, and any C/Go fixtures. Within a
single tree, the encoder change and the enforcement check land **together**, so a
tree is never in a state where it emits brackets but rejects them (or vice-versa).
`brong/t/interop.t` (Perl verifying Python fixtures) stays green because both
sides emit and expect the bracketed form after the change; cross-language
verification of the regenerated fixtures is the acceptance test.

## Testing (per tree)

- **Encode:** a freshly signed message has `mf=` decoding to `<addr>` and `rt=` to
  `<addr>`; a null-sender/DSN message has `mf=` = `<>` (`PD4=`).
- **Enforce:** a crafted signature whose `mf=` (and separately `rt=`) decodes to a
  bare address → verify **fails** with the §7.5/§7.6 reason; a bracketed value →
  pass. Cover the null sender `<>` as still-valid.
- **Relaxed-match regression:** chain-of-custody (`mf`↔prev-`rt`) and `d=`↔`mf`
  domain matches still pass with bracketed values; the null-sender/DSN path still
  verifies.
- **Web validator:** posting a message with a bracket-less `mf=` produces a report
  whose affected level shows the spec-violation failure, and the front-end renders
  it.
- **Interop:** regenerated fixtures cross-verify across all trees.

## Sequencing (for the plan)

1. **Perl + Python together** (they share `interop.t`): land encoder + enforcement
   in both, regenerate both fixture sets, keep `interop.t` green, update the web
   validator + its front-end.
2. **C**, then **Go**: encoder + enforcement + regenerate that tree's fixtures.
Each tree is independently testable and leaves the ecosystem consistent when it
lands.

## Out of scope

- Tightening the §8.2 exact-match (local-part) logic beyond the bracket-presence
  check — matching stays relaxed-domain as today.
- `rnc1/`, `hs/`, `arobins/`.
- Any change to `should_skip()` / header canonicalisation, or to the body/MI
  hashing.
