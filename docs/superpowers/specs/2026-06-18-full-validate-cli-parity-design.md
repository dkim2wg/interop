# Full-validate CLI parity across implementations — Design

**Date:** 2026-06-18
**Status:** Approved (pending spec review)
**Author:** brong + Claude

## Goal

Give every implementation's command-line verifier a consistent **full validation
mode** — chain crypto verification + the §10.7 Message-Instance hash check across
**every** instance in the chain (undoing each recipe) — with an optional
**ignore-timestamps** switch. Default behaviour is full validation; the timestamp
(§10.3) check can be turned off with one canonically-named flag.

## Current state (from audit, 2026-06-18)

| Impl | CLI | Full-chain MI-undo | Ignore-timestamps |
|------|-----|--------------------|-------------------|
| Python | `python/dkim2verify.py` | `--full-chain` (opt-in) | `--skip-timestamp-check` |
| C | `c/dkim2verify` | automatic (default); `--full-chain` no-op | `--no-timestamp-check` |
| Go | `go/cmd/dkim2verify` | **missing** — `Verify()` checks top MI only; undo logic is in the separate `dkim2undo` tool | field `VerifyOptions.SkipTimestampCheck` exists, **no CLI flag** |
| Perl | `brong/bin/validate.pl` | full chain (walks + undoes); dies on first error | none (no flag) |

So: Go needs the full-chain walk added to its verify CLI; Go and Perl need the
timestamp flag; Python's default flips to full; everyone gets the canonical flag
name + aliases.

## Canonical CLI surface (all four)

- **Full-chain validation is the DEFAULT.** Verify always performs:
  1. chain crypto verification for every signature i=1..N (already done);
  2. §10.7 top-MI header+body hash check against current content;
  3. walk every MI from top down — undo its recipe, re-verify the reconstructed
     content against the next instance's recorded hashes — stopping at m=1 or a
     null/unrecoverable recipe; fail on hash mismatch or unclean undo.
- **`--ignore-timestamps`** — canonical flag; disables the §10.3 (>14 days /
  future) check.
- **Back-compat aliases retained** (no breakage): `--skip-timestamp-check`
  (Python), `--no-timestamp-check` (C) both continue to work as aliases of
  `--ignore-timestamps`. `--full-chain` is still accepted everywhere but is now a
  redundant no-op (full is default).
- Go uses Go-style single-dash spelling (`-ignore-timestamps`); the flag word is
  the same across languages. Go's `flag` package also accepts `--ignore-timestamps`.

## Per-language changes

### Go (the real implementation) — `go/`
- Add a full-chain MI validation step to the verification the CLI runs, reusing
  the existing undo logic in `go/dkim2/undo.go` (the `Undo()` reconstruction used
  today only by `cmd/dkim2undo`).
- Keep the library `Verify()` semantics intact (top-MI as today). Add a new
  exported helper in package `dkim2`, e.g. `VerifyFull(msg, opts) ([]Result, error)`
  (name to be finalised in the plan) that: runs the existing per-signature
  `Verify`, then walks the MI chain via `Undo`, verifying each instance's
  recorded header/body hashes against the reconstructed message; returns a
  combined verdict. Stop at a null/unrecoverable recipe; treat unclean undo or
  hash mismatch as failure.
- `cmd/dkim2verify/main.go`: call `VerifyFull` by default; add `-ignore-timestamps`
  bool flag wired to `VerifyOptions.SkipTimestampCheck`. (Also accept a no-op
  `-full-chain` for parity.)
- Output/exit codes unchanged (PASS/FAIL text, 0/1).

### C — `c/`
- `dkim2verify_cli.c`: accept `--ignore-timestamps` as an alias of the existing
  `--no-timestamp-check` (sets the same `skip_timestamp_check`). `--full-chain`
  stays a recognised no-op. No verification-logic change (full walk already
  default in the CLI).

### Python — `python/dkim2verify.py`
- Make the full-chain walk the **default** (run the existing `--full-chain` code
  path unconditionally). Keep `--full-chain` as an accepted no-op.
- Add `--ignore-timestamps` as the canonical flag; keep `--skip-timestamp-check`
  as an alias (argparse: same `dest`).
- Keep `tests/run_tests.sh` green (it already passes `--full-chain` and
  `--skip-timestamp-check`, which still work). Regenerate expected verify output
  only if the default-full change alters printed text.

### Perl — `brong/bin/validate.pl`
- Add an `--ignore-timestamps` flag that sets `skip_timestamp_check(1)` on the
  `Mail::DKIM2::Verifier` it constructs. (validate.pl already walks + undoes the
  full chain.) Default remains full validation with the timestamp check on.

## Testing

- **Go:** add tests (in `go/dkim2/`) for: a valid multi-hop chain → full-chain
  verify passes; a chain whose **inner** MI no longer matches (tamper below the
  top) → full-chain verify **fails** (this is the gap being closed, distinct from
  top-MI-only); `-ignore-timestamps` lets an old-timestamp signature pass. Build
  the CLI and smoke-test the flag.
- **Python:** `tests/run_tests.sh` stays green with default-full; add a check that
  `--ignore-timestamps` and `--skip-timestamp-check` behave identically.
- **C:** `make test` stays green; add a check that `--ignore-timestamps` is
  accepted and equals `--no-timestamp-check`.
- **Perl:** existing suite green; add a `validate.pl --ignore-timestamps` check
  that an old-timestamp message passes (and fails without the flag).

## Out of scope

- The **milter** verify paths (Perl/C streaming milters) — they intentionally do
  top-MI-only for streaming efficiency; not changed here.
- JSON output for the CLIs (text + exit codes retained).
- Any spec-behaviour change; this is CLI ergonomics + Go reaching parity.

## Notes / risks

- Go: confirm the CLI reads the whole message (not streaming) so the body is
  available for recipe undo — the audit shows it reads stdin fully, so undo is
  feasible.
- "null/unrecoverable recipe stops the walk" must match the Perl semantics
  already shipped (`unrecoverable()` → stop, accept what verified) so all impls
  agree on redacted-style messages. Per the 2026-06-17 interim, the **header**
  null recipe is being removed in a future spec rev; the **body** null recipe
  stays — keep the stop-on-null behaviour keyed on the body recipe.
