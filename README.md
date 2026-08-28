# DKIM2 Interop at IETF 124, Montreal

This repository is a place to share materials and examples for the IETF 124 hackathon.

Please feel free to clone and make pull requests, or ask for direct commit privileges on this repo.

## Conformance vectors

Steve Atkins' test vectors (<https://forge.turscar.ie/turscar/dkim2tests>) are a
git submodule at `dkim2tests/`. To run all of them against every verifier here
(Python, Perl, Go, C, browser JS):

    git submodule update --init
    ./util/turscar-all.sh

Each language's runner is also runnable on its own — see the comment at the top
of `util/turscar-all.sh`.

## Hash agility

`draft-05` added sha512 alongside sha256. To check that every signer's output
verifies in every implementation, at each algorithm:

    ./util/hash-matrix.sh

This signs one message with each of the four signers (Python, Go, C, Perl) at
`--hash sha256`, `sha512` and `both`, then verifies every output with all
five verifiers (adding browser JS) — 60 signer/algorithm/verifier
combinations in total.

## Negative vectors

`util/negative-vectors.sh` hand-builds one cryptographically valid message
per spec-06 PERMERROR — a duplicate hash algorithm, a duplicate
Selector, more selectors than allowed, and malformed Recipe JSON —
plus one positive control (the same algorithm signed twice under distinct
Selectors, which §8.9 explicitly permits) and feeds all five through every
verifier's real CLI entry point, asserting each negative vector is REJECTED
and the positive control is ACCEPTED:

    ./util/negative-vectors.sh

Each fixture is built to be otherwise valid (correct hashes, correct
signature bytes) so a check that's implemented but unreachable from the real
verify path — the exact bug class found more than once during this
upgrade — shows up as a false accept rather than being masked by an
unrelated signature failure.

## Cross-testing against croessner/dkim2

<https://github.com/croessner/dkim2> is the other actively developed DKIM2
implementation (Go, tracking `draft-ietf-dkim-dkim2-spec-06`). To feed his
verifier everything this repo can produce:

    ./util/croessner-verify.sh

It signs one message with each of our four signers at each of the three hash
algorithms, then runs the whole negative-vector set, and gates on his verdict —
18 cells. His implementation has no file-based CLI, so the runner builds his
`dkim2d` daemon, mints a capability, boots it on a loopback port and POSTs each
message to `/v1/process`.

Two consequences worth knowing:

- **It needs the network.** `dkim2d` resolves DNS live and has no offline
  records file, so this runner depends on the published `test1.dkim2.com` keys
  rather than `dns.json`. That's why it's a separate script: `hash-matrix.sh`
  and the other runners stay offline-clean.
- **It skips instead of failing.** His repository is not vendored here. Point
  the runner at a checkout with `DKIM2_GO_PEER=/path/to/dkim2`, or put one
  beside this repo as `../mailde-dkim2`; with no checkout, no Go toolchain, or
  no DNS it prints `SKIPPED` and exits 0.

Signing in the other direction — his signer against our five verifiers — isn't
covered yet. `/v1/sign` returns an append-only action plan rather than a signed
message, and enabling it requires a full protected generation (datasource,
private-key manifest with SPKI digests, PKCS#8 children), so that direction is
waiting on a command-line signer.

## Licence

BSD 3-Clause — see [`LICENSE`](LICENSE). This work was contributed under the
IETF Note Well ([BCP 78](https://www.rfc-editor.org/info/bcp78)), whose Trust
Legal Provisions license code components under the Revised BSD licence, so that
is what applies here. Copyright is held by the DKIM2 interop contributors; by
sending a pull request you licence your contribution under the same terms.

Two things in this tree are not covered by that licence:

- `dkim2tests/` is a git submodule pointing at Steve Atkins'
  <https://forge.turscar.ie/turscar/dkim2tests>, which carries its own
  BSD-2-Clause licence (`Copyright (c) 2026 Turscar`). Nothing here relicenses
  it.
- `deploy/patches/pmilter-null-sender-envfrom.patch` is a diff against
  `Sendmail::PMilter`, and its context lines remain under that distribution's
  own terms.

# An Alternative Proposal

A Deployment Profile for DKIM2 via Milter Interface (IETF Datatracker):
[https://datatracker.ietf.org/doc/draft-moccia-dkim2-deployment-profile/](https://datatracker.ietf.org/doc/draft-moccia-dkim2-deployment-profile/)