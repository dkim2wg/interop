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
per new spec-05 PERMERROR — a duplicate hash algorithm, a duplicate
Selector, too many same-algorithm signatures, and malformed Recipe JSON —
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

# An Alternative Proposal

A Deployment Profile for DKIM2 via Milter Interface (IETF Datatracker):
[https://datatracker.ietf.org/doc/draft-moccia-dkim2-deployment-profile/](https://datatracker.ietf.org/doc/draft-moccia-dkim2-deployment-profile/)