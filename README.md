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
