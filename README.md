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

## Signer gate

A signer that is handed a message with a DKIM2 chain must verify that chain
before extending it (see "Verify before you sign" in
`docs/dkim2-implementer-guide.md`). `util/signer-gate.sh` runs a set of
chain-shaped fixtures (no chain, valid chain, broken signature, broken MI
chain, null body Recipe, fake "coverage" signatures, Message-Instance-only
chains, `nd=` bridges) through all four signer CLIs, plain and with
`--allow-null-body-recipe`, and checks each signs or refuses as specified
(21 fixtures, 168 cells):

    ./util/signer-gate.sh

A DKIM2-Signature with `m=k` covers Message-Instances 1..k. A null body
Recipe on any instance above the highest `m=` of the valid upstream
signatures is refused without `--allow-null-body-recipe`: a null this hop
introduces, whether it is the top instance (`null-top`, `mi-only-null`) or
another unsigned instance was added over it (`null-below-unsigned-top`). A
null that arrived already signed (`null-top-signed`: a list post the list
host signed, forwarded unchanged; `null-below-signed`: the same with an
ordinary unsigned instance on top) is signed without the option. Only a
host that introduces a null body Recipe and signs it itself — a list host whose
list manager adds an unsigned instance — needs the option; a forwarder needs
nothing. Only a signature with a valid `i=` counts as covering the top: the
`fake-cover-*` fixtures put a DKIM2-Signature naming `m=2` with no `i=`,
`i=0`, `i=abc`, a rewritten `m=` or no tag-list syntax on top of `null-top`,
and every signer refuses them in both modes, because every verifier reports
such a signature as a PERMERROR rather than skipping it.

It needs the built `c/dkim2sign` and `go/dkim2sign`, and uses `dns.json` for
the verification keys. The Perl milters make the same decision with the same
`Mail::DKIM2::Gate`: `perl/t/milter-script.t` covers `dkim2-milter`, and
`perl/t/milter-sign-gate.t` runs these cases through the authentication_milter
`DKIM2Sign` handler (`allow_null_body_recipe` in its config).

## Negative vectors

`util/negative-vectors.sh` hand-builds one cryptographically valid message
per spec-06 PERMERROR — a duplicate hash algorithm, a duplicate
Selector, more selectors than allowed, malformed Recipe JSON, an unsigned
top instance, a wrongly-keyed `nd=` bridge, and Recipe copy ranges that are
out of order or overlap (§5.2), a duplicated Message-Instance `m=`, and a
DKIM2-Signature with no usable `i=` (missing, or not a positive integer) on
top of an otherwise valid chain or on its own, and an `i=` or `m=` above the
chain length limit of 32 (`i=33`, `i=99999999999999999999`, a signature
`m=4294967297`, a Message-Instance `m=99999999999999999999`), which must be a
PERMERROR before any gap check walks up to it — plus positive controls (the same algorithm
signed twice under distinct Selectors, which §8.9 explicitly permits; a
Recipe on the bottom instance; a correct bridge; an unsigned lower Message-Instance under a signed higher one; and a Recipe whose `b`
items restore non-UTF-8 octets) and feeds them all through every verifier's
real CLI entry point, asserting each negative vector is REJECTED and each
positive control is ACCEPTED:

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

## Charset corpus

The hand-written fixtures are ASCII and UTF-8. `util/charset-corpus.sh`
fetches public archives that still serve full raw messages (the Apache
ponymail mbox API, a HyperKitty export, the SpamAssassin public corpus), keeps
a sample spread over every charset / transfer-encoding combination they
contain -- ISO-2022-JP 7bit, GB18030 base64, Big5 and EUC-KR with raw 8-bit
Subjects, Latin-1, `charset=3Dbig5` -- and then:

    ./util/charset-corpus.sh                # all stages
    ./util/charset-corpus.sh --stage matrix # local only: 4 signers x 5 verifiers per sample
    ./util/charset-corpus.sh --stage lists  # replay through the dkim2corpus lists on the box

The `matrix` stage is `util/hash-matrix.sh`'s shape on real bytes. The `lists`
stage signs each sample as dkim2.com/sel1, posts it to the Mailman and Sympa
corpus lists on mail.dkim2.com (members: the local capture address only; see
`deploy/SERVER.md`), pulls the captured copies back and checks that each list's
`m=2` Recipe rebuilds the signed `m=1` under every verifier. Results land in
`corpus/results/` (not committed): per-cell TSVs, summaries by charset, and
the failing messages with verifier logs under `corpus/results/fail/`.

Pipermail's "Gzip'd Text" archives are scrubbed (no `Content-Type`, bodies
re-encoded), which is why the many `lists.ubuntu.com` locale lists are not a
source despite looking ideal; `util/charset-corpus-sample.py` lists what is.

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

# An Alternative Proposal

A Deployment Profile for DKIM2 via Milter Interface (IETF Datatracker):
[https://datatracker.ietf.org/doc/draft-moccia-dkim2-deployment-profile/](https://datatracker.ietf.org/doc/draft-moccia-dkim2-deployment-profile/)