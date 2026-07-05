# DKIM2 Interop Status Report

**Spec:** draft-ietf-dkim-dkim2-spec-04  
**Date:** 2026-05-01  
**Audience:** DKIM2 Working Group participants, hackathon attendees

---

## Implementations

Four independent implementations exist in this repository:

| Language | Location | Signing | Verification | Notes |
|----------|----------|---------|--------------|-------|
| Python | `python/` | ✅ | ✅ | Script-based; reference for test vectors |
| Perl | `brong/` | ✅ | ✅ | `Mail::DKIM2`; streaming object API |
| Go | `go/` | ✅ | ✅ | Library + CLI; streaming, zero-copy body |
| C | `c/` | ✅ | ✅ | Low-level; libmilter integration included |

A fifth implementation (`hs/`) contains Haskell key material used for interop
testing but is not yet a complete sign/verify implementation.

---

## Spec sections implemented

| Section | Topic | Py | Perl | Go | C |
|---------|-------|----|------|----|---|
| §5.1 | Body hash (SHA-256, simple canon) | ✅ | ✅ | ✅ | ✅ |
| §5.2 | Header hash (sorted, canonicalized) | ✅ | ✅ | ✅ | ✅ |
| §6 | Message-Instance header format | ✅ | ✅ | ✅ | ✅ |
| §6 | MI recipe field (`r=`) — undo support | ✅ | ✅ | ✅ | ✅ |
| §7 | DKIM2-Signature header format | ✅ | ✅ | ✅ | ✅ |
| §7.1 | i= and m= sequence contiguity check | ✅ | ✅ | ✅ | ✅ |
| §7.3 | n= nonce ≤ 64 characters | ✅ | ✅ | ✅ | ✅ |
| §7.7 | d= must be suffix of mf= domain | ✅ | ✅ | ✅ | ✅ |
| §8 | Signing flow | ✅ | ✅ | ✅ | ✅ |
| §8.2 | Inter-sig chain custody (mf=/rt= domain match) | ✅ | ✅ | ✅ | ✅ |
| §9.5 | Signing input construction | ✅ | ✅ | ✅ | ✅ |
| §10.3 | Timestamp: reject >14 days old or in future | ✅ | ✅ | ✅ | ✅ |
| §10.4 | Envelope exact-match (MAIL FROM / RCPT TO) | ✅ | ✅ | ✅ | ✅ |
| §10.6 | Verify all s= items (algorithm agility) | ✅ | ✅ | ✅ | ✅ |
| §10.7 | Verify MI body + header hashes | ✅ | ✅ | ✅ | ✅ |
| §10 | Full chain walk with recipe undo | ✅ | ✅ | ✅ | ✅ |

---

## Test vector set

### Python-generated (16 emails, `python/tests/expected/`)

All four implementations verify all 16 emails.

| File | What it tests |
|------|---------------|
| `simple-ed25519.eml` | Single-hop Ed25519 signing |
| `simple-rsa1024.eml` | Single-hop RSA-1024 |
| `simple-rsa2048.eml` | Single-hop RSA-2048 |
| `simple-sel2.eml`, `simple-sel3.eml` | Multiple selectors |
| `emptybody-ed25519.eml` | Empty message body |
| `multiheader-ed25519.eml` | Multiple same-name headers |
| `multirecipient-ed25519.eml` | Multiple RCPT TO |
| `dsn-ed25519.eml` | DSN (null sender `<>`) |
| `dupheaders-ed25519.eml` | Duplicate header fields |
| `multihop-3hop-dup-headers.eml` | Three-hop chain, duplicate headers |
| `multihop-body-footer.eml` | Two-hop: relay adds body footer |
| `multihop-dup-headers.eml` | Two-hop: duplicate headers |
| `multihop-header-add.eml` | Two-hop: relay adds a header |
| `multihop-header-replace.eml` | Two-hop: relay replaces a header |

### Perl-generated (10 emails, `brong/tests/expected/`)

All four implementations verify all 10 emails.

### Cross-implementation verification

The Perl `t/interop.t` test verifies all Python expected emails.  The Python
`tests/run_tests.sh` verifies Python-generated emails with the Python verifier.
The Go test suite includes verification of the shared test vectors.

---

## Running the test suite

### Python

```bash
cd python
python3 -m venv venv && source venv/bin/activate
pip install cryptography
bash tests/run_tests.sh
```

Add `--generate` to regenerate expected emails.

### Perl

```bash
cd brong
cpanm --installdeps .   # installs CryptX and other deps
perl -I lib t/full-chain.t
perl -I lib t/interop.t
perl -I lib t/verifier-mi-coverage.t
```

### Go

```bash
cd go
go test ./dkim2/...
```

### C

```bash
cd c
make             # requires OpenSSL and cjson via pkg-config
make test        # runs test_base64, test_tagparse, test_hash, test_header,
                 #           test_recipe, test_crypto, test_verify
```

The C milter binary (`dkim2-milter`) requires libmilter from a local sendmail
source tree; the sign/verify CLIs and unit tests build without it.

---

## Interoperability issues encountered

These issues were discovered during cross-implementation testing.  All are now
fixed in the reference implementations.  They are recorded here as input for
future spec revisions.

### Critical for interop

**Trailing semicolon in tag-value headers (Issue #1 / Spec issue S1)**  
The spec ABNF permits a trailing `;` after the last tag.  Python always emits it;
some implementations omitted it.  Because canonicalization retains `;`, the
signing input differed:

```
# With trailing `;` (Python):
message-instance:m=1;h=sha256:abc:def;\r\n

# Without (some implementations):
message-instance:m=1;h=sha256:abc:def\r\n
```

Fix: verifiers must use the raw header bytes, not a reconstructed form.  The spec
should normatively require the trailing `;`.

**Verifier using reconstructed form instead of raw bytes (Issue #2)**  
The C verifier initially called format functions on parsed structs to reconstruct
the signing input.  This lost any formatting details from the original header.  The
correct approach: take the raw header value as received, blank the `s=` sig bytes
in-place, and canonicalize.

**Ed25519 prehash convention (Spec issue S2)**  
The spec does not explicitly state whether Ed25519 signing uses the raw message or a
SHA-256 pre-hash.  All reference implementations use SHA-256 pre-hash (i.e., sign
`SHA256(signing_input)` rather than signing `signing_input` directly).  The spec
should add a normative statement.

**Same-name header ordering (Spec issue S5)**  
The spec describes sorting headers by name but does not specify the relative order
of same-name headers.  All implementations use the message's original bottom-up
order within each name group (i.e., oldest instance first).

### High severity

**Which MI headers are in scope for a signature (Spec issue S7)**  
The spec is ambiguous about whether the signing input for signature `i=K` should
include all MI headers in the message or only those with `m= ≤ sig.m`.  All
implementations now use `m ≤ sig.m`, but this should be made explicit in the spec.

**Folded base64 in MI headers (Issue #14)**  
The C implementation initially compared base64 hash values as strings.  Long hash
values may be folded with CRLF whitespace, making string comparison unreliable.
Fix: decode base64 before comparing.

**MAIL FROM angle bracket handling (Issue #8)**  
The `mf=` value is base64 of the MAIL FROM *with* angle brackets (e.g.,
`<user@example.com>`).  Some implementations decoded it without brackets or with
inconsistent bracket handling, causing domain matching to fail.

### Medium severity

**Ascending m=/i= order conflicts with storage order (Spec issue S6)**  
Headers are prepended to the message (newest first), but the signing input requires
ascending order.  Implementations must reverse the order when building the signing
input.  The spec should make this explicit.

**Leading whitespace in header values (Spec issue S4)**  
Header values after the colon often have leading whitespace.  §5.2 canonicalization
strips this, but the interaction with §8.5 (which strips all whitespace including
folded continuations) was easy to conflate.

---

## Open spec issues

These have not been resolved and should be addressed in a future draft revision:

| ID | Issue | Impact |
|----|-------|--------|
| S1 | Trailing `;` in tag-value should be normative | Critical for interop |
| S2 | Ed25519 prehash convention must be stated | Critical for interop |
| S5 | Same-name header ordering within name group | Medium |
| S6 | Signing input order (ascending) vs wire order (descending) | Medium |
| S7 | Which MI headers are in scope for each signature | Critical for interop |
| S8 | No worked test-vector example in spec | High — helps all implementors |

---

## Shared test infrastructure

```
dns.json       DNS TXT records for all test domains (test1..test5.dkim2.com)
keys/          Private key files for all selectors, all test domains
               Format: <selector>._domainkey.<domain>.pem  (PKCS#8 PEM)
spec/          draft-ietf-dkim-dkim2-spec-04.txt
```

Test domains: `test1.dkim2.com` through `test5.dkim2.com`  
Test selectors per domain: `ed25519`, `rsa1024`, `sel1`, `sel2`, `sel3`

Key format: PKCS#8 PEM (Go, Python, C) and Crypt::PK objects (Perl).  The
`DKIM2TestKeys` Perl module loads keys from the shared `keys/` directory.

---

## Contributing a new implementation

1. Clone the repo.
2. Add your implementation under a new top-level directory.
3. Point your verifier at `dns.json` for public key lookup.
4. Run verification against `python/tests/expected/*.eml` and
   `brong/tests/expected/*.eml`.
5. Generate signed emails from the source messages in `python/tests/emails/` and
   verify them with at least one other implementation.
6. Add your expected emails directory to `brong/t/interop.t` and
   `python/tests/run_tests.sh` so the cross-check runs automatically.

The most common first-failure mode is the signing input construction — use the
Python implementation's `--verbose` output to trace what headers are being hashed.
