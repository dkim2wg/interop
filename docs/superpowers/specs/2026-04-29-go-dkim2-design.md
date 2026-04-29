# Go DKIM2 Implementation Design

**Date:** 2026-04-29
**Spec:** draft-ietf-dkim-dkim2-spec-01
**Module:** `github.com/dkim2wg/interop/go`

---

## Goal

A Go library (`package dkim2`) implementing DKIM2 sign and verify per
draft-ietf-dkim-dkim2-spec-01, plus two CLI tools (`dkim2sign`, `dkim2verify`).
The library is designed for reuse by other Go projects; the CLIs serve as
interop test tools alongside the existing Python, Perl, and C implementations.

## File Layout

```
go/
├── go.mod                        # module github.com/dkim2wg/interop/go
├── dkim2/
│   ├── message.go                # header parsing, wire → []Header
│   ├── tagvalue.go               # tag-value list parser/builder (internal)
│   ├── canon.go                  # body hash (§5.1), header hash (§5.2), sig canonicalization (§9.5)
│   ├── mi.go                     # MessageInstance: build, parse, Recipe field
│   ├── recipe.go                 # Recipe type, JSON encoding, ComputeDiff
│   ├── signature.go              # DKIM2Signature: build, parse, AsStringWithoutData
│   ├── sign.go                   # Sign(r, w, key, opts)
│   ├── verify.go                 # Verify(r, fetcher) → []VerifyResult
│   ├── dns.go                    # KeyFetcher interface, NetKeyFetcher, JSONKeyFetcher
│   └── dkim2_test.go             # table-driven tests against shared expected .eml files
└── cmd/
    ├── dkim2sign/main.go         # CLI: flags → Sign → stdout
    └── dkim2verify/main.go       # CLI: flags → Verify → exit code
```

## Core Types

```go
// Header is one RFC 5322 header field with continuations already joined.
type Header struct {
    Name  string // original case
    Value string // unfolded value (without leading space after colon)
    Raw   string // "Name: Value\r\n" — used when building signing input
}

// MessageInstance is a parsed or constructed Message-Instance header.
type MessageInstance struct {
    Version    int
    BodyHash   []byte  // SHA-256
    HeaderHash []byte  // SHA-256
    Recipe     *Recipe // nil for v=1 / no-diff MIs
}

// DKIM2Signature is a parsed or constructed DKIM2-Signature header.
type DKIM2Signature struct {
    Sequence  int
    MIVersion int
    Timestamp int64
    Domain    string
    MailFrom  string
    RcptTo    []string
    Sigs      []SigItem
}

type SigItem struct {
    Selector  string
    Algorithm string // "rsa-sha256" or "ed25519-sha256"
    Value     []byte // nil when building signing input (empty s= per §8.5)
}

// SignOptions carries per-message signing parameters.
type SignOptions struct {
    Selector  string
    Domain    string
    MailFrom  string
    RcptTo    []string
    Timestamp int64    // 0 = use time.Now()
}

// VerifyResult is the outcome for one DKIM2-Signature in the message.
type VerifyResult struct {
    Sequence int
    Domain   string
    Error    error  // nil = pass
}

// KeyFetcher is the DNS abstraction. Implementations: NetKeyFetcher (real DNS),
// JSONKeyFetcher (dns.json file for testing).
type KeyFetcher interface {
    FetchPublicKey(selector, domain string) (crypto.PublicKey, string, error)
    // Returns (key, algorithm, error). algorithm is "rsa-sha256" or "ed25519-sha256".
}
```

`TagValueList` is unexported — callers interact only with `MessageInstance`
and `DKIM2Signature`.

## Public API

```go
// Sign reads r, prepends a new Message-Instance and DKIM2-Signature header,
// and writes the complete signed message to w.
// Headers are read into memory; the body is streamed through the body hasher.
func Sign(r io.Reader, w io.Writer, key crypto.PrivateKey, opts SignOptions) error

// Verify reads r, verifies all DKIM2-Signature headers, and returns one
// VerifyResult per signature. The body is streamed — never buffered.
func Verify(r io.Reader, fetcher KeyFetcher) ([]VerifyResult, error)
```

These are the only two entry points callers need. The CLI tools wire
`os.Stdin` → `os.Stdout` through them.

## Body Hash Streaming (§5.1)

Body canonicalization strips all trailing empty lines and adds exactly one
CRLF. Streaming implementation:

- Maintain a `pendingCRLFs int` counter.
- For each `\r\n` pair: if the following byte is `\r` (another empty line),
  increment `pendingCRLFs`. If a non-empty line follows, flush `pendingCRLFs`
  CRLFs into the hasher and reset, then hash the non-empty line.
- At end of stream: discard all `pendingCRLFs`, write exactly one `\r\n`
  to the hasher.

For `Sign`, the body must also be written to `w`. Since the signed headers
must be prepended, the flow is:
1. Buffer headers in memory.
2. Stream body through hasher AND into a temporary `bytes.Buffer`.
3. Compute MI and sig.
4. Write: new sig header + new MI header + buffered headers + buffered body.

Body buffering is acceptable for the CLI use case. A future milter integration
could accept a pre-computed body hash to avoid buffering.

## Signing Flow (§8, §9.5)

1. Parse all headers into `[]Header`; stream body through body hasher.
2. Collect existing `Message-Instance` headers (sorted ascending by `m=`).
3. Collect existing `DKIM2-Signature` headers (sorted ascending by `i=`).
4. Determine `m = max(existing m=) + 1` (or 1 if none).
5. Determine `i = max(existing i=) + 1` (or 1 if none).
6. Compute header hash over current headers (excluding MI, DKIM2-Sig, etc.).
7. Build new `MessageInstance{Version: m, BodyHash: …, HeaderHash: …}`.
8. Build incomplete `DKIM2Signature` with `SigItem.Value = nil` (empty `s=` per §8.5); fold at 72 chars.
9. Build signing input: all MI headers ascending, all prior sig headers ascending, incomplete sig — canonicalize each (§9.5: unfold, lowercase name, delete ALL WSP from value), concatenate, SHA-256.
10. Sign digest with private key (RSA PKCS#1v15 or Ed25519).
11. Insert real signature value into `SigItem.Value`; fold complete header.
12. Write new sig + new MI + original headers + body to `w`.

## Verification Flow (§10)

1. Parse headers; stream body through body hasher.
2. Check: number of `DKIM2-Signature` headers equals number of `Message-Instance` headers. If not, return `FAIL` for all (spec review note #3).
3. For each `DKIM2-Signature` in descending `i=` order:
   a. Fetch public key via `KeyFetcher`.
   b. Build signing input using headers present at the time this sig was created: MI headers with `m= <= this sig's m=`, sig headers with `i= < this sig's i=`, plus the incomplete form of this sig.
   c. Verify signature over SHA-256 of signing input.
4. Return `[]VerifyResult`, one per signature, `Error == nil` means pass.

## Recipe / MI Diff (§6)

`recipe.go` exposes:

```go
type Recipe struct { /* JSON-encodable diff structure */ }

// ComputeDiff computes the Recipe that describes how `after` differs from
// `before`. Used by intermediaries to build MI v=N headers.
// Neither message's body is retained; callers pass pre-parsed Header slices
// and body content.
func ComputeDiff(beforeHeaders []Header, beforeBody []byte,
                 afterHeaders []Header, afterBody []byte) (*Recipe, error)
```

No snapshot store in this library — that is milter infrastructure.

## DNS

```go
// NetKeyFetcher looks up real DNS TXT records via net.LookupTXT.
type NetKeyFetcher struct{}

// JSONKeyFetcher reads from a dns.json file in the same format used by
// the Python, Perl, and C implementations.
type JSONKeyFetcher struct {
    Path string // path to dns.json
}
```

## Testing

All tests are in `dkim2/dkim2_test.go`, using `go test ./...`.
No copies of test data — tests reference shared files by relative path.

**Sign tests** — table-driven. Each row matches a Python test case: same
input email, selector, domain, key, MAIL FROM, RCPT TO, fixed timestamp
`1740000000`. Go output must be byte-for-byte identical to
`../../python/tests/expected/<name>.eml`.

**Verify tests** — three loops:
- `../../python/tests/expected/*.eml`
- `../../brong/tests/expected/*.eml`
- `../../c/tests/` (C implementation expected outputs)

Go verifier must pass on all of them. Uses `JSONKeyFetcher` with
`../../dns.json`.

**Key fixture** — `../../keys/*.pem` for signing. Same key files used by
all other implementations.

When the spec changes and expected files are regenerated, `go test ./...`
immediately catches any Go divergence.

## Dependencies

Standard library only for crypto and hashing (`crypto/rsa`, `crypto/ed25519`,
`crypto/sha256`). JSON via `encoding/json`. No third-party dependencies
anticipated.
