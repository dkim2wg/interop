# DKIM2 Implementer Guide

**Spec:** draft-ietf-dkim-dkim2-spec-01  
**Audience:** Authors writing a DKIM2 library or integrating DKIM2 into an MTA

---

## What DKIM2 adds over DKIM1

DKIM1 puts one signature per hop, and each relay can only sign things it added — it
has no visibility into whether the message was tampered between hops.  DKIM2 fixes
this with two new mechanisms:

1. **Message-Instance (MI) header** — a hash snapshot of the message at each relay.
   Every hop records what the message looked like when it arrived.  Verifiers can
   check that the chain of snapshots is intact.

2. **Chained DKIM2-Signature headers** — each relay signs the current MI header
   *and* all previous signatures.  This creates a tamper-evident chain: forging a
   message or inserting a hop requires breaking a signature.

---

## Core concepts

### Message-Instance header (`m=`)

```
Message-Instance: m=1; h=sha256:<hdr-hash>:<body-hash>;
```

`m=` is the revision number (1-based, sequential).  `h=` contains a SHA-256 hash of
the message headers (`hdr-hash`) and body (`body-hash`), both base64url-encoded
without padding.

**Header hash**: sort all non-DKIM2 / non-MI headers by name (case-insensitive,
stable), canonicalize each as `lowercase-name:collapsed-value\r\n`, then SHA-256
the concatenation.

**Body hash**: simple canonicalization (strip trailing CRLF runs, ensure single
trailing CRLF), then SHA-256.

### DKIM2-Signature header (`i=`)

```
DKIM2-Signature: i=1; m=1; t=<unix-ts>; d=example.com;
  mf=<base64(MAIL FROM)>; rt=<base64(RCPT TO)>,...;
  s=<selector>:<alg>:<base64-sig>;
```

Key tags:

| Tag | Meaning |
|-----|---------|
| `i=` | Hop sequence number (1-based, sequential across chain) |
| `m=` | Highest MI revision this signature covers |
| `t=` | Unix timestamp |
| `d=` | Signing domain (must be a suffix of the `mf=` domain) |
| `mf=` | Base64-encoded MAIL FROM (with angle brackets, e.g. `<user@example.com>`) |
| `rt=` | Comma-separated base64-encoded RCPT TO values |
| `s=` | Comma-separated `selector:algorithm:base64-sig` triples (algorithm agility) |
| `n=` | Optional nonce ≤ 64 characters |

### Signing input (§9.5)

The data signed is the SHA-256 of all of the following concatenated,
each header canonicalized as `lowercase-name:collapsed-value\r\n`:

1. All Message-Instance headers with `m=` ≤ the signed MI version, in ascending `m=` order
2. All DKIM2-Signature headers with `i=` ≤ the current hop, in ascending `i=` order
3. The incomplete DKIM2-Signature being created — same header but with each `s=` value
   replaced by an empty string (i.e. `selector:alg:`)

**Canonicalization**: lowercase the name, strip all whitespace (including folded
continuations) from the value.  The resulting bytes must end with `\r\n`.  Apply this
consistently to both the signer and verifier or signatures will not match.

---

## Signing: step by step

```
1. Parse the incoming message into headers + body.
2. Compute body hash (§5.1).
3. Compute header hash (§5.2) using existing non-DKIM2/non-MI headers.
4. Determine m= for the new MI:
     - If no existing MI headers: m=1
     - Otherwise: highest existing m= + 1
5. Build the MI header value:
     m=<n>; h=sha256:<hdr_b64>:<body_b64>;
   Prepend as "Message-Instance: <value>" to the message.
6. Determine i= for the new signature:
     - If no existing signatures: i=1
     - Otherwise: highest existing i= + 1
7. Build the incomplete signature (all s= values empty):
     i=<n>; m=<MI>; t=<ts>; d=<domain>; mf=<mf_b64>; rt=<rt_b64>; s=<sel>:<alg>:;
8. Compute the signing input (§9.5) using the incomplete signature.
9. SHA-256 the signing input; sign with the private key.
10. Insert the signature value into the s= field.
11. Prepend "DKIM2-Signature: <value>" to the message (after the MI header).
```

Multi-algorithm signing (algorithm agility): create multiple `sel:alg:sig` triples in
the `s=` tag, one per key.  The verifier is expected to verify all of them.

---

## Verification: step by step

```
1. Parse all Message-Instance and DKIM2-Signature headers.
2. Check chain completeness: i=1 through i=N must all be present with no gaps.
   Same for m=1 through m=M.
3. Check top signature coverage: top sig's m= must equal the highest MI version.
4. For each signature i=1..N (verify all, not just the outermost):
   a. §10.3: reject if timestamp is >300s in the future or >14 days in the past.
   b. §7.7: d= must be a suffix of the mf= domain (relaxed match).
   c. §7.3: n= nonce must not exceed 64 characters.
   d. §10.6: for each s= item, look up the public key and verify the signature.
      Any crypto failure is a hard failure. If no items could be looked up, PERMERROR.
   e. Build the signing input using only MI headers with m ≤ this sig's m=,
      and only DKIM2-Signature headers with i ≤ this sig's i=.
5. §8.2: inter-sig chain custody: for each consecutive pair sig[k-1], sig[k],
   the domain of sig[k]'s mf= must relaxed-match at least one domain in sig[k-1]'s rt=.
6. §10.7: verify the top MI's header hash and body hash against the live message.
```

### Relaxed domain match

`d1` relaxed-matches `d2` if `d1 == d2` or `d1` ends with `"." + d2`.  This means
`mail.example.com` matches `example.com` but not `notexample.com`.

---

## Implementation API comparison

All four reference implementations provide the same logical operations; the API shape
varies by language idiom.

### Go (`github.com/dkim2wg/interop/go/dkim2`)

```go
// Sign reads r, adds MI + DKIM2-Signature headers, writes to w.
func Sign(r io.Reader, w io.Writer, key crypto.PrivateKey, opts SignOptions) error

// Verify reads r, verifies all signatures. Returns one result per sig.
func Verify(r io.Reader, fetcher KeyFetcher, opts ...VerifyOptions) ([]VerifyResult, error)

type SignOptions struct {
    Selector  string
    Domain    string
    MailFrom  string
    RcptTo    []string
    Timestamp int64    // 0 = time.Now()
}

type VerifyOptions struct {
    MailFrom           string   // optional §10.4 envelope check
    RcptTo             []string
    SkipTimestampCheck bool     // for testing with old messages
}

type VerifyResult struct {
    Sequence int
    Domain   string
    Error    error  // nil = pass
}

// KeyFetcher interface for pluggable key lookup
type KeyFetcher interface {
    FetchPublicKey(selector, domain string) (crypto.PublicKey, string, error)
}

// Implementations: JSONKeyFetcher (dns.json file), NetKeyFetcher (live DNS)
```

Streaming: Sign and Verify process headers + body in one pass; the body is never
buffered in memory (body hash is computed incrementally).

### Python (`python/dkim2sign.py`, `python/dkim2verify.py`)

Script-level API via functions:

```python
# Returns signed message bytes
sign_message(raw: bytes, key, domain, selector, mail_from, rcpt_to, timestamp=None) -> bytes

# Returns list of error strings (empty = pass)
verify_message(raw: bytes, dns_data: dict, full_chain: bool = False,
               skip_timestamp_check: bool = False) -> list[str]

# Lower-level: verify a single DKIM2-Signature header
verify_dkim2_signature(sig_hdr, mi_headers, other_sig_headers, dns_data,
                       skip_timestamp_check=False) -> list[str]
```

Key lookup is via a `dns_data` dict loaded from `dns.json`, or live DNS.  The
`full_chain` flag enables walking backwards through MI versions and undoing recipes at
each step before verifying that hop's hashes.

### Perl (`brong/lib/Mail/DKIM2/`)

Streaming object API modelled on `Mail::DKIM`:

```perl
# Signing
my $signer = Mail::DKIM2::Signer->new(
    Domain    => 'example.com',
    Selector  => 'sel1',
    Key       => $privkey_object,   # Crypt::PK::RSA or Crypt::PK::Ed25519
    MailFrom  => 'sender@example.com',
    RcptTo    => ['rcpt@example.com'],
    Timestamp => $unix_ts,          # optional
);
$signer->PRINT($message_text);
$signer->CLOSE;
my $header = $signer->as_string();  # "DKIM2-Signature: ..."

# Verification
my $v = Mail::DKIM2::Verifier->new();
$v->set_pubkey_callback(sub { my ($sig, $idx) = @_; return $pubkey_obj; });
$v->skip_timestamp_check(1);       # for testing
$v->PRINT($message_text);
$v->CLOSE;
print $v->result();         # 'pass', 'fail', 'none', 'permerror', 'temperror'
print $v->result_detail();  # human-readable detail
```

The `set_pubkey_callback` receives a `Mail::DKIM2::Signature` object and the s= item
index; return a `Crypt::PK::RSA` or `Crypt::PK::Ed25519` object, or undef to skip.

### C (`c/dkim2_sign.h`, `c/dkim2_verify.h`)

Low-level context-based API. The caller is responsible for feeding headers and body:

```c
// Signing
dkim2_ctx_t ctx = {0};
ctx.headers    = header_array;    // char** of "Name: value\r\n" strings
ctx.n_headers  = n;
ctx.mail_from  = "<sender@example.com>";
ctx.rcpt_to    = rcpt_array;      // NULL-terminated char**
eml_parse(path, &ctx.headers, &ctx.n_headers, ctx.body_digest); // or set manually

dkim2_sign_config_t cfg = {
    .domain = "example.com", .selector = "sel1",
    .privkey_path = "sel1.pem", .alg = "ed25519-sha256",
};
char *mi_val, *sig_val;
dkim2_do_sign(&ctx, &cfg, &mi_val, &sig_val);
// mi_val / sig_val are the header values (not full "Name: value" lines); caller frees

// Verification
dkim2_ctx_t vctx = {0};
// ... populate headers, n_headers, body_digest, mail_from, rcpt_to,
//     mi_list (via dkim2_mi_parse), sig_list (via dkim2_sig_parse)
vctx.skip_timestamp_check = 1;   // for testing
dkim2_verify_result_t result;
dkim2_do_verify(&vctx, &result);
// result.status: DKIM2_OK, DKIM2_FAIL, DKIM2_PERMERROR, DKIM2_TEMPERROR
// result.message: human-readable string
```

The C implementation uses `eml_parse()` to parse a `.eml` file into the header array
and body digest in a single streaming pass.  DNS key lookup goes through a pluggable
function pointer set via `dkim2_dns_set_override()`.

---

## Key generation

DKIM2 uses standard DKIM1 DNS TXT records.  Supported algorithms:

- **Ed25519** (recommended): 32-byte keys, fast, small signatures
- **RSA-SHA256**: 2048-bit minimum recommended; 1024-bit supported but weak

```bash
# Ed25519
openssl genpkey -algorithm ed25519 -out sel1.ed25519.pem
openssl pkey -in sel1.ed25519.pem -pubout | \
  openssl pkey -pubin -outform DER | base64 | tr -d '\n'
# → publish as: v=DKIM1; k=ed25519; p=<base64>

# RSA-2048
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out sel1.rsa.pem
openssl pkey -in sel1.rsa.pem -pubout -outform DER | base64 | tr -d '\n'
# → publish as: v=DKIM1; k=rsa; p=<base64>
```

DNS record format (`selector._domainkey.domain IN TXT`):

```
v=DKIM1; k=ed25519; p=hwjviTXyzUXSCWayBqE17s/4NSynQKxw58jayHudRAI=
```

---

## Common implementation mistakes

**Signing input whitespace**: The canonicalization strips all inter-word whitespace
from header values.  A single space and a run of spaces must produce the same bytes.
Folded continuation lines (`\r\n `) must also be collapsed.

**Header ordering**: MI headers go before DKIM2-Signature headers in the signing
input.  Within each group, ascending order by `m=` or `i=`.  The email itself stores
them newest-first (prepend), so the signing input order is the reverse of wire order.

**Incomplete signature form**: The `s=` values are blanked (empty string after the
second colon) in the signing input — but the structure `selector:algorithm:` must
remain.  If there are multiple `sel:alg:sig` triples, blank all of them in the
signing input.

**Trailing semicolons**: The spec's tag-list grammar requires a trailing `;` on each
header value.  Some implementations omit it.  Verifiers should be lenient (accept
headers with or without trailing `;`) but signers should always emit one.

**mf= and rt= encoding**: These fields are base64-encoded on the wire.  The decoded
value includes angle brackets: `<user@example.com>`.

**Algorithm agility**: When verifying, check all `s=` items, not just the first.  Any
item that fails cryptographically is a hard failure, even if another item passes.

**Inner signatures**: Verify all signatures i=1..N, not just the outermost.  Each
inner signature's signing input must use only the MI and sig headers that existed at
the time that hop signed — i.e., MI with `m ≤ sig.m` and sigs with `i ≤ sig.i`.

**MTA-injected headers at signing time (the `Delivered-To` / `Received-SPF` trap)**:
The §5.2 hash excludes a fixed set of trace/transient headers — `Received`,
`Return-Path`, `Authentication-Results`, `X-*`, `DKIM-Signature`, `ARC-*`,
`Message-Instance`, `DKIM2-Signature` — but **not** every header an MTA may add.
Two real-world headers bite signers that run *inside* an MTA delivery pipeline:

- **`Delivered-To`** — Postfix `local(8)` prepends it when delivering to a
  `.forward`/alias **`|command`**. A signer invoked that way (e.g. a mailing-list
  or reflector hook) will hash a `Delivered-To` that is **renamed or stripped
  before the message is delivered onward**, so the header-field hash can never be
  reproduced by the verifier. `Delivered-To` is *not* an IANA trace header (only
  `Received`/`Return-Path` are; `Delivered-To` is provisionally registered, RFC
  9228), so it is correctly *not* in the skip list — the signer must not let it
  into the message it hashes. Fixes: invoke the signer via a transport that does
  not add it (Postfix `pipe(8)` instead of a `local(8)` alias; set
  `prepend_delivered_header` to drop the `command` context; or strip the header
  before signing).
- **`Received-SPF`** — added by receiving MTAs (RFC 7208). Same shape: present
  when a downstream hop signs/verifies, absent or different elsewhere.

General rule: **a signer must hash only headers that will travel unchanged with
the message.** If your signing point sits inside an MTA, audit exactly which
headers that MTA injects/rewrites at that hop, and keep transient ones out of the
signed message. The reflector in this repo hit this with `Delivered-To`; see
`deploy/postfix-dkim2-reflect.master.cf` for the `pipe(8)` transport that avoids it.

---

## Recipe field (§6 — undo support)

The optional `r=` tag in the MI header carries a base64-encoded JSON structure
describing how to reconstruct the previous message state from the current one.  This
allows multi-hop verifiers to "undo" modifications made by each relay and verify that
each hop's MI hashes were correct at the time of signing.

Recipe structure:
```json
{
  "h": {
    "subject": [{"op": "set", "val": "old subject"}],
    "x-custom": [{"op": "del"}]
  },
  "b": [{"op": "del", "pos": 5, "val": "appended line\r\n"}]
}
```

`h` recipes operate on headers; `b` recipes operate on body lines.  Operations are
`set` (add/replace), `del` (remove), and `ins` (insert).  Apply in reverse order to
undo.

Implementations that only verify the final delivery state do not need to implement
recipe decoding — they can verify the topmost MI's hashes directly against the live
message.

---

## Test vectors

The `python/tests/expected/` directory contains signed `.eml` files covering:

- Simple Ed25519 and RSA signing
- Multi-hop chains (2–3 hops, header additions/deletions, body modifications)
- Multi-recipient messages
- DSN (null sender `<>`)
- Empty body
- Duplicate headers

Use these to validate a new implementation before integrating with live traffic.  The
shared `dns.json` and `keys/` directory provides the key material used by all
reference implementations.
