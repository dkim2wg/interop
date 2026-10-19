# DKIM2 Implementer Guide

**Spec:** draft-ietf-dkim-dkim2-spec-07  
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
| `d=` | Signing domain (the `mf=` domain must relaxed-match it, -07 §7) |
| `mf=` | Base64-encoded MAIL FROM (with angle brackets, e.g. `<user@example.com>`) |
| `rt=` | Comma-separated base64-encoded RCPT TO values |
| `s=` | Comma-separated `selector:algorithm:base64-sig` triples (algorithm agility) |
| `n=` | Optional nonce ≤ 64 characters |
| `nd=` | Imaginary-hop bridge (-07 §12.3): the `d=` of the next signature; replaces `mf=`/`rt=` |
| `f=` | Optional flag list (-07 §10.10). `exploded` is the only flag -07 defines |

### Signing input (-07 §12.8)

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
1. Parse the incoming message into headers + body. If it already carries
   DKIM2 headers, verify that chain first ("Verify before you sign"). If it
   has no DKIM2-Signature yet, or an unsigned instance changed From, From
   must be Authentic for <domain> (-07 §12.4), or refuse.
2. Compute body hash (-07 §6.1).
3. Compute header hash (-07 §6.2) using existing non-DKIM2/non-MI headers.
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
8. Compute the signing input (-07 §12.8) using the incomplete signature.
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
3. Check top signature coverage: no Message-Instance may have an m= above
   every signature's m= ("Message-Instance m=<x> is not signed").
4. For each signature i=1..N (verify all, not just the outermost):
   a. -07 §12.6/§14: PERMERROR if t= is more than 1 day (86400 s) in the
      future or more than 14 days (1209600 s) in the past.
   b. n= nonce must not exceed 64 characters.
   c. For each s= item, look up the public key and verify the signature.
      Any crypto failure is a hard failure. If no items could be looked up, PERMERROR.
   d. Build the signing input using only MI headers with m ≤ this sig's m=,
      and only DKIM2-Signature headers with i ≤ this sig's i=.
5. -07 §14.4: Chain of Custody (table below).
6. Verify the top MI's header hash and body hash against the live message,
   then undo each Recipe and check each lower instance's hashes.
7. -07 §14.8: From must be Authentic (below).
```

Every error has an exact -07 text of the form `STATE: text`, e.g.
`PERMERROR: DKIM2-Signature i=2 d= does not match the rt= of i=1`. A message
with no DKIM2 header fields at all is result `none` (A-R `dkim2=none`), not
an error. `util/negative-vectors.sh` checks the strings across all five
verifiers.

### Relaxed domain match (-07 §7.2)

`relaxed_match(p1, p2)` is asymmetric: only `p1` is shortened. If either
is a domain literal (`[192.0.2.1]`), no match. Otherwise loop: if `p1 == p2`,
match; if `p1` has no dot, no match; else drop `p1`'s leftmost label. So
`p1 = mail.example.com` matches `p2 = example.com`, but not the other way
round, and `notexample.com` never matches `example.com`.

Take a domain from an address as the text between the last `@` and the
closing `>`, lowercased, with one trailing dot stripped (Postfix may record
`<A@Example.COM.>`). A non-ASCII label is compared as its A-label (`xn--`
Punycode, -07 §18); signers record `mf=`/`rt=` domains as A-labels.

### Chain of Custody (-07 §7.1, §14.4)

Every failure is a PERMERROR. For each signature S with `mf=` that is not
`<>` and no `nd=`: `relaxed_match(domain(mf), S.d)`, else
`DKIM2-Signature i=<S> MAIL FROM and d= do not match`. Then for i = 2..N,
with P the signature below S:

| Case | Test | Error |
|------|------|-------|
| P has `nd=` | `S.d` equals `P.nd`, ignoring case (steps below skipped) | `DKIM2-Signature i=<P> nd= does not match` |
| S has `nd=` | some `rt=` R of P: `relaxed_match(domain(R), S.d)` | `DKIM2-Signature i=<S> d= does not match the rt= of i=<P>` |
| S has `mf=<>` (a bounce) | as the row above | `DKIM2-Signature i=<S> d= does not match the rt= of i=<P>` |
| otherwise | some R of P: `relaxed_match(domain(S.mf), domain(R))` | `DKIM2-Signature i=<S> mf= does not match the rt= of i=<P>` |

A top signature carrying `nd=` gives `DKIM2-Signature i=<N> unexpected nd=
tag` inbound (a signer whose own `d=` is the `nd=` may still extend it), and
`nd=` with `mf=` or `rt=` gives `... tag=mf was unexpected`.

### From must be Authentic (-07 §11, §14.8)

Let state k be the message as it was when Message-Instance m=k was the
highest (state N is the message as received; state k−1 is state k with MI
k's header Recipe applied). Check the From in effect when each signature
was made:

- From at state m(i=1) against signature i=1;
- for each i ≥ 2, if some instance k with m(i−1) < k ≤ m(i) has a `from`
  key (any case) in its header Recipe, From at state m(i) against i.

A From replaced before any signature covered it (a list's unsigned ingress
`m=1` with the author's From, rewritten in `m=2` before the list signed
`i=1` over `m=2`) is never checked; instances above the top signature's
`m=` are left to the signer.

A pair passes when that state has exactly one From field holding exactly one
mailbox (`Name <a@b>` or `a@b`; a group or a list fails), the domain is not
a literal, and `relaxed_match(A-label(domain), sig.d)`. Otherwise
`PERMERROR: DKIM2-Signature i=<i> matching From is not authentic`.

So a list or forwarder that changes a message, or originates one (its hop
is i=1), rewrites From into its own signing domain. The signer checks
this itself: before signing as D, if the message has no DKIM2-Signature yet,
or an instance above the highest signed `m=` changed From, From must pass
against D, or the signer refuses with
`From header field is not Authentic for d=<D>`.

### The `exploded` flag (-07 §12.5)

Above i=1 a signer adds `exploded` to `f=` when it was asked to, or when
`rt=` holds more than one address; at i=1 it never does. A list manager
asks by adding the header field `X-DKIM2-Exploded: yes` to each copy it
distributes; a signing milter treats that field as the request and deletes
it before signing. The -06 `donotmodify`/`donotexplode` flags and their
checks are gone.

---

## Verify before you sign

A signer that is given a message already carrying DKIM2 headers is extending a
chain of custody, so it must verify that chain first and refuse to sign on top
of one that does not check out. All four signers (Python, Go, C, Perl) do this;
`util/signer-gate.sh` is the cross-implementation test.

- **The gate.** Verify the upstream chain as an outbound signer would: the top
  Message-Instance may be unsigned (it is the one about to be signed), but
  every signature below must verify and the Recipes must undo cleanly back to
  the instance below. Any failure means refuse ("not signing: upstream DKIM2
  chain ..."), exit non-zero and emit no new signature. A message with no
  DKIM2 headers is just signed.
- **Null body Recipe.** An *unsigned* instance whose body Recipe is
  `"b": null` (the previous body is not recoverable) is refused by default,
  because the signer would be vouching for a change it cannot check. A
  signature's `m=` is the highest instance at signing time (-07 §10.2), so
  a DKIM2-Signature with `m=k` covers instances 1..k, and "unsigned" means an
  instance whose `m=` is above the highest `m=` of every valid upstream
  signature. Check every such instance, not only the top: a hop (or a list
  manager in front of it) can add its own ordinary instance over an unsigned
  null, and the null is still one nobody upstream vouched for
  (`null-below-unsigned-top`). This hop is the one introducing the null. The
  operator opts in with `--allow-null-body-recipe`
  (Go: `-allow-null-body-recipe`). A null that arrived already signed —
  a list host declared it and signed it, and this hop forwards the message,
  unchanged or with its own ordinary instance on top (`null-below-signed`) —
  is extended without the option: the domain that made the change
  vouched for it. So only a host that introduces a null body Recipe and signs
  it itself (a list host whose list manager adds an unsigned instance) needs
  the option; a forwarder needs nothing. Either way the upstream signatures
  must verify, and the flag does not excuse a forged history: the header
  Recipe is still undone and checked.
- **Only a keyable signature is coverage.** Count a signature towards
  "the top is signed" only if its `i=` is a positive integer, and have the
  verifier report any DKIM2-Signature it cannot key — no `i=`, `i=0`,
  `i=abc`, a field that does not parse — as a PERMERROR, never skip it. A
  verifier that ignores such a field while the gate reads its `m=` lets a
  junk `DKIM2-Signature: m=2` turn an unsigned null top into a "signed" one.
- **Bound `i=` and `m=` before you loop.** Every `i=` and `m=` must be
  1*DIGIT in ASCII — `int()`, `atoi()`, `parseInt` and `strconv.Atoi` all
  take something else (`"0_1"`, the digit prefix of `"4294967297x"`, `"+1"`)
  — at most three digits naming 1..100 (`MAX_CHAIN_NUMBER`; `01` and `001`
  are 1), and, since each names one hop, no more than the chain length limit
  (32 here, `MAX_CHAIN_LENGTH`). Anything else is a PERMERROR found while
  parsing, before any check walks 1..max looking for gaps. Do not convert
  first: `i=99999999999999999999` overflows an `int`, and a loop to
  4294967297 runs a browser out of memory.
- **Refuse duplicate keys in Recipe JSON.** JSON parsers disagree on which
  of two equal keys wins (cJSON keeps the first; Python, Go, Perl and JS
  the last), so `{"b":[...],"b":null}` is a real body Recipe to one verifier
  or gate and a null one to another. Treat a key given twice in any object
  of the Recipe as invalid JSON.
- **Message-Instance-only chains sign.** A list that adds unsigned
  Message-Instances but no DKIM2-Signature (Mailman does this for an unsigned
  post) gives a chain with m=1 and m=2 and no i=1. That is signable: verify
  the Recipes, then sign i=1 over the highest m=. An instance below the
  highest signed m= need not be referenced by any signature; -07 §14 only
  forbids an instance with an m= higher than every signature's.
- **From Authentic.** A signer that originates (no DKIM2-Signature yet) or
  signs over an unsigned instance that changed From checks From against its
  own `d=` and refuses with `From header field is not Authentic for d=<D>`.
  The gate's verification of the unsigned top instances does not apply the
  verifier's From check: the signer's own check covers them.
- **The `nd=` bridge rule.** When the top DKIM2-Signature carries `nd=` (a §12.3
  bridge), the signer may extend the chain only if `nd=` equals its own
  signing `d=` (case-insensitive). Otherwise refuse: "not signing: top
  signature nd=X names another domain".
- **Test tools.** The gate fetches keys like a verifier does. The CLIs take
  them from `dns.json` via `$DKIM2_DNS_JSON`, and fixtures with old `t=` values
  need `--ignore-timestamps` (Go: `-ignore-timestamps`); the signer no longer
  ignores timestamps on its own. The Python verifier likewise needs a
  `dns.json` (`--dns-json`) because it does no live DNS lookups.
- **Fixture builders** that must sign over a deliberately broken chain use
  Python's `sign_message(..., skip_upstream_check=True)`; there is no CLI
  flag for that.

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
    MailFrom           string   // optional -07 §14.4 envelope check
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
`full_chain` flag enables walking backwards through MI versions and undoing Recipes at
each step before verifying that hop's hashes.

### Perl (`perl/lib/Mail/DKIM2/`)

Streaming object API modelled on `Mail::DKIM`, with a one-shot `load()`. The
conventions (CamelCase options, snake_case methods, results vs. croaks) are in
the `Mail::DKIM2` module's POD.

```perl
# Signing
my $signer = Mail::DKIM2::Signer->new(
    Domain    => 'example.com',
    Selector  => 'sel1',
    Key       => $privkey_object,   # Crypt::PK::RSA or Crypt::PK::Ed25519
    MailFrom  => '<sender@example.com>',
    RcptTo    => ['<rcpt@example.com>'],
    Timestamp => $unix_ts,          # optional
)->load($message_text);             # or PRINT($chunk)... CLOSE for streaming
die $signer->result_detail unless $signer->result eq 'signed';
my $header = $signer->as_string();  # "DKIM2-Signature: ..."

# Verification
my $v = Mail::DKIM2::Verifier->new(
    SkipTimestampCheck => 1,        # for testing
    PubkeyCallback     => sub { my ($sig, $idx, $verifier) = @_; return $pubkey_obj; },
)->load($message_text);
print $v->result();         # 'pass', 'fail', 'none', 'permerror', 'temperror'
print $v->result_detail();  # human-readable detail
my $top = $v->top_signature;  # for Authentication-Results header.d / header.i
```

Without `PubkeyCallback` the Verifier looks keys up in DNS through a
`Net::DNS::Resolver` (the `Resolver` option). The callback receives the
`Mail::DKIM2::Signature`, the s= item index, and the verifier; return a
`Crypt::PK::RSA` or `Crypt::PK::Ed25519` object, undef to skip, or fall back to
`$verifier->fetch_public_key($sig, $idx)`.

CLI: `perl/bin/dkim2sign` and `perl/bin/dkim2verify --dns-json dns.json`.

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
The §4 hash excludes a fixed set of trace/transient headers — `Received`,
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

### Signing an MTA's own bounces (-07 §16) — EXPERIMENTAL

DKIM2 §16 expects a bounce/DSN to be signed like any other outbound message,
but most MTAs run no milters or content filters on the bounces they generate
themselves — a *delayed* bounce (accept at RCPT, delivery fails later,
`bounce(8)`-style DSN with `MAIL FROM <>`) would otherwise leave unsigned.

This repo demonstrates two distinct ways to produce a signed DSN, at two
different addresses:

- **`reflector-dsn@dkim2.com`** hand-builds a DSN synchronously in our own
  code (`Mail::DKIM2::DSN`) and injects it — a *reflector transform*, not a
  real delivery failure.
- **`reflector-delayedbounce@dkim2.com`** is genuinely **Postfix-originated**:
  the address is accepted, delivery is made to fail, and Postfix's own
  `bounce(8)` builds the RFC3464 DSN. We only arrange for the outbound DKIM2
  milter to run over it and sign it on the way out — no DSN construction code
  at all. The signing side needs one fallback: with `MAIL FROM <>` there is no
  envelope-sender domain to sign as, so the milter derives the domain from the
  `From:` header instead (only signing if that domain resolves to a held key)
  and emits `mf=<>` on the resulting `DKIM2-Signature`.

Under -07 no DSN may be generated or propagated for a message whose top
`mf=` is `<>`, nor for one that is not Provisionally Verified (top signature
valid and top MI hashes match, -07 §13.1). The copy-pasteable Postfix recipe
(`internal_mail_filter_classes = bounce` + an outbound-only
`non_smtpd_milters`, plus the routing map) and the §16
conformance notes/limits live in `deploy/SERVER.md`, under "Signing
Postfix-generated (delayed) DKIM2 bounces".

---

## Recipe field (-07 §5 — undo support)

The optional `r=` tag in the MI header carries a base64-encoded JSON structure
describing how to reconstruct the previous message state from the current one.  This
allows multi-hop verifiers to "undo" modifications made by each relay and verify that
each hop's MI hashes were correct at the time of signing. An absent `r=` means
"no change": the previous state is this one.

Recipe structure:
```json
{
  "h": {
    "subject": [{"d": ["old subject"]}],
    "x-custom": []
  },
  "b": [{"c": [1, 4]}, {"u": ["Y2Fm6Q=="]}, {"c": [6, 9]}]
}
```

`h` maps a header field name to the steps that rebuild that field's previous
instances (an empty list: the field did not exist); `b` rebuilds the previous
body lines, or is `null` when the previous body is not recoverable. Each
step is an object with exactly one key:

- `"c": [from, to]` copies current lines (or field instances) from..to,
  1-based; ranges ascend and never overlap;
- `"d": [...]` gives literal lines or values as JSON strings (valid UTF-8, no
  CR or LF);
- `"u": [...]` gives literals that are not valid UTF-8 as canonical base64 of
  the raw octets (padded, zero pad bits, decoded value without CR or LF).
  `"u"` replaces the -06 `"b"` step, which is now an unknown key.

Signers emit every key in lower case; verifiers match keys case-insensitively,
and two keys in one object that differ only in case are a duplicate. Any
Recipe problem (bad JSON, a duplicate key, an unknown or missing step key,
bad copy ranges, a bad literal) is
`PERMERROR: Message-Instance m=<x> contains invalid JSON`.

Implementations that only verify the final delivery state do not need to implement
Recipe decoding — they can verify the topmost MI's hashes directly against the live
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
