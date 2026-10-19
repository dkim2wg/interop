# DKIM2 draft -07: implementation contract

Spec: `spec/draft-ietf-dkim-dkim2-spec-07.txt` (landed 2026-10-18). Our code targets -06.
Audit findings per implementation: `docs/superpowers/specs/2026-10-18-dkim2-spec-07-audit.md`.

This document fixes every choice that the spec leaves open, so that all of the
implementations behave identically. Where it says "MUST", that is our contract,
not necessarily the spec's.

## Decisions (Bron, 2026-10-18)

1. **MLDSA44-Ed25519-SHA512: skipped for now.** DKIMKEYS defines no `k=`/`p=` for it.
   An unknown sig-name stays "disregarded" (§3.5) exactly as today.
2. **JSON keys: conservative in send, liberal in receive.** Signers emit every key
   in lowercase. Verifiers match keys case-insensitively at every level: top level
   (`h`/`b`), header names inside `h`, and step keys (`c`/`d`/`u`). Two keys that are
   equal ignoring case, in the same object, count as a duplicate and give
   "contains invalid JSON". The same principle applies to tag names in
   Message-Instance and DKIM2-Signature: accept any case, and treat duplicates ignoring case.
3. **From rewriting.** A list manager or reflector that changes a message, or that
   originates it (its hop becomes i=1), rewrites From to an address in its own
   signing domain. That keeps From Authentic (§11).

## C1. "u" Recipe step (§5, §5.1, §5.2) — replaces our "b" step

- Emit: group consecutive literal lines or values into steps. A line goes in a
  `"d"` run if it is valid UTF-8 (ASCII included), and in a `"u"` run otherwise.
  `"u"` strings are canonical base64 of the raw octets.
- Parse: each step object has exactly one key, and that key is one of `c`/`d`/`u`
  (any case, per decision 2). Zero keys, two keys or any other key gives
  "contains invalid JSON". The old `"b"` step key is now just an unknown key, so it
  is invalid.
- A `"u"` string must match all three schema patterns:
  `^[A-Za-z0-9+/]*={0,2}$`, `^(.{4})*$` and `^([^=]*|.*[AQgw]==|.*[AEIMQUYcgkosw048]=)$`.
  The last one is the zero-pad-bits rule: "QR==" is invalid. The decoded octets
  must not contain CR or LF.
- A `"d"` string must not contain CR or LF. Where the language can tell, it must
  be valid UTF-8: JS/Python lone surrogates (U+D800–DFFF) are invalid.
- `"h": {}` (no properties) and a top-level object with neither `h` nor `b` are
  "contains invalid JSON".

## C2. Flags (§10.10, §12.5)

- Delete all `donotmodify`/`donotexplode` enforcement and its error strings.
  `f=` stays a generic flag list.
- Signer API gains `exploded` (bool). The signer adds `exploded` to `f=` when
  i > 1 and either `exploded` was requested or rt= holds more than one address.
  Requesting `exploded` at i = 1 is ignored (never emitted). Existing generic
  flag options keep working, but a caller-supplied `exploded` at i = 1 is dropped.
- Hint header `X-DKIM2-Exploded: yes`. Mailman and Sympa add it to every
  distribution copy. Signing milters treat its presence as `exploded` requested,
  and delete it before signing. It is an X- header, so it is unsigned anyway.

## C3. Relaxed domain match (§7.2) and address domains (§18)

- `domain_of(addr)`: take the text between the last `@` and the closing `>`.
  Lowercase it and strip one trailing dot. A domain literal (starts with `[`) is
  returned marked as a literal.
- A-label mapping: each label that contains non-ASCII is lowercased and becomes
  `xn--` + Punycode (RFC 3492). Use the language's IDNA facility where it is in the
  stdlib (Python `encodings.idna` per label, JS `new URL`); otherwise hand-roll
  RFC 3492 encode (Go, C, Perl may use `URI::_punycode`). No full UTS-46 mapping.
  Signers record mf=/rt= domains as A-labels. Verifiers compare A-labels.
- `relaxed_match(p1, p2)`: if either is a literal, no match. Otherwise loop: if
  p1 == p2, match; if p1 has no dot, no match; else drop p1's leftmost label.
  Only p1 is shortened.

## C4. Chain of Custody (§7.1 item 1, §14.4) — every failure is PERMERROR

For every signature S: if S has mf=, mf is not `<>`, and S has no nd=, then
relaxed_match(domain_of(mf), S.d) must hold. Otherwise:
`PERMERROR: DKIM2-Signature i=<S> MAIL FROM and d= do not match`

For i = 2..N, with P = signature i−1:
1. If P has nd=: S.d must equal P.nd, compared without regard to case. Otherwise:
   `PERMERROR: DKIM2-Signature i=<P> nd= does not match`. Then skip steps 2–4 for S.
2. Else if S has nd=: some rt= address R of P must satisfy relaxed_match(domain_of(R), S.d). Otherwise:
   `PERMERROR: DKIM2-Signature i=<S> d= does not match the rt= of i=<P>`
3. Else if S's mf decodes to `<>`: the same test as step 2, with the same error string.
4. Else: some R of P must satisfy relaxed_match(domain_of(S.mf), domain_of(R)). Otherwise:
   `PERMERROR: DKIM2-Signature i=<S> mf= does not match the rt= of i=<P>`

- If the top signature has nd=, inbound verification gives
  `PERMERROR: DKIM2-Signature i=<N> unexpected nd= tag`. Keep each implementation's
  existing outbound/signer-gate allowance (its own d= is about to satisfy the nd=).
- nd= together with mf= or rt= gives `PERMERROR: DKIM2-Signature i=<x> tag=mf was unexpected`
  (or `tag=rt`).
- The envelope checks against the top signature keep the existing strings, with a colon:
  `PERMERROR: DKIM2-Signature i=<x> MAIL FROM <value> did not match`,
  `... RCPT TO <value> did not match`.

## C5. From Authentic (§11, §14.8)

Let N be the top Message-Instance. State k is the header set of the message as
it was when MI m=k was the highest. State N is the message as received; state k−1
is state k with MI k's header Recipe applied. Reuse the planned/undo walk that
already reconstructs header states.

Pairs to check: the From in effect when each relevant signature was made
(§11; corrected 2026-10-18 with Bron. A From that was replaced before any
signature covered it, such as the author's From in an unsigned ingress m=1 that a
list rewrote in m=2 before signing i=1, is never checked. §13.3 makes that
original-form check an optional receiver assessment.)
- (From at state m(i=1), signature i=1), where m(i=1) is i=1's m= value.
- For each signature i ≥ 2: if any MI k with m(i−1) < k ≤ m(i) has a `from`
  key in its header Recipe (any case), check (From at state m(i), signature i).
- Instances above the top signature's m= (unsigned top instances, outbound/gate
  mode) are not checked here; the signer's own check covers them.

A pair passes when that state has exactly one From field, the field holds exactly
one mailbox, the addr-spec domain is not a literal, and
relaxed_match(A-label(domain), sig.d). Otherwise:
`PERMERROR: DKIM2-Signature i=<i> matching From is not authentic`

Use the language's address parser leniently: take `Name <a@b>` or `a@b`. A group,
or more than one address, fails.

**Signer:** before signing with domain D, if the message has no DKIM2-Signature
yet, or any Message-Instance above the highest signed m= has a `from` key in its
header Recipe, then the current From must pass the same test against D.
Otherwise refuse to sign, with:
`From header field is not Authentic for d=<D>`.
The signer gate's outbound-mode verification must not apply C5 to the unsigned
top instances (the signer's own check covers them).

## C6. Error strings (§14.1–§14.8)

Format: `<STATE>: <text>`. STATE is PERMERROR, FAIL or TEMPERROR, followed by a
colon and one space. Where an implementation stores the state separately, the
text it shows/records is still the full string. Exact texts:

```
(no DKIM2 header fields at all: result "none", A-R "dkim2=none", NO error string and no PERMERROR — Bron 2026-10-18)
PERMERROR: Message-Instance m=<x> missing
PERMERROR: Message-Instance m=<x> syntax error
PERMERROR: Message-Instance m=<x> tag=<y> missing
PERMERROR: Message-Instance m=<x> is not signed         (also: MIs present but no signature)
PERMERROR: Message-Instance m=<x> has a duplicate hash algorithm
PERMERROR: Message-Instance m=<x> contains invalid JSON (JSON syntax AND schema/C1 violations)
PERMERROR: Message-Instance m=<x> JSON is unacceptably complex   (only where a local limit exists)
PERMERROR: DKIM2-Signature i=<x> missing
PERMERROR: DKIM2-Signature i=<x> syntax error           (also: duplicate tag, unbracketed mf/rt, bad i=/m= number)
PERMERROR: DKIM2-Signature i=<x> tag=<y> missing
PERMERROR: DKIM2-Signature i=<x> tag=<y> was unexpected
PERMERROR: DKIM2-Signature i=<x> has a duplicate selector
PERMERROR: DKIM2-Signature i=<x> has more selectors than allowed
PERMERROR: DKIM2-Signature i=<x> signature expired       (t more than 14 days = 1209600 s before now)
PERMERROR: DKIM2-Signature i=<x> signature is from the future   (t more than 1 day = 86400 s after now)
(C4 strings)
TEMPERROR: DKIM2-Signature i=<x> public key <s1> could not be fetched
PERMERROR: DKIM2-Signature i=<x> public key <s1> does not exist
PERMERROR: DKIM2-Signature i=<x> public key <s1> has multiple records
PERMERROR: DKIM2-Signature i=<x> public key <s1> has a syntax error
PERMERROR: DKIM2-Signature i=<x> public key <s1> algorithm mismatch
PERMERROR: DKIM2-Signature i=<x> public key <s1> has been revoked
FAIL: DKIM2-Signature i=<x> selector <s1> incorrect signature                  (all checkable sigs failed)
FAIL: DKIM2-Signature i=<x> signature <s1> signature <s2> failed               (s1 passed, s2 failed)
FAIL: Message-Instance m=<x> header hash <alg> mismatch
FAIL: Message-Instance m=<x> body hash <alg> mismatch
PERMERROR: DKIM2-Signature i=<x> matching From is not authentic
```

`<alg>` is the hash name, e.g. `sha256`. For a local check with no -07 string
(RSA key too short, no supported algorithm, nonce too long, chain-length limits),
keep the existing wording, but give it the `STATE: ` prefix and make the state
PERMERROR.

## C7. DSN (§16) and SMTP (§13)

- Never generate or propagate a DSN when the top signature's mf= decodes to `<>`.
  Never generate one for a message that was not Provisionally Verified (top
  signature valid, and top MI hashes match).
- C milter: when the signer gate refuses, return REJECT with
  `smfi_setreply("550", "5.7.1", <reason>)` instead of ACCEPT. Verify-mode
  rejections use 550/5.7.1 with the -07 string, and TEMPERROR uses 451/4.7.5.
- Perl milters: if a gate refusal currently forwards a message that carries DKIM2
  headers, change that to 550 5.7.1 <reason>. Otherwise keep the behaviour, and
  report what it is.

## C8. Bookkeeping

- `DKIM2_DRAFT = ietf-dkim-dkim2-spec-07`. Each repo bumps `DKIM2_DATE` to the
  date its emitted output changed (2026-10-18 for all of this work).
- Update section references to -07 numbering (table in the audit doc). History
  comments ("spec-05 narrowed ...", "draft-05 added sha512") keep their versions.
- Replace `c/dkim2-spec.txt` with the -07 text.
- Perl dist goes to 0.23, with a Changes entry. Bron uploads to CPAN and refreshes hm himself.
- Fixtures: change From addresses so that From is Authentic against i=1 (and
  against later From-changing signers), then regenerate the expected files.
  Never weaken the check to keep an old fixture passing.

## C9. Check order and the primary result (added 2026-10-19, final review I1)

All five verifiers report the same primary error and state for the same input.
They run, or at least rank, the checks in -07 §14 section order:

1. §14.2: header field validity (syntax, tags, Recipes, duplicate hash/selector, "is not signed", missing)
2. §14.3: timestamps (expired, from the future)
3. §14.4: Chain of Custody, envelope match, then the C4 steps
4. §14.5: public keys (TEMPERROR/PERMERROR key strings)
5. §14.6: signature verification (FAIL selector strings)
6. §14.7: body and header hashes (FAIL hash mismatch)
7. §14.8: From Authentic

The PRIMARY error is the first one in this order. Within one section, the lowest
i= (or m=) comes first.

How "within one section" applies (fix wave, 2026-10-19; vectors in
util/negative-vectors.sh pin each):
- §14.3, §14.5, §14.6, §14.8 (checks made per signature): the lowest i= first.
  Within one signature, its key errors (§14.5) come before its signature
  verdict (§14.6). "has no signature with a supported algorithm" ranks with §14.5.
- §14.4: in the order C4 walks: an unexpected top nd=, the envelope (MAIL FROM,
  then RCPT TO), then each signature S from i=1 up, S against the signature
  below it before S's own mf= against its d=.
- §14.7: top down. A lower instance is rebuilt from the one above it, so the
  highest instance that fails is primary (a Subject changed after signing a
  two-instance chain is `m=2 ... mismatch`, though m=1 mismatches too).
- §14.2 includes every Recipe on its own, checked for every instance (highest
  m= first) whether or not the chain walk reaches it: its base64, its JSON, the
  §5 schema, and the "c" ranges ascending without overlap. A Recipe that keeps
  all of that but does not fit the message (a "c" range past the last line or
  field) can only be found by applying it, so it is the chain walk's: it ranks
  in §14.7, after the hash check of its own instance, with the same
  "contains invalid JSON" text. Otherwise §14.2 errors keep the order each
  implementation reads the fields in (no vector has two §14.2 faults).
- Every signature is checked whether or not the chain walk reaches the
  instance it covers. The result state (and the A-R result) is the primary
error's state. A verifier may list later errors after the primary one, but they
never change the state, and the primary error is the first `STATE: text` line
the CLI prints. A From tampered on a signed message is therefore
`FAIL: Message-Instance m=<x> header hash <alg> mismatch` (§14.7 comes before §14.8)
in every verifier.
