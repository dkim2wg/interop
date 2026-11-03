# DKIM2 Operator Guide

- **Spec:** draft-ietf-dkim-dkim2-spec-09, with draft-ietf-dkim-dkim2-dns-03
- **Audience:** MTA operators and postmasters deploying DKIM2
- **Installing it:** see the [Postfix mailing-list host guide](dkim2-postfix-list-host-guide.md),
  or [DKIM2 for stock Mailman](dkim2-postfix-stock-mailman-guide.md) for
  an unpatched Mailman with DKIM2 on chosen lists

---

## What changes in your mail flow

DKIM2 changes how signing and verification happen at each relay hop.  In DKIM1, each
relay either adds a new, independent signature or ignores the existing ones.  In
DKIM2:

- **Every receiving relay** adds a Message-Instance header recording hashes of the
  message as received.
- **Every sending relay** adds a DKIM2-Signature header covering those hashes plus
  all previous signatures.
- **Verifiers** check the complete chain — not just the outermost signature.

The result: a verifier can tell exactly which relays handled the message, whether
anyone modified it in transit, and whether the Chain of Custody (MAIL FROM → RCPT TO
→ next MAIL FROM) is intact.

---

## DNS setup

DKIM2 uses standard DKIM1 TXT records.  The record format is identical:

```
selector._domainkey.yourdomain.com. IN TXT "v=DKIM1; k=ed25519; p=<pubkey>"
```

No new record type is required.  If you already publish DKIM1 records, you can reuse
the same Selectors (or create new ones — the keys are independent).

### Generating keys

**Ed25519** (recommended — 32-byte keys, fast, small signatures):

```bash
# Generate private key (keep secret)
openssl genpkey -algorithm ed25519 -out /etc/mail/dkim2/sel1.pem
chmod 600 /etc/mail/dkim2/sel1.pem

# Extract the public key bytes for the DNS record
openssl pkey -in /etc/mail/dkim2/sel1.pem -pubout -outform DER \
  | tail -c 32 | base64 | tr -d '\n'
```

Publish the output as:
```
sel1._domainkey.yourdomain.com. IN TXT "v=DKIM1; k=ed25519; p=<output>"
```

**RSA-2048** (broader compatibility):

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out /etc/mail/dkim2/sel1-rsa.pem
chmod 600 /etc/mail/dkim2/sel1-rsa.pem

openssl pkey -in /etc/mail/dkim2/sel1-rsa.pem -pubout -outform DER \
  | base64 | tr -d '\n'
```

Publish as:
```
sel1-rsa._domainkey.yourdomain.com. IN TXT "v=DKIM1; k=rsa; p=<output>"
```

RSA keys under 1024 bits are refused (`public key <s> too short`). A TXT
record at the selector name that begins with a `v=` other than `DKIM1` (an
SPF record, say) is ignored; two DKIM1 key records at one selector are a
PERMERROR (`has multiple records`).

### Key rotation

Add a new Selector with the new key.  Configure your MTA to sign with the new
Selector.  Keep the old Selector record live for at least 14 days (the maximum
signature validity window) so in-flight messages still verify.  Then delete the old
DNS record and private key.

---

## What the headers look like

A message arriving at the second relay might carry:

```
Message-Instance: m=1; h=sha256:abc...def:ghi...jkl;
DKIM2-Signature: i=1; m=1; t=1740000000; d=sender.example;
  mf=c2VuZGVyQHNlbmRlci5leGFtcGxl; rt=cmVjaXBpZW50QHJlbGF5LmV4YW1wbGU=;
  s=sel1:ed25519-sha256:AAAA...sig...ZZZZ;
```

After the second relay processes and forwards it:

```
Message-Instance: m=2; h=sha256:xyz...uvw:rst...opq; r=<recipe-json-base64>;
DKIM2-Signature: i=2; m=2; t=1740000060; d=relay.example;
  mf=cmVsYXlAcmVsYXkuZXhhbXBsZQ==; rt=ZmluYWxAZGVzdC5leGFtcGxl;
  s=sel1:ed25519-sha256:BBBB...sig...YYYY;
Message-Instance: m=1; h=sha256:abc...def:ghi...jkl;
DKIM2-Signature: i=1; m=1; t=1740000000; d=sender.example;
  mf=c2VuZGVyQHNlbmRlci5leGFtcGxl; rt=cmVjaXBpZW50QHJlbGF5LmV4YW1wbGU=;
  s=sel1:ed25519-sha256:AAAA...sig...ZZZZ;
```

Headers accumulate — older entries are lower in the header block.  Verifiers read
them all.

The `mf=` and `rt=` fields are base64 encodings of the SMTP envelope values
(including angle brackets, e.g. `<sender@sender.example>`).

The optional `r=` field in the MI header carries a base64-encoded JSON "Recipe"
describing modifications the relay made to the message, so upstream verifiers can
reconstruct the message state at each hop.

---

## Signing configuration

When your MTA accepts a message from a previous relay and is about to forward it,
the DKIM2 module needs:

| Parameter | Where it comes from |
|-----------|---------------------|
| `d=` domain | Your MTA's domain (the domain you control the key for) |
| Selector | The Selector for your signing key |
| MAIL FROM | The `MAIL FROM` command from the SMTP session |
| RCPT TO | The `RCPT TO` command(s) from the SMTP session |
| Private key | Your signing key file |

The signing module reads the existing MI and DKIM2-Signature headers to determine
the next `m=` and `i=` values automatically.

### The `d=` / MAIL FROM relationship

The `d=` signing domain must be the same as or a parent of the MAIL FROM domain.
`d=example.com` can sign for `sender@example.com` or `sender@sub.example.com`.
It cannot sign for `sender@other.com`.

For DSN messages (null sender `<>`) there is no MAIL FROM domain, so under
-09 the signing domain must instead match a RCPT TO domain of the hop
before: a bounce travels back along the chain.

### The `d=` / From relationship (-09 §11, §14.8)

From must also be Authentic: its domain must be `d=` or a subdomain of it,
or (since -09) a parent of `d=` whose Domain Policy Record does not say
`f=strict` (below). From must hold one address, not a domain literal.
A verifier checks the From each signature signed: the one i=1 signed, and
again the one any later signature signed after a hop changed From. Your signer checks it whenever it
originates a message (no DKIM2-Signature on it yet) or signs over an
unsigned change of From, and otherwise refuses with:

```
From header field is not Authentic for d=yourdomain.example
```

In practice: sign your own users' mail only with a domain that covers their
From addresses, and see "From rewriting" below for lists and forwarders.

### Domain Policy Record (-09 §3.8; dns-03 §6)

A `d=` below the From domain (`d=mail.example.com` signing for
`user@example.com`) makes From Authentic unless the From domain forbids it
with a Domain Policy Record: a TXT record at `_domainkey.<From domain>`
(no selector) holding

```
_domainkey.example.com. IN TXT "v=DKIM1; f=strict"
```

Verifiers look it up only for that upward case, once per domain per
message (Mail::DKIM2 0.30 sends it in the background with the keys). No record, or one without `strict` in `f=`, allows
subdomain signing. A record that begins `v=DKIM1` but does not parse counts
as strict. The failures are `FAIL: ... From <dom> forbids subdomain
signing`, `PERMERROR: ... multiple records for <dom> policy` and, when the
lookup fails, `TEMPERROR: ... policy for <dom> unavailable`.

**Signers do not look it up** (Mail::DKIM2 0.30, and the Python, Go and C
signers): you know your own domains' policy, so you list, per signing
domain, the parent domains whose From it may sign for. Anything else below
the From domain is refused (`From header field is not Authentic for
d=...`), with no DNS lookup:

| Signer | Setting |
|---|---|
| `dkim2-milter` | `--parent-from example.com` (single domain, repeatable), or a `parent-from` file in the domain's keydir directory (one domain per line) |
| authentication_milter `DKIM2Sign` | `"parent_from_domains": ["example.com"]` in the domain's entry |
| `dkim2sign` (Perl, Python, Go, C) | `--parent-from example.com` (repeatable) |
| library | Perl `Signer->new(ParentFromCallback => sub { ($dom, $signer) = @_; ... })`, Python `parent_from=`, Go `SignOptions.ParentFrom`, C `parent_from` hook |

List a parent only if it does not publish `f=strict`: verifiers enforce it
whatever the signer thinks.

**Publish `f=strict`** on any domain whose subdomains are controlled by
someone else: a hosting provider, SaaS or university domain that hands
`customer.example.com` to its tenants, so that a tenant's key cannot make
mail From `@example.com` Authentic. A domain that runs all its own
subdomains needs no record.

---

## Verification at delivery

When your MTA delivers an inbound message, the DKIM2 verifier needs:

- The full message (headers + body)
- The SMTP MAIL FROM and RCPT TO from the final delivery session (optional but
  recommended — enables the -09 §14.4 envelope integrity check)
- Access to DNS for public key lookup

The verifier checks:

1. All MI and DKIM2-Signature headers are present with no gaps in `m=` / `i=`
   sequences
2. The top signature covers the topmost MI
3. Every signature in the chain verifies cryptographically
4. Each signature's timestamp is no more than 14 days old and no more than
   1 day in the future
5. The Chain of Custody is intact: each signature's MAIL FROM domain is under
   its `d=`, each relay's MAIL FROM domain matches a RCPT TO domain from the
   previous relay (a bounce's `d=` does), and a hop after an `nd=` bridge is
   the `nd=` domain
6. Every From the chain introduces is Authentic for the signature that
   introduced it
7. If MAIL FROM / RCPT TO are available: the top signature's `mf=` and `rt=` exactly
   match the envelope values

Every failure carries an exact -09 reason, e.g.
`FAIL: DKIM2-Signature i=1 matching From is not authentic` or
`FAIL: Message-Instance m=1 header hash sha256 mismatch`, which the milters
put in the Authentication-Results comment.

Possible verification outcomes:

| Result | Meaning |
|--------|---------|
| `pass` | All signatures verified, chain intact |
| `fail` | Verification completed and the message is not a Fully Verified DKIM2 Message: a bad signature or hash, a broken Chain of Custody, a timestamp out of range, or a From that is not Authentic |
| `none` | No DKIM2 header fields at all (`NONE: No DKIM2 header fields found`) |
| `permerror` | Structural problem (missing headers, bad format, no usable key, an algorithm the verifier does not implement, a null body Recipe) |
| `temperror` | Transient failure (key or policy DNS lookup error) |

### What a result does not tell you

A list that rewrote the body without a Recipe for it records a null body
Recipe (`"b": null`). Under -09 (§13, §14.2) every verifier reports that as
`PERMERROR: Message-Instance m=<x> has a null recipe`. (Under -08 it was a
`pass` flagged "not fully verified".)

Per -09 §14.1, these states report only whether the message reached you without
being modified or replayed in a way the specification disallows.  They say
nothing about whether the message is wanted, whether it is spam, or whether
any modification a relay declared in its Recipe was benign.

A `pass` means the chain of custody is intact and every hop that changed the
message owned up to it.  It does not mean the message is safe to deliver, and
DKIM2 is not a substitute for content filtering or reputation.

---

## Signature lifetime

Signatures are valid for **14 days** from the timestamp in the `t=` field.  Messages
that take longer than 14 days to deliver (highly unusual) will fail DKIM2 verification
at delivery.  If this is a concern, consider:

- Forwarding services that re-sign messages they relay (the correct behaviour)
- Relaxing the timestamp check on your final delivery verifier (a local policy
  decision)

The `t=` timestamp is set at signing time and never changes.  Verifiers compare it
against the current clock.

---

## Interaction with mailing lists and forwarders

Mailing lists and forwarders that modify messages **must** re-sign with DKIM2 if they
want the chain to remain valid downstream.  The process:

1. Accept the message (verify the incoming chain if desired)
2. Make any modifications (add list footer, change subject, etc.)
3. Compute a new MI header that hashes the modified message and includes a Recipe
   describing what was changed
4. Sign the new MI and all previous signatures with the list's key

If the list does not re-sign, the DKIM2-Signature chain from the original sender
will fail because the message was modified.  Downstream verifiers will see a `fail`
result.  This is intentional — it is accurate.

Forwarders that do not modify the message can forward as-is; the original chain will
still verify at the final destination, provided the final SMTP MAIL FROM matches the
forwarder's domain (which it will if SRS is used correctly).

### From rewriting (-09 §11)

A list host or forwarder that **changes** a message, or **originates** one
(its hop becomes i=1, e.g. because the post arrived without a DKIM2
signature), must rewrite From into its own signing domain, typically
`"Author Name via List" <list@lists.example.org>` with the author's address
kept in Reply-To. Without that the verifier reports
`matching From is not authentic` and your own signer refuses to sign. A
forwarder that passes the message on unchanged leaves From alone.

- **Patched Mailman / Sympa** from this project rewrite From in code on every
  list copy they change.
- **Stock Mailman** cannot; set `dmarc_mitigate_action = munge_from` with
  `dmarc_mitigate_unconditionally = True` on each DKIM2 list (see the
  [stock Mailman guide](dkim2-postfix-stock-mailman-guide.md)).
- **The dkim2.com reflector** rewrites From to
  `"<sender> via DKIM2 reflector" <reflector-<mode>@dkim2.com>` whenever it
  originates or changes the message.

**The posting address must be in the signing domain.** The rewritten From
is only Authentic if the list's posting-address domain is equal to, or a
subdomain of, the domain the outbound milter signs that list's mail with:
`list@lists.example.org` signed with `d=lists.example.org` or
`d=example.org` works. Under -09 `list@example.org` signed with
`d=lists.example.org` works too when the signer lists example.org as a
parent (see "Domain Policy Record") and example.org does not publish
`f=strict`. Otherwise the signer refuses every rewritten
post (`From header field is not Authentic for d=...`), and a post that
arrived with a DKIM2-Signature is answered `550 5.7.1` (see "Milter
integration"), which the list manager counts as a bounce. Check this for
every DKIM2 list when you set it up. Both milters log the two domains on
such a refusal: `From domain <posting domain> is not d=<signing domain> or
below it`.

A list manager that sends one copy per subscriber also marks each copy with
`X-DKIM2-Exploded: yes`; the signing milter turns that into `f=exploded` on
its signature (-09 §12.5) and removes the header.

Every signer here verifies the incoming chain before adding its own signature
and refuses if it does not check out (see "Milter integration" for what the
milters do with a refused message).
A **null body Recipe** (`"b": null`: the hop that made the instance
rewrote the body and could not record how) is not refused when this host
introduced it: the signer signs over its own unsigned null, so the header
changes are signed even though the message will PERMERROR downstream, and
adds `X-DKIM2-Info: ... action=null-body-recipe;`. A null that arrived
already signed fails upstream verification and is refused like any other
broken chain. The old `--allow-null-body-recipe` (`dkim2-milter`,
`dkim2sign`) and `allow_null_body_recipe` (`DKIM2Sign`) options are
deprecated no-ops that warn when set true; remove them from your config.
A list manager that rewrites bodies (content filtering, DMARC wrap) causes
such nulls; the [list host guide](dkim2-postfix-list-host-guide.md) covers
them.

---

## Milter integration

Two Perl milters implement this for Postfix: the standalone `dkim2-milter`
and the `DKIM2Sign`/`DKIM2Verify` handlers for Mail::Milter::Authentication.
Both take MAIL FROM and RCPT TO from the MTA rather than from the message,
and both decide whether to sign with the same `Mail::DKIM2::Gate`: a message
whose upstream chain (a signed null body Recipe included) or
Message-Instance chain does not check out, or whose From is not Authentic for the signing domain, is refused. What happens
next depends on whether it already carries an upstream DKIM2-Signature:

- **With one**, the milter rejects it: `550 5.7.1 <reason>` (-09 §12 says it
  MUST NOT be signed, and §13 that it MUST NOT be sent on as it is). A list host's MTA reports such a reject to the list manager as a
  bounce for that recipient, so watch for refusals before they bounce-disable
  subscribers; with the patched list managers, which rewrite From, they
  should not happen for list traffic as long as each list's posting address
  is in the signing domain (see "From rewriting").
- **Without one**, it is delivered unsigned as before, with this host's own
  unsigned Message-Instances removed and
  `X-DKIM2-Info: ... action=not-signed=<reason>;` for the Message-Instance
  refusals.

The C milter in this repo (`c/dkim2_milter.c`, not the one deployed on
dkim2.com) behaves the same way: `550 5.7.1 <reason>` for a refused message
with an upstream DKIM2-Signature, unsigned delivery (hint and unsigned
Message-Instances removed) without one. Its verify mode rejects a FAIL or
PERMERROR with `550 5.7.1` and a TEMPERROR with `451 4.7.5`.

---

## Privacy considerations

The `mf=` and `rt=` fields encode the SMTP envelope addresses into every signature
header.  These values travel with the message and are readable by anyone who receives
it.  They are base64-encoded, not encrypted.

Consider this when handling messages that involve sensitive envelope addresses (e.g.,
confidential mailing lists, abuse reports).  A future revision of the spec may add
encryption support; for now, treat `mf=`/`rt=` as plaintext.
