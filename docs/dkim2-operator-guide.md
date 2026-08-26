# DKIM2 Operator Guide

**Spec:** draft-ietf-dkim-dkim2-spec-05  
**Audience:** MTA operators and postmasters deploying DKIM2

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

For DSN messages (null sender `<>`), this check is skipped.

---

## Verification at delivery

When your MTA delivers an inbound message, the DKIM2 verifier needs:

- The full message (headers + body)
- The SMTP MAIL FROM and RCPT TO from the final delivery session (optional but
  recommended — enables §10.4 envelope integrity check)
- Access to DNS for public key lookup

The verifier checks:

1. All MI and DKIM2-Signature headers are present with no gaps in `m=` / `i=`
   sequences
2. The top signature covers the topmost MI
3. Every signature in the chain verifies cryptographically
4. Each signature's timestamp is within 14 days
5. The Chain of Custody is intact (each relay's MAIL FROM domain matches a RCPT TO
   domain from the previous relay)
6. If MAIL FROM / RCPT TO are available: the top signature's `mf=` and `rt=` exactly
   match the envelope values

Possible verification outcomes:

| Result | Meaning |
|--------|---------|
| `pass` | All signatures verified, chain intact |
| `fail` | A signature failed or the chain is broken |
| `none` | No DKIM2-Signature headers present |
| `permerror` | Structural problem (missing headers, bad format, no usable key) |
| `temperror` | Transient failure (DNS lookup error) |

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

---

## Milter integration

The C reference implementation includes a libmilter integration (`dkim2-milter`)
that can be used with Sendmail and Postfix.  The Perl implementation includes milter
handlers in `Mail::Milter::Authentication::Handler::DKIM2Sign` and
`DKIM2Verify`.

Milter configuration provides the SMTP envelope values (MAIL FROM, RCPT TO)
automatically from the MTA, eliminating the need to extract them from the message
headers.

---

## Privacy considerations

The `mf=` and `rt=` fields encode the SMTP envelope addresses into every signature
header.  These values travel with the message and are readable by anyone who receives
it.  They are base64-encoded, not encrypted.

Consider this when handling messages that involve sensitive envelope addresses (e.g.,
confidential mailing lists, abuse reports).  A future revision of the spec may add
encryption support; for now, treat `mf=`/`rt=` as plaintext.
