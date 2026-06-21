# Design: `reflector-brand@dkim2.com` — delegated two-signature brand demo

**Date:** 2026-06-20
**Status:** approved, ready for implementation plan

## Purpose

Demonstrate the DKIM2 **brand/delegation** case: a brand domain (e.g. `brong.net`)
delegates a signing key to a platform (`dkim2.com`) by publishing a CNAME, and the
platform originates a brand-new message carrying **two DKIM2-Signatures on a single
Message-Instance** — one signed *as the brand* (using the delegated key) and one
*as the platform* — forming a valid chain of custody.

This is the second of the two requested addresses (the "clever" one), building on
the `reflector-fresh` generator. It deliberately uses **no `nextd` tag** (the
`nextd` override from the 2026-06-17 interim is not yet in a published draft);
this is the two-step delegated-key construction the current spec already supports
(spec-02 §, "the domain owner publishes a CNAME pointing at this").

## Flow

On mail to `reflector-brand@dkim2.com` from `<sender>` (e.g. `brong@brong.net`):

1. Extract the sender domain `D` (e.g. `brong.net`). A null/empty/`MAILER-DAEMON`
   sender is dropped (nothing to reply to), as elsewhere.
2. **CNAME check:** is `dkim2test._domainkey.D` a CNAME whose target is
   `dkim2test._domainkey.dkim2.com`?
3. **Not delegated** (no CNAME, or it points elsewhere): send the **fresh-style**
   message (From the `dkim2.com` generator identity, single `m=1` + single `i=1`)
   but with an **error body** explaining that `dkim2test._domainkey.D` is not a
   CNAME to `dkim2test._domainkey.dkim2.com`, and how to set it up.
4. **Delegated:** originate a brand-new message (single `m=1`) with two signatures
   (below).

## The delegated (two-signature) message

| | |
|---|---|
| `From` | `<sender>` (the brand, e.g. `brong@brong.net`) |
| `To` | `reflector-brand@dkim2.com` |
| `Subject` | `Brand-signed DKIM2 message` |
| Date / Message-ID | fresh, unique `<…@dkim2.com>` |
| Content-Type | `text/plain; charset=utf-8` (single part) |
| Body | explainer: brand-new message, two signatures on one `m=1`; `i=1` signs as `D` via the delegated `dkim2test` key, `i=2` signs as `dkim2.com`; validator link |

Signatures (signed in this order, each stamped `m=1` since there is one MI):

- **`i=1`**: `d=D`, `s=dkim2test`, rsa-sha256, signed with the **delegated key**
  (the `dkim2test` private key `dkim2.com` holds); `mf=<sender>` (relaxed-matches
  `d=D`), `rt=reflector-brand@dkim2.com`. Documents "brand → reflector".
- **`i=2`**: `d=dkim2.com`, `s=sel1`, rsa-sha256, signed with the `dkim2.com` key;
  `mf=reflector-bounces@dkim2.com`, `rt=<sender>`. The outbound hop.

Chain of custody: `i=2`'s `mf` domain (`dkim2.com`) is in `i=1`'s `rt`
(`reflector-brand@dkim2.com` → `dkim2.com`); `i=1` is the base (no predecessor),
its `mf` domain matches `d=D`. Single `Message-Instance m=1` (the message is never
modified).

Provenance: `X-DKIM2-Info: … action=brand` (milter format). Envelope MAIL FROM is
`reflector-bounces@dkim2.com`, RCPT is `<sender>` — matching `i=2`.

**Deliverability:** `From: <sender>` (the brand domain) is NOT aligned with the
`dkim2.com` SPF/signature, so classic DMARC for the brand domain will likely fail
and Fastmail will Junk it — accepted, as it faithfully represents the brand case
in a not-yet-DKIM2-aware world. (Verification in the web validator is unaffected.)

## Code

In `Mail::DKIM2::Reflector` (building on `generate()` from the fresh address):

- Refactor the message-building half of `generate()` into a private
  `_fresh_message_text(%args)` → returns headers + body + `m=1` MI (no signature).
  Args include `from`, `to`, `subject`, `body`, `sender`, `domain`, `now`,
  `message_id`.
- `generate(%args)` = `_fresh_message_text(...)` + one `dkim2.com` signature +
  `X-DKIM2-Info action=generate`. Add an optional `body` arg so callers can
  override the default fresh body (used by the brand error case).
- `generate_brand(%args)`:
  - `delegated` (bool), `sender`, `domain`/`selector`/`key`/`keyfile` (the
    `dkim2.com` signer), `brand_key`/`brand_keyfile` + `brand_selector`
    (default `dkim2test`) for the `i=1` signature, injectable `now`/`message_id`.
  - **not delegated** → return `generate(sender => …, body => <error explainer>)`.
  - **delegated** → `_fresh_message_text(from => <sender>, to =>
    'reflector-brand@dkim2.com', subject => 'Brand-signed DKIM2 message',
    body => <brand explainer>, …)`, then sign `i=1` (brand key, `d=`sender
    domain, `s=brand_selector`, `mf=<sender>`, `rt=reflector-brand@dkim2.com`),
    prepend; sign `i=2` (`dkim2.com`, `mf=reflector-bounces@dkim2.com`,
    `rt=<sender>`), prepend; prepend `X-DKIM2-Info action=brand`.
- `_dkim2test_cname_ok($domain)` → live `Net::DNS::Resolver` CNAME query of
  `dkim2test._domainkey.$domain`; true iff the target is
  `dkim2test._domainkey.dkim2.com`. Kept separate from `generate_brand` so the
  message logic is testable without network.

`bin/dkim2-reflector.pl`: add `brand` to `%VALID_MODE`; for `brand`, compute
`delegated = _dkim2test_cname_ok($sender_domain)` and call `generate_brand`.

## Keys / DNS (operator step)

- Generate an RSA-2048 `dkim2test` keypair. Install the private copy at
  `/etc/dkim2/reflector/dkim2test.key` (owned `nobody:nogroup`, `0600`), like the
  existing `sel1.key`. Print the `dkim2test._domainkey.dkim2.com` TXT record
  (`v=DKIM1; k=rsa; p=…`) for manual publication.
- The brand publishes `dkim2test._domainkey.<branddomain>` as a CNAME to
  `dkim2test._domainkey.dkim2.com`.
- For interop tests: a `dkim2test` key in `keys/` (e.g. for `brong.net` or a test
  domain) plus a pubkey callback mapping `(<branddomain>, dkim2test)` → that key,
  simulating the CNAME delegation.

## Postfix

Add `reflector-brand@dkim2.com  dkim2-reflect:` to `deploy/postfix-dkim2-transport`
(serves both `transport_maps` and `local_recipient_maps`); reuses the existing
`dkim2-reflect` pipe service (`${user}=reflector-brand` → mode `brand`).

## Testing

In `brong/t/`:

- `generate_brand(delegated => 1, …)` with a test `dkim2test` key and a pubkey
  callback that resolves `(<branddomain>, dkim2test)` to it: validate the output —
  exactly two signatures `i=1` and `i=2`, both `m=1`, both pass; chain-of-custody
  ok; exactly one `Message-Instance m=1` (header + body match); `From` is the
  brand, `To` is `reflector-brand@dkim2.com`; `X-DKIM2-Info action=brand`.
- `generate_brand(delegated => 0, …)`: exactly one signature; body contains the
  CNAME error explainer; `From` is the `dkim2.com` generator identity.
- Determinism via fixed `now`/`message_id`.
- `_dkim2test_cname_ok` is network I/O; not unit-tested (exercised by the live
  smoke test at deploy).

## Out of scope

- The `nextd` override (deferred to the post-interim draft).
- From-munging / ARC to make the brand message reach the inbox.
- Automatic publication of DNS records (operator publishes manually).
