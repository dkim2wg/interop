# Design: `reflector-fresh@dkim2.com` — fresh DKIM2 message generator

**Date:** 2026-06-20
**Status:** approved, ready for implementation plan

## Purpose

Add a reflector address that **originates a brand-new DKIM2 message** rather than
reflecting the incoming one. It demonstrates the simplest valid DKIM2 message — a
single Message-Instance (`m=1`) and a single DKIM2-Signature (`i=1`) with no
forwarding chain — and, because it is sent `From` a `dkim2.com` identity, it
passes DMARC and lands in the recipient's **inbox** (unlike the modifying reflector
modes, whose preserved `From` breaks the originator's DMARC).

This is the first of two new addresses requested. The second ("clever" `nextd` /
imaginary-hop address) is **deferred** until the post-2026-06-17-interim draft
publishes the `nextd` semantics; it is out of scope here.

## Behaviour

On mail to `reflector-fresh@dkim2.com`:

1. The incoming message content is **ignored** except for the envelope sender,
   which is the reply target.
2. A null/empty/`MAILER-DAEMON` sender is dropped quietly (nothing to reply to),
   matching the existing wrapper behaviour.
3. A brand-new message is generated, addressed to the sender, signed as
   `dkim2.com`, and submitted to the milter-free injector (`127.0.0.1:10588`) —
   the same delivery path as the reflector.

There is no auth gate: origination does not depend on the incoming message
verifying (the message is `dkim2.com`'s own, not a forward).

## Generated message

| Field | Value |
|-------|-------|
| `From` | `"DKIM2 Generator" <fresh@dkim2.com>` |
| `To` | `<sender>` (envelope sender of the incoming) |
| `Subject` | `Freshly generated DKIM2 message` |
| `Date` | current time |
| `Message-ID` | fresh unique `<…@dkim2.com>` |
| `Content-Type` | `text/plain; charset=utf-8` (single part) |

Body: a short text/plain explainer —

- states this is a freshly-originated DKIM2 message: one `m=1`, one `i=1`, no
  forwarding chain;
- echoes who/when it was requested by (the sender address and the time received);
- links to `https://dkim2.com/validate/`.

DKIM2 structure:

- `Message-Instance` computed by `MessageInstance->calculate($msg)` with no
  previous message → `m=1` (hashes only, no recipes).
- One `DKIM2-Signature i=1`: `d=dkim2.com`, `s=sel1`, `rsa-sha256`,
  `mf=reflector-bounces@dkim2.com` (relaxed-matches `d=`), `rt=[sender]`.
- No predecessor signature, so no chain-of-custody link is required.

## Deliverability

`From: …@dkim2.com` with envelope `MAIL FROM: reflector-bounces@dkim2.com`:

- `dkim2.com` SPF is `v=spf1 a mx -all`, which authorises the sending host
  (`mail.dkim2.com` / `134.209.211.166`).
- Envelope domain `dkim2.com` aligns with the `From` domain → **SPF-aligned DMARC
  pass**; `_dmarc.dkim2.com` is `p=none`.
- Result: inbox delivery. No DKIM1 signature is needed (and none is added — the
  injector bypasses the outbound milter).

Bounces/DSNs for the generated message return to `reflector-bounces@dkim2.com`
and are captured in `/var/spool/reflector-bounces/mbox` (existing alias).

## Code

**Approach:** a new `Mail::DKIM2::Reflector::generate(%args)`, *not* a new
`reflect()` mode. `reflect()` transforms an incoming message; this originates a
new one — different enough that adding it to `reflect()`'s mode switch would muddy
both code paths. Keep them separate.

- `Mail::DKIM2::Reflector::generate(%args)` → returns the signed message text.
  - Args: `sender` (reply target), `domain` (default `dkim2.com`), `selector`
    (default `sel1`), `key`/`keyfile`, `mailfrom` (default
    `reflector-bounces@dkim2.com`), and injectable `now` + `message_id` for
    deterministic tests.
  - Builds the message above, computes `m=1` via `MessageInstance::calculate`,
    signs `i=1` via `Mail::DKIM2::Signer`, prepends the MI + signature, and
    prepends an `X-DKIM2-Info` provenance header (`action=generate`, milter
    format, via the shared `_dkim2_info`/constants).
- `bin/dkim2-reflector.pl`: add `fresh` to `%VALID_MODE`; when `mode eq 'fresh'`
  call `generate()` instead of `reflect()`; inject and log identically (the
  success log line notes `mode=fresh`).

## Postfix

The `reflector-fresh` address reuses the existing `dkim2-reflect` `pipe(8)`
service (no new `master.cf` service): `${user}=reflector-fresh` → wrapper mode
`fresh`. Only the map changes:

- Add `reflector-fresh@dkim2.com  dkim2-reflect:` to `/etc/postfix/dkim2-transport`
  (sources in `deploy/postfix-dkim2-transport`), `postmap`, `postfix reload`. The
  one map continues to serve both `transport_maps` and `local_recipient_maps`.

## Testing

In `brong/t/` (extend `reflector.t` or a sibling):

- Call `generate()` with a `DKIM2TestKeys` key and fixed `now`/`message_id`.
- Assert via `Mail::DKIM2::Validate::report` (or the verifier): overall **pass**;
  exactly one signature level `i=1 (m=1)` pass; MI `m=1` header hash + body hash
  **match**, recipe `none`, undo `n/a`; `From` is the `dkim2.com` generator
  identity; `To` is the sender.
- Determinism: fixed `now`/`message_id` so the signed bytes are reproducible.

## Out of scope

- The `nextd` / imaginary-hop "clever" address (deferred to the new draft).
- From-munging / ARC for the modifying reflector modes (separate, optional).
- Any change to the shared `should_skip()` canonicalisation.
