# Design: `reflector-delayedbounce@dkim2.com` — signing Postfix-originated bounces

**Date:** 2026-06-30
**Status:** approved, ready for implementation plan

## Purpose

Answer a question raised on the DKIM mailing list against draft-02: **how can
Postfix be configured to DKIM2-sign the bounces it generates itself?**

The hard case is a *delayed* (asynchronous) bounce. A message is accepted at
RCPT (250), delivery fails *later*, and Postfix's own `bounce(8)` daemon
originates an [RFC3464] `multipart/report` DSN with `MAIL FROM <>`. By default
Postfix runs **no** content filters or milters on its own bounce/notification
messages, so these DSNs leave unsigned and cannot be verified per spec §11.

This is distinct from the existing `reflector-dsn@dkim2.com`, which *hand-builds*
a DSN synchronously in our own code (`Mail::DKIM2::DSN`) and injects it. Here the
DSN is genuinely **Postfix-originated**; we only arrange for it to be signed on
its way out. The deliverable is therefore mostly a **Postfix recipe** plus one
small milter change — the kind of thing another operator can copy.

`reflector-delayedbounce@dkim2.com` is the live demonstration address: mail to it
is accepted and then deliberately fails, producing a real, signed, verifiable
delayed bounce.

## Behaviour

On mail to `reflector-delayedbounce@dkim2.com`:

1. The recipient is accepted at RCPT (it is in `local_recipient_maps`), so the
   sending system gets a `250` and the SMTP session completes.
2. `transport_maps` routes the queued message to Postfix's built-in **`error:`**
   transport, which fails it **permanently** (5.x.x).
3. `bounce(8)` builds an RFC3464 DSN: `multipart/report`, `From:
   MAILER-DAEMON@…dkim2.com`, envelope `MAIL FROM <>`, addressed to the original
   envelope sender, with a `message/rfc822` (or `text/rfc822-headers`) part
   carrying the original message.
4. Because `internal_mail_filter_classes = bounce` is set, the DSN is passed
   through `non_smtpd_milters` → our **outbound** DKIM2 milter, which origin-signs
   it (`Message-Instance m=1` + `DKIM2-Signature i=1`, `d=dkim2.com`, `mf=<>`).
5. The signed DSN is delivered to the original sender and verifies as a valid
   DKIM2 origin message at `https://dkim2.com/validate/`.

There is no auth gate and no transformation of the original — the bounce is
Postfix's, signed verbatim.

## Components

### 1. Force a genuine bounce (`error:` transport)

`reflector-delayedbounce@dkim2.com` must **not** go through the existing
`dkim2-reflect` `pipe(8)` map — that map originates replies. It is a separate
routing entry:

- `local_recipient_maps`: accept the address at RCPT.
- `transport_maps`: route it to
  `error:5.1.1 DKIM2 delayed-bounce demo: address intentionally undeliverable
  (this triggers a Postfix-generated, milter-signed DKIM2 bounce)`.

`error:` is chosen over a real failing SMTP sink: it is deterministic, has no
external dependency, and accept-then-permanent-fail exactly models a delayed
bounce.

### 2. Postfix bounce-signing config (the list's answer)

Two `main.cf` settings:

- `internal_mail_filter_classes = bounce` — makes Postfix run
  `non_smtpd_milters` (and content filters) on its own bounce DSNs. Off by
  default; this is the key knob.
- `non_smtpd_milters = unix:var/run/dkim2-milter-out.sock` — **outbound milter
  only**. Today `deploy/SERVER.md` lists *both* the inbound and outbound sockets
  here; left as-is, the inbound milter would stamp the bounce with
  `Authentication-Results` and a spurious `Message-Instance` before the outbound
  milter signs. Dropping the inbound socket loses nothing: a genuine *inbound*
  DSN from outside still reaches the inbound milter via `smtpd_milters` on port
  25. Internally-injected mail (bounces, local submissions) only ever needs the
  outbound (signing) milter.

### 3. Teach the outbound milter to sign a null-sender bounce

This is the only code change, both in `brong/bin/dkim2-milter.pl`:

- **Signing-domain fallback for null sender.** `_get_sign_config($env_from)`
  returns undef for a bounce because `MAIL FROM <>` has no `@domain`. When
  `env_from` is empty, fall back to the **`From:` header** domain
  (`MAILER-DAEMON@mail.dkim2.com`); the existing keydir parent-walk maps
  `mail.dkim2.com → dkim2.com`. Sign **only** if that domain resolves to a held
  key — i.e. it is genuinely *our* bounce. A null-sender message whose `From:`
  domain we do not hold a key for is left unsigned (unchanged behaviour).
- **Emit `mf=<>`.** `_do_sign` currently passes `MailFrom => $priv->{env_from}`.
  For a null sender, sign with a null `MailFrom` so the `DKIM2-Signature` carries
  `mf=<>` per §11.1, while `rt=` is the original sender taken from
  `RcptTo`/`env_rcpt`.

No existing DKIM2 chain is present on a fresh bounce, so the milter's existing
path computes `Message-Instance m=1` and `DKIM2-Signature i=1` — the bounce
leaves as a clean **origin** DKIM2 message. The chain-undo check
(`chain_verifies`) is a no-op when there is no chain, so it does not interfere.

### 4. Spec §11 conformance and known limits (documented, not coded)

- **Addressing.** Postfix addresses the DSN to the envelope `MAIL FROM`, which in
  a DKIM2 chain *is* the `mf=` of the highest-numbered `DKIM2-Signature` — so this
  satisfies §11 "A DSN MUST be addressed to the MTA that sent the message."
- **Null mf on the DSN itself.** The DSN's own signature has `mf=<>`; you cannot
  bounce a bounce, matching "If this field is null (`mf=<>`) then a DSN MUST NOT
  be sent."
- **Embedded-original verification (§11.1.2).** Verifying the *enclosed* message's
  `DKIM2-Signature`/`Message-Instance` is a receiver-side concern. We preserve the
  embedded headers, but if Postfix truncates the original body
  (`bounce_size_limit`), inner *body*-MI verification may not hold — draft-02
  removed the `z` body recipe that §11 had relied on for truncated bodies. This is
  acceptable for a demo and is documented; for the demo the enclosed message is
  usually not itself DKIM2-signed anyway.

## Code

`brong/bin/dkim2-milter.pl` only:

- `_get_sign_config`: add the null-`env_from` → `From:`-header-domain fallback,
  gated on a held key. To do this cleanly the From: domain must be available; the
  caller already parses the `From:` header for alignment logging (`cb_eom`), so
  pass that domain (or the parsed headers) into `_get_sign_config`.
- `_do_sign`: when `env_from` is empty, construct the `Signer` with a null
  `MailFrom` (→ `mf=<>`) while keeping `RcptTo => $priv->{env_rcpt}` (→ `rt=`).

**Library round-trip for null `MailFrom` (in scope).** The signing path assumes
`Signer`/`Signature` encode a null `MailFrom` as `mf=<>` and that the `Verifier`
accepts it (skipping the `d=`/`mf=` alignment check for a null sender, as
`Verifier.pm` already flags for DSNs), and that `MessageInstance->calculate`
produces `m=1` for a message with no prior MI. The plan's **first** step verifies
this end-to-end with a focused test (sign with null `MailFrom` → verify `pass`,
`mf=<>` present). If any leg does not round-trip, the library fix
(`Signer`/`Signature`/`Verifier`) is folded into this feature rather than deferred —
the milter change is worthless without it.

## Postfix deploy artifacts

- `deploy/postfix-dkim2-transport` is **not** the place for this address (that map
  feeds the `dkim2-reflect` pipe). Add a **new** map file
  `deploy/postfix-dkim2-delayedbounce` holding the single entry
  `reflector-delayedbounce@dkim2.com  error:5.1.1 DKIM2 delayed-bounce demo …`,
  referenced from **both** `transport_maps` (to route to `error:`) and
  `local_recipient_maps` (to accept at RCPT) — the same dual-use pattern as the
  existing `dkim2-transport` map. `postmap` it and `postfix reload`; install
  steps documented in the file header and `SERVER.md`.
- `main.cf`: add `internal_mail_filter_classes = bounce`; change
  `non_smtpd_milters` to the outbound socket only.

## Testing

In `brong/t/` (new `delayedbounce.t` or extend the milter test):

- Construct a synthetic Postfix-style DSN: `multipart/report`,
  `From: MAILER-DAEMON@dkim2.com`, a `message/delivery-status` part, a
  `message/rfc822` part, **null** envelope-from, `RcptTo => ['sender@origin.example']`.
- Drive it through the outbound milter signing path (the milter's `cb_eom` logic,
  or a thin harness that calls the same `_compute_mi` + `_get_sign_config` +
  `_do_sign` sequence) with a `DKIM2TestKeys` key for `dkim2.com`.
- Assert: a `Message-Instance m=1` is added; a `DKIM2-Signature i=1` is added with
  `d=dkim2.com`, `mf=<>`, and `rt=sender@origin.example`; and the result verifies
  **pass** via `Mail::DKIM2::Validate::report` / the verifier.
- Negative: a null-sender message whose `From:` domain has no key is left
  unsigned.

## Docs

- `deploy/SERVER.md` + `deploy/README.md`: a copy-pasteable "Signing
  Postfix-generated (delayed) DKIM2 bounces" recipe — `internal_mail_filter_classes
  = bounce`, `non_smtpd_milters` outbound-only, and why. This is the substance of
  the mailing-list reply.
- Add `reflector-delayedbounce@dkim2.com` to the reflector address list
  (`deploy/reflector-aliases` commentary or the transport docs), the validator
  page's address list, and `docs/dkim2-implementer-guide.md`.

## Out of scope

- Bounce *propagation* through a forwarder (§11.1.1) — already covered by
  `Mail::DKIM2::DSN->propagate` and `reflector-dsn`.
- Reconstructing/rewriting the enclosed original or re-addressing the DSN to a
  different hop's `mf=` (§11.1.1 "alternatively"). We sign Postfix's bounce as-is.
- Any change to `should_skip()` canonicalisation or to the inbound milter's
  verification behaviour for externally-received DSNs.
- The `z` truncated-body recipe (removed in draft-02).
