# Design: DKIM1 signatures on reflector output

**Date:** 2026-06-21
**Status:** approved, ready for implementation plan

## Purpose

Add classic **DKIM1** signatures to every message the reflector sends, so the
demo mail looks like real-world mail (which always carries DKIM1) and — for the
brand case — actually delivers the way a real ESP's mail does.

The brand case is the substantive win: signing a **DKIM1 `d=<brand>`** with the
same delegated `dkim2test` key (its published TXT is a valid DKIM1 record, and
the brand's CNAME serves DKIM1 lookups) makes `From: dkim2demo@<brand>`
DMARC-aligned → **inbox instead of Junk**, exactly as a real ESP achieves with
brand-delegated DKIM1. For the other addresses the DKIM1 signature is `d=dkim2.com`
and is cosmetic (fidelity only), since `From` is not `dkim2.com` on the reflect
modes.

This work sequences **before** the website copy describing the addresses, because
it flips the brand message from Junk to inbox.

## Dependency

Add `Mail::DKIM` (Debian `libmail-dkim-perl`). It is already installed on the
server; it must be installed in the local test environment (`cpanm Mail::DKIM`)
for the test run. This is a deliberate new dependency (the DKIM2 lib otherwise
avoids `Mail::DKIM`), accepted for DKIM1 signing.

## Component: `Mail::DKIM2::Reflector::sign_dkim1`

`sign_dkim1($text, @specs) -> $text` — prepend a classic `DKIM-Signature:` header
for each spec.

- Each spec is a hashref `{domain, selector, keyfile}` (or `{domain, selector,
  key => <PEM string>}`).
- For each spec, construct a `Mail::DKIM::Signer` with `Algorithm => 'rsa-sha256'`,
  `Method => 'relaxed/relaxed'`, `Domain`, `Selector`, and the private key
  (`Mail::DKIM::PrivateKey->load(File => $keyfile)` or `Data => $pem`), feed the
  current message (`PRINT`/`CLOSE` with CRLF line endings), take
  `$signer->signature->as_string`, normalise to a single `DKIM-Signature: …\r\n`
  header, and prepend it to `$text`.
- Multiple specs are each prepended; order among them is not significant (each is
  an independent signature). The DKIM1 signatures sit above the DKIM2 chain
  headers; DKIM1's `h=` covers the normal author headers (`From`, `To`, `Subject`,
  `Date`, `Message-ID`, `MIME-Version`, `Content-Type`, …), not `DKIM2-Signature`
  or `Message-Instance`, so the two schemes do not interfere.
- `$text` already has CRLF endings (all reflector output does). `sign_dkim1`
  leaves the body untouched.

This is a composable post-step: it does not change `reflect`, `generate`, or
`generate_brand`; it runs on their output.

## Wrapper wiring (`bin/dkim2-reflector.pl`)

After building `$result->{message}` and before injecting to `:10588`, assemble
the DKIM1 specs and call `sign_dkim1`:

- **Always** include `{ domain => 'dkim2.com', selector => 'sel1', keyfile =>
  '/etc/dkim2/reflector/sel1.key' }`.
- **When `mode eq 'brand'` and the delegation CNAME resolved** (`$delegated`
  true, brand domain `$bd`), also include `{ domain => $bd, selector =>
  'dkim2test', keyfile => '/etc/dkim2/reflector/dkim2test.key' }`.

Then `$result->{message} = Mail::DKIM2::Reflector::sign_dkim1($result->{message},
@specs);` and inject as today. Applies to every mode (raw/subject/body/both/
redacted/damage/fresh/brand) since the `dkim2.com` spec is unconditional.

Keys reused (no new keys): `dkim2.com/sel1` (published DKIM2 TXT doubles as a
DKIM1 record) and the delegated `dkim2test` key (brand only).

## Effects

| Address(es) | DKIM1 added | DMARC effect |
|---|---|---|
| `reflector-brand` (delegated) | `d=<brand>` (delegated) + `d=dkim2.com` | `d=<brand>` aligns with `From` → **inbox** |
| `reflector-brand` (not delegated) / `reflector-fresh` | `d=dkim2.com` | aligns with `From: …@dkim2.com` → inbox |
| `reflector-{raw,subject,body,both,redacted,damage}` | `d=dkim2.com` | not aligned (From = original sender) — cosmetic |

No change to the DKIM2 chain, Message-Instance, the validator, or the
`Received-SPF` handling.

## Testing

In `brong/t/` (a new `t/reflector-dkim1.t`, or extend `reflector.t`):

- Skip the file gracefully if `Mail::DKIM` is unavailable (`use Mail::DKIM::Signer;
  plan skip_all => 'Mail::DKIM not installed' if $@;`) so the rest of the suite
  is unaffected where the dep is missing.
- `sign_dkim1($msg, {domain=>'test2.dkim2.com', selector=>'sel1', key=>$pem})`
  prepends exactly one `DKIM-Signature:` header with `d=test2.dkim2.com`,
  `s=sel1`, `a=rsa-sha256`, `c=relaxed/relaxed`, and non-empty `bh=`/`b=`.
- Two specs → two `DKIM-Signature` headers with the two distinct `d=` values.
- The body and existing DKIM2/MI headers are unchanged (the function only
  prepends).
- Full crypto verification is left to the live smoke test (real DNS key lookups).

## Deploy & verify

- Ensure `libmail-dkim-perl` on the server (already present).
- `make install` the updated `Reflector.pm`; install the updated wrapper.
- Smoke test: a `reflector-fresh` reply carries `DKIM-Signature d=dkim2.com`; a
  `reflector-brand` reply (from a delegated domain) carries both `d=<brand>` and
  `d=dkim2.com`. Final confirmation: a real `brong@brong.net → reflector-brand`
  message now lands in the **inbox** and the brand DKIM1 passes DMARC.

## Out of scope

- Website copy for the addresses (next; will describe inbox delivery once this
  lands).
- `nextd`. Any DKIM2 signing/hash change. Delegated DKIM1 for the non-brand
  reflect modes (those get `d=dkim2.com` only).
