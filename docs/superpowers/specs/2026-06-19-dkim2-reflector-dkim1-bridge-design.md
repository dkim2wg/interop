# DKIM2 Reflector — DKIM1-bridge signing & always-on Message-Instance — Design

**Date:** 2026-06-19
**Status:** Approved (pending spec review)
**Spec basis:** draft-ietf-dkim-dkim2-spec-02
**Author:** brong + Claude
**Builds on:** `2026-06-18-dkim2-reflector-design.md`

## Goal

Extend the `dkim2.com` reflector in two ways:

1. **DKIM1-bridge signing.** Today the reflector adds a `dkim2.com`
   DKIM2-Signature only when the incoming DKIM2 chain verified
   (DKIM2-only). Broaden this: when a message has **no DKIM2 chain** but
   carries **at least one valid classic-DKIM (DKIM1) signature aligned with
   the `From:` domain**, the reflector notes that and signs it too — acting as
   a DKIM1→DKIM2 bridge (the reflector becomes the first DKIM2 signer in the
   chain, vouching on the strength of the validated DKIM1 signature).

2. **Always-on Message-Instance.** Today a change-recording MI is emitted only
   when the reflector signs. Change this so the MI for the reflector's
   transformation is emitted in **all** cases (signed or not), for the modes
   that actually change content.

## Auth model — three tiers

The reflector derives two signals for an incoming message:

- **DKIM2 verdict** — computed by the reflector itself via
  `Mail::DKIM2::Verifier` (as today): `pass` / `fail` / `none`.
- **DKIM1 verdict** — read from the inbound `Authentication-Results` header
  added by OpenDKIM on receipt (see "Reading the DKIM1 verdict").

| Tier | Condition | Sign? | Basis |
|---|---|---|---|
| **T1** | DKIM2 chain verifies (`dkim2=pass`) | yes | `dkim2` |
| **T2** | `dkim2=none` **and** ≥1 valid DKIM1 sig aligned with `From:` domain | **yes (new)** | `dkim1` |
| **T3** | neither | no | — |

**Scope decision:** the bridge applies only when `dkim2=none` (no DKIM2 chain
present). A DKIM2 chain that is present but broken (`dkim2=fail`) does **not**
fall back to DKIM1 — a broken chain is an active failure signal, not an
absence, so it is treated as T3 (no signature).

## Reading the DKIM1 verdict

### Server (deployment)

- OpenDKIM is already installed and active, but only on the **outbound**
  (`non_smtpd_milters`) path for signing. Add it to the **inbound**
  (`smtpd_milters`) path in verify mode so it stamps an
  `Authentication-Results` header on every received message, e.g.:

  ```
  Authentication-Results: <authserv-id>; dkim=pass (2048-bit key)
      header.d=brong.net header.i=@brong.net header.s=fm3
  ```

- Configure OpenDKIM to **remove any pre-existing `Authentication-Results`
  for our authserv-id** before adding its own (so an externally-forged A-R
  bearing our authserv-id can't be trusted).
- The `authserv-id` is fixed and documented in SERVER.md; the reflector is
  configured with the same value.

### Reflector

- Parse the incoming `Authentication-Results` headers, considering **only**
  those whose authserv-id matches our configured value. (A-R with any other
  authserv-id — i.e. added by some other host upstream — are ignored.)
- Collect every `dkim=pass` result and its `header.d`.
- A message has a valid, aligned DKIM1 signature if **any one** of those
  `header.d` values aligns with the domain of the message's `From:` header.
  Multiple DKIM signatures for different domains are expected; only one needs
  to match. `dkim=fail` / `dkim=none` results are ignored.

### Alignment rule (relaxed, PSL-free)

`From:` domain `f` aligns with DKIM `header.d` value `d` when:

- `f` equals `d` (case-insensitive), **or**
- `f` is a subdomain of `d` (`f` ends with `.d`), **or**
- `d` is a subdomain of `f` (`d` ends with `.f`).

This approximates DMARC relaxed alignment without a Public Suffix List
dependency (the project has no PSL). It is intentionally slightly more
permissive than true organizational-domain alignment; acceptable for a demo.

## Message-Instance in all cases

Today MI creation happens inside the "only when signed" block. Move it out:

- For the transforming modes (`subject`, `body`, `both`, `redacted`) the
  change-recording MI is **always** built and prepended — in every tier,
  whether or not the reflector signs. It is computed as a diff against the
  incoming message, which always carries at least the inbound milter's `m=1`
  Message-Instance (the milter adds `m=1` when a message arrives with no
  DKIM2 chain).
- `raw` and `damage` continue to reuse the top `m=` in all tiers — they make
  no content change, so there is no new instance to record.
- When the reflector signs (T1/T2), its DKIM2-Signature covers the MI exactly
  as before. When it does not sign (T3), the MI is still present as unsigned
  metadata documenting what the reflector changed.

### Ordering note

For a signed transforming mode the header order is unchanged from today:
the new MI is prepended first, then the DKIM2-Signature is computed over the
message (including that MI) and prepended above it. For an unsigned
transforming mode (T3), only the MI is prepended (no signature).

## Explanation headers (the "note that")

- `Authentication-Results: dkim2.com; dkim2=<pass|fail|none>` and, when a
  bridging DKIM1 signature was found, an additional
  `dkim2.com; dkim=pass header.d=<domain>` clause/header recording the basis.
- `X-DKIM2-Reflector: mode=<mode>; auth=<dkim2 verdict>; dkim1=<pass|none>; `
  `basis=<dkim2|dkim1|none>; signed=<yes|no>; note=<text>`

`dkim1=` reports the raw finding — `pass` whenever an aligned valid DKIM1
signature was found, **independent** of whether we signed on it. `basis=`
reports what we actually signed on. These can differ: a message with
`dkim2=fail` and an aligned DKIM1 reports `dkim2=fail; dkim1=pass; basis=none;
signed=no` (the bridge is suppressed by the broken chain per the scope
decision).

Both remain excluded from the DKIM2 header hash by `should_skip()` (`^x-` and
`authentication-results`), so they never affect the signature.

## Components & boundaries

- **`Mail::DKIM2::Reflector`** — `reflect()` gains:
  - a new arg, e.g. `authserv_id`, used to scope A-R parsing;
  - a helper to extract aligned `dkim=pass` `header.d` from the message's
    `Authentication-Results` headers and decide the DKIM1 verdict;
  - a helper for the relaxed alignment test;
  - reworked control flow implementing the three-tier sign decision and the
    always-on MI for transforming modes.
- **`brong/bin/dkim2-reflector.pl`** — pass the configured `authserv_id`
  through to `reflect()`.
- **Server config** — OpenDKIM inbound verify; documented in SERVER.md §6.

## Error handling (unchanged in spirit)

- No `Authentication-Results` present, or none from our authserv-id → DKIM1
  verdict is `none` → tier decided by DKIM2 alone (T1 or T3).
- Malformed `From:` / no `From:` domain → cannot align → DKIM1 verdict `none`.
- Signing-key problems → as today (reflect unsigned, `note=no-key`).
- The reflector never bounces.

## Testing

Unit (`brong/t/reflector.t`), no real mail:

- **T2 bridge signs:** incoming message with no DKIM2 chain but an
  `Authentication-Results: <our-authserv-id>; dkim=pass header.d=<from-domain>`
  → signed, `basis=dkim1`, DKIM2-Signature present.
- **Alignment required:** same but `header.d` is an unrelated domain → not
  signed (`signed=no`).
- **Subdomain alignment:** `header.d` is a parent/child of the `From:` domain
  → signed.
- **Multiple signatures, one matches:** several `dkim=pass` clauses, only one
  aligned → signed.
- **Foreign authserv-id ignored:** `dkim=pass` aligned but under a different
  authserv-id → not signed.
- **No DKIM1 fallback on broken chain:** `dkim2=fail` present with an aligned
  `dkim=pass` → not signed (T3).
- **MI always emitted:** each transforming mode (`subject`/`body`/`both`/
  `redacted`) in an **unsigned** (T3) message still adds its change-recording
  MI; `raw`/`damage` add none.
- Existing T1 (DKIM2 verified → signed) and T3 (nothing → unsigned) cases and
  the mode-transform/undo assertions continue to pass.

End-to-end (manual, on the server): send a DKIM1-signed (no DKIM2) message
from an aligned domain to each `reflector-*@dkim2.com`; confirm the reply is
signed with `basis=dkim1`, carries the MI for changing modes, and that the
explanation headers report the bridge.

## Out of scope

- SPF and DMARC policy evaluation. Alignment here is a relaxed domain match
  only; no DMARC record lookup, no `p=` enforcement.
- A Public Suffix List dependency (the relaxed match is the PSL-free
  approximation above).
- Bridging on `dkim2=fail`.
- Changing the reflect-to-sender envelope, the per-mode transforms, or the
  damage/redacted semantics.
