# Design: `DKIM2-DSN` singleton-header prototype (generator + handler)

**Date:** 2026-07-01
**Status:** approved, ready for implementation plan

## Purpose

Prototype a dedicated, minimal `DKIM2-DSN` header for Delivery Status
Notifications, replacing the general `DKIM2-Signature` + `Message-Instance`
machinery for the bounce case. DSNs have special, fixed properties — always
`i=1`, always `MAIL FROM <>`, never modifiable (no recipe), `rt=`/`d=` derivable
from the bounced message — so a single self-describing header carries everything
a bounce processor needs.

**Sequencing is prototype-first** (user decision): build a working generator and
handler, let the running code shake out the exact format, then write the -03
draft text (a *separate, later* cycle — out of scope here). A working
implementation is also the strongest artifact to attach to the WG proposal.

Basis: the mailing-list proposal (Bron, 2026-07-01) plus this session's findings
that DSNs are always origin/`i=1`/`mf=<>`/no-recipe, should carry headers only
(no body), and that the top `Message-Instance` already hashes the headers it
covers and is self-verifying.

## The `DKIM2-DSN` header (the format the prototype defines)

```
DKIM2-DSN: d=example.com; rt=<bounce@sender.com>;
    h=sha256:<headerhash>; s=sel1:rsa-sha256:<base64sig>
```

- **`d=`** — signing domain of the bouncing hop (the DSN generator).
- **`rt=`** — the DSN's destination, = the **`mf=` of the bounced message's
  top (highest `i=`) hop** (where bounces go). Angle-bracketed per §7.6
  (consistent with the `mf=`/`rt=` bracket work shipped this session).
- **`h=`** — `sha256:<headerhash>`, the **header-hash component of the bounced
  message's top `Message-Instance`** (no body-hash half — the DSN discards the
  body). This is the value that binds the DSN to a specific message.
- **`s=`** — `selector:algorithm:signature`; the signature is computed over the
  `DKIM2-DSN` header itself with the `s=` value blanked, using the same folding
  and canonicalization discipline as `DKIM2-Signature` (see `brong/CLAUDE.md`).
- **No `t=`.** The DSN cannot be forged (an attacker cannot produce a valid
  `h=`+`s=` pair for a message it did not legitimately handle), and its lifespan
  is **inherited from the bounced message**: the embedded original carries its
  own `DKIM2-Signature` `t=`, so a recipient bounds freshness off *that*.
- Envelope **`MAIL FROM <>`**. The DSN carries **only this one header** — no
  `DKIM2-Signature` and no `Message-Instance` of its own.
- The DSN's embedded original is **headers-only** (`text/rfc822-headers`); the
  body is discarded and unsigned (bounce processors act on the verified headers,
  not the human-readable notice).

### Verification (a bounce processor)

Given a `DKIM2-DSN` header and the included (headers-only) original:

1. **`rt=`** is the processor's own bounce address (= the `mf=` it used) and
   equals the `mf=` of the included message's top hop — derivable/cross-checked.
2. **`d=`** relaxed-domain-matches (§8.3) an `rt=` domain of the included
   message's **top hop** — i.e. the DSN was minted by a *legitimate recipient*
   of the message (§11.1.2 anti-backscatter authentication).
3. **`h=`** equals the header-hash recomputed over the included headers (the
   same computation that produced the bounced message's top `Message-Instance`
   header-hash) — confirms the returned headers are genuine and unaltered.
4. **`s=`** verifies over the `DKIM2-DSN` header (sig blanked) using the
   `d=`/selector public key.

**Anti-forgery:** minting a valid `DKIM2-DSN` requires (2) a `d=` aligned to a
real recipient of the message AND (4) that domain's private key AND (3) a correct
`h=` for the message's headers. Only a legitimate handling domain can do all
three.

## Components

### C1. `Mail::DKIM2::DSNHeader` (new, small, self-contained)

Build / sign / parse / verify the singleton header. Mirrors `Signature.pm`'s
sign-vs-verify input discipline (fold at 72 chars; sign over the folded,
sig-blanked form; verify over the unfolded form via canonicalization).

- `->new(Domain, RcptTo, HeaderHash, Selector, Key, Algorithm)` → object.
- `->as_folded_string_without_data()` / `->as_folded_string()` — signing input
  and final insertable header (as `Signature.pm`).
- `DSNHeader->parse($value)` → object with accessors `domain`, `rcpt_to`
  (bracket-decoded), `header_hash`, `selector`, `algorithm`, `signature`.
- `->verify($pubkey)` → boolean over the sig-blanked canonical form.

### C2. Generator — `Mail::DKIM2::DSN` + `bin/dkim2-reflector.pl` (`dsn` mode)

On the DSN path, verify the incoming DKIM2 chain (reuse `Mail::DKIM2::Verifier`):
- **Legit chain** → build a DSN whose embedded original is **headers-only**
  (`text/rfc822-headers`, reusing `DSN.pm`'s existing headers-only branch), then
  add a `DKIM2-DSN` header via C1: `d=` = our domain (`dkim2.com`), `rt=` =
  the incoming message's top-hop `mf=`, `h=` = its top-MI header-hash. Envelope
  `MAIL FROM <>`; deliver to `rt=`. The DSN carries **no** `DKIM2-Signature`/
  `Message-Instance`.
- **No legit chain** → today's plain RFC3464 DSN, **no** `DKIM2-DSN` header
  (unchanged behaviour).

`Mail::DKIM2::DSN` gains a `generate_dkim2_dsn(%args)` alongside the existing
`generate`/`propagate`; `reflector-dsn` calls it when the incoming chain
verifies.

### C3. Handler — `dkim2-bounces@dkim2.com` (new pipe processor)

`dkim2-bounces@dkim2.com` becomes the envelope `MAIL FROM` on reflector-sent
mail (supersedes `reflector-bounces@` as the source; the `reflector-bounces`
mbox alias stays for debug capture of anything unhandled). A `pipe(8)` processor
(same pattern/rationale as the existing `dkim2-reflect` transport) that, on an
inbound bounce to `dkim2-bounces@`:

1. If it carries a `DKIM2-DSN`, verify it (the four checks above).
2. **Apply the undo** — reverse the `Message-Instance` chain to reconstruct the
   original message (reuse the existing MI chain-undo logic;
   `MessageInstance`/`Reflector` undo).
3. **Relay** the bounce (with the reconstructed original) to the originator
   derived from the reconstructed **top-hop `mf=` / `From:`**, via the
   milter-free injector (`127.0.0.1:10588`, already-signed path).
4. Unverifiable / non-`DKIM2-DSN` input → fall back to the mbox capture + log
   (prototype: do not relay what we can't authenticate).

### Deploy

- `reflector-dsn` is already routed via the `dkim2-reflect` pipe — no new
  routing for C2.
- C3: add a `dkim2-bounces@dkim2.com` entry to the pipe transport map (like the
  reflector addresses), a wrapper mode, and repoint the reflector's `MAIL FROM`
  to `dkim2-bounces@`. Deliver reconstructed mail via the `10588` injector.

## Testing

- **C1 unit:** build → sign → parse → verify round-trips; tamper each field
  (`h=`, `d=`, `rt=`, `s=`) → verify fails; folding round-trips.
- **C2:** a message with a legit DKIM2 chain → a `DKIM2-DSN` DSN whose four
  checks pass, embedded original is headers-only, `rt=` = top-hop `mf=`, `h=` =
  top-MI header-hash; a message with no legit chain → plain DSN, no `DKIM2-DSN`.
- **C3:** feed a `DKIM2-DSN` bounce → verify + undo reconstructs the original →
  relays to the derived originator (assert relay envelope + reconstructed
  content); an unverifiable bounce → captured, not relayed.
- **Live (dkim2.com):** `reflector-dsn` emits a `DKIM2-DSN`; a message sent with
  `MAIL FROM dkim2-bounces@` that bounces is undone and relayed to its
  originator.

## Out of scope

- **The -03 draft spec text (#1)** — written in a *separate later cycle*, from
  the format this prototype settles, on its own branch for Richard.
- **Postfix delayed-bounce as a `DKIM2-DSN`** — `bounce(8)` owns that DSN's body
  and can't emit the custom singleton cleanly; it stays the "sign the MTA's own
  bounce as-is" demonstration (with `disable_mime_output_conversion=yes`).
- Multi-hop undo correctness beyond what the existing MI chain-undo already
  supports; no new recipe work (DSNs have no recipe by construction).
