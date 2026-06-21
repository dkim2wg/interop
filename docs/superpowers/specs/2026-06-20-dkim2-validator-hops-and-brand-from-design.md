# Design: validator per-hop details + brand-message ESP From/To

**Date:** 2026-06-20
**Status:** approved, ready for implementation plan

Two small, independent changes bundled into one pass:

- **A. Validator results** — spell out each hop's `From`/`To` on signature cards, and the recovered recipe values on Message-Instance cards.
- **B. Brand message** — make `reflector-brand`'s delegated message model an ESP: visible `From`/`To` show only the brand and the recipient; `dkim2.com` appears only in the signature chain and SMTP envelope.

---

## A. Validator results: per-hop details

### A1. Signature cards — From/To

`Mail::DKIM2::Validate::_sig_level` already parses the `Mail::DKIM2::Signature`
(it reads `mail_from`/`rcpt_to` for the chain-of-custody check). Add to the
signature level hashref:

- `mail_from` => `$sig->mail_from` (decoded address string, `''` if none)
- `rcpt_to`   => arrayref of decoded recipient addresses (`$sig->rcpt_to`,
  normalised to a list)

`deploy/www/validate/validate.js` `render()` — on each signature card, after
`domain`, add:

- `from: <mail_from>`
- `to: <rcpt_to joined with ", ">`

(Omit a line if the value is empty.)

### A2. Message-Instance cards — recovered recipe values

`_mi_level` already undoes to a clone (to test `undo: clean`). Reuse that clone.
When the MI has a recipe and is recoverable, add:

- `header_recipes` => arrayref of `{ name, current, previous }`, one per header in
  the MI's `rh` recipe (`$mi->get_tag('rh')` keys, sorted). `current` =
  `$msg->header($name)` at this level; `previous` = the value in the undone clone
  (`$clone->header($name)`). A missing side is rendered as `(absent)`. Multiple
  values for a header are joined with ` / `.
- `body_recipe` => one of: `diff` (a `rb` recipe is present and recoverable),
  `null` (unrecoverable / redacted — previous body not recoverable), or `none`.

When the MI is `unrecoverable` (null recipe), set `header_recipes => []` and
`body_recipe => 'null'`, and the cards note "previous not recoverable" rather
than values. The base `m=1` (and any no-recipe MI) keeps `recipe: none` with no
extra lines, exactly as today.

`validate.js` `render()` — on each MI card, after the existing `recipe` line:

- for each `header_recipes` entry: `recipe — <name>: "<current>" ← "<previous>"`
- `body recipe: <body_recipe>` (only when not `none`)

### A3. Notes

- `current`/`previous` use the decoded `header()` value (display-friendly). This
  is presentation only; the hashes/verification are unchanged.
- No change to the overall verdict, level results, or the `Received-SPF`
  strip-and-retry.

---

## B. Brand message: ESP-style From/To

In `Mail::DKIM2::Reflector::generate_brand`, the **delegated** path changes the
user-visible headers so the platform (`dkim2.com`) is not shown:

| | before | after |
|---|---|---|
| `From` | `<sender>` | `dkim2demo@<brand domain>` |
| `To` | `reflector-brand@<domain>` | `<sender>` |
| `Subject` | `Brand-signed DKIM2 message` | unchanged |

Signature chain (unchanged except `i=1` `mf`):

- **i=1** `d=<brand domain>`, `s=dkim2test`, `mf=dkim2demo@<brand domain>` (now
  matches `From`), **`rt=reflector-brand@<domain>`** — unchanged; the
  reflector-brand recipient stays in the signature (protocol-level), not in the
  visible `To`.
- **i=2** `d=<domain>`, `s=sel1`, `mf=reflector-bounces@<domain>`, `rt=<sender>`
  — unchanged. Chain-of-custody still links (`<domain>` ∈ i=1's `rt`).

So `dkim2.com` appears only in the `i=2` signature and the SMTP envelope — never
in `From`/`To`/`Subject`. The body explainer is updated to describe the ESP
framing (brand-visible, platform-signed) and still references both `i=1`/`i=2`.

The **not-delegated** path is unchanged: it remains the fresh generator (`From:
"DKIM2 Generator" <fresh@<domain>>`) with the CNAME-setup error body — that
message is legitimately *from* `dkim2.com` telling the sender to publish the
CNAME, so showing `dkim2.com` there is correct.

### Deliverability note (unchanged)

`From: <brand domain>` is not aligned with the `dkim2.com` SPF/signature, so
classic DMARC for the brand domain will likely fail → Junk at Fastmail. Expected;
it models the ESP/brand case in a not-yet-DKIM2-aware world.

---

## Files

- `brong/lib/Mail/DKIM2/Validate.pm` — add `mail_from`/`rcpt_to` (A1) and
  `header_recipes`/`body_recipe` (A2) to the level hashrefs.
- `deploy/www/validate/validate.js` — render the new fields (A1, A2).
- `brong/lib/Mail/DKIM2/Reflector.pm` — `generate_brand` delegated From/To/`mf`
  + body (B).
- `brong/t/validate-report.t` — assert `mail_from`/`rcpt_to` on a signature
  level and `header_recipes`/`body_recipe` on a diff MI (reuse the existing
  reflect-`both` chain, which has a `subject` recipe).
- `brong/t/reflector.t` — update the brand assertions for the new From/To.

## Testing

- **A:** on the existing valid 2-hop reflect-`both` report, assert a signature
  level has `mail_from`/`rcpt_to` populated, and the `m=2` MI level has a
  `header_recipes` entry for `subject` with `current` = the `[DKIM2] …` subject
  and `previous` = the original subject, and `body_recipe` = `diff`.
- **B:** in `reflector.t`, the delegated `generate_brand` message has
  `From: dkim2demo@test1.dkim2.com`, `To: brand@test1.dkim2.com` (the sender),
  no `dkim2.com`/`test2.dkim2.com` in `From`/`To`/`Subject`, and still verifies
  (two sigs, chain-of-custody ok).

## Out of scope

- `nextd` (deferred). From-munging/ARC for inbox delivery. Any signing/hash
  algorithm change.
