# Design: website docs for reflector-fresh + reflector-brand

**Date:** 2026-06-21
**Status:** approved; implementing directly (review gate waived by user)

Document the two originating reflector addresses on the dkim2.com landing page
(`deploy/www/index.html`), in the existing "Try it: reflector addresses" section.

## Changes

1. **Intro update.** The section opens "Six addresses on this host…". Reword to
   cover two categories: the six reflect-and-transform addresses (existing
   table) and the two that originate a brand-new message (new subsection).

2. **New subsection "Originate a new message"** (after the "Headers to look at"
   table, before "Learn more"):

   - **`reflector-fresh@dkim2.com`** — a paragraph: originates a brand-new DKIM2
     message back to you — a single Message-Instance (`m=1`) and one `dkim2.com`
     DKIM2-Signature, no chain. Sent from a `dkim2.com` address (with a matching
     `dkim2.com` DKIM1), so it is DMARC-aligned and lands in your inbox. The
     simplest valid DKIM2 message.

   - **`reflector-brand@dkim2.com`** — an `<h3>` spotlight modelling an ESP that
     signs on a brand's behalf:
     - What it shows: a brand-new message with two DKIM2-Signatures on one MI —
       `i=1` as *your* domain (via a delegated key), `i=2` as `dkim2.com` — plus,
       like real ESP mail, two DKIM1 signatures (`d=<yourdomain>` delegated and
       `d=dkim2.com`). Visible `From: dkim2demo@<yourdomain>`, `To:` you;
       `dkim2.com` is never in the headers a reader sees.
     - Why it inboxes: the delegated `d=<yourdomain>` DKIM1 aligns with `From`,
       so it passes DMARC and lands in the inbox — how Mailchimp/SendGrid/etc.
       send for a brand.
     - Setup — one CNAME (shown in a code box):
       `dkim2test._domainkey.<yourdomain>  CNAME  dkim2test._domainkey.dkim2.com`.
       The same delegation serves both the DKIM2 chain signature and the DKIM1
       signature (one key, held by dkim2.com).
     - Then email `reflector-brand@dkim2.com` from `<yourdomain>` and paste the
       reply into the validator to watch both DKIM2 signatures verify.
     - Without the CNAME: a plain fresh message that explains how to set it up.

3. **DKIM1 row** added to the existing "Headers to look at in the reflected
   message" table: `DKIM-Signature` (classic DKIM1) — every reply now carries
   one (`d=dkim2.com`; brand also `d=<brand>`), so the demo mail looks like real
   mail.

## Constraints

- Reuse the existing `<section>`/`<h3>`/`<table>`/`<code>` patterns. A small CSS
  rule may be added to `deploy/www/style.css` for the CNAME code box (e.g. a
  `pre`/`.cname` block); only if needed.
- Content only — no behaviour change. Deploy by installing `index.html` (and
  `style.css` if changed) to `/var/www/dkim2.com/`.

## Verification

- HTML well-formed (balanced tags; `tidy`/grep checks).
- New addresses, the CNAME box, and the DKIM1 row are present and the
  `mailto:`/validator links resolve.
- Deploy and eyeball the live page.

## Out of scope

- `nextd`. Any code/behaviour change. The reflect-mode rows (already documented)
  are unchanged.
