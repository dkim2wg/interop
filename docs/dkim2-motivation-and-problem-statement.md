# DKIM2 — Motivation & Problem Statement (research synthesis)

**Compiled:** 2026-06-18
**Purpose:** Capture the *why* of DKIM2 — the chartered reasoning, the sharpest
"DKIM1 cannot assert this" problem framings, and the anchor purpose statements —
sourced and quoted so it can be reused for dkim2.com copy, talks, and docs.

> Method note: this was produced by a multi-source research pass over IETF
> primary sources (drafts, meeting materials) and the ietf-dkim list archive,
> with adversarial verification of each claim. Where revisions disagree, the
> revision is named. One plausible claim was refuted and is recorded below so we
> don't repeat it.

---

## 1. Provenance & timeline

- **`draft-gondwana-dkim2-motivation`** — individual draft, authors **Bron
  Gondwana (Fastmail), Richard Clayton (Yahoo), Wei Chuang (Google)**.
  `-00` published **2024-10-21**; through `-03` (**2025-06-25**); now **expired**.
- Presented at **IETF 121 ALLDISPATCH, 2024-11-04** (`slides-121-alldispatch-dkim2-00`).
- The original **DKIM WG closed 2024-01-18** (the replay-problem doc's IETF/WG
  state was removed "with the closure of the DKIM WG").
- WG **rechartered for DKIM2** — IETF "WG Action: Rechartered Domain Keys
  Identified Mail (dkim)" announcement **2025-02-20**.
- Motivation draft then WG-adopted as **`draft-ietf-dkim-dkim2-motivation`**
  (`-02`, late 2025).
- Spec: **`draft-ietf-dkim-dkim2-spec`** (this repo tracks `-02`, 2026-05-17).
- DKIM2 "grew out of the stalled dkim-replay effort" and **"replaces ARC"**
  (IETF 121 slides: *"The dkim-replay group didn't progress because it didn't
  solve enough problems, this work replaces ARC and has significant buy-in."*).

---

## 2. The three "these things can't be asserted" problems

Verbatim, **`draft-ietf-dkim-dkim2-motivation-02` §1** (current WG wording — the
best problem statement to quote):

1. *"You can legitimately receive a validly DKIM signed email, where there is no
   evidence inside the signed part that you were an intended recipient"*
   → **recipient binding** (enables replay).
2. *"An email can have a bounce (SMTP-FROM) email address for a domain which was
   never involved in the transit of that message"*
   → **return / bounce path** (backscatter, untraceable DSNs/abuse reports).
3. *"An email can be altered by forwarders or mailing lists, and there's no way
   to know what parts of the message were changed"*
   → **modification opacity** (mailing lists / forwarding break DKIM+DMARC).

> The older `draft-gondwana-dkim2-motivation-00/-01` expressed the same three
> ideas in different prose; the clean three-bullet list above is specifically
> the IETF `-02` revision.

---

## 3. The three purpose statements (hop responsibilities)

Verbatim, **`draft-gondwana-dkim2-motivation` §1** (the now-expired draft). DKIM2
makes *every hop in a forwarding chain* responsible for:

1. *"verifying the path that messages have taken to get to it, including by being
   able to reverse modifications or by asserting that it trusts the previous hop
   unconditionally"*
2. *"declaring (under protection of its own signature) where the message is being
   sent to next"*
3. *"promising that it will pass control messages (including bounces, abuse
   reports and delivery notifications) back to the previous hop for a reasonable
   time"*

> `-00` used "asserting" rather than "promising" in item 3, and item 1 had a
> trailing clause "…and that it is the declared next hop in the chain".
> CAVEAT: the draft *also* has a separate "Goals to be addressed" section
> (DKIM-replay, Backscatter); these three are the **hop responsibilities /
> mechanism** the document is built around, not labelled "the goals".

**The two trios map 1:1** (problem → responsibility):
recipient binding → declare next-hop/recipient;
return path → promise to carry control messages back;
modification opacity → verify path & reverse modifications.

---

## 4. Sharpest supporting framings (quotable)

- **Replay, million-fold** — `draft-*-dkim2-motivation` §4.7:
  *"Because an email can currently be sent as 'Bcc' such that there's no evidence
  in the message data of who the recipient is expected to be, it's possible to
  take a message that is correctly signed and replay it millions of times to
  different destination addresses as if they had been BCC'd."*
  DKIM2 fix: encode the recipient in the signature so *"messages will be unable
  to be replayed to any other destination"* (the `rt=` recipient tag).

- **Replay definition** — `draft-ietf-dkim-replay-problem` (WG-adopted; from
  `draft-chuang-dkim-replay-problem-03` §1.1):
  *"In a Replay Attack, a recipient of a DKIM-signed message re-posts the message
  to other recipients, while retaining the original, validating signature, and
  thereby leveraging the reputation of the original signer."*

- **Why replay is unfixable with DKIM1** — same draft:
  *"Although DKIM covers portions of the message content … it does not cover the
  envelope addresses, used by the email transport service … So this message can
  then be replayed to arbitrary thousands or millions of other recipients, none
  of whom were specified by the original author."* and
  *"DKIM Replay is impossible to detect or prevent with current standards and
  practices. Simply put, email authentication does not distinguish benign
  re-posting flows from a DKIM Replay Attack."*
  Real-world incidents cited in WG discussion: no-reply@google.com OAuth
  phishing; Apple/PayPal invoice abuse.

- **Mailing-list / forwarding breakage** — `draft-gondwana-dkim2-motivation-00/-01`
  §4.5 "The mailing list DMARC issue":
  *"Once an intermediate (for example, a mailing list or alumni forwarder) makes
  a change to the header or body of a message, the hashes covered by the sender's
  DKIM signature no longer match, and it's not possible to see whether the message
  is semantically similar, or has been completely replaced by a bad actor."*
  DKIM2 fix: intermediaries record header/body changes so recipients can undo
  them, re-verify prior signatures, and see who injected bad content.
  > CAVEAT: this "Issue:" passage is in `-00/-01`; restructured/removed by `-03`.

---

## 5. Abstract / rationale (framing language)

- **Gondwana drafts (stronger "replace" language):**
  *"This memo provides a rationale for replacing the existing email security
  mechanisms with a new mechanism based around a more strongly authenticated
  email delivery pathway, including an asynchronous return channel."*
  §1: *"There is no way to add these properties to existing DKIM1 in a way which
  is both backwards and forwards compatible, so a new specification will need new
  headers…"*
- **WG-adopted draft (softer "accountability" language):**
  *"This memo provides a rationale for building a new email accountability
  mechanism, based on the lessons learned from implementing the ARC experiment
  from RFC 8617 and other experiences from email system operators."*

For public copy, prefer the **WG-adopted** framing ("accountability mechanism,
lessons from ARC") and the `-02` three-bullet problem list; cite revisions.

---

## 6. Design goals (verbatim, motivation §2)

1. Legacy interop, *"after a period of parallel running"* eventual mandatory
   upgrade.
2. *"We favor simplicity over obscure functionality."*
3. *"keep the number of cryptographic operations required the same or less, for
   all the most common types of email flow."*
4. *"make all parts of the specification mandatory to implement because experience
   shows that interworking is adversely affected by providing optional
   functionality."*

Per IETF 121 slides, DKIM2 is designed to support/mitigate: **DKIM Replay,
Backscatter, asynchronous spam-scanning/bounces, reversible modification algebra,
mailing lists, forwarding services, and abuse reporting for intermediaries.**

---

## 7. Refuted claim (do not repeat)

> "DKIM1 breaks at naive forwarders/mailing lists *because the new destination
> address is never recorded*, which DKIM2 fixes by signing the forwarding path."

**Refuted (0–3).** The recorded cause of breakage is **content/header
modification**, not a missing destination record. (Recipient binding/`rt=` is
about *replay*, a separate problem from list breakage.)

---

## 8. Open questions (not fully resolved by this pass)

- The exact **chartered problem statement** in the WG charter text itself
  (`datatracker.ietf.org/group/dkim/about/`) was not separately quoted — the
  synthesis leaned on the recharter announcement + motivation draft.
- Documented **WG consensus "key points"** across IETF 117–124 minutes (beyond
  the 121 slides), including list pushback on "trusts the previous hop
  *unconditionally*" and on backwards-compatibility claims.
- The precise **DMARC-alignment mechanism** (reversible modification algebra) vs
  ARC, if it is to be described on the site.

---

## 9. Primary sources

- `draft-ietf-dkim-dkim2-motivation` — https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-motivation/
- `draft-gondwana-dkim2-motivation` (expired) — https://datatracker.ietf.org/doc/draft-gondwana-dkim2-motivation/
  (`-00`: https://www.ietf.org/archive/id/draft-gondwana-dkim2-motivation-00.html)
- `draft-ietf-dkim-dkim2-spec` — https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-spec/
- `draft-ietf-dkim-replay-problem` — https://datatracker.ietf.org/doc/draft-ietf-dkim-replay-problem/
  (`draft-chuang-dkim-replay-problem-03`: https://www.ietf.org/archive/id/draft-chuang-dkim-replay-problem-03.html)
- IETF 121 ALLDISPATCH slides "Why DKIM needs replacing" —
  https://datatracker.ietf.org/meeting/121/materials/slides-121-alldispatch-dkim2-00
- DKIM WG — https://datatracker.ietf.org/group/dkim/about/
- ietf-dkim list archive — https://mailarchive.ietf.org/arch/browse/ietf-dkim/
  (corroborating threads incl. Dave Crocker's review of `-01`, 2025-01-31)
