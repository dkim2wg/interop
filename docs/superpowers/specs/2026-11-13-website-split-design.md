# dkim2.com: a multi-page site built around the grey area

## Intent

dkim2.com is one long page (`deploy/www/index.html`, 416 lines) written for
implementers: half of it is reflector addresses. Bron's talks (most recently
ESPC, Washington DC, 3 November 2026, deck at
`~/Documents/DKIM2 for Nov 3 - ESPC v2.pptx`) now send senders and operators
there — "the one address to remember is dkim2.com".

Rebuild it as a few linked pages whose spine is the talk's central argument:

> **DKIM2 shrinks the grey area** — the mail a receiver can't tell is good or
> bad. **Good** means: from who it says it's from, with every change
> attributable to whoever made it. Legitimate mail gets a verifiable way to
> show that, so whatever is still grey can be treated as bad.

Attribution is the important bit in every case. Small changes (a list's
`[tag]`, a footer, an `[EXTERNAL]` banner) keep the author's From and are
recorded against the hop that made them. A hop that makes significant changes
becomes the author and must put its own From on the message — **proposed for
the next draft**, not current spec; the site says so in those words.

Also add a **Deployment status** page — who runs DKIM2 on real mail (Fastmail,
1&1, Squarespace today) — that is easy to extend as more sites come on.

## Goals

- Home page leads with the grey-area diagram and the definition of good.
- Deck material (why / how it works / what to do now / status) on the site,
  in the deck's order and wording where it reads well as prose.
- Existing implementer material (reflectors, demo lists, other
  implementations) kept verbatim on its own pages.
- Deployment status page, added to by PR without merge clashes.

## Non-goals

- No backend, no self-serve submission form, no auto-detection.
- No mention of `draft-clayton-dkim-canmodify` or slide 9's list of
  permitted change types (Bron: skip it). The From rule is stated without
  defining where "significant" starts.
- No Topicbox example (slide 17), no "Thank you" / section-divider slides.
- No dark theme (the site has none today).

## Anti-goals

- Breaking links people already have (`/#originate`, `/#bounces`,
  `/#reflector-brand`, `/#reflector-brand-nd`, `/#reflector-signing`,
  `/#other-implementations`).
- Presenting the From rule, or "on track to become what large mailbox
  providers require", as decided by the WG.
- Diagrams as images: unreadable on phones, uneditable without Keynote.

## Approaches considered

**Diagrams**
1. **HTML + CSS in the page** — *chosen* (Bron). Sharp at any size, stacks on
   phones, labels readable by screen readers, editable as text, uses the
   site's palette. Costs some layout work.
2. Slide PNGs exported from Keynote — no work, but slide-shaped, tiny text on
   phones, re-export on every wording change.
3. Hand-written SVG — sharp and editable, but harder to make responsive than
   HTML and no easier to maintain.

**Deployment data**
1. **One JSON file per site in the repo, rendered into the page at deploy
   time** — *chosen* (Bron: one file per site so PRs don't clash). We stay in
   control of public claims.
2. Self-serve form — needs a backend and moderation.
3. Auto-detect from reflector traffic — sees senders only, never verifiers.

## Pages

Plain static HTML under `deploy/www/`, one shared `style.css`, the same nav on
every page: **Home · How it works · Get ready · Try it · Implementations ·
Deployments · Validate · Verify**. The current page's link carries
`aria-current="page"`. Directory URLs (`/how/` → `how/index.html`; nginx
already does `try_files $uri $uri/`).

### `/` — Home

1. Hero: "DKIM2", tagline "Shrink the grey area." (replaces today's tagline),
   the IETF work-in-progress badge.
2. **Grey-area diagram** (slide 6): "Today, a lot of legitimate mail is
   impossible to tell apart from abuse." Two horizontal bars labelled TODAY
   and WITH DKIM2, each Clearly good / Grey / Clearly bad, with today's grey
   wide and DKIM2's narrow; caption under the first bar: "forwarding ·
   mailing lists · replayed signatures · forged bounces"; a callout
   "**The goal:** move legitimate mail out of the grey area — so anything
   still there can be treated as bad."; "Proportions are illustrative."
   Immediately beside/below it, the definition of good (Intent, above).
3. **Four things you can't verify today** (slides 3–4, notes for prose):
   replay (no proof you were the intended recipient), backscatter (can't
   safely bounce after the connection closes), changes in transit (can't
   tell new content from original — so lists rewrite From), crypto (no
   upgrade without a flag day). Root cause of the first two: the RFC 5321
   envelope has no authenticity checks.
4. **DKIM2 fixes all four** (slide 5): envelope signed into the message;
   every change recorded; several algorithms per signature. Each links to
   its section on `/how/`. "Not trust — accountability": DKIM2 doesn't say
   who to trust; it records who did what at every step.
5. **Status** (slide 8): re-chartered IETF DKIM WG; WG drafts dkim2-spec,
   dkim2-bcp, dkim2-dns; individual drafts dkim2-authres,
   dkim2-debug-header, dkim2-sender-policy — each with one-line purpose and
   current revision, linked to datatracker. Pointer to `/deployments/`.
6. **Get involved** (slide 28): WG mailing list ("this is where it's
   decided"), the drafts, the interop repo, the feedback format is still
   open. Plus today's "Learn more" links (validator, verifier, list-host
   guides).
7. Old-anchor redirect script (below).

### `/how/` — How it works (slides 12–16, 18–21)

Sections, each with an id: `chain` (It's a chain — i=1/2/3, all m=1),
`accountability` (**diagram**: brand.example → lists.example →
alumni.example → Inbox, each card saying sent to / flag / changed, closing
"Every hop is on the record — so reputation lands on whoever actually did
it."), `changes` (**diagram**: Message-Instance before/after the corporate
gateway adding `[EXTERNAL]`, m=1 → m=1 + m=2 with r=; then the From rule as
the closing paragraph of this section), `envelope` (signed MAIL FROM /
RCPT TO: replay, backscatter, stripping doesn't rewind), `domains` (the two
required matches, with slide 16's ✓/✗ examples as two small tables),
`flags` (feedback / feedhere / exploded), `algorithms` (several at once:
RSA-SHA256, Ed25519-SHA256, ML-DSA-44), `keys` (reuses existing DKIM keys,
no new DNS), `debugging` (X-DKIM2-Info example, draft-gondwana-dkim2-debug-header).

### `/get-ready/` — What to do now (slides 23–26)

"If you already DKIM-sign, you're most of the way there." Alignment
(MAIL FROM, From, d= must line up; SPF-only DMARC won't carry over); ESPs,
async bounces, `f=feedback`; the five steps (get DKIM keys first, pick an
owner, map your modifications, plan your signing workflow, ask your vendors).

### `/try/` — Try it

Today's "Try it: reflector addresses" (with both h3s and both tables),
"Originate a new message" and "Bounces & delivery notifications", verbatim,
ids kept.

### `/implementations/` — Implementations

Today's "Implementations & demo" and "Other DKIM2 implementations", verbatim
except three factual updates from slide 10: add a dkim2.pub row (Christian
Rößner, mail.de — validator, SMTP reflectors); dkim2.eu's "operator not
stated" → Steve Atkins; SocketLabs row notes Brian Godiksen (SocketLabs,
now Infobip). Update the "As observed" date.

### `/deployments/` — Deployment status

Generated at deploy time (a browser can't list a directory). Two tables, each
from its own directory of one-file-per-entry JSON:

- **Services running DKIM2** — `deploy/www/deployments/sites/<slug>.json`:
  operators signing or verifying real mail.
- **Supporting software** — `deploy/www/deployments/software/<slug>.json`:
  products you can deploy that sign/verify DKIM2 (mail servers, MTAs). Not
  services. (Libraries and test tools stay on `/implementations/`.)

Both use the same schema. Slug `[a-z0-9-]+`, keys exactly
`{name, url, kind, signs, verifies, since, notes, source}`: required
`name`, `url` (https only), `kind` (e.g. "mailbox provider", "sender
platform", "mail server", "MTA"), `signs`, `verifies` (JSON booleans);
optional `since` (`YYYY-MM`), `notes`, and `source` (https URL of a public
statement). **Verifies** means: checks DKIM2 on incoming mail and records
the result (it need not yet act on it) — stated on the page and in the
README. The Since column links to `source` when present; entries without
one show "reported to us" in small text beside the date.

`deploy/bin/build-deployments.pl` (core Perl only) reads every `*.json` in
both directories (other files ignored), validates all of them (any unknown
key, missing/mistyped field, bad date, non-https URL, bad filename, invalid
JSON → errors naming the file, nothing written, exit 1), HTML-escapes all
text, sorts by `since` then name (undated last), and replaces
`<!-- SITES -->` and `<!-- SOFTWARE -->` in `deployments/index.html.in` with
a table each: Name · Type · Signs · Verifies · Since · Notes (✓ for true).
It writes via a temp file + rename. `--check` validates only and runs in
the test suite. The page ends: "Running DKIM2 in production, or shipping
it? Open a pull request adding a file under
`deploy/www/deployments/sites/` or `software/` (copy an existing one), or
tell us on GitHub." A `README.md` beside the directories says the same.

Initial services:
- Fastmail — mailbox provider, signs + verifies, 2026-09, source
  https://mailarchive.ietf.org thread "Fastmail email now being signed by
  DKIM2" (29 Sep 2026; builder resolves the mailarchive.ietf.org msg URL).
- 1&1 — mailbox provider, signs + verifies, 2026-11, url
  https://www.1und1.de/, reported to us.
- Squarespace — sender platform, signs, 2026-11, reported to us.
- Bird — sender platform, signs, 2026-10, reported to us.

Initial software:
- Stalwart mail server — mail server, signs + verifies (also validates
  inbound DKIM2 DSNs), 2026-07, source
  https://mailarchive.ietf.org/arch/msg/ietf-dkim/LKutLi03M6QvjgAxV0ktjqpdOzQ
- Halon (Engage / Protect) — MTA, experimental signing + verification via the
  open-source `halon-extras-dkim2` module, 2026-08, source
  https://halon.io/blog/halon-introduces-experimental-dkim2-support
- Momentum MTA (Bird) — MTA, experimental signing + verification in v5.3,
  2026-07, source
  https://mailarchive.ietf.org/arch/msg/ietf-dkim/iJjYkj3nsBlVW2F08tW-Ix2Jz90

### Old anchors

A small script at the end of `/` maps the six old fragments to the same id
on `/try/` or `/implementations/` with `location.replace`.

### Diagrams (HTML + CSS)

Each is a `<figure>` with a `<figcaption>`; text lives in the markup, not in
CSS. Grey-area bars: flex rows with segment widths set inline (illustrative,
e.g. 28/50/22 today, 63/11/26 with DKIM2), labels in the segments, colours
taken from the deck (teal good, light grey-blue grey, brick red bad),
contrast ≥ 4.5:1 for the labels. Accountability chain: a row of cards with
→ between them, stacking vertically with ↓ below ~40rem. Message-Instance:
two panels (subject/body box + header code block) side by side, stacking on
narrow screens, the `[EXTERNAL]` highlighted.

### Preview before switch-over

Bron checks the whole new site at `https://dkim2.com/preview/` before it
replaces the live pages. So every link between the new pages is relative
(only the live tools `/validate/` and `/verify/` stay absolute), and a
`deploy/bin/stage-www.sh DEST` script assembles the site (static pages +
generated `/deployments/`) into any directory. The preview is built locally
and copied to `/var/www/dkim2.com/preview/` over ssh — no push, live pages
untouched. After his go-ahead: merge, deploy (which runs the same script
into the web root), remove `/preview/`.

### Tool pages and deploy

The validator and browser verifier keep their own layout; their header line
gains links to Home, How it works and Deployments. `deploy.sh` runs the site
tests, installs every page directory, and builds `/deployments/` straight
into `/var/www/dkim2.com/` (the repo never holds the generated file).
`SERVER.md`/`README.md` list the new web-root contents.

## Constraints

- Draft revisions on the site must be current at build time: the slides
  (spec -09, bcp -01, dns -03, authres -02, debug-header -03,
  sender-policy -04) are a starting point, to be checked on datatracker.
- Speaker notes are stale in places (they say spec -08); slide text wins.
- Existing reflector/implementation text is moved, not rewritten.
- Core Perl only for the builder; no JS on `/deployments/`.

## Calls made while writing this up (not Bron's — check these)

- Today's home prose ("Status", "What DKIM can't tell you", "How DKIM2
  fixes it") is replaced, but two things survive: the links to
  draft-ietf-dkim-replay-problem (on the replay problem, home §3) and
  draft-ietf-dkim-dkim2-motivation (in Get involved), and the "promises to
  carry control messages back to the previous hop" point (in `/how/#envelope`,
  with bounces).
- `perl/t/guide-links.t` asserts the home page links both list-host guides;
  they stay in the home page's Learn more, so it keeps passing.
- Slide 21's X-DKIM2-Info example says spec-06; the site shows a current one.
- Momentum MTA listed under supporting software (Bron named Stalwart; Momentum
  is the same kind of thing and the software Bird signs with). "Verifies"
  defined as "checks and records the result".
- `/implementations/` "other implementations" table gains Momentum MTA and
  the Stalwart playground link; `mail-auth` stays there as a library.
- Slide 8's "on track to become what the large mailbox providers require"
  is kept, worded as an expectation, not a fact.

## Left to the builder

Exact wording of the prose adapted from slides and notes; nav and diagram
styling within the existing palette; segment proportions; how the page
header looks on subpages.
