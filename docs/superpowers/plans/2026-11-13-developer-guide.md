# dkim2.com Developer Guide Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `/developers/` to the rebuilt dkim2.com: advice for building a signer and a validator, and a section on the single-pass Message-Instance verification algorithm.

**Architecture:** One more static page in the existing site (`deploy/www/developers/index.html`), same shell, relative links, shared `nav.css`/`style.css`; a "Developers" nav item on every page; diagram in HTML + CSS; staged by `deploy/bin/stage-www.sh`.

**Tech Stack:** HTML/CSS, Perl `prove` tests (`deploy/t/`).

**Spec:** `docs/superpowers/specs/2026-11-13-developer-guide-design.md`

## Global Constraints

- Nav on every page becomes: DKIM2 (brand) · How it works · Get ready · Try it · Implementations · **Developers** · Deployments · Verify — `developers/` between `implementations/` and `deployments/`.
- -09 is the reference. Recipe size is a recommendation: "about 100 literal lines". Null Recipe = PERMERROR under -09; "allowed when the hop also changes the From" is labelled as being worked on. `f=exploded` exactly per -09 §12.5 (copies to more than one address, even if they differ; never on `i=1`).
- Our implementations' 1000-line cap is not mentioned as a recommendation and not changed.
- No `canmodify`. All links relative except external `https:`.

## Review Focus

- A reader taking the Recipe-size or null-Recipe text as spec — both must carry "recommendation"/"proposal" wording (Task 1 content asserts).
- The algorithm section wrong about an edge a porter will hit: trailing blank lines, copy ranges reaching past the body end, instances sharing digests — each named in the prose (Task 1 asserts the terms).
- The diagram unreadable at 400px — screenshot (Task 1).
- Nav change missed on a page — `www-links.t` checks every page (Task 1).

---

### Task 1: `/developers/` page, nav item, tests

**Files:**
- Create: `deploy/www/developers/index.html`
- Modify: every page's nav (`index.html`, `how/`, `get-ready/`, `try/`, `implementations/`, `deployments/index.html.in`, `verify/`, `validate/`), `deploy/www/style.css` (`.plan` diagram), `deploy/bin/stage-www.sh` (add `developers` to the page loop), `deploy/t/www-links.t` (`@pages`, `@SITE_LINKS`, `%CURRENT`), `deploy/t/www-content.t` (subtest `developers`)

**Interfaces:**
- Produces: section ids `start signer validator one-pass testing` (Task 2 links `#one-pass`).

- [ ] **Step 1: Tests.** `www-links.t`: add `developers/index.html` to `@pages`, `['developers/' => 'Developers']` after implementations in `@SITE_LINKS`, `%CURRENT{'developers/index.html'} = 'developers/'`. `www-content.t` subtest `developers`: ids `start signer validator one-pass testing` present; links to `https://github.com/dkim2wg/interop/blob/master/docs/dkim2-implementer-guide.md`, `https://forge.turscar.ie/turscar/dkim2tests`, `../verify/`, `../try/`; `#signer` text matches `about 100` and `recommend`, `null Recipe`, `PERMERROR`, `From`, `more than one address`, `i=1`; `#signer` does not match `1000`; `#validator` names `PASS`, `PERMERROR`, `TEMPFAIL`, `NONE`, `14 days`, `Domain Policy Record`, `Authentication-Results`; `#one-pass` has a `<figure class="plan">` and its text names `segment`, `trailing blank`, `ascend`, `share`, `prefetch`, `undo walk`, and each of `perl/lib/Mail/DKIM2/BodyPlan.pm`, `go/dkim2/plan.go`, `c/dkim2_plan.c`, `python/dkim2plan.py`, `deploy/www/verify/plan.js`; a `<pre>` pseudo-code block in `#one-pass`.
- [ ] **Step 2: Run** `prove deploy/t/` — Expected: FAIL (page missing, navs lack Developers).
- [ ] **Step 3: Write the page + nav + CSS + stage loop.** Content per spec §Design 1–5. Diagram `<figure class="plan">`: three rows (m=3 current body, m=2, m=1), each a horizontal strip of segment boxes — current-body line runs in teal, literals in amber — e.g. m=3 `[lines 1–40]`; m=2 (Recipe `[[1,2],"Subject…",[4,38]]`-style example) `[1–2][lit A][4–38]`; m=1 `[1–2][lit A][4–20][lit B]`; caption explaining one read feeds all three. Stacks/wraps at 400px. Pseudo-code ≈20 lines: build lists top-down via compose(parent_list, parent_recipe); group equal lists; stream lines: for each group emit lines in its current segment, literals when reached, blank lines into `pending`, flush pending before a non-blank line, drop at end.
- [ ] **Step 4: Run** `prove deploy/t/ perl/t/guide-links.t` — Expected: PASS. Stage and screenshot `/developers/#one-pass` at 1200px and 400px; look at both.
- [ ] **Step 5: Commit** `www: developer guide`.

### Task 2: Implementer-guide links, preview

**Files:**
- Modify: `docs/dkim2-implementer-guide.md` (intro: link to `https://dkim2.com/developers/`; the "Streaming:" line in the Go section → points to `https://dkim2.com/developers/#one-pass`)

- [ ] **Step 1:** Edit the guide; `grep -c "dkim2.com/developers" docs/dkim2-implementer-guide.md` → ≥ 2.
- [ ] **Step 2:** `prove deploy/t/ perl/t/guide-links.t` → PASS; commit `docs: implementer guide links the developer page`.
- [ ] **Step 3:** Stage + rsync to `/preview/` (as before); `curl` → 200 for `/preview/developers/`; every page's nav contains `developers/`. **Stop for Bron's review.**
