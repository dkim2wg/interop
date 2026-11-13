# dkim2.com Site Split + Deployment Status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the one-page dkim2.com landing page into Home / Try it / Implementations, and add a Deployments page generated at deploy time from one JSON file per site.

**Architecture:** Plain static HTML under `deploy/www/`, one shared `style.css`, a hand-copied nav block on each page. `/deployments/index.html` is produced by a core-Perl script from `deploy/www/deployments/sites/*.json` + a template, run by `deploy.sh` straight into the web root (the repo never holds the generated file).

**Tech Stack:** HTML/CSS, Perl 5 with core modules only (`JSON::PP`, `File::Basename`, `Getopt::Long`), `prove`, nginx `try_files $uri $uri/`.

**Spec:** `docs/superpowers/specs/2026-11-13-website-split-design.md`

## Global Constraints

- Existing section text moves verbatim; no content rewrite beyond intros/nav.
- Old anchor ids stay on the new pages: `reflector-signing`, `originate`, `reflector-brand`, `reflector-brand-nd`, `bounces`, `other-implementations`.
- Site file keys: exactly `name, url, kind, signs, verifies, since, notes`; required `name, url, kind, signs, verifies`; `since` = `YYYY-MM`, optional; `notes` optional.
- Builder script uses core Perl modules only; non-zero exit on any invalid site file.
- No client-side JS on `/deployments/`.
- Nav order: Home · Try it · Implementations · Deployments · Validate · Verify.

## Review Focus

- A site name/notes containing `<`, `&` or `"` — expect it HTML-escaped in the page, never raw markup (test in Task 2).
- A `url` that isn't `https://…` (e.g. `javascript:`) — expect rejection with the filename in the error (test in Task 2).
- A file not named `[a-z0-9-]+.json` (e.g. `Fastmail.JSON`, `notes.txt`, editor backup `fastmail.json~`) — expect `.json` files with bad names rejected, non-`.json` files ignored (test in Task 2).
- An entry with no `since` — expect it sorted after all dated entries, cell shows "—" (test in Task 2).
- An internal link left pointing at an anchor that moved (e.g. `/#originate` text inside `/try/` or `href="#bounces"` on the home page) — expect every internal `href` to resolve (link test in Task 1).

---

### Task 1: Split the landing page into three pages with shared nav

**Files:**
- Modify: `deploy/www/index.html` (keep hero, Status, "What DKIM can't tell you", "How DKIM2 fixes it", Learn more)
- Create: `deploy/www/try/index.html` (sections: Try it: reflector addresses incl. both h3s + both tables, `#originate`, `#bounces`)
- Create: `deploy/www/implementations/index.html` (sections: Implementations & demo, `#other-implementations`)
- Modify: `deploy/www/style.css` (add `nav.site` styles)
- Test: `deploy/t/www-links.t`

**Interfaces:**
- Produces: nav markup used verbatim by every page (Task 2's template copies it, with `aria-current` moved):
  ```html
  <nav class="site"><a href="/">Home</a> <a href="/try/">Try it</a> <a href="/implementations/">Implementations</a> <a href="/deployments/">Deployments</a> <a href="/validate/">Validate</a> <a href="/verify/">Verify</a></nav>
  ```
  The current page's link gets `aria-current="page"`. Subpages link the stylesheet as `/style.css` (absolute). Each subpage has a compact header (`<header class="hero">` with `<h1>` page title, no tagline/badge) and the same footer.
- Produces: `deploy/t/www-links.t` — Task 2 relies on it to check the deployments template.

- [ ] **Step 1: Write the failing link test `deploy/t/www-links.t`**

  For each of `deploy/www/index.html`, `try/index.html`, `implementations/index.html`, and `deployments/index.html.in` if it exists: extract every `href="..."` and every `id="..."`. Assertions:
  - each page contains the exact nav `<nav class="site">` and exactly one `aria-current="page"`;
  - every `href` starting with `/` (not `/validate/`, `/verify/`, `/deployments/` which other tasks own, nor `/style.css`) maps to an existing file: `/` → `index.html`, `/x/` → `x/index.html`; with `#frag`, that target file contains `id="frag"`;
  - every `href="#frag"` exists as `id="frag"` in the same file;
  - the six preserved ids each appear on exactly one page: `originate`, `bounces`, `reflector-signing`, `reflector-brand`, `reflector-brand-nd` in `try/`; `other-implementations` in `implementations/`;
  - `index.html` contains a `<script>` that maps those six ids (assert each id string appears in the script).

- [ ] **Step 2: Run to verify it fails**

  Run: `prove deploy/t/www-links.t`
  Expected: FAIL (no `try/index.html`, no nav).

- [ ] **Step 3: Move the sections and add the nav**

  Cut sections verbatim into the new pages. Rewrite moved-anchor links: in `try/` the "(Originate a new message)"/"(Bounces …)" links stay `#originate`/`#bounces` (same page); any link from the home page to them becomes `/try/#…`. "Learn more" on home gains `/implementations/` and `/deployments/` items. Footer unchanged.

  Old-anchor redirect at the end of `index.html`'s body:
  ```html
  <script>
  (function () {
    var m = { "originate": "/try/", "bounces": "/try/", "reflector-signing": "/try/",
              "reflector-brand": "/try/", "reflector-brand-nd": "/try/",
              "other-implementations": "/implementations/" };
    var h = location.hash.slice(1);
    if (m[h]) location.replace(m[h] + "#" + h);
  })();
  </script>
  ```
  CSS: `nav.site` sits above the header at the 46rem column, links spaced with gap, wraps on narrow screens, `[aria-current=page]` bold and not underlined; use existing `--accent`/`--rule`/`--muted` tokens.

- [ ] **Step 4: Run to verify it passes**

  Run: `prove deploy/t/www-links.t`
  Expected: PASS. Also open each page via `cd deploy/www && python3 -m http.server 8099` and check `http://localhost:8099/#originate` lands on `/try/#originate`.

- [ ] **Step 5: Commit**

  ```bash
  git add deploy/www/index.html deploy/www/try deploy/www/implementations deploy/www/style.css deploy/t/www-links.t
  git commit -m "www: split the landing page into Home / Try it / Implementations"
  ```

### Task 2: Deployment status builder, template and first site files

**Files:**
- Create: `deploy/bin/build-deployments.pl`
- Create: `deploy/www/deployments/index.html.in`
- Create: `deploy/www/deployments/sites/fastmail.json`, `1and1.json`, `squarespace.json`
- Create: `deploy/www/deployments/README.md` (how to add a site: copy a file, field meanings)
- Test: `deploy/t/build-deployments.t` (fixtures written to a tempdir inside the test)

**Interfaces:**
- Consumes: nav markup from Task 1 (with `aria-current` on Deployments); `deploy/t/www-links.t` extended to include `deployments/index.html.in`.
- Produces: CLI used by Task 3:
  - `build-deployments.pl --sites DIR --template FILE --out FILE` → writes page, exit 0; on any error prints `FILE: message` lines to stderr, writes nothing, exit 1.
  - `build-deployments.pl --sites DIR --check` → validate only, same errors/exit codes.
  - Template contains the literal marker `<!-- DEPLOYMENTS -->`, replaced by the `<table>`; and `<!-- COUNT -->` replaced by the number of entries.

- [ ] **Step 1: Write the failing test `deploy/t/build-deployments.t`**

  Helper writes given files into a `File::Temp` dir and runs the script via `system $^X, ...`, capturing stderr. Tests:
  - `valid_builds`: two sites (one with `since` `2026-11`, one `2026-09`) + one without `since` → exit 0; output contains rows in order 2026-09, 2026-11, undated; undated row shows `—`; `signs:true` renders `✓`, `false` renders empty cell; name cell links to `url`; `<!-- COUNT -->` replaced with `3`.
  - `escapes_html`: name `A&B <x>` and notes `"q"` → output contains `A&amp;B &lt;x&gt;` and `&quot;q&quot;`, not `<x>`.
  - `rejects_*`, each → exit 1, stderr names the file, `--out` file not created: unknown key `foo`; missing `kind`; `signs` as `"yes"`; `since` `2026-11-11`; `since` `2026-13`; `url` `javascript:alert(1)`; `url` `http://x` (https only); invalid JSON; filename `Fastmail.json`.
  - `ignores_non_json`: `notes.txt` and `fastmail.json~` present alongside a valid file → exit 0.
  - `check_mode`: `--check` on the repo's real `deploy/www/deployments/sites` → exit 0.

- [ ] **Step 2: Run to verify it fails**

  Run: `prove deploy/t/build-deployments.t`
  Expected: FAIL (script missing).

- [ ] **Step 3: Implement `deploy/bin/build-deployments.pl`**

  `use strict; use warnings; use utf8;` JSON decoded with `JSON::PP->new->utf8` (booleans must be `JSON::PP::Boolean`). Collect all errors before exiting. Sort: dated entries by `since` ascending, ties by `lc name`; undated after, by `lc name`. Columns: Site · Type (`kind`) · Signs · Verifies · Since · Notes. Write output to `$out.tmp` then rename, so a failed run never leaves a partial page.

  Template: page shell per Task 1 (title "Deployment status", nav, header), one intro paragraph ("Who runs DKIM2 on real mail today. <!-- COUNT --> sites listed."), `<!-- DEPLOYMENTS -->`, then: "Running DKIM2 in production? Open a pull request adding `deploy/www/deployments/sites/<you>.json` (copy an existing one) at <a href="https://github.com/dkim2wg/interop">github.com/dkim2wg/interop</a>, or tell us there." 

  Site files:
  - `fastmail.json`: `{"name":"Fastmail","url":"https://www.fastmail.com/","kind":"mailbox provider","signs":true,"verifies":true,"since":"2026-09"}`
  - `1and1.json`: `{"name":"1&1","url":"https://www.1und1.de/","kind":"mailbox provider","signs":true,"verifies":true,"since":"2026-11"}`
  - `squarespace.json`: `{"name":"Squarespace","url":"https://www.squarespace.com/","kind":"sender platform","signs":true,"verifies":false,"since":"2026-11"}`

- [ ] **Step 4: Run to verify it passes**

  Run: `prove deploy/t/build-deployments.t deploy/t/www-links.t`
  Expected: PASS. Then `perl deploy/bin/build-deployments.pl --sites deploy/www/deployments/sites --template deploy/www/deployments/index.html.in --out /tmp/dep.html` and eyeball: three rows, Fastmail first, 1&1 escaped as `1&amp;1`.

- [ ] **Step 5: Commit**

  ```bash
  git add deploy/bin/build-deployments.pl deploy/www/deployments deploy/t/build-deployments.t deploy/t/www-links.t
  git commit -m "www: deployment status page built from one JSON file per site"
  ```

### Task 3: Deploy wiring, tool-page links, docs, live deploy

**Files:**
- Modify: `deploy/deploy.sh:84-100` (static web assets block)
- Modify: `deploy/www/validate/index.html:15`, `deploy/www/verify/index.html` (the "About DKIM2 · …" line)
- Modify: `deploy/SERVER.md` / `deploy/README.md` wherever the web root contents are listed

**Interfaces:**
- Consumes: Task 2 CLI; Task 1 page paths.

- [ ] **Step 1: Wire `deploy.sh`**

  In the `/var/www/dkim2.com` block, before installing anything: `prove deploy/t/www-links.t deploy/t/build-deployments.t` (under `set -e`, a failure stops the deploy). Then install `try/index.html` and `implementations/index.html` into matching dirs (`install -d -m 755`), and run
  `perl deploy/bin/build-deployments.pl --sites deploy/www/deployments/sites --template deploy/www/deployments/index.html.in --out /var/www/dkim2.com/deployments/index.html` after `install -d -m 755 /var/www/dkim2.com/deployments`. Update the block's comment to mention the generated page.

- [ ] **Step 2: Tool-page links**

  Change the validator/verifier header lines to `<a href="/">About DKIM2</a> · <a href="/try/">Try it</a> · <a href="/deployments/">Deployments</a> · <a href="/verify/">browser verifier</a>` (validator) and the equivalent with `server validator` (verifier). Layout otherwise unchanged.

- [ ] **Step 3: Docs**

  `grep -n "dkim2.com/\|www/" deploy/SERVER.md deploy/README.md` and update any description of the web root to list `try/`, `implementations/`, `deployments/` (generated). Note in `deploy/README.md` how to add a deployment entry (pointer to `deploy/www/deployments/README.md`).

- [ ] **Step 4: Verify locally, commit**

  Run: `bash -n deploy/deploy.sh && prove deploy/t/`
  Expected: syntax OK, all PASS.
  ```bash
  git add deploy/deploy.sh deploy/www/validate/index.html deploy/www/verify/index.html deploy/SERVER.md deploy/README.md
  git commit -m "deploy: install the split site and build the deployments page"
  ```

- [ ] **Step 5: Merge and deploy (with Bron)**

  Merge locally to master, push, then `ssh dkim2 'cd /root/interop && git pull --ff-only && deploy/deploy.sh'` (needs Bron's ssh approval). Acceptance on prod: `curl -s https://dkim2.com/deployments/ | grep -c '<tr>'` → 4 (header + 3); `curl -sI https://dkim2.com/try/` and `/implementations/` → 200; open `https://dkim2.com/#originate` in a browser → lands on `/try/#originate`.
