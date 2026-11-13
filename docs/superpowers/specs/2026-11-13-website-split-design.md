# dkim2.com: split the landing page + add a deployment status page

## Intent

The landing page (`deploy/www/index.html`, 416 lines) is one long scroll.
Split it into a few logically grouped pages with shared navigation, and add a
**Deployment status** page showing who runs DKIM2 for real — currently Fastmail
and 1&1 (sign + verify) and senders including Squarespace — that is easy to
extend as more sites come on.

Non-goals: no backend, no self-serve submission form, no auto-detection from
reflector traffic. No content rewrite beyond what the split needs.
Anti-goal: breaking links people already have (`/#originate`, `/#bounces`,
`/#reflector-brand`, `/#other-implementations`, …).

## Approaches considered

1. **Data in the repo, rendered into the page** — *chosen.* One JSON file per
   site (Bron: fewer PR clashes than a single file); sites ask to be added by
   PR or email; we stay in control of public claims.
2. Self-serve web form — needs a backend and moderation.
3. Auto-detect from DKIM2 mail reaching the reflectors — sees senders only,
   never verifiers.

## Design

Pages (plain static HTML, directory-style clean URLs, one shared `style.css`,
a nav bar on every page — Home · Try it · Implementations · Deployments ·
Validate · Verify):

| URL | Content (moved verbatim from today's page) |
|---|---|
| `/` | hero, status, what DKIM can't tell you, how DKIM2 fixes it, learn more |
| `/try/` | reflector addresses, when the reply is signed, headers table, originate, bounces |
| `/implementations/` | our four impls + demo lists, other implementations table |
| `/deployments/` | new: deployment status table |

**Old anchors:** a few lines of JS on `/` map the old fragments
(`#originate`, `#bounces`, `#reflector-*`, `#other-implementations`, …) to the
same anchor on the new page and redirect. Anchor ids are kept on the new pages.

**Deployment data:** one file per site, `deploy/www/deployments/sites/<slug>.json`,
so PRs adding different sites never touch the same file. Each is
`{name, url, kind, signs, verifies, since, notes}` where `kind` is e.g.
"mailbox provider" / "sender platform", `since` is `YYYY-MM`
(optional), `notes` optional.

A browser can't list a directory, so the page is **generated at deploy time**:
a small Perl script (`deploy/bin/build-deployments.pl`, core `JSON::PP` only)
reads every `sites/*.json`, validates the fields (unknown key, missing
name/url/kind, non-boolean signs/verifies, bad date → non-zero exit, so a
broken PR fails `deploy.sh` loudly rather than publishing a half page), sorts
by `since` then name, and fills a table into
`deployments/index.html.in` → `index.html`. No client-side JS. Signs/Verifies
are ✓ columns. The page ends with "Running DKIM2 in production? Open a PR
adding `sites/<you>.json` (copy an existing one), or email us." The script also
runs in the repo's test suite (a `--check` mode) so a PR's file is validated
before merge.

Initial entries: Fastmail (mailbox provider, signs + verifies, since 2026-09),
1&1 (mailbox provider, signs + verifies, since 2026-11), Squarespace
(sender platform, signs, since 2026-11).

**Deploy:** `deploy.sh` installs the new directories alongside `validate/`
and `verify/`; the validator/verifier pages get a link back into the nav
(their own layout unchanged).

## Left to the builder

Exact nav styling (match the existing palette in `style.css`), wording of the
short intro on each page, and the redirect map's full anchor list.
