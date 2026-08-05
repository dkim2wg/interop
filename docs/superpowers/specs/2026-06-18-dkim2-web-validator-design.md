# DKIM2 Web Validator — Design

**Date:** 2026-06-18
**Status:** Approved (pending spec review)
**Spec basis:** draft-ietf-dkim-dkim2-spec-02
**Author:** brong + Claude

## Goal

A web form at `https://dkim2.com/validate/` where you paste an entire email and
get a full validation breakdown: the DKIM2-Signature check at each chain level
and the Message-Instance check at each level, including the undo of each MI back
to the previous version. Two-column layout: paste text on the left, outcome on
the right.

## Architecture

- **Static page** `https://dkim2.com/validate/` — two-column HTML/CSS plus a
  small `validate.js`. Left: a monospace `<textarea>`, a "Validate" button, and
  a "load example" link. Right: a results pane.
- **JSON API** `POST https://dkim2.com/validate/api` — the JS posts the pasted
  message as raw `text/plain`; the endpoint returns a JSON breakdown; the JS
  renders the right column from it. The API is independently usable.
- **Serving (nginx on dkim2.com):**
  - `location /validate/` → static files under `/var/www/dkim2.com/validate/`.
  - `location = /validate/api` → `fastcgi_pass` to **fcgiwrap** running the CGI
    `brong/bin/validate.cgi` (deployed to a fixed path).
- **Reporter module** `Mail::DKIM2::Validate` — walks the chain top-down (the
  `brong/bin/validate.pl` algorithm: interleave MI-verify+undo with per-signature
  verification) but **collects every level's outcome and keeps going**, returning
  structured data. Uses **live DNS** for public-key lookup of whatever domains
  appear in the message (`dns.json` override for the interop test domains, then
  `Signature->fetch_public_key` real-DNS fallback — same pattern as the milter
  and reflector).

This is the first server-side dynamic component on the apex (the landing page is
static). It is read-only: it parses text and does read-only DNS TXT lookups.

## Reporter API

`Mail::DKIM2::Validate::report($message_text, %opts) -> \%result`

`%opts`: `pubkey_cb` (optional, for tests), `skip_timestamp_check` (optional).

Returned structure:

```
{
  overall  => 'pass' | 'fail' | 'none',   # none = no DKIM2-Signature at all
  summary  => 'i=1..N verified; Message-Instance m=1..N intact',  # or error text
  counts   => { signatures => N, instances => M },
  levels   => [ ... top-down (highest i / m first) ... ],
}
```

Each `levels[]` entry is one of:

```
# DKIM2-Signature level
{ kind => 'signature', i => 2, m => 1, domain => 'dkim2.com',
  items => [ { selector => 'sel1', algorithm => 'rsa-sha256', result => 'pass' } ],
  timestamp => { ok => 1, detail => '' },      # §10.3 age/future
  custody   => { ok => 1, detail => '' },       # §8.2 mf/rt domain match (undef for i=1)
  result => 'pass' | 'fail' | 'not-checked',
  detail => '' }

# Message-Instance level
{ kind => 'mi', m => 2,
  header_hash => 'match' | 'mismatch',
  body_hash   => 'match' | 'mismatch',
  recipe => 'diff' | 'null' | 'none',           # null = unrecoverable (§4.2)
  undo   => 'clean' | 'failed' | 'unrecoverable' | 'n/a',  # n/a for m=1
  result => 'pass' | 'fail' | 'not-checked',
  detail => '' }
```

Behaviour:
- Walk from the top instance/signature down. At each step verify the current top
  MI hashes against content (§10.7), record the MI level, then undo to the
  previous version; verify each signature `i` and record its level.
- If an MI undo fails or hits a `null`/unrecoverable recipe, stop descending and
  mark remaining lower levels `not-checked` (with a reason in `summary`).
- Never die: every parse/verify/DNS error becomes a recorded `fail`/`not-checked`
  with a human-readable `detail`.
- `overall` = `pass` only if every reachable level passed; `none` if there are no
  DKIM2-Signature headers; otherwise `fail`.

## CGI (`brong/bin/validate.cgi`)

- Reads the POST body (raw message). Enforces a size cap (256 KB); over-limit →
  JSON error.
- Normalises line endings to CRLF, calls `Mail::DKIM2::Validate::report`.
- Emits `Content-Type: application/json` with the structure above. Always returns
  HTTP 200 with a JSON body (errors are represented inside the JSON), except a
  413-style JSON error for oversize input.
- No shell execution; DNS lookups are read-only and time-boxed (resolver timeout).

## Front-end

- `deploy/www/validate/index.html` — two-column layout (CSS grid), shared visual
  style with the landing page (reuse `../style.css` conventions; a small
  `validate.css` for the two-column + result cards). Left column: `<textarea>` +
  Validate button + "load example" (fills a known signed sample). Right column:
  a verdict banner (green `pass` / red `fail` / grey `none`) then one card per
  level in chain order, color-coded, showing the fields above.
- `deploy/www/validate/validate.js` — on Validate: `fetch('/validate/api', {method:'POST', body:text})`,
  render JSON into the right column; show parse/HTTP errors inline. Small,
  dependency-free vanilla JS.
- Responsive: columns stack on narrow viewports.
- A link to `/validate/` is added to the landing page's "Implementations & demo"
  or "Learn more" section.

## Safety / limits

- nginx `client_max_body_size` on the API location (e.g. 512k) + CGI 256 KB cap.
- Optional nginx `limit_req` on `/validate/api` to bound abuse.
- The endpoint performs **live DNS TXT lookups** for the selectors/domains in the
  pasted message — expected and necessary; resolver timeouts bound latency.
- Pure text parsing; no code execution, no message is stored or sent anywhere.

## Files

- Create: `brong/lib/Mail/DKIM2/Validate.pm` (reporter)
- Create: `brong/bin/validate.cgi` (POST → JSON)
- Create: `brong/t/validate-report.t` (unit tests)
- Create: `deploy/www/validate/index.html`, `validate.js`, `validate.css`
- Modify: `deploy/www/index.html` (link to the validator)
- Modify: `deploy/SERVER.md` (fcgiwrap + nginx location + deploy steps)
- Server (documented, applied at deploy): install `fcgiwrap`; nginx vhost
  locations for `/validate/` and `/validate/api`; deploy the CGI + static files.

## Testing

**Unit (`brong/t/validate-report.t`, no real mail; `pubkey_cb` + `skip_timestamp_check`):**
build inputs with the test keys and assert the structured `levels`:
- valid multi-hop chain → `overall=pass`, every level `pass`, MI `undo=clean`.
- post-sign body tamper → top MI `body_hash=mismatch`, `overall=fail`.
- broken/missing signature (gap) → that signature level `fail`.
- missing DNS key → signature item `result=fail` with a key-not-found detail.
- redacted null recipe → top MI `recipe=null`, `undo=unrecoverable`, lower
  levels `not-checked`, `overall=pass` (current content verified).
- no DKIM2 at all → `overall=none`.

**CGI:** posting a sample returns valid JSON matching the schema (compile + a
piped-body smoke test).

**Server e2e:** `curl --data-binary @signed.eml https://dkim2.com/validate/api`
returns the expected JSON; the page loads and renders.

## Out of scope

- Accounts, history, persistence (nothing is stored).
- Verifying SPF/DKIM1 (DKIM2 + MI only, consistent with the rest of the project).
- Showing reconstructed message bytes per undo (chosen "Detailed per level", not
  the bytes-per-undo variant) — could be added later.
