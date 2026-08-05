# DKIM2 Standalone Browser Verifier — Design

**Date:** 2026-07-18
**Status:** Approved (pending spec review)
**Spec basis:** draft-ietf-dkim-dkim2-spec-04
**Author:** brong + Claude

## Goal

A **new static page** where you paste a complete email and get a full DKIM2
validation breakdown that is computed **entirely in the browser** — no server
round-trip. Unlike the existing `/validate/` page (which POSTs to `/validate/api`,
a Perl CGI), this verifier does all parsing, canonicalization, hashing,
signature cryptography, chain-of-custody and Message-Instance undo in
client-side JavaScript. The only network access is DNS-over-HTTPS to fetch
signer public keys.

Both pages coexist: `/validate/` (server-backed) stays untouched, and the new
page (proposed path `/verify/`) sits beside it so the two can be compared.

## Non-goals / YAGNI

- No build step, bundler, framework, or third-party runtime dependency — plain
  static files and native ES modules, matching the rest of the site.
- No accounts, history, or persistence; nothing is stored or sent anywhere
  except the DoH key lookups.
- No SPF / DMARC / DKIM1 verification (DKIM2 + Message-Instance only, consistent
  with the project).
- No polyfill/bundling of a pure-JS Ed25519 fallback for legacy browsers; rely
  on WebCrypto and degrade gracefully with a clear message where unsupported.

## Spec basis

The verification core is written **fresh from
`spec/draft-ietf-dkim-dkim2-spec-04.txt`**, not ported from the C / Python /
Perl / Go implementations. Relevant sections:

- §3 algorithms (SHA256, RSA-SHA256, Ed25519-SHA256), §3.5 selectors, §3.6 keys
- §5 recipes (header / body), §6 message hash values (§6.1 body, §6.2 headers)
- §7 Message-Instance (`m=`, `r=`, `h=`)
- §8 DKIM2-Signature (`i=`, `m=`, `n=`, `t=`, `mf=`, `rt=`, `nd=`, `d=`, `s=`, `f=`)
- §9 signer actions (esp. §9.2/§9.3 chain of custody, §9.4 relaxed domain match,
  §9.6 signature calculation / signing input canonicalization)
- §10 verification requirements, §11 verifier actions (§11.1 output states,
  §11.2 validity, §11.3 timestamps, §11.4 chain-of-custody, §11.5 fetch key,
  §11.6 signature verification, §11.7 body/header hashes, §11.8 flags)

## Browser capabilities & constraints

- **SHA-256:** `crypto.subtle.digest('SHA-256', …)`. Universally available.
- **RSA-SHA256:** `crypto.subtle.importKey('spki', …, {name:'RSASSA-PKCS1-v1_5',
  hash:'SHA-256'})` + `verify`. Universally available.
- **Ed25519-SHA256:** `crypto.subtle.importKey('raw'/'spki', …, {name:'Ed25519'})`
  + `verify`. Available in current Chrome/Safari/Firefox; on browsers that lack
  it, `importKey`/`verify` throws → report a per-signature
  `ed25519 unsupported in this browser` notice (not a silent fail).
  Note §3.3: Ed25519 signs the SHA-256 hash value as its message, so the 32-byte
  hash is the input passed to `verify`.
- **DNS:** browsers cannot do raw DNS. Public keys are fetched via
  **DNS-over-HTTPS from Cloudflare** (`https://cloudflare-dns.com/dns-query`,
  `Accept: application/dns-json`), querying TXT at
  `selector._domainkey.domain`. A visible privacy note states that queried
  domains/selectors are sent to Cloudflare.

## Architecture

New directory `deploy/www/verify/` served as static files:

```
deploy/www/verify/
  index.html      two-column layout (mirrors /validate/), loads main.js as a module
  verify.css      styling (adapted from validate.css for visual consistency)
  parse.js        message + tag-value parsing
  canon.js        canonicalization + hashing input construction
  crypto.js       WebCrypto wrappers (sha256, rsa verify, ed25519 verify)
  doh.js          Cloudflare DoH TXT lookup + key-record parsing
  verify.js       §10/§11 orchestrator → report object
  report.js       DOM renderer (adapted from validate.js render())
  main.js         wiring: textarea, Validate button, example loader, privacy note
```

Native ES modules (`<script type="module" src="main.js">`); no bundling.

### Module responsibilities

- **`parse.js`**
  - `parseMessage(raw)` → `{ headers: [{name, rawName, value, raw}], body }`.
    Unfolds header fields, preserves raw bytes, splits on the first blank line;
    normalizes line endings to CRLF.
  - `parseTagList(value)` → ordered `[{tag, value, decoded?}]` plus a map.
    Preserves the raw tag string (needed because §8.5/§9.5 canonicalization keeps
    the trailing `;` — see c/INTEROP-NOTES.md item 1).
  - Collects `DKIM2-Signature` (by `i=`) and `Message-Instance` (by `m=`) levels.

- **`canon.js`**
  - `bodyHashInput(body, recipe)` (§6.1) and `headerHashInput(headers, …)`
    (§6.2): produce the exact byte sequences to hash.
  - `signingInput(sigTag, …)` (§9.6): the canonical bytes a DKIM2-Signature
    signs, including prior signatures for chain of custody (§9.2/§9.3);
    whitespace stripped, `;` retained (§8.5/§9.5).

- **`crypto.js`**
  - `sha256(bytes)` → base64/hex per spec.
  - `verifyRsa(spki, sig, msg)` / `verifyEd25519(pub, sig, hash)` → boolean,
    throwing a tagged error on unsupported-algorithm.

- **`doh.js`**
  - `fetchKey(selector, domain)` → `{ k, p, raw }` or a tagged failure
    (`notfound` / `temperror`). Parses the `_domainkey` TXT tag-value record
    (`k=`, `p=`; empty `p=` = revoked). Caches per `(selector,domain)` per run.

- **`verify.js`** — the orchestrator implementing §10/§11:
  - Walk from the top instance/signature **down** (highest `m`/`i` first).
  - At each step: verify current top MI header+body hashes against content
    (§10, §11.7); record the MI level; **undo** the MI recipe (§5, §7.2) to
    reconstruct the previous version; verify each signature `i` (§11.2–§11.6):
    validity, timestamps (§11.3), chain-of-custody (§11.4: `mf=`/`rt=`/`nd=`
    relaxed-domain match, §9.4), fetch key (§11.5, via `doh.js`), signature
    calculation (§11.6); record the signature level.
  - If an MI undo fails or hits a `null`/unrecoverable recipe, stop descending;
    mark remaining lower levels `not-checked` with a reason.
  - **Never throw:** every parse/crypto/DoH error becomes a recorded
    `fail` / `not-checked` / `temperror` with human-readable `detail`.
  - Returns a **report object** (shape below) consumed by `report.js`.

- **`report.js`** — renders the report object into the results pane. Adapted from
  the current `deploy/www/validate/validate.js` `render()` so the two pages look
  identical; the report object shape matches what that renderer already consumes.

- **`main.js`** — binds the Validate button to `verify.verifyMessage(textarea)`,
  renders via `report.js`, loads an example, shows the DoH privacy note, and
  surfaces a one-time WebCrypto-Ed25519 capability check.

## Report object shape (matches the existing renderer)

```
{
  overall: 'pass' | 'fail' | 'none' | 'temperror',
  summary: 'i=1..N verified; Message-Instance m=1..N intact',   // or error text
  levels: [ /* top-down, highest i / m first */ ]
}
```

Each `levels[]` entry (fields as consumed by `validate.js` `render()`):

```
# DKIM2-Signature level
{ kind: 'signature', i: 2, m: 1,
  tags: [{tag, label, value, decoded?}],                 // full parsed breakdown
  items: [{selector, algorithm, result}],                // crypto per s= value
  timestamp: {ok, status?, detail},                      // §11.3
  custody:   {ok, detail},                               // §11.4 (n/a for i=1)
  result: 'pass' | 'fail' | 'warn' | 'not-checked',
  detail: '' }

# Message-Instance level
{ kind: 'instance', m: 2,
  tags: [{tag, label, value, decoded?}],
  header_hash: 'match' | 'mismatch',
  body_hash:   'match' | 'mismatch',
  header_recipes: [{name, current, previous}],
  undo: 'clean' | 'failed' | 'unrecoverable' | 'n/a',
  result: 'pass' | 'fail' | 'warn' | 'not-checked',
  detail: '' }
```

`overall` = `pass` only if every reachable level passed; `none` if there are no
DKIM2-Signature headers; `temperror` if a key fetch was transiently
unavailable and no hard failure occurred; otherwise `fail`.

## Output states & error handling (§11.1)

- **pass / fail** — normal verified / broken results.
- **temperror** — DoH lookup transiently failed (network error, 5xx, SERVFAIL);
  consistent with the project's existing TEMPERROR treatment of transient DNS
  key-fetch failure.
- **permerror-style** — malformed headers, missing key (`p=` empty / NXDOMAIN),
  unsupported algorithm → recorded as `fail`/`not-checked` on the affected level
  with a clear `detail`.
- Ed25519-unsupported browser → per-signature `not-checked` with
  `ed25519 unsupported in this browser`.
- Input size cap (e.g. 256 KB) to bound work; oversize → a single error verdict.

## Testing

A **Node harness** (Node 18+ has `crypto.subtle` and global `fetch`) imports the
same ES modules and exercises the verification core without a browser:

- **Conformance / parity (offline):** run against the `dkim2tests` Turscar
  vectors (submodule) and repo `keys/`, using an injected `fetchKey` stub that
  serves keys from local key material — asserts per-level results match the
  reference verifiers. Covers: clean multi-hop chain (all `pass`, `undo=clean`);
  post-sign body tamper (top MI `body_hash=mismatch`, `overall=fail`); broken /
  missing signature; missing key; redacted `null` recipe
  (`undo=unrecoverable`, lower levels `not-checked`, `overall=pass`); no DKIM2
  at all (`overall=none`); `nd=` imaginary-hop chain; RSA and Ed25519 signatures.
- **Canonicalization units:** body-hash, header-hash, and signing-input byte
  sequences for known inputs (incl. trailing-semicolon case).
- **Live DoH smoke (optional, network):** verify a real `reflector-fresh` /
  `reflector-brand` reply fetched against Cloudflare DoH.

Test files live under `deploy/www/verify/tests/` (or a sibling `test/` dir)
runnable via `node`.

## Files

- Create: `deploy/www/verify/index.html`, `verify.css`, `main.js`, `parse.js`,
  `canon.js`, `crypto.js`, `doh.js`, `verify.js`, `report.js`
- Create: `deploy/www/verify/tests/*.mjs` (Node harness + fixtures)
- Modify: `deploy/www/index.html` — link the new verifier from "Learn more" /
  "Implementations & demo", noting it runs entirely in the browser
- Modify: `deploy/www/validate/index.html` — a cross-link to the standalone
  verifier (optional)
- Modify: deploy docs (`deploy/SERVER.md` or equivalent) — add the static
  `/verify/` location (static files only; no CGI, no new server component)

## Deployment

Per the full-change workflow: implement, then deploy the static files to the box
(nginx `location /verify/` → static dir, no dynamic backend), and acceptance-test
on prod by pasting a real reflector reply and confirming the client-side result
matches `/validate/`.

## Open questions

- Final page path: `/verify/` (assumed). Could be `/browser-validate/` or similar
  — cosmetic, decide at implementation.
- Whether to add a resolver-choice UI later (deferred; Cloudflare-only for now
  per the chosen DNS approach).
