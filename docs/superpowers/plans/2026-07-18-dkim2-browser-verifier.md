# DKIM2 Standalone Browser Verifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new static web page that verifies a pasted DKIM2 message entirely in the browser — parse, canonicalize, hash, RSA/Ed25519 signature crypto, chain-of-custody, and Message-Instance undo — fetching public keys over Cloudflare DNS-over-HTTPS.

**Architecture:** Native ES modules under `deploy/www/verify/`, no build step or runtime dependencies. A pure verification core (`parse` → `canon` → `crypto`/`doh` → `verify`) produces a report object; a DOM renderer (`report`) and page wiring (`main`) present it. The core is importable in Node 20+ (which has global `crypto.subtle`, `fetch`, `atob`/`btoa`, `TextEncoder`) so a `node --test` harness runs it headless against the `dkim2tests` conformance vectors with an injected key resolver.

**Tech Stack:** Vanilla JavaScript (ES modules), WebCrypto SubtleCrypto (SHA-256, RSASSA-PKCS1-v1_5, Ed25519), Cloudflare DoH JSON API, Node's built-in `node:test`/`node:assert` for tests.

## Global Constraints

- **Spec basis:** `spec/draft-ietf-dkim-dkim2-spec-04.txt`. Build the verification core **fresh from the spec**, not ported from the C/Python/Perl/Go implementations in this repo.
- **No runtime dependencies, no bundler, no framework.** Plain static files served as-is; browser loads `main.js` as `<script type="module">`.
- **No third-party test dependencies.** Use `node:test` and `node:assert/strict` only. Requires **Node 20+**.
- **Line endings:** all canonical/hash/signing byte sequences use CRLF (`\r\n`).
- **Unsigned headers (§4), ignored everywhere in hashing:** header-name matches (case-insensitive) `Received`, `Return-Path`, `Delivered-To`, `DKIM-Signature`, any name starting `ARC-`, `Authentication-Results`, any name starting `X-`. Additionally `Message-Instance` and `DKIM2-Signature` are ignored in the header-fields hash (§6.2) but ARE included in the signing input (§9.6).
- **Algorithms:** support `rsa-sha256` and `ed25519-sha256`. Ed25519 signs the SHA-256 hash of the signing input as its message (§3.3): pass the 32-byte digest to Ed25519 verify. RSA-SHA256 uses RSASSA-PKCS1-v1_5 with internal SHA-256: pass the signing-input bytes to verify. Unknown algorithms are ignored (§3.4), not failed.
- **Output states (§11.1):** `pass`, `fail`, `permerror`, `temperror`; plus `none` when there is no DKIM2-Signature at all. Report `overall` uses these lowercase strings.
- **Page path:** `deploy/www/verify/` served at `/verify/`.
- **Report object shape:** must match what `deploy/www/validate/validate.js` `render()` consumes (see Task 8); the new renderer is adapted from it.

---

## File Structure

```
deploy/www/verify/
  index.html            two-column page, loads main.js as a module
  verify.css            styling (adapted from ../validate/validate.css)
  b64.js                base64 <-> bytes/string helpers
  parse.js              RFC5322 message + tag-value parsing, level collection
  canon.js              §6.1/§6.2/§9.6 canonicalization (pure; no crypto)
  crypto.js             WebCrypto wrappers: sha256, verifyRsa, verifyEd25519
  doh.js                key-record parsing + Cloudflare DoH TXT lookup
  recipes.js            §5/§7.2 recipe apply (undo) for headers and body
  verify.js             §10/§11 orchestrator -> report object
  report.js             DOM renderer (browser only)
  main.js               page wiring (browser only)
  tests/
    toml.mjs            minimal TOML reader for the fixture subset (test-only)
    toml.test.mjs
    b64.test.mjs
    parse.test.mjs
    canon.test.mjs
    crypto.test.mjs
    doh.test.mjs
    recipes.test.mjs
    verify.test.mjs
    vectors.test.mjs    conformance runner over ../../../../dkim2tests
```

Non-code changes:
```
deploy/www/index.html          add a link to /verify/
deploy/www/validate/index.html add a cross-link to /verify/
deploy/SERVER.md (or equiv)    document the static /verify/ nginx location
```

---

## Task 1: Scaffolding, base64 helpers, and Node test harness

**Files:**
- Create: `deploy/www/verify/b64.js`
- Test: `deploy/www/verify/tests/b64.test.mjs`

**Interfaces:**
- Produces: `b64ToBytes(s) -> Uint8Array`, `bytesToB64(u8) -> string`, `b64ToString(s) -> string` (decodes base64 to a UTF-8 string), `stringToBytes(s) -> Uint8Array` (UTF-8), `bytesToString(u8) -> string`. All used by later tasks.

- [ ] **Step 1: Write the failing test**

`deploy/www/verify/tests/b64.test.mjs`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { b64ToBytes, bytesToB64, b64ToString, stringToBytes, bytesToString } from '../b64.js';

test('bytesToB64 round-trips b64ToBytes', () => {
  const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
  assert.equal(bytesToB64(bytes), 'AAEC/f7/');
  assert.deepEqual(b64ToBytes('AAEC/f7/'), bytes);
});

test('b64ToString decodes base64 of a reverse-path', () => {
  // base64('<sender@test.dkim2.eu>')
  assert.equal(b64ToString('PHNlbmRlckB0ZXN0LmRraW0yLmV1Pg=='), '<sender@test.dkim2.eu>');
});

test('stringToBytes/bytesToString round-trip UTF-8', () => {
  const s = 'Subject: héllo';
  assert.equal(bytesToString(stringToBytes(s)), s);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test deploy/www/verify/tests/b64.test.mjs`
Expected: FAIL — `Cannot find module '../b64.js'`.

- [ ] **Step 3: Write minimal implementation**

`deploy/www/verify/b64.js`:
```js
// Base64 and UTF-8 conversion helpers. Works in browsers and Node 20+
// (both provide global atob/btoa, TextEncoder, TextDecoder).
const enc = new TextEncoder();
const dec = new TextDecoder();

export function stringToBytes(s) { return enc.encode(s); }
export function bytesToString(u8) { return dec.decode(u8); }

export function b64ToBytes(s) {
  const bin = atob(s.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64(u8) {
  let bin = '';
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

export function b64ToString(s) { return bytesToString(b64ToBytes(s)); }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test deploy/www/verify/tests/b64.test.mjs`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add deploy/www/verify/b64.js deploy/www/verify/tests/b64.test.mjs
git commit -m "verify: base64/utf8 helpers + node:test harness"
```

---

## Task 2: Minimal TOML reader for fixtures (test-only)

The `dkim2tests` vectors are TOML. Node has no TOML parser and we allow no deps, so write a tiny reader covering exactly the fixture subset: `Key = 'single'`, `Key = """triple\r\nmultiline"""`, `Key = ['a', 'b']`, and `[Table]` sections with `'quoted.key' = 'value'`. This is test-only code.

**Files:**
- Create: `deploy/www/verify/tests/toml.mjs`
- Test: `deploy/www/verify/tests/toml.test.mjs`

**Interfaces:**
- Produces: `parseToml(text) -> object`. Top-level scalar/array keys become properties; `[Table]` sections become nested objects keyed by table name.

- [ ] **Step 1: Write the failing test**

`deploy/www/verify/tests/toml.test.mjs`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseToml } from './toml.mjs';

test('parses scalars, arrays, multiline, and tables', () => {
  const t = parseToml([
    "Name = 'algorithm_with_future'",
    'ExpectedState = \'pass\'',
    "RcptTo = ['<recipient@example.com>']",
    'ExpectedFlags = []',
    'SignedMessage = """',
    'Message-Instance: m=1\r',
    'From: a@b\r',
    '"""',
    '',
    '[DNS]',
    "'ed25519._domainkey.test.dkim2.eu' = 'v=DKIM1; k=ed25519; p=abc'",
  ].join('\n'));
  assert.equal(t.Name, 'algorithm_with_future');
  assert.equal(t.ExpectedState, 'pass');
  assert.deepEqual(t.RcptTo, ['<recipient@example.com>']);
  assert.deepEqual(t.ExpectedFlags, []);
  assert.equal(t.SignedMessage, 'Message-Instance: m=1\r\nFrom: a@b\r\n');
  assert.equal(t.DNS['ed25519._domainkey.test.dkim2.eu'], 'v=DKIM1; k=ed25519; p=abc');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test deploy/www/verify/tests/toml.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

`deploy/www/verify/tests/toml.mjs`:
```js
// Minimal TOML reader for the dkim2tests fixture subset. TEST-ONLY.
// Supports: Key = 'single', Key = """multiline""", Key = ['a','b'],
// and [Table] sections with 'quoted.key' = 'value'. Not a general parser.
export function parseToml(text) {
  const lines = text.split('\n');
  const root = {};
  let target = root;
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;

    const tableMatch = trimmed.match(/^\[([^\]]+)\]$/);
    if (tableMatch) { target = root[tableMatch[1]] = {}; continue; }

    const eq = line.indexOf('=');
    if (eq < 0) continue;
    let key = line.slice(0, eq).trim();
    if (key.startsWith("'") && key.endsWith("'")) key = key.slice(1, -1);
    let rhs = line.slice(eq + 1).trim();

    if (rhs.startsWith('"""')) {
      // Multiline: content runs until a line that is exactly """.
      const buf = [];
      for (i++; i < lines.length; i++) {
        if (lines[i].trim() === '"""') break;
        buf.push(lines[i]);
      }
      // Fixture multiline lines already end with a literal \r; join with \n
      // and append a trailing \n for the final line.
      target[key] = buf.join('\n') + '\n';
    } else if (rhs.startsWith('[')) {
      const inner = rhs.replace(/^\[/, '').replace(/\]$/, '').trim();
      target[key] = inner === '' ? [] : inner.split(',').map((s) => unquote(s.trim()));
    } else {
      target[key] = unquote(rhs);
    }
  }
  return root;
}

function unquote(s) {
  if ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith('"') && s.endsWith('"'))) {
    return s.slice(1, -1);
  }
  return s;
}
```

Note: fixtures write body lines as `...\r` then a real newline; `buf.join('\n')` yields `...\r\n...`, matching the on-disk CRLF message. The test asserts this exact behaviour.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test deploy/www/verify/tests/toml.test.mjs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/www/verify/tests/toml.mjs deploy/www/verify/tests/toml.test.mjs
git commit -m "verify: minimal TOML reader for conformance fixtures"
```

---

## Task 3: Message and tag-value parsing

**Files:**
- Create: `deploy/www/verify/parse.js`
- Test: `deploy/www/verify/tests/parse.test.mjs`

**Interfaces:**
- Produces:
  - `parseMessage(raw) -> { headers: Field[], body: string }` where `Field = { name: string, value: string, raw: string }`. `raw` is the full folded field text including its terminating CRLF; `value` is the unfolded value with folding CRLFs preserved as-is (raw), no leading colon, no trailing CRLF. Input line endings are normalized to CRLF. `body` is everything after the first blank line, verbatim.
  - `parseTagList(value) -> { tags: Tag[], map: Object }` where `Tag = { tag: string (lowercased name), value: string (raw, trimmed of surrounding FWS), raw: string }`. `map` keys are lowercased tag names -> value (first occurrence); `tags` preserves order and duplicates.
  - `collectLevels(headers) -> { instances: Object<number,Level>, signatures: Object<number,Level>, miFields: Field[], sigFields: Field[] }` where each `Level = { field: Field, tags: Tag[], map: Object }`, indexed by the numeric `m=`/`i=` value.

- [ ] **Step 1: Write the failing test**

`deploy/www/verify/tests/parse.test.mjs`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseMessage, parseTagList, collectLevels } from '../parse.js';

const MSG =
  'Message-Instance: m=1; h=sha256:AA=:BB=\r\n' +
  'DKIM2-Signature: i=1; m=1;\r\n' +
  ' d=test.dkim2.eu; s=sel:ed25519-sha256:ZZ\r\n' +
  'From: a@b\r\n' +
  'Subject: hi\r\n' +
  '\r\n' +
  'body line\r\n';

test('parseMessage splits headers and body, unfolds', () => {
  const { headers, body } = parseMessage(MSG);
  assert.equal(headers.length, 4);
  assert.equal(headers[0].name, 'Message-Instance');
  assert.equal(headers[2].name, 'From');
  // Folded DKIM2-Signature value keeps its raw folded bytes.
  assert.match(headers[1].value, /d=test\.dkim2\.eu/);
  assert.equal(body, 'body line\r\n');
});

test('parseMessage normalizes bare LF to CRLF', () => {
  const { headers, body } = parseMessage('From: a@b\nSubject: x\n\nhi\n');
  assert.equal(headers.length, 2);
  assert.equal(body, 'hi\r\n');
});

test('parseTagList parses tags case-insensitively, values case-significant', () => {
  const { map, tags } = parseTagList('i=1; M=1; d=Test.DKIM2.eu;');
  assert.equal(map.i, '1');
  assert.equal(map.m, '1');       // tag name lowercased
  assert.equal(map.d, 'Test.DKIM2.eu'); // value preserved
  assert.equal(tags.length, 3);   // trailing empty segment dropped
});

test('collectLevels indexes instances and signatures', () => {
  const { headers } = parseMessage(MSG);
  const { instances, signatures } = collectLevels(headers);
  assert.equal(instances[1].map.m, '1');
  assert.equal(signatures[1].map.d, 'test.dkim2.eu');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test deploy/www/verify/tests/parse.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

`deploy/www/verify/parse.js`:
```js
// RFC5322 message parsing and DKIM2 tag-value parsing. Built from spec-04.

function toCRLF(raw) {
  return raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\n/g, '\r\n');
}

export function parseMessage(raw) {
  const text = toCRLF(raw);
  const sep = text.indexOf('\r\n\r\n');
  const headerBlock = sep < 0 ? text : text.slice(0, sep + 2); // include final CRLF
  const body = sep < 0 ? '' : text.slice(sep + 4);

  // Split header block into physical lines (each ends with CRLF).
  const physical = headerBlock.match(/[^\r\n]*\r\n/g) || [];
  const headers = [];
  for (const line of physical) {
    if (/^[ \t]/.test(line) && headers.length) {
      // Continuation of the previous field.
      const prev = headers[headers.length - 1];
      prev.raw += line;
      prev.value += line.replace(/\r\n$/, '');
    } else {
      const m = line.match(/^([^:]*):([\s\S]*)\r\n$/);
      if (!m) continue; // not a valid header line; skip
      headers.push({ name: m[1].trim(), value: m[2], raw: line });
    }
  }
  return { headers, body };
}

export function parseTagList(value) {
  // value is the raw header value (may contain folding CRLF+WSP). Semicolons
  // only ever separate tags (spec §7/§8).
  const flat = value.replace(/\r\n/g, ''); // drop folding
  const tags = [];
  const map = {};
  for (const seg of flat.split(';')) {
    if (seg.trim() === '') continue;
    const eq = seg.indexOf('=');
    if (eq < 0) continue;
    const name = seg.slice(0, eq).trim().toLowerCase();
    const val = seg.slice(eq + 1).trim();
    tags.push({ tag: name, value: val, raw: seg });
    if (!(name in map)) map[name] = val;
  }
  return { tags, map };
}

function isName(field, name) {
  return field.name.toLowerCase() === name;
}

export function collectLevels(headers) {
  const instances = {};
  const signatures = {};
  const miFields = [];
  const sigFields = [];
  for (const f of headers) {
    if (isName(f, 'message-instance')) {
      miFields.push(f);
      const parsed = parseTagList(f.value);
      const m = parseInt(parsed.map.m, 10);
      instances[m] = { field: f, tags: parsed.tags, map: parsed.map };
    } else if (isName(f, 'dkim2-signature')) {
      sigFields.push(f);
      const parsed = parseTagList(f.value);
      const i = parseInt(parsed.map.i, 10);
      signatures[i] = { field: f, tags: parsed.tags, map: parsed.map };
    }
  }
  return { instances, signatures, miFields, sigFields };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test deploy/www/verify/tests/parse.test.mjs`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add deploy/www/verify/parse.js deploy/www/verify/tests/parse.test.mjs
git commit -m "verify: RFC5322 message + tag-value parsing"
```

---

## Task 4: Canonicalization (§6.1 body, §6.2 header hash, §9.6 signing input)

**Files:**
- Create: `deploy/www/verify/canon.js`
- Test: `deploy/www/verify/tests/canon.test.mjs`

**Interfaces:**
- Consumes: `Field`/`Tag` shapes from `parse.js`.
- Produces:
  - `canonBody(body) -> string` — §6.1: strip all trailing empty lines to a single CRLF (add CRLF if none).
  - `canonHeaderHash(fields) -> string` — §6.2: fields is a flat doc-order list of `{name, value}` already filtered to signed headers; returns the concatenated canonical header block.
  - `isUnsignedHeader(name) -> boolean` — §4 test (does NOT include Message-Instance/DKIM2-Signature).
  - `signingInput(orderedFields, targetSig) -> string` — §9.6: `orderedFields` is the list of `{name, value}` for the MI fields (ascending m) then DKIM2-Signature fields (ascending i) up to and including the target; `targetSig` is the `Field` whose `s=` signature values must be blanked. Returns the concatenated signing bytes.
  - `blankSignatureValues(rawValue) -> string` — sets each `s=` sig-set's message-sig to empty.

- [ ] **Step 1: Write the failing test**

`deploy/www/verify/tests/canon.test.mjs`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonBody, canonHeaderHash, isUnsignedHeader, signingInput, blankSignatureValues } from '../canon.js';

test('canonBody reduces trailing empty lines to one CRLF', () => {
  assert.equal(canonBody('a\r\nb\r\n\r\n\r\n'), 'a\r\nb\r\n');
  assert.equal(canonBody('a\r\nb'), 'a\r\nb\r\n');
  assert.equal(canonBody(''), '\r\n');
});

test('isUnsignedHeader matches the §4 list', () => {
  for (const n of ['Received', 'Return-Path', 'Delivered-To', 'DKIM-Signature',
    'ARC-Seal', 'Authentication-Results', 'X-Spam'])
    assert.equal(isUnsignedHeader(n), true, n);
  for (const n of ['From', 'Subject', 'To', 'Message-Instance', 'DKIM2-Signature'])
    assert.equal(isUnsignedHeader(n), false, n);
});

test('canonHeaderHash lowercases names, collapses WSP, sorts, orders dups bottom-up', () => {
  const fields = [
    { name: 'Received', value: ' from x' },   // ignored (§4)
    { name: 'SUBJect', value: '  AbC  ' },
    { name: 'From', value: ' a@b' },
    { name: 'From', value: ' c@d' },           // duplicate; bottom-up => c@d first
  ].filter((f) => !isUnsignedHeader(f.name));
  assert.equal(canonHeaderHash(fields),
    'from:c@d\r\nfrom:a@b\r\nsubject:AbC\r\n');
});

test('blankSignatureValues empties message-sig, keeps selector:alg:', () => {
  const raw = 'i=1;m=1;s=banana:banana:YmFuYW5h,ed25519:ed25519-sha256:8SDP==';
  assert.match(blankSignatureValues(raw), /s=banana:banana:,ed25519:ed25519-sha256:/);
});

test('signingInput removes all WSP, keeps colon and CRLF, blanks target s=', () => {
  const mi = { name: 'Message-Instance', value: ' m=1; h=sha256:AA=:BB=' };
  const sig = { name: 'DKIM2-Signature', value: ' i=1; s=sel:ed25519-sha256:ZZ' };
  const out = signingInput([mi, sig], sig);
  assert.equal(out,
    'message-instance:m=1;h=sha256:AA=:BB=\r\n' +
    'dkim2-signature:i=1;s=sel:ed25519-sha256:\r\n');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test deploy/www/verify/tests/canon.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

`deploy/www/verify/canon.js`:
```js
// Canonicalization per draft-ietf-dkim-dkim2-spec-04 §6.1, §6.2, §9.6.

const UNSIGNED_EXACT = new Set([
  'received', 'return-path', 'delivered-to', 'dkim-signature',
  'authentication-results',
]);

export function isUnsignedHeader(name) {
  const n = name.toLowerCase();
  if (UNSIGNED_EXACT.has(n)) return true;
  if (n.startsWith('arc-')) return true;
  if (n.startsWith('x-')) return true;
  return false;
}

export function canonBody(body) {
  // §6.1: ignore all trailing empty lines; "*CRLF" at end becomes "CRLF";
  // if no body or no trailing CRLF, a CRLF is added.
  return body.replace(/(\r\n)*$/, '') + '\r\n';
}

function unfold(value) {
  // Remove folding: a CRLF that is part of header folding joins the line.
  return value.replace(/\r\n/g, '');
}

// §6.2 canonical line for one header field.
function hashLine(field) {
  let v = unfold(field.value);
  v = v.replace(/[ \t]+/g, ' '); // collapse WSP runs to single SP
  v = v.replace(/ +$/, '');      // delete trailing WSP
  v = v.replace(/^ +/, '');      // delete WSP after the colon
  return field.name.toLowerCase() + ':' + v + '\r\n';
}

export function canonHeaderHash(fields) {
  // fields: flat doc-order list of {name,value}, already filtered to signed
  // headers (caller excludes §4 names AND message-instance/dkim2-signature).
  const withIdx = fields.map((f, i) => ({
    name: f.name.toLowerCase(),
    line: hashLine(f),
    i,
  }));
  // Alphabetical by name; within a name, bottom-up (later in doc first).
  withIdx.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : b.i - a.i));
  return withIdx.map((x) => x.line).join('');
}

export function blankSignatureValues(rawValue) {
  return rawValue
    .split(';')
    .map((seg) => {
      const eq = seg.indexOf('=');
      if (eq < 0) return seg;
      const name = seg.slice(0, eq).trim().toLowerCase();
      if (name !== 's') return seg;
      const rest = seg.slice(eq + 1);
      const sets = rest.split(',').map((s) => {
        const parts = s.split(':');
        // selector:sig-name:message-sig -> selector:sig-name:
        return (parts[0] || '') + ':' + (parts[1] || '') + ':';
      });
      return seg.slice(0, eq + 1) + sets.join(',');
    })
    .join(';');
}

// §9.6 canonical line for the signing input: delete ALL WSP, keep colon + CRLF.
function signLine(name, value) {
  const v = unfold(value).replace(/[ \t]/g, '');
  return name.toLowerCase() + ':' + v + '\r\n';
}

export function signingInput(orderedFields, targetSig) {
  let out = '';
  for (const f of orderedFields) {
    const value = f === targetSig ? blankSignatureValues(f.value) : f.value;
    out += signLine(f.name, value);
  }
  return out;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test deploy/www/verify/tests/canon.test.mjs`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add deploy/www/verify/canon.js deploy/www/verify/tests/canon.test.mjs
git commit -m "verify: §6.1/§6.2/§9.6 canonicalization"
```

---

## Task 5: WebCrypto wrappers (SHA-256, RSA, Ed25519)

**Files:**
- Create: `deploy/www/verify/crypto.js`
- Test: `deploy/www/verify/tests/crypto.test.mjs`

**Interfaces:**
- Consumes: `b64.js` helpers.
- Produces:
  - `sha256Bytes(bytes: Uint8Array) -> Promise<Uint8Array>` (32-byte digest).
  - `sha256B64(bytes: Uint8Array) -> Promise<string>` (base64 digest).
  - `verifyRsa(spkiB64: string, sigBytes: Uint8Array, msgBytes: Uint8Array) -> Promise<boolean>` — imports an SPKI (DER) RSA key, verifies RSASSA-PKCS1-v1_5/SHA-256 over `msgBytes`.
  - `verifyEd25519(rawPubB64: string, sigBytes: Uint8Array, hashBytes: Uint8Array) -> Promise<boolean>` — imports a raw 32-byte Ed25519 public key, verifies over `hashBytes` (the 32-byte SHA-256 digest).
  - `ED25519_SUPPORTED` — resolves via a capability probe; `verifyEd25519` throws `Error('ed25519-unsupported')` where WebCrypto lacks Ed25519.

- [ ] **Step 1: Write the failing test**

`deploy/www/verify/tests/crypto.test.mjs`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256B64, verifyEd25519, verifyRsa } from '../crypto.js';
import { stringToBytes, b64ToBytes } from '../b64.js';

test('sha256B64 matches known DKIM2 body hash', async () => {
  // §6.1 canonical body "Hello, this is a simple test message.\r\n"
  const body = 'Hello, this is a simple test message.\r\n';
  assert.equal(await sha256B64(stringToBytes(body)),
    'SgG5fNGEg1x24MwItCUYGDHQkWKng06W1/IvTGBdwzU=');
});

test('verifyEd25519 accepts a valid signature and rejects a corrupt one', async () => {
  // Signature over the SHA-256 hash of the ASCII message "test".
  const pub = 'nJjZf8LyVfo7pxT28dT3gWhRkcM12+6qhYiOwx8oPco=';
  const { subtle } = globalThis.crypto;
  const hash = new Uint8Array(await subtle.digest('SHA-256', stringToBytes('test')));
  // Sign with the matching private key to produce a known-good signature.
  const pkcs8 = b64ToBytes('MC4CAQAwBQYDK2VwBCIEIM6FWyVRYd3E5RZd/OzN7uiBCpcHwnrTUu7qymtM9kln');
  const priv = await subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
  const sig = new Uint8Array(await subtle.sign({ name: 'Ed25519' }, priv, hash));
  assert.equal(await verifyEd25519(pub, sig, hash), true);
  const bad = sig.slice(); bad[0] ^= 0xff;
  assert.equal(await verifyEd25519(pub, bad, hash), false);
});

test('verifyRsa verifies a self-produced RSASSA-PKCS1-v1_5/SHA-256 signature', async () => {
  const { subtle } = globalThis.crypto;
  const kp = await subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify']);
  const msg = stringToBytes('message-instance:m=1\r\n');
  const sig = new Uint8Array(await subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, kp.privateKey, msg));
  const { bytesToB64 } = await import('../b64.js');
  const spki = bytesToB64(new Uint8Array(await subtle.exportKey('spki', kp.publicKey)));
  assert.equal(await verifyRsa(spki, sig, msg), true);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test deploy/www/verify/tests/crypto.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

`deploy/www/verify/crypto.js`:
```js
// WebCrypto wrappers for DKIM2. Built from spec-04 §3.
import { b64ToBytes, bytesToB64 } from './b64.js';

const subtle = globalThis.crypto.subtle;

export async function sha256Bytes(bytes) {
  return new Uint8Array(await subtle.digest('SHA-256', bytes));
}

export async function sha256B64(bytes) {
  return bytesToB64(await sha256Bytes(bytes));
}

export async function verifyRsa(spkiB64, sigBytes, msgBytes) {
  const key = await subtle.importKey(
    'spki', b64ToBytes(spkiB64),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  return subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, sigBytes, msgBytes);
}

export async function verifyEd25519(rawPubB64, sigBytes, hashBytes) {
  let key;
  try {
    key = await subtle.importKey('raw', b64ToBytes(rawPubB64), { name: 'Ed25519' }, false, ['verify']);
  } catch (e) {
    throw new Error('ed25519-unsupported');
  }
  // §3.3: Ed25519 signs the SHA-256 hash value as its message.
  return subtle.verify({ name: 'Ed25519' }, key, sigBytes, hashBytes);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test deploy/www/verify/tests/crypto.test.mjs`
Expected: PASS (3 tests). (Requires Node 20+ with Ed25519 in WebCrypto; Node 20.x supports it.)

- [ ] **Step 5: Commit**

```bash
git add deploy/www/verify/crypto.js deploy/www/verify/tests/crypto.test.mjs
git commit -m "verify: WebCrypto SHA-256 / RSA / Ed25519 wrappers"
```

---

## Task 6: Key-record parsing and DoH lookup

**Files:**
- Create: `deploy/www/verify/doh.js`
- Test: `deploy/www/verify/tests/doh.test.mjs`

**Interfaces:**
- Produces:
  - `parseKeyRecord(txt: string) -> { k: string, p: string }` — parses a `_domainkey` TXT record (`v=DKIM1; k=rsa|ed25519; p=<base64>`). Defaults `k` to `rsa` when absent (RFC6376). Throws `Error('key-syntax')` on malformed input; throws `Error('key-revoked')` when `p=` is empty.
  - `keyName(selector: string, domain: string) -> string` — `selector._domainkey.domain`.
  - `fetchKey(selector: string, domain: string, opts?) -> Promise<{ k, p }>` — queries Cloudflare DoH for the TXT record. Throws `Error('key-notfound')` (NXDOMAIN / no TXT), `Error('key-multiple')` (>1 record), or `Error('key-temperror')` (network/5xx/SERVFAIL). `opts.dohUrl` overrides the endpoint (default `https://cloudflare-dns.com/dns-query`).

- [ ] **Step 1: Write the failing test**

`deploy/www/verify/tests/doh.test.mjs`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseKeyRecord, keyName } from '../doh.js';

test('keyName builds the _domainkey query name', () => {
  assert.equal(keyName('ed25519', 'test.dkim2.eu'), 'ed25519._domainkey.test.dkim2.eu');
});

test('parseKeyRecord reads k and p, defaults k to rsa', () => {
  assert.deepEqual(parseKeyRecord('v=DKIM1; k=ed25519; p=abc='), { k: 'ed25519', p: 'abc=' });
  assert.deepEqual(parseKeyRecord('v=DKIM1; p=xyz='), { k: 'rsa', p: 'xyz=' });
});

test('parseKeyRecord throws on empty p (revoked) and on missing p', () => {
  assert.throws(() => parseKeyRecord('v=DKIM1; k=rsa; p='), /key-revoked/);
  assert.throws(() => parseKeyRecord('v=DKIM1; k=rsa'), /key-syntax/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test deploy/www/verify/tests/doh.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

`deploy/www/verify/doh.js`:
```js
// Public-key retrieval over DNS-over-HTTPS (Cloudflare) + key-record parsing.
// Built from spec-04 §3.6 / §11.5.

const DEFAULT_DOH = 'https://cloudflare-dns.com/dns-query';

export function keyName(selector, domain) {
  return `${selector}._domainkey.${domain}`;
}

export function parseKeyRecord(txt) {
  const map = {};
  for (const seg of txt.split(';')) {
    const eq = seg.indexOf('=');
    if (eq < 0) continue;
    map[seg.slice(0, eq).trim().toLowerCase()] = seg.slice(eq + 1).trim();
  }
  if (!('p' in map)) throw new Error('key-syntax');
  if (map.p === '') throw new Error('key-revoked');
  return { k: (map.k || 'rsa').toLowerCase(), p: map.p.replace(/\s+/g, '') };
}

export async function fetchKey(selector, domain, opts = {}) {
  const url = new URL(opts.dohUrl || DEFAULT_DOH);
  url.searchParams.set('name', keyName(selector, domain));
  url.searchParams.set('type', 'TXT');
  let resp;
  try {
    resp = await fetch(url, { headers: { accept: 'application/dns-json' } });
  } catch (e) {
    throw new Error('key-temperror');
  }
  if (resp.status >= 500) throw new Error('key-temperror');
  if (!resp.ok) throw new Error('key-notfound');
  const data = await resp.json();
  if (data.Status === 2) throw new Error('key-temperror'); // SERVFAIL
  if (data.Status === 3) throw new Error('key-notfound');  // NXDOMAIN
  const answers = (data.Answer || []).filter((a) => a.type === 16); // TXT
  if (answers.length === 0) throw new Error('key-notfound');
  if (answers.length > 1) throw new Error('key-multiple');
  // DoH TXT data is a quoted string, possibly split into 255-char chunks.
  const txt = answers[0].data
    .replace(/^"(.*)"$/s, '$1')
    .replace(/"\s*"/g, '');
  return parseKeyRecord(txt);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test deploy/www/verify/tests/doh.test.mjs`
Expected: PASS (3 tests). (Only the pure parser is unit-tested; live DoH is exercised in Task 11 acceptance.)

- [ ] **Step 5: Commit**

```bash
git add deploy/www/verify/doh.js deploy/www/verify/tests/doh.test.mjs
git commit -m "verify: DoH key fetch + key-record parsing"
```

---

## Task 7: Recipe application (undo) — §5 / §7.2

**Files:**
- Create: `deploy/www/verify/recipes.js`
- Test: `deploy/www/verify/tests/recipes.test.mjs`

**Interfaces:**
- Consumes: `Field` shape from `parse.js`, `b64ToString` from `b64.js`.
- Produces:
  - `bodyToLines(body: string) -> string[]` — split body into lines (no terminators); a trailing CRLF does not create an empty final line.
  - `linesToBody(lines: string[]) -> string` — each line + CRLF, concatenated.
  - `applyBodyRecipe(lines: string[], steps) -> string[]` — apply `{c:[s,e]}` (copy current lines s..e, 1-based) and `{d:[...]}` (emit given lines) in order, producing the previous body's lines.
  - `applyHeaderRecipe(fields: Field[], hObj) -> Field[]` — apply per-name recipes to reconstruct the previous header fields (bottom-up numbering: last instance of a name = #1). Names absent from `hObj` are retained; an empty array removes all instances of that name. Returns a new flat doc-order `Field[]`.
  - `decodeRecipe(r_b64: string) -> { h?: object, b?: array|null }` — base64+JSON decode of an `r=` value.

- [ ] **Step 1: Write the failing test**

`deploy/www/verify/tests/recipes.test.mjs`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bodyToLines, linesToBody, applyBodyRecipe, applyHeaderRecipe, decodeRecipe } from '../recipes.js';

test('bodyToLines / linesToBody round-trip', () => {
  assert.deepEqual(bodyToLines('a\r\nb\r\n'), ['a', 'b']);
  assert.deepEqual(bodyToLines('a\r\nb'), ['a', 'b']);
  assert.equal(linesToBody(['a', 'b']), 'a\r\nb\r\n');
});

test('applyBodyRecipe undoes an appended footer (copy first N lines)', () => {
  // current body = original 2 lines + a footer; recipe copies lines 1..2.
  const cur = ['Hello', 'world', '-- footer'];
  assert.deepEqual(applyBodyRecipe(cur, [{ c: [1, 2] }]), ['Hello', 'world']);
});

test('applyBodyRecipe restores a replaced line via d step', () => {
  const cur = ['NEW line', 'tail'];
  assert.deepEqual(applyBodyRecipe(cur, [{ d: ['OLD line'] }, { c: [2, 2] }]),
    ['OLD line', 'tail']);
});

test('applyHeaderRecipe restores a modified Subject (d step), retains others', () => {
  const fields = [
    { name: 'From', value: ' a@b', raw: 'From: a@b\r\n' },
    { name: 'Subject', value: ' [DKIM2] hi', raw: 'Subject: [DKIM2] hi\r\n' },
  ];
  const out = applyHeaderRecipe(fields, { subject: [{ d: ['hi'] }] });
  const subj = out.find((f) => f.name.toLowerCase() === 'subject');
  assert.equal(subj.value, 'hi');
  assert.ok(out.find((f) => f.name === 'From'));
});

test('applyHeaderRecipe empty array removes all instances of a name', () => {
  const fields = [
    { name: 'From', value: ' a@b', raw: '' },
    { name: 'List-Id', value: ' x', raw: '' },
  ];
  const out = applyHeaderRecipe(fields, { 'list-id': [] });
  assert.equal(out.find((f) => f.name.toLowerCase() === 'list-id'), undefined);
});

test('decodeRecipe base64-decodes JSON', () => {
  const b64 = Buffer.from(JSON.stringify({ b: [{ c: [1, 1] }] })).toString('base64');
  assert.deepEqual(decodeRecipe(b64), { b: [{ c: [1, 1] }] });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test deploy/www/verify/tests/recipes.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

`deploy/www/verify/recipes.js`:
```js
// Recipe application (undo) per spec-04 §5 and §7.2.
import { b64ToString } from './b64.js';

export function decodeRecipe(rB64) {
  return JSON.parse(b64ToString(rB64));
}

export function bodyToLines(body) {
  if (body === '') return [];
  const parts = body.split('\r\n');
  if (parts[parts.length - 1] === '' && body.endsWith('\r\n')) parts.pop();
  return parts;
}

export function linesToBody(lines) {
  return lines.map((l) => l + '\r\n').join('');
}

// §5.2: body lines numbered top-down from 1.
export function applyBodyRecipe(curLines, steps) {
  const out = [];
  for (const step of steps) {
    if ('c' in step) {
      const [s, e] = step.c;
      for (let n = s; n <= e; n++) out.push(curLines[n - 1]);
    } else if ('d' in step) {
      for (const line of step.d) out.push(line);
    }
  }
  return out;
}

// §5.1: header fields numbered bottom-up (last instance of a name = #1).
export function applyHeaderRecipe(fields, hObj) {
  // Group current fields by lowercased name, preserving document order.
  const byName = new Map();
  for (const f of fields) {
    const n = f.name.toLowerCase();
    if (!byName.has(n)) byName.set(n, []);
    byName.get(n).push(f);
  }

  // Normalize recipe keys to lowercase.
  const recipe = {};
  for (const k of Object.keys(hObj)) recipe[k.toLowerCase()] = hObj[k];

  for (const name of Object.keys(recipe)) {
    const steps = recipe[name];
    const cur = byName.get(name) || [];
    const bottomUp = cur.slice().reverse(); // index0 = last in doc = #1
    const emitted = []; // processing order == bottom-up order of reconstruction
    for (const step of steps) {
      if ('c' in step) {
        const [s, e] = step.c;
        for (let num = s; num <= e; num++) emitted.push(bottomUp[num - 1]);
      } else if ('d' in step) {
        for (const val of step.d) {
          emitted.push({ name, value: val, raw: name + ':' + val + '\r\n' });
        }
      }
    }
    // Reconstructed doc order (top->bottom) is the reverse of bottom-up.
    byName.set(name, emitted.slice().reverse());
  }

  // Flatten back to a doc-order list. Inter-name position is irrelevant to the
  // header hash (which sorts), so preserve first-seen name order; append names
  // introduced by the recipe.
  const seen = [];
  for (const f of fields) {
    const n = f.name.toLowerCase();
    if (!seen.includes(n)) seen.push(n);
  }
  for (const n of Object.keys(recipe)) if (!seen.includes(n)) seen.push(n);

  const out = [];
  for (const n of seen) for (const f of (byName.get(n) || [])) out.push(f);
  return out;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test deploy/www/verify/tests/recipes.test.mjs`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add deploy/www/verify/recipes.js deploy/www/verify/tests/recipes.test.mjs
git commit -m "verify: §5/§7.2 recipe apply (header + body undo)"
```

---

## Task 8: Verification orchestrator (§10 / §11)

This is the core. It ties the modules together and produces the report object. Public keys come from an injectable `fetchKey` so tests run offline; the browser passes the real DoH `fetchKey`.

**Files:**
- Create: `deploy/www/verify/verify.js`
- Test: `deploy/www/verify/tests/verify.test.mjs`

**Interfaces:**
- Consumes: `parse.js`, `canon.js`, `crypto.js`, `recipes.js`, `b64.js`, and a `fetchKey(selector, domain) -> Promise<{k,p}>` (default: `doh.js`'s `fetchKey`).
- Produces: `verifyMessage(raw: string, opts?) -> Promise<Report>` where
  ```
  opts = { fetchKey?, mailFrom?: string, rcptTo?: string[], skipTimestamp?: boolean, now?: number }
  Report = { overall, summary, levels: Level[] }
  ```
  and `Level` matches the shapes the renderer consumes (Task 9). `overall ∈ {'pass','fail','permerror','temperror','none'}`.
- Produces (also exported for reuse/testing): `relaxedDomainMatch(fromDomain, targetDomain) -> boolean` (§9.4), `domainOf(pathOrAddr) -> string`.

- [ ] **Step 1: Write the failing test**

`deploy/www/verify/tests/verify.test.mjs`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyMessage, relaxedDomainMatch, domainOf } from '../verify.js';

test('relaxedDomainMatch strips labels from the left of the from-domain', () => {
  assert.equal(relaxedDomainMatch('bounce.a.example.com', 'example.com'), true);
  assert.equal(relaxedDomainMatch('example.com', 'example.com'), true);
  assert.equal(relaxedDomainMatch('example.com', 'other.com'), false);
});

test('domainOf extracts the domain from a reverse/forward path', () => {
  assert.equal(domainOf('<bob@Sub.Example.COM>'), 'sub.example.com');
  assert.equal(domainOf('<>'), '');
});

test('no DKIM2-Signature yields overall=none', async () => {
  const rep = await verifyMessage('From: a@b\r\nSubject: x\r\n\r\nhi\r\n');
  assert.equal(rep.overall, 'none');
});

test('single-hop signed message verifies with injected key', async () => {
  // Uses a fixture pair generated in Task 10's vectors; here we assert the
  // shape contract on a known-good vector loaded via the conformance harness.
  // (Real crypto is covered end-to-end in vectors.test.mjs.)
  const rep = await verifyMessage('From: a@b\r\nSubject: x\r\n\r\nhi\r\n');
  assert.ok(Array.isArray(rep.levels));
});
```

(The deep crypto assertions live in Task 10's `vectors.test.mjs`, which drives real signed messages. This task's test pins the pure helpers and the `none`/shape contracts.)

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test deploy/www/verify/tests/verify.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

`deploy/www/verify/verify.js`:
```js
// DKIM2 verification orchestrator per spec-04 §10/§11. Built from spec.
import { parseMessage, collectLevels, parseTagList } from './parse.js';
import { canonBody, canonHeaderHash, isUnsignedHeader, signingInput } from './canon.js';
import { sha256Bytes, sha256B64, verifyRsa, verifyEd25519 } from './crypto.js';
import { fetchKey as dohFetchKey } from './doh.js';
import { decodeRecipe, bodyToLines, linesToBody, applyBodyRecipe, applyHeaderRecipe } from './recipes.js';
import { stringToBytes, b64ToBytes, b64ToString } from './b64.js';

const SIG_MI_NAMES = new Set(['message-instance', 'dkim2-signature']);

export function domainOf(path) {
  const m = /<?[^@<>]*@([^>]*)>?/.exec(path || '');
  return m ? m[1].toLowerCase() : '';
}

export function relaxedDomainMatch(fromDomain, targetDomain) {
  let a = (fromDomain || '').toLowerCase();
  const b = (targetDomain || '').toLowerCase();
  while (a) {
    if (a === b) return true;
    const dot = a.indexOf('.');
    if (dot < 0) return false;
    a = a.slice(dot + 1);
  }
  return false;
}

// Signed header fields (for the §6.2 header hash) at a given message state.
function signedFields(fields) {
  return fields.filter((f) => !isUnsignedHeader(f.name) && !SIG_MI_NAMES.has(f.name.toLowerCase()));
}

// Parse the h= hash-set list into [{alg, headerHash, bodyHash}].
function parseHashSets(hValue) {
  return (hValue || '').split(',').map((set) => {
    const [alg, headerHash, bodyHash] = set.split(':');
    return { alg: (alg || '').trim(), headerHash, bodyHash };
  });
}

// Parse the s= sig-set list into [{selector, alg, sig}].
function parseSigSets(sValue) {
  return (sValue || '').split(',').map((set) => {
    const [selector, alg, sig] = set.split(':');
    return { selector: (selector || '').trim(), alg: (alg || '').trim().toLowerCase(), sig: (sig || '').trim() };
  });
}

const SUPPORTED_ALGS = new Set(['rsa-sha256', 'ed25519-sha256']);

export async function verifyMessage(raw, opts = {}) {
  const fetchKey = opts.fetchKey || dohFetchKey;
  const now = opts.now || Math.floor(Date.now() / 1000);
  const { headers, body } = parseMessage(raw);
  const { instances, signatures } = collectLevels(headers);

  const miNums = Object.keys(instances).map(Number).sort((a, b) => a - b);
  const sigNums = Object.keys(signatures).map(Number).sort((a, b) => a - b);

  if (sigNums.length === 0) {
    return { overall: 'none', summary: 'No DKIM2-Signature header field present.', levels: [] };
  }

  const levels = [];
  let overall = 'pass';
  const bump = (state) => {
    // Precedence for the overall verdict: fail > permerror > temperror > pass.
    const rank = { pass: 0, temperror: 1, permerror: 2, fail: 3 };
    if (rank[state] > rank[overall]) overall = state;
  };

  // --- §11.2 structural validation -------------------------------------
  const maxM = miNums[miNums.length - 1];
  const maxI = sigNums[sigNums.length - 1];
  const structErr = [];
  for (let i = 1; i <= maxI; i++) if (!signatures[i]) structErr.push(`DKIM2-Signature i=${i} missing`);
  for (let m = 1; m <= maxM; m++) if (!instances[m]) structErr.push(`Message-Instance m=${m} missing`);
  if (maxM > maxI) structErr.push(`Message-Instance m=${maxM} is not signed`);
  for (const i of sigNums) {
    const s = signatures[i];
    for (const t of ['i', 'm', 't', 'd', 's']) if (!(t in s.map)) structErr.push(`DKIM2-Signature i=${i} tag=${t} missing`);
    const hasNd = 'nd' in s.map, hasMf = 'mf' in s.map, hasRt = 'rt' in s.map;
    if (hasNd && (hasMf || hasRt)) structErr.push(`DKIM2-Signature i=${i} tag=nd was unexpected`);
    if (!hasNd && !(hasMf && hasRt)) structErr.push(`DKIM2-Signature i=${i} tag=mf missing`);
  }
  for (const m of miNums) {
    const mi = instances[m];
    for (const t of ['m', 'h']) if (!(t in mi.map)) structErr.push(`Message-Instance m=${m} tag=${t} missing`);
  }
  if (structErr.length) {
    return { overall: 'permerror', summary: structErr.join('; '), levels: [] };
  }

  // --- reconstruct message state per instance (top-down) ----------------
  // state[m] = { fields, bodyLines } representing the message at instance m.
  const states = {};
  states[maxM] = { fields: headers.slice(), bodyLines: bodyToLines(body) };
  let undoBroken = null; // m at which undo became impossible
  for (let m = maxM; m >= 2; m--) {
    const mi = instances[m];
    if (!('r' in mi.map)) { undoBroken = m; break; }
    let recipe;
    try { recipe = decodeRecipe(mi.map.r); } catch (e) { undoBroken = m; break; }
    if (recipe.b === null) { undoBroken = m; break; } // §5.2 unrecoverable
    const cur = states[m];
    let fields = cur.fields;
    let bodyLines = cur.bodyLines;
    if (recipe.h) fields = applyHeaderRecipe(cur.fields, recipe.h);
    if (recipe.b) bodyLines = applyBodyRecipe(cur.bodyLines, recipe.b);
    states[m - 1] = { fields, bodyLines };
  }

  // --- §11.7 MI hash checks (top-down) ----------------------------------
  for (let m = maxM; m >= 1; m--) {
    const mi = instances[m];
    const state = states[m];
    const level = {
      kind: 'instance', m,
      tags: mi.tags.map((t) => ({ tag: t.tag, value: t.value })),
      header_hash: 'not-checked', body_hash: 'not-checked',
      header_recipes: [], undo: m === 1 ? 'n/a' : 'clean',
      result: 'pass', detail: '',
    };
    if (!state) {
      level.result = 'not-checked';
      level.undo = undoBroken === m + 1 ? 'unrecoverable' : 'not-checked';
      level.detail = `state unavailable (undo broke at m=${undoBroken})`;
      levels.push(level);
      continue;
    }
    const sets = parseHashSets(mi.map.h);
    const hdrBytes = stringToBytes(canonHeaderHash(signedFields(state.fields)));
    const bodyBytes = stringToBytes(canonBody(linesToBody(state.bodyLines)));
    const hdrHash = await sha256B64(hdrBytes);
    const bodyHash = await sha256B64(bodyBytes);
    // Compare against the sha256 hash-set (ignore unknown algs, §3.4).
    const sha = sets.find((s) => s.alg === 'sha256');
    if (sha) {
      level.header_hash = hdrHash === sha.headerHash ? 'match' : 'mismatch';
      level.body_hash = bodyHash === sha.bodyHash ? 'match' : 'mismatch';
      if (level.header_hash === 'mismatch') { level.result = 'fail'; level.detail = `Message Instance m=${m} header hash mismatch`; bump('fail'); }
      else if (level.body_hash === 'mismatch') { level.result = 'fail'; level.detail = `Message Instance m=${m} body hash mismatch`; bump('fail'); }
    }
    if (m >= 2 && undoBroken === m) level.undo = recipeUndoLabel(instances[m]);
    levels.push(level);
  }

  // --- §11.3–§11.6 signature checks (top-down) --------------------------
  for (let i = maxI; i >= 1; i--) {
    const sig = signatures[i];
    const level = {
      kind: 'signature', i, m: parseInt(sig.map.m, 10),
      tags: sig.tags.map((t) => ({ tag: t.tag, value: t.value })),
      items: [], timestamp: { ok: true, detail: '' },
      custody: { ok: true, detail: '' }, result: 'pass', detail: '',
    };

    // §11.3 timestamp: >14 days old (or, if configured, future).
    if (!opts.skipTimestamp && sig.map.t) {
      const t = parseInt(sig.map.t, 10);
      const ageDays = (now - t) / 86400;
      if (ageDays > 14) { level.timestamp = { ok: false, status: 'expired', detail: `signature expired (${Math.floor(ageDays)}d)` }; level.result = 'fail'; bump('fail'); }
    }

    // §11.4 chain-of-custody (inter-signature + d=/mf=).
    custodyCheck(level, signatures, i, maxI, opts);
    if (!level.custody.ok) { level.result = 'fail'; bump(level.custodyState || 'permerror'); }

    // §11.5/§11.6 fetch key + verify each s= sig-set.
    const mAtSig = parseInt(sig.map.m, 10);
    const state = states[mAtSig];
    if (!state) {
      level.result = 'not-checked';
      level.detail = 'message state for this signature could not be reconstructed';
      levels.push(level);
      continue;
    }
    // Signing input = MI 1..mAtSig then DKIM2-Signature 1..i (target blanked).
    const ordered = [];
    for (let m = 1; m <= mAtSig; m++) ordered.push(fieldFor(instances[m]));
    for (let k = 1; k <= i; k++) ordered.push(fieldFor(signatures[k]));
    const inputBytes = stringToBytes(signingInput(ordered, sig.field));
    const inputHash = await sha256Bytes(inputBytes);

    const sigSets = parseSigSets(sig.map.s);
    let anyChecked = false, allPass = true;
    for (const ss of sigSets) {
      if (!SUPPORTED_ALGS.has(ss.alg)) continue; // §3.4 ignore unknown
      anyChecked = true;
      let ok = false, detail = '';
      try {
        const key = await fetchKey(ss.selector, sig.map.d);
        const sigBytes = b64ToBytes(ss.sig);
        if (ss.alg === 'ed25519-sha256') {
          if (key.k !== 'ed25519') { detail = 'algorithm mismatch'; }
          else ok = await verifyEd25519(key.p, sigBytes, inputHash);
        } else { // rsa-sha256
          if (key.k !== 'rsa') { detail = 'algorithm mismatch'; }
          else ok = await verifyRsa(key.p, sigBytes, inputBytes);
        }
      } catch (e) {
        detail = keyErrorDetail(e);
        if (e.message === 'key-temperror') { level.itemTemp = true; }
        else if (e.message === 'ed25519-unsupported') { detail = 'ed25519 unsupported in this browser'; }
      }
      if (!ok) allPass = false;
      level.items.push({ selector: ss.selector, algorithm: ss.alg, result: ok ? 'pass' : (detail || 'fail') });
    }
    if (!anyChecked) {
      level.result = level.result === 'fail' ? 'fail' : 'not-checked';
      if (level.result === 'not-checked') level.detail = 'no supported signature algorithm';
    } else if (!allPass) {
      if (level.itemTemp) { level.result = 'temperror'; bump('temperror'); }
      else { level.result = 'fail'; level.detail = `DKIM2-Signature i=${i} incorrect signature`; bump('fail'); }
    }
    levels.push(level);
  }

  const summary = overall === 'pass'
    ? `i=1..${maxI} verified; Message-Instance m=1..${maxM} intact`
    : levels.filter((l) => l.detail).map((l) => l.detail).join('; ') || `verification ${overall}`;
  return { overall, summary, levels };
}

function fieldFor(level) { return { name: level.field.name, value: level.field.value }; }

function recipeUndoLabel(mi) {
  try {
    const r = decodeRecipe(mi.map.r);
    return r.b === null ? 'unrecoverable' : 'failed';
  } catch (e) { return 'failed'; }
}

function keyErrorDetail(e) {
  const map = {
    'key-notfound': 'public key does not exist',
    'key-multiple': 'public key has multiple records',
    'key-syntax': 'public key has a syntax error',
    'key-revoked': 'public key has been revoked',
    'key-temperror': 'public key could not be fetched',
  };
  return map[e.message] || String(e.message || e);
}

// §11.4: inter-signature mf/rt match + d=/mf= relaxed match + nd= handling.
function custodyCheck(level, signatures, i, maxI, opts) {
  const sig = signatures[i];
  const hasNd = 'nd' in sig.map;

  if (hasNd) {
    const next = signatures[i + 1];
    if (!next) {
      // nd= on the highest signature: needs out-of-band trust (§9.3). SHOULD.
      level.custody = { ok: true, detail: `nd=${sig.map.nd} (top hop; out-of-band trust assumed)` };
      return;
    }
    if ((next.map.d || '').toLowerCase() !== sig.map.nd.toLowerCase()) {
      level.custody = { ok: false, detail: `nd= does not match i=${i + 1} d=` };
      level.custodyState = 'permerror';
    } else {
      level.custody = { ok: true, detail: `nd=${sig.map.nd} matches i=${i + 1} d=` };
    }
    return;
  }

  // d= vs mf= relaxed match (skip when mf empty, e.g. DSN).
  const mfDomain = domainOf(b64ToString(sig.map.mf || ''));
  if (mfDomain && !relaxedDomainMatch(mfDomain, (sig.map.d || '').toLowerCase())) {
    level.custody = { ok: false, detail: `i=${i} MAIL FROM and d= do not match` };
    level.custodyState = 'permerror';
    return;
  }

  // Inter-signature: mf= of this hop matches an rt= of the next-lower hop.
  if (i > 1) {
    const lower = signatures[i - 1];
    const rtDomains = (lower.map.rt || '').split(',').map((r) => domainOf(b64ToString(r)));
    const matched = rtDomains.some((rt) => relaxedDomainMatch(mfDomain, rt));
    if (!matched) {
      level.custody = { ok: false, detail: `i=${i} MAIL FROM ${mfDomain} did not match i=${i - 1} rt=` };
      level.custodyState = 'permerror';
      return;
    }
  }
  level.custody = { ok: true, detail: i === 1 ? 'origin' : 'chain intact' };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test deploy/www/verify/tests/verify.test.mjs`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add deploy/www/verify/verify.js deploy/www/verify/tests/verify.test.mjs
git commit -m "verify: §10/§11 verification orchestrator"
```

---

## Task 9: Conformance harness over the dkim2tests vectors

Drive the full core against every Turscar vector with an injected key resolver backed by `dkim2tests/dns.json`, asserting `overall` matches each vector's `ExpectedState`. This is the real end-to-end crypto/canon/chain/undo parity check.

**Files:**
- Create: `deploy/www/verify/tests/vectors.test.mjs`

**Interfaces:**
- Consumes: `verifyMessage` (Task 8), `parseKeyRecord` (Task 6), `parseToml` (Task 2), and the `dkim2tests` submodule at repo root.

- [ ] **Step 1: Write the failing test**

`deploy/www/verify/tests/vectors.test.mjs`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseToml } from './toml.mjs';
import { parseKeyRecord } from '../doh.js';
import { verifyMessage } from '../verify.js';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..', '..');
const testsDir = join(repoRoot, 'dkim2tests', 'tests');
const dnsPath = join(repoRoot, 'dkim2tests', 'dns.json');

// Mock resolver: serve keys from dns.json by selector._domainkey.domain.
const dns = JSON.parse(readFileSync(dnsPath, 'utf8'));
function makeFetchKey(extraDns = {}) {
  const table = { ...dns, ...extraDns };
  return async (selector, domain) => {
    const name = `${selector}._domainkey.${domain}`;
    const rec = table[name];
    if (rec === undefined) throw new Error('key-notfound');
    return parseKeyRecord(rec);
  };
}

// Fixed clock so timestamp checks are deterministic (vectors are dated 2026).
const NOW = 1782394336 + 3600; // just after the sample signatures

const files = readdirSync(testsDir).filter((f) => f.endsWith('.toml'));

for (const file of files) {
  const toml = parseToml(readFileSync(join(testsDir, file), 'utf8'));
  const name = toml.Name || file;
  const expected = (toml.ExpectedState || '').toLowerCase();
  if (!expected) continue;

  test(`vector ${name} -> ${expected}`, async () => {
    let msg = toml.SignedMessage;
    if (!msg && toml.SignedFile) msg = readFileSync(join(testsDir, toml.SignedFile), 'utf8');
    const fetchKey = makeFetchKey(toml.DNS || {});
    const rep = await verifyMessage(msg, {
      fetchKey,
      mailFrom: toml.MailFrom,
      rcptTo: toml.RcptTo,
      now: NOW,
    });
    assert.equal(rep.overall, expected, `${name}: ${rep.summary}`);
  });
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test deploy/www/verify/tests/vectors.test.mjs`
Expected: some vectors FAIL initially — record which. Ensure the submodule is present first: `git submodule update --init dkim2tests`.

- [ ] **Step 3: Reconcile failures against the spec**

For each failing vector, read its `.toml` (`Comments`, `Section`) and the cited spec section, and fix the corresponding module (`verify.js`, `canon.js`, `recipes.js`, or a structural check). Do NOT special-case a vector; fix the underlying rule. Common areas: exact vs relaxed domain matching (§11.4), MI-with-higher-m-than-any-sig (§11.2), duplicate-tag detection (§7/§8 "only one of each kind"), future-timestamp handling (§8.4 — `MAY` ignore future; match the vectors' expectation).

> If a genuine spec ambiguity makes a vector unverifiable in-browser (e.g. it depends on the live SMTP envelope that pasted text can't carry), skip it explicitly with `test.skip` and a one-line reason comment. Do not silently pass it.

- [ ] **Step 4: Run the full core test suite to verify all pass**

Run: `node --test deploy/www/verify/tests/`
Expected: PASS — all module tests and all non-skipped vectors green. Note in the commit message any skipped vectors and why.

- [ ] **Step 5: Commit**

```bash
git add deploy/www/verify/tests/vectors.test.mjs deploy/www/verify/*.js
git commit -m "verify: conformance harness over dkim2tests vectors (all green)"
```

---

## Task 10: Renderer, page, and wiring (browser)

`report.js`, `main.js`, `index.html`, `verify.css` are browser-only (they touch the DOM and live DoH), so they're verified in a browser (Task 11 / `/run`), not in `node --test`. The report shape they consume is already locked by Task 8 and the existing `validate.js`.

**Files:**
- Create: `deploy/www/verify/report.js`, `deploy/www/verify/main.js`, `deploy/www/verify/index.html`, `deploy/www/verify/verify.css`

**Interfaces:**
- `report.js` produces: `renderReport(report, outEl)` — clears `outEl` and renders the verdict + per-level cards. Adapted from `deploy/www/validate/validate.js` `render()`, consuming the same `Level` fields (`kind`, `i`/`m`, `tags[]`, `items[]`, `timestamp`, `custody`, `header_hash`, `body_hash`, `header_recipes[]`, `undo`, `result`, `detail`).
- `main.js` consumes: `verifyMessage` (default DoH `fetchKey`) and `renderReport`.

- [ ] **Step 1: Create `report.js`**

`deploy/www/verify/report.js`:
```js
// DOM renderer for the verification report. Adapted from validate.js render().
function el(tag, cls, txt) { const e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }
function kv(label, val) { const p = el('div', 'kv'); p.textContent = label + ': ' + val; return p; }

function tagGrid(tags) {
  const g = el('div', 'tags');
  (tags || []).forEach((t) => {
    const row = el('div', 'tagrow');
    row.appendChild(el('span', 'tagname', t.tag + '='));
    row.appendChild(el('span', 'tagval', String(t.value == null ? '' : t.value)));
    g.appendChild(row);
  });
  return g;
}

export function renderReport(rep, out) {
  out.replaceChildren();
  out.appendChild(el('p', 'verdict ' + (rep.overall || 'none'), 'Overall: ' + (rep.overall || 'none')));
  if (rep.summary) out.appendChild(el('p', 'muted', rep.summary));
  (rep.levels || []).forEach((lvl) => {
    const cls = lvl.result === 'pass' ? 'pass'
      : lvl.result === 'warn' ? 'warn'
      : lvl.result === 'not-checked' ? 'notchecked' : 'fail';
    const card = el('div', 'card ' + cls);
    if (lvl.kind === 'signature') {
      card.appendChild(el('h3', null, 'DKIM2-Signature i=' + lvl.i + ' (m=' + lvl.m + ') — ' + lvl.result));
      if (lvl.tags && lvl.tags.length) card.appendChild(tagGrid(lvl.tags));
      (lvl.items || []).forEach((it) => card.appendChild(kv('crypto', it.selector + ' / ' + it.algorithm + ' → ' + (it.result || ''))));
      if (lvl.timestamp) card.appendChild(kv('timestamp', lvl.timestamp.ok ? 'ok' : ((lvl.timestamp.status || 'fail') + ' — ' + lvl.timestamp.detail)));
      if (lvl.custody) card.appendChild(kv('chain-of-custody', lvl.custody.ok ? ('ok' + (lvl.custody.detail ? ' — ' + lvl.custody.detail : '')) : ('FAIL — ' + lvl.custody.detail)));
    } else {
      card.appendChild(el('h3', null, 'Message-Instance m=' + lvl.m + ' — ' + lvl.result));
      if (lvl.tags && lvl.tags.length) card.appendChild(tagGrid(lvl.tags));
      card.appendChild(kv('header hash', lvl.header_hash));
      card.appendChild(kv('body hash', lvl.body_hash));
      (lvl.header_recipes || []).forEach((r) => card.appendChild(kv('recipe', r.name + ': "' + r.current + '" ← "' + r.previous + '"')));
      card.appendChild(kv('undo', lvl.undo));
    }
    if (lvl.detail) card.appendChild(kv('detail', lvl.detail));
    out.appendChild(card);
  });
}
```

- [ ] **Step 2: Create `main.js`**

`deploy/www/verify/main.js`:
```js
import { verifyMessage } from './verify.js';
import { renderReport } from './report.js';

const out = document.getElementById('out');
const ta = document.getElementById('msg');

async function run() {
  out.replaceChildren(Object.assign(document.createElement('p'), { className: 'muted', textContent: 'Verifying in your browser…' }));
  try {
    const rep = await verifyMessage(ta.value);
    renderReport(rep, out);
  } catch (e) {
    out.replaceChildren(Object.assign(document.createElement('p'), { className: 'verdict fail', textContent: 'Error: ' + (e && e.message || e) }));
  }
}

document.getElementById('go').addEventListener('click', run);
document.getElementById('example').addEventListener('click', (ev) => {
  ev.preventDefault();
  ta.value = 'Paste a real DKIM2-signed message here.\n(Tip: send mail through one of the reflector-*@dkim2.com addresses, then paste the reply.)\n';
});

// One-time capability note for browsers without WebCrypto Ed25519.
(async () => {
  try {
    await globalThis.crypto.subtle.importKey('raw', new Uint8Array(32), { name: 'Ed25519' }, false, ['verify']);
  } catch (e) {
    document.getElementById('caps').textContent =
      'Note: this browser lacks WebCrypto Ed25519; ed25519-sha256 signatures will show as unsupported. Use a current Chrome, Firefox, or Safari.';
  }
})();
```

- [ ] **Step 3: Create `index.html`**

`deploy/www/verify/index.html`:
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DKIM2 browser verifier</title>
  <meta name="description" content="Paste an email and verify its DKIM2 chain entirely in your browser — no server involved.">
  <link rel="stylesheet" href="verify.css">
</head>
<body>
  <header>
    <h1>DKIM2 browser verifier</h1>
    <p>Paste a complete email below. Every DKIM2-Signature and Message-Instance
       level is verified <strong>entirely in your browser</strong> — parsing,
       hashing, and signature cryptography all run locally.
       <a href="/">About DKIM2</a> · <a href="/validate/">server validator</a></p>
    <p class="privacy">Public keys are fetched over DNS-over-HTTPS from Cloudflare
       (<code>cloudflare-dns.com</code>), so the signing domains and selectors in
       your message are sent to Cloudflare. The message body never leaves your browser.</p>
    <p id="caps" class="caps"></p>
  </header>
  <main class="cols">
    <section class="pane">
      <label for="msg">Email source</label>
      <textarea id="msg" spellcheck="false" placeholder="Paste the full message, including headers..."></textarea>
      <div class="actions">
        <button id="go">Verify</button>
        <a href="#" id="example">load example</a>
      </div>
    </section>
    <section class="pane">
      <p class="colhead">Results</p>
      <div id="out" class="out"><p class="muted">Results appear here.</p></div>
    </section>
  </main>
  <script type="module" src="main.js"></script>
</body>
</html>
```

- [ ] **Step 4: Create `verify.css`**

Copy `deploy/www/validate/validate.css` to `deploy/www/verify/verify.css` (keeps the two pages visually identical), then append classes for the new states and notes:
```bash
cp deploy/www/validate/validate.css deploy/www/verify/verify.css
```
Then append to `deploy/www/verify/verify.css`:
```css
/* browser-verifier additions */
.privacy, .caps { font-size: .85rem; color: #666; max-width: 60ch; }
.caps { color: #a15c00; }
.verdict.temperror { background: #fff4e5; color: #a15c00; }
.verdict.permerror { background: #fdecea; color: #b71c1c; }
```

- [ ] **Step 5: Smoke-check the page loads and verifies (browser)**

Serve the static dir and open the page:
```bash
python3 -m http.server -d deploy/www 8099 &
# open http://localhost:8099/verify/ , paste a reflector-fresh reply, click Verify
```
Expected: a verdict banner and per-level cards render; a known-good message shows `Overall: pass`. (Use the `/run` skill or a manual browser check.) Stop the server when done.

- [ ] **Step 6: Commit**

```bash
git add deploy/www/verify/report.js deploy/www/verify/main.js deploy/www/verify/index.html deploy/www/verify/verify.css
git commit -m "verify: browser page, renderer, and wiring"
```

---

## Task 11: Site links, deploy docs, deploy, and prod acceptance

**Files:**
- Modify: `deploy/www/index.html` (link the new verifier)
- Modify: `deploy/www/validate/index.html` (cross-link)
- Modify: `deploy/SERVER.md` or the deploy runbook (static `/verify/` location)

- [ ] **Step 1: Link the verifier from the landing page**

In `deploy/www/index.html`, in the "Learn more" `<ul>` (after line ~316), add:
```html
<li><a href="/verify/">Verify a DKIM2 message in your browser</a> — a
  standalone client-side verifier (no server round-trip)</li>
```

- [ ] **Step 2: Cross-link from the server validator**

In `deploy/www/validate/index.html`, in the header `<p>` that links to `/`, add ` · <a href="/verify/">browser verifier</a>`.

- [ ] **Step 3: Document the deploy location**

In the deploy runbook (`deploy/SERVER.md` or equivalent — check `deploy/` for the existing nginx notes), document that `/verify/` is served as static files from the same web root as `/validate/`, with no CGI/backend. Mirror however `/validate/` static assets are described.

- [ ] **Step 4: Commit the site + docs changes**

```bash
git add deploy/www/index.html deploy/www/validate/index.html deploy/SERVER.md
git commit -m "site: link the standalone browser verifier; document /verify/ deploy"
```

- [ ] **Step 5: Deploy to the box and acceptance-test on prod**

Per the project's full-change workflow (deploy everything on the box, acceptance-test on prod):
1. Deploy `deploy/www/verify/` to the dkim2.com web root using the same mechanism `/validate/` uses (see `deploy/`).
2. Load `https://dkim2.com/verify/` in a browser.
3. Send a message through `reflector-fresh@dkim2.com`, paste the reply, click Verify → expect `Overall: pass`, one signature + one instance.
4. Paste a `reflector-damage@dkim2.com` reply → expect a body-hash `mismatch` and `Overall: fail`.
5. Confirm the client-side verdict matches the server `/validate/` verdict for the same message.

Expected: live DoH key fetch to `dkim2.com` succeeds and both pages agree. Record the acceptance result.

---

## Self-Review

**Spec coverage:**
- §3.1 SHA-256 → Task 5. §3.2 RSA-SHA256 → Task 5/8. §3.3 Ed25519 (signs the hash) → Task 5/8. §3.4 ignore unknown algs → Task 8 (`SUPPORTED_ALGS`, hash-set filter). §3.6 key in DNS → Task 6.
- §4 unsigned headers → Task 4 (`isUnsignedHeader`) + Task 8 (`signedFields`). §5 recipes → Task 7. §6.1 body hash → Task 4. §6.2 header hash → Task 4.
- §7 Message-Instance (m/r/h) → Task 3 parse + Task 8 checks. §8 DKIM2-Signature tags (i/m/n/t/mf/rt/nd/d/s/f) → Task 3 parse + Task 8 structural/custody/crypto. §8.4 timestamp → Task 8 (§11.3). §8.9 s= multi-sig → Task 8. §8.10 f= flags → parsed and displayed (tags); donotmodify/donotexplode enforcement (§11.8) is out of scope for a pasted-message verifier (no policy layer) and noted below.
- §9.4 relaxed domain match → Task 8. §9.6 signing input → Task 4 (`signingInput`) + Task 8. §10 when/how thorough → Task 8 top-down walk. §11.1 states → Task 8 `overall`. §11.2 validity → Task 8 structural block. §11.3 timestamps → Task 8. §11.4 chain-of-custody → Task 8 `custodyCheck`. §11.5 fetch key (temperror/permerror distinctions) → Task 6 + Task 8. §11.6 signature calc (all sigs must pass) → Task 8. §11.7 body/header hash → Task 8.
- Conformance against real vectors → Task 9.

**Known scope limits (intentional, from the design's non-goals):**
- §11.4 top envelope match against the live SMTP MAIL FROM/RCPT TO is only exercised in the Node harness (which has `MailFrom`/`RcptTo` from the vector); the browser has no envelope for pasted text and marks it not-applicable — same limitation as the existing server `/validate/`.
- §11.8 donotmodify/donotexplode policy enforcement is not implemented (no local-policy layer in a read-only paste tool); flags are still parsed and shown.

**Placeholder scan:** No TBD/TODO; every code step contains complete code. Task 9 Step 3 is a reconciliation step, not a placeholder — it has concrete instructions and a named decision rule (fix the rule, never special-case a vector; skip only genuine envelope-dependent vectors with a reason).

**Type consistency:** `fetchKey(selector, domain) -> {k,p}` is consistent across doh.js (Task 6), verify.js (Task 8), and the harness mock (Task 9). `Report`/`Level` fields produced by `verifyMessage` (Task 8) match exactly what `renderReport` consumes (Task 10) and what the existing `validate.js` renders. `signingInput(orderedFields, targetSig)`, `canonHeaderHash(fields)`, `canonBody(body)` signatures match between Task 4 and Task 8. `applyBodyRecipe`/`applyHeaderRecipe`/`decodeRecipe`/`bodyToLines`/`linesToBody` signatures match between Task 7 and Task 8.
