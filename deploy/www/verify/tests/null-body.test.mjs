// A null body Recipe ("b": null, §5.2) means the previous body cannot be
// recreated. Since draft -09 (§13, §14.2; contract E2) that is a PERMERROR,
// "Message-Instance m=<x> has a null recipe", made in the §14.2
// per-instance content checks: ascending m=, right after that instance's
// own Recipe checks. So the lowest null is named, a lower instance's own
// Recipe fault beats a higher null, and nothing below a null is walked (a
// forged history below one is never reached).
// Vectors come from build-null-fixtures.py, over the chain builder of
// util/build-negative-vectors.py (as in negative-vectors.sh).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { selectKeyRecord } from '../doh.js';
import { bytesToBinary } from '../b64.js';
import { verifyMessage } from '../verify.js';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..', '..');
const dns = JSON.parse(readFileSync(join(repoRoot, 'dns.json'), 'utf8'));
const fetchKey = (selector, domain) => selectKeyRecord(
  (dns[domain]?.[`${selector}._domainkey`] || []).filter(([t]) => t === 'txt').map(([, v]) => v));
const fetchPolicy = (domain) => (dns[domain]?._domainkey || []).filter(([t]) => t === 'txt').map(([, v]) => v);
const tmp = mkdtempSync(join(tmpdir(), 'nullbody-'));
execFileSync('python3', [join(here, 'build-null-fixtures.py'), tmp], { stdio: 'ignore' });

async function run(file) {
  const msg = new Uint8Array(readFileSync(join(tmp, file)));
  const ts = [...bytesToBinary(msg).matchAll(/[;\s]t=(\d+)/gi)].map((m) => parseInt(m[1], 10));
  return verifyMessage(msg, { fetchKey, fetchPolicy, now: Math.max(...ts, 0) + 3600 });
}

const lv = (rep, m) => rep.levels.find((l) => l.kind === 'instance' && l.m === m);
const nullAt = (m) => `PERMERROR: Message-Instance m=${m} has a null recipe`;

function assertNull(rep, m) {
  assert.equal(rep.overall, 'permerror', rep.summary);
  assert.equal(rep.errors[0], nullAt(m), rep.summary);
  assert.equal(rep.fullyVerified, false);
  assert.equal(lv(rep, m).result, 'permerror');
  assert.equal(lv(rep, m).undo, 'unrecoverable');
  // Nothing is walked, and no key is used.
  for (const l of rep.levels) if (l.kind === 'instance') assert.equal(l.header_hash, 'not-checked');
  for (const l of rep.levels) if (l.kind === 'signature') assert.deepEqual(l.items, []);
}

for (const [file, m, what] of [
  ['null-body.eml', 2, 'null at m=2 over a signed m=1'],
  ['null-body-over-recipe.eml', 3, 'null at m=3 over an ordinary m=2'],
  ['null-body-forged-history.eml', 2, 'a forged history below the null is never reached'],
  ['null-below-ordinary.eml', 2, 'null at m=2 below an ordinary m=3'],
  ['null-below-ordinary-forged.eml', 2, 'null at m=2, forged To:, below an ordinary m=3'],
  ['empty-body-null.eml', 2, 'empty body, null body Recipe'],
  ['empty-body-null-forged.eml', 2, 'empty body, null body Recipe, hidden To: change'],
  ['bad-header-below-null.eml', 3, 'a header Recipe below the null that would not apply'],
]) {
  test(`E2: ${what} is "${nullAt(m)}" (${file})`, async () => assertNull(await run(file), m));
}

test('empty body, ordinary header-only Recipe passes; hidden To: fails', async () => {
  const ok = await run('empty-body-plain.eml');
  assert.equal(ok.overall, 'pass', ok.summary);
  assert.equal(ok.fullyVerified, true);
  const bad = await run('empty-body-plain-forged.eml');
  assert.notEqual(bad.overall, 'pass');
  assert.match(bad.summary, /FAIL: Message-Instance m=1 header hash sha256 mismatch/);
});

for (const [f, want] of [
  ['bad-body-int-below-null.eml', 'PERMERROR: Message-Instance m=2 contains invalid JSON'],
  ['bad-body-steps-below-null.eml', 'PERMERROR: Message-Instance m=2 recipe b[0] is invalid'],
]) {
  test(`E2: a bad body Recipe below a null beats the null (${f})`, async () => {
    const rep = await run(f);
    assert.equal(rep.overall, 'permerror', rep.summary);
    assert.equal(rep.errors[0], want, rep.summary);
    assert.equal(rep.errors[1], nullAt(3), rep.summary);
    assert.equal(lv(rep, 2).undo, 'failed');
    assert.equal(lv(rep, 1).undo, 'failed');
  });
}

test.after(() => rmSync(tmp, { recursive: true, force: true }));
