// A null body Recipe ("b": null, spec-06 §5.2) means the previous BODY cannot
// be recreated, but header Recipes are mandatory so the header history below
// it is still checked (header hashes only; the body is not-checked).
// Vectors come from util/build-negative-vectors.py, as in negative-vectors.sh.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseKeyRecord } from '../doh.js';
import { bytesToBinary } from '../b64.js';
import { verifyMessage } from '../verify.js';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..', '..');
const dns = JSON.parse(readFileSync(join(repoRoot, 'dns.json'), 'utf8'));
const fetchKey = (selector, domain) => {
  const rec = dns[domain]?.[`${selector}._domainkey`]?.[0]?.[1];
  if (rec === undefined) throw new Error('key-notfound');
  return parseKeyRecord(rec);
};
const tmp = mkdtempSync(join(tmpdir(), 'nullbody-'));
execFileSync('python3', [join(repoRoot, 'util', 'build-negative-vectors.py'), tmp], { stdio: 'ignore' });
execFileSync('python3', [join(here, 'build-null-fixtures.py'), tmp], { stdio: 'ignore' });

async function run(file) {
  const msg = new Uint8Array(readFileSync(join(tmp, file)));
  const ts = [...bytesToBinary(msg).matchAll(/[;\s]t=(\d+)/gi)].map((m) => parseInt(m[1], 10));
  return verifyMessage(msg, { fetchKey, now: Math.max(...ts, 0) + 3600 });
}

test('null body Recipe at m=2 over signed m=1 passes', async () => {
  const rep = await run('positive-control-null-body.eml');
  assert.equal(rep.overall, 'pass', rep.summary);
  const m1 = rep.levels.find((l) => l.kind === 'instance' && l.m === 1);
  assert.equal(m1.header_hash, 'match');
  assert.equal(m1.body_hash, 'not-checked');
  assert.match(rep.summary, /body not checked below m=2/);
});

test('null body Recipe at m=3 over a normal m=2 passes', async () => {
  const rep = await run('positive-control-null-body-over-recipe.eml');
  assert.equal(rep.overall, 'pass', rep.summary);
  const lv = (m) => rep.levels.find((l) => l.kind === 'instance' && l.m === m);
  assert.equal(lv(3).undo, 'unrecoverable');
  assert.equal(lv(2).header_hash, 'match');
  assert.equal(lv(2).body_hash, 'not-checked');
  assert.equal(lv(1).header_hash, 'match');
});

test('forged history below a null body Recipe fails on the m=1 header hash', async () => {
  const rep = await run('null-body-forged-history.eml');
  assert.notEqual(rep.overall, 'pass');
  assert.match(rep.summary, /m=1 .*header hash mismatch/);
});

const lv = (rep, m) => rep.levels.find((l) => l.kind === 'instance' && l.m === m);

test('null at m=2 below an ordinary m=3 passes; every null instance is unrecoverable', async () => {
  const rep = await run('null-below-ordinary.eml');
  assert.equal(rep.overall, 'pass', rep.summary);
  assert.equal(lv(rep, 3).body_hash, 'match');
  assert.equal(lv(rep, 2).undo, 'unrecoverable');
  assert.equal(lv(rep, 1).body_hash, 'not-checked');
});

test('forged To: hidden in the null instance below an ordinary m=3 fails at m=1 header hash', async () => {
  const rep = await run('null-below-ordinary-forged.eml');
  assert.notEqual(rep.overall, 'pass');
  assert.match(rep.summary, /m=1 .*header hash mismatch/);
});

test('empty body, null body Recipe, header-only history passes', async () => {
  const rep = await run('empty-body-null.eml');
  assert.equal(rep.overall, 'pass', rep.summary);
  assert.equal(lv(rep, 1).header_hash, 'match');
});

test('empty body, null body Recipe, hidden To: change fails at m=1 header hash', async () => {
  const rep = await run('empty-body-null-forged.eml');
  assert.notEqual(rep.overall, 'pass');
  assert.match(rep.summary, /m=1 .*header hash mismatch/);
});

test('empty body, ordinary header-only Recipe passes; hidden To: fails', async () => {
  const ok = await run('empty-body-plain.eml');
  assert.equal(ok.overall, 'pass', ok.summary);
  const bad = await run('empty-body-plain-forged.eml');
  assert.notEqual(bad.overall, 'pass');
  assert.match(bad.summary, /m=1 .*header hash mismatch/);
});

for (const f of ['bad-body-int-below-null.eml', 'bad-body-steps-below-null.eml']) {
  test(`malformed body Recipe below a null is a malformed-Recipe PERMERROR (${f})`, async () => {
    const rep = await run(f);
    assert.equal(rep.overall, 'permerror', rep.summary);
    assert.match(rep.summary, /PERMERROR Message-Instance m=2 has a malformed Recipe/);
    assert.equal(lv(rep, 2).undo, 'failed');
    assert.equal(lv(rep, 1).undo, 'failed');
  });
}

test('a header Recipe that does not apply below the null (re-signed) is a malformed-Recipe PERMERROR', async () => {
  const rep = await run('bad-header-below-null.eml');
  assert.equal(rep.overall, 'permerror', rep.summary);
  assert.match(rep.summary, /PERMERROR Message-Instance m=2 has a malformed Recipe/);
  assert.equal(lv(rep, 2).undo, 'failed');
  assert.equal(lv(rep, 1).undo, 'failed');
});

test.after(() => rmSync(tmp, { recursive: true, force: true }));
