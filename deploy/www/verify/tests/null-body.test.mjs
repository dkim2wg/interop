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

async function run(file, edit) {
  let msg = new Uint8Array(readFileSync(join(tmp, file)));
  if (edit) msg = Uint8Array.from(Buffer.from(edit(Buffer.from(msg).toString('latin1')), 'latin1'));
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

test('a header Recipe that does not apply below the null fails', async () => {
  // Corrupt the "h" of m=2's Recipe in the m=3-null chain: point a "c" range
  // beyond the field count. The tampered r= is base64 JSON; rewrite it.
  const rep = await run('positive-control-null-body-over-recipe.eml', (text) => {
    return text.replace(/(Message-Instance: m=2;[^]*?\br=)([A-Za-z0-9+\/=\s]+?)(;|\r?\n(?=\S))/, (all, pre, b64, post) => {
      const json = JSON.parse(Buffer.from(b64.replace(/\s+/g, ''), 'base64').toString('utf8'));
      const h = json.h || {};
      h.subject = [{ c: [5, 9] }];
      json.h = h;
      return pre + Buffer.from(JSON.stringify(json)).toString('base64') + post;
    });
  });
  assert.notEqual(rep.overall, 'pass');
});

test.after(() => rmSync(tmp, { recursive: true, force: true }));
