import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseToml } from './toml.mjs';
import { parseKeyRecord } from '../doh.js';
import { verifyMessage } from '../verify.js';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..', '..');
const testsDir = join(repoRoot, 'dkim2tests', 'tests');
const dnsPath = join(repoRoot, 'dkim2tests', 'dns.json');

// Mock resolver: serve keys from dns.json by selector._domainkey.domain,
// merged with each vector's own [DNS] table (vector wins on conflict).
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

// Pick a deterministic clock PER VECTOR so that the §11.3 "older than 14 days"
// rule never spuriously expires a well-formed sample: use the newest t= across
// all DKIM2-Signature headers in the message + 1h. None of the current vectors
// is about timestamp expiry, so this cannot mask a genuine expiry vector; if
// the message has no parseable t=, fall back to just after the sample epoch.
function pickNow(msg) {
  const ts = [...(msg || '').matchAll(/[;\s]t=(\d+)/gi)].map((m) => parseInt(m[1], 10));
  const max = ts.filter(Number.isFinite).reduce((a, b) => Math.max(a, b), 0);
  return (max || 1782394336) + 3600;
}

const files = readdirSync(testsDir).filter((f) => f.endsWith('.toml'));

// Upstream vectors we cannot honour because the fixture itself is broken.
// tags_whitespace: the generator (dkim2tests commit 9c48edf) emitted an EMPTY
// s= signature value ("...s = rsa2048:rsa-sha256:" with no bytes) while still
// labelling ExpectedState='pass'; no conformant verifier can accept a signature
// that is not present, so this is a fixture bug, not a rule to implement. (The
// repo's other reference runners skip it for the same reason.)
const BROKEN_VECTORS = new Set(['tags_whitespace']);

for (const file of files) {
  const toml = parseToml(readFileSync(join(testsDir, file), 'utf8'));
  const name = toml.Name || file;
  const expected = (toml.ExpectedState || '').toLowerCase();
  if (!expected) continue;

  const run = BROKEN_VECTORS.has(name) ? test.skip : test;
  run(`vector ${name} -> ${expected}`, async () => {
    let msg = toml.SignedMessage;
    if (!msg && toml.SignedFile) msg = readFileSync(join(testsDir, toml.SignedFile), 'utf8');
    const fetchKey = makeFetchKey(toml.DNS || {});
    const rep = await verifyMessage(msg, {
      fetchKey,
      mailFrom: toml.MailFrom,
      rcptTo: toml.RcptTo,
      now: pickNow(msg),
    });
    assert.equal(rep.overall, expected, `${name}: ${rep.summary}`);
  });
}
