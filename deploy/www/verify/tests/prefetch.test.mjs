// Public-key prefetch: every DoH lookup the DKIM2-Signatures need starts
// together, before any signature is checked, once per name; an answer that
// does not settle it (SERVFAIL, network error) is looked up again the
// ordinary way, so every verdict is what it was without the prefetch.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyMessage } from '../verify.js';
import { fetchKey as dohFetchKey } from '../doh.js';
import { bytesToBinary } from '../b64.js';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..', '..');
// Five hops, five distinct keys (test1..test5.dkim2.com), all in dns.json.
const MSG = new Uint8Array(readFileSync(join(repoRoot, 'perl', 'tests', 'expected', 'chain-hop5-final-delivery.eml')));
const NOW = Math.max(...[...bytesToBinary(MSG).matchAll(/[;\s]t=(\d+)/g)].map((m) => +m[1])) + 3600;
const dns = {};
for (const [domain, names] of Object.entries(JSON.parse(readFileSync(join(repoRoot, 'dns.json'), 'utf8')))) {
  for (const [name, recs] of Object.entries(names)) dns[`${name}.${domain}`] = recs[0][1];
}
const NAMES = ['sel1._domainkey.test1.dkim2.com', 'sel2._domainkey.test2.dkim2.com', 'sel3._domainkey.test3.dkim2.com',
  'sel1._domainkey.test4.dkim2.com', 'sel2._domainkey.test5.dkim2.com'];

const json = (obj) => ({ ok: true, status: 200, json: async () => obj });
const answer = (name) => (dns[name] === undefined
  ? json({ Status: 3 })
  : json({ Status: 0, Answer: [{ name, type: 16, data: dns[name] }] }));

// A fake DoH fetch: records each query name; `respond(name, n)` gives the
// n-th (1-based) response for a name (a response object, or throws).
function fakeDoh(respond = (name) => answer(name)) {
  const calls = [];
  const fetch = async (url) => {
    const name = new URL(url).searchParams.get('name');
    calls.push(name);
    return respond(name, calls.filter((c) => c === name).length);
  };
  return { fetch, calls, count: (name) => calls.filter((c) => c === name).length };
}

// The verdict without any prefetch: the same DoH answers, through the
// ordinary per-signature lookup (an override key source, so no prefetch).
async function ordinary(respond) {
  const doh = fakeDoh(respond);
  return verifyMessage(MSG, { now: NOW, fetchKey: (s, d) => dohFetchKey(s, d, { fetch: doh.fetch }) });
}

test('every key is requested before any is answered, once each', async () => {
  // Hold every answer until all five names have been asked for. Without a
  // prefetch the first signature check waits on its own lookup and never
  // asks for the others; the safety release only stops that hanging.
  let release;
  const gate = new Promise((r) => { release = r; });
  const safety = setTimeout(() => release(), 2000);
  let askedWhenReleased = null;
  const doh = fakeDoh(async (name) => {
    if (new Set(doh.calls).size === NAMES.length && askedWhenReleased === null) {
      askedWhenReleased = [...new Set(doh.calls)];
      release();
    }
    await gate;
    return answer(name);
  });
  const rep = await verifyMessage(MSG, { now: NOW, dohFetch: doh.fetch });
  clearTimeout(safety);
  assert.deepEqual((askedWhenReleased || []).sort(), [...NAMES].sort());
  for (const n of NAMES) assert.equal(doh.count(n), 1, n);
  assert.equal(rep.overall, 'pass', rep.summary);
  assert.deepEqual(rep, await ordinary(answer));
});

test('a name shared by two signatures is looked up once', async () => {
  // Point two hops at the same key name: the second signature fails its
  // crypto, but there is still one lookup per name.
  const bin = bytesToBinary(MSG).replace('d=test5.dkim2.com', 'd=test4.dkim2.com').replace('s=sel2:rsa-sha256:OUwr', 's=sel1:rsa-sha256:OUwr');
  const msg = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  const doh = fakeDoh();
  await verifyMessage(msg, { now: NOW, dohFetch: doh.fetch });
  assert.equal(doh.count('sel1._domainkey.test4.dkim2.com'), 1);
  assert.equal(doh.count('sel2._domainkey.test5.dkim2.com'), 0);
});

for (const [what, bad] of [
  ['SERVFAIL', () => json({ Status: 2 })],
  ['HTTP 503', () => ({ ok: false, status: 503, json: async () => ({}) })],
  ['a network error', () => { throw new TypeError('network down'); }],
  ['a bad JSON body', () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError('bad json'); } })],
]) {
  test(`${what} on the prefetch is looked up again the ordinary way`, async () => {
    const victim = NAMES[2];
    const respond = (name, n) => (name === victim && n === 1 ? bad() : answer(name));
    const doh = fakeDoh(respond);
    const rep = await verifyMessage(MSG, { now: NOW, dohFetch: doh.fetch });
    assert.equal(rep.overall, 'pass', rep.summary);
    assert.equal(doh.count(victim), 2);
    for (const n of NAMES.filter((x) => x !== victim)) assert.equal(doh.count(n), 1, n);
  });

  test(`${what} every time gives the same verdict as without the prefetch`, async () => {
    const victim = NAMES[2];
    const respond = (name) => (name === victim ? bad() : answer(name));
    const rep = await verifyMessage(MSG, { now: NOW, dohFetch: fakeDoh(respond).fetch });
    const before = await ordinary(respond);
    assert.notEqual(before.overall, 'pass');
    assert.deepEqual(rep, before);
  });
}

for (const [what, resp] of [
  ['NXDOMAIN', () => json({ Status: 3 })],
  ['NOERROR without a TXT record', () => json({ Status: 0, Answer: [{ type: 5, data: 'x.example.' }] })],
  ['two TXT records', () => json({ Status: 0, Answer: [{ type: 16, data: 'p=AAAA' }, { type: 16, data: 'p=AAAA' }] })],
  ['a revoked key', () => json({ Status: 0, Answer: [{ type: 16, data: 'v=DKIM1; p=' }] })],
]) {
  test(`${what} on the prefetch is used as it is`, async () => {
    const victim = NAMES[1];
    const respond = (name) => (name === victim ? resp() : answer(name));
    const doh = fakeDoh(respond);
    const rep = await verifyMessage(MSG, { now: NOW, dohFetch: doh.fetch });
    assert.equal(doh.count(victim), 1);
    assert.deepEqual(rep, await ordinary(respond));
  });
}

test('no prefetch with an override key source', async () => {
  const doh = fakeDoh();
  const asked = [];
  const rep = await verifyMessage(MSG, {
    now: NOW, dohFetch: doh.fetch,
    fetchKey: (s, d) => { asked.push(`${s}._domainkey.${d}`); return dohFetchKey(s, d, { fetch: async (u) => answer(new URL(u).searchParams.get('name')) }); },
  });
  assert.equal(rep.overall, 'pass', rep.summary);
  assert.equal(doh.calls.length, 0);
  assert.equal(asked.length, NAMES.length);
});

test('no prefetch for algorithms not implemented, or a message that fails §11.2', async () => {
  const bin = bytesToBinary(MSG).replace('s=sel2:rsa-sha256:OUwr', 's=sel2:rsa-sha1:OUwr');
  const doh = fakeDoh();
  await verifyMessage(Uint8Array.from(bin, (c) => c.charCodeAt(0)), { now: NOW, dohFetch: doh.fetch });
  assert.equal(doh.count('sel2._domainkey.test5.dkim2.com'), 0);
  const broken = fakeDoh();
  const rep = await verifyMessage('DKIM2-Signature: i=2; m=1; t=1; d=x.example; s=a:rsa-sha256:AAAA; nd=y\r\n\r\nhi\r\n', { dohFetch: broken.fetch });
  assert.equal(rep.overall, 'permerror');
  assert.equal(broken.calls.length, 0);
});
