// draft-ietf-dkim-dkim2-spec-09: the verifier behaviour the -09 contract
// (docs/superpowers/specs/2026-11-03-dkim2-spec-09-design.md, E1-E8)
// changes, through the REAL verifyMessage() entry point on genuinely
// Ed25519-signed chains (E3.4 is a signer's, and this verifier signs
// nothing).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyMessage } from '../verify.js';
import { selectKeyRecord, evaluatePolicy, fetchPolicy, fetchKey as dohFetchKey } from '../doh.js';
import { signChain as sign, newKeyPair, publicKeyB64, T } from './sign-chain.mjs';

// Fake DNS: every "sel*" Selector at example.com, or any name below it, or
// at xn--bcher-kva.example and below, publishes the one key; anything else
// does not exist. Every key and policy lookup is recorded.
const keyPair = newKeyPair();
const keyLookups = [];
async function fetchKey(selector, domain) {
  keyLookups.push(`${selector}._domainkey.${domain}`);
  if (!/^sel/.test(selector) || !/(?:^|\.)(?:example\.com|xn--bcher-kva\.example)$/.test(domain.toLowerCase())) {
    throw new Error('key-notfound');
  }
  return { k: 'ed25519', p: await publicKeyB64(keyPair) };
}
// policies: From domain -> the TXT records at _domainkey.<domain>, or a
// function that is called (it may throw: a temporary failure).
let policies = {};
const policyLookups = [];
async function fakePolicy(domain) {
  policyLookups.push(domain);
  const p = policies[domain];
  return typeof p === 'function' ? p() : (p || []);
}
const signChain = (states, hops) => sign(states, hops, keyPair);
function verify(msg, opts = {}) {
  keyLookups.length = 0;
  policyLookups.length = 0;
  return verifyMessage(msg, { now: T + 10, fetchKey, fetchPolicy: fakePolicy, ...opts });
}

const BODY = 'hello\r\n';
const FIELDS = (from = 'a@example.com') => [['From', from], ['Subject', 'hi']];
const one = (over = {}) => ({ d: 'example.com', m: 1, mf: '<a@example.com>', rt: ['<b@example.net>'], ...over });
const oneHop = (hop = {}, state = {}) => signChain([{ fields: FIELDS(), body: BODY, ...state }], [one(hop)]);
// One hop signed by d=<d> (mf= in d=) over From <from>.
const fromHop = (from, d) => signChain([{ fields: FIELDS(from), body: BODY }], [one({ d, mf: `<bounce@${d}>` })]);

function assertPass(rep) { assert.equal(rep.overall, 'pass', rep.summary); }
function assertPrimary(rep, overall, text) {
  assert.equal(rep.errors[0], text, rep.summary);
  assert.equal(rep.overall, overall, rep.summary);
}

// --- E1: NONE ----------------------------------------------------------------

test('E1: no DKIM2 header fields at all is NONE, "No DKIM2 header fields found"', async () => {
  const rep = await verify('From: a@example.com\r\nDKIM-Signature: v=1; d=example.com\r\n\r\nhi\r\n');
  assert.equal(rep.overall, 'none');
  assert.equal(rep.summary, 'No DKIM2 header fields found');
  assert.deepEqual(rep.errors, []);
  assert.equal(rep.fullyVerified, false);
});

test('E1: nothing else is NONE: instances alone, or signatures alone, are PERMERRORs', async () => {
  const msg = Buffer.from(await oneHop()).toString('latin1');
  const noSig = msg.replace(/^DKIM2-Signature:[^\r]*\r\n/m, '');
  assertPrimary(await verify(noSig), 'permerror', 'PERMERROR: Message-Instance m=1 is not signed');
  const noMi = msg.replace(/^Message-Instance:[^\r]*\r\n/m, '');
  assertPrimary(await verify(noMi), 'permerror', 'PERMERROR: Message-Instance m=1 missing');
});

// --- E2: a null Recipe is a PERMERROR ------------------------------------------

const FROM_LIST = [['From', 'a@example.com'], ['Subject', '[list] hi']];
const two = (over = {}) => ({ d: 'example.com', m: 2, mf: '<list@example.com>', rt: ['<c@example.net>'], ...over });
const three = (over = {}) => ({ d: 'example.com', m: 3, mf: '<fwd@example.com>', rt: ['<d@example.net>'], ...over });
const toList = (over = {}) => one({ rt: ['<list@example.com>'], ...over });
const NULL = { h: { subject: [{ d: ['hi'] }] }, b: null };
const nullAt = (m) => `PERMERROR: Message-Instance m=${m} has a null recipe`;
const lvl = (rep, m) => rep.levels.find((l) => l.kind === 'instance' && l.m === m);

test('E2: a null at the top instance is a PERMERROR naming it; no hash is checked, no key used', async () => {
  const msg = await signChain([
    { fields: FIELDS(), body: BODY },
    { fields: FROM_LIST, body: 'a whole new body\r\n', recipe: NULL },
  ], [toList(), two()]);
  const rep = await verify(msg);
  assertPrimary(rep, 'permerror', nullAt(2));
  assert.equal(rep.fullyVerified, false);
  assert.equal(lvl(rep, 2).undo, 'unrecoverable');
  assert.equal(lvl(rep, 1).header_hash, 'not-checked');
  assert.deepEqual(keyLookups, []);
  assert.doesNotMatch(rep.summary, /fully verified/);
});

test('E2: a null with nothing below it (m=1) is still a PERMERROR', async () => {
  const msg = await oneHop({}, { recipe: { b: null } });
  assertPrimary(await verify(msg), 'permerror', nullAt(1));
});

test('E2: with nulls at m=2 and m=3 the lowest is named', async () => {
  const msg = await signChain([
    { fields: FIELDS(), body: BODY },
    { fields: FROM_LIST, body: 'new\r\n', recipe: NULL },
    { fields: FROM_LIST, body: 'newer\r\n', recipe: { b: null } },
  ], [toList(), two({ rt: ['<fwd@example.com>'] }), three()]);
  const rep = await verify(msg);
  assertPrimary(rep, 'permerror', nullAt(2));
  assert.equal(rep.errors[1], nullAt(3));
});

test('E2: a lower instance\'s own Recipe fault beats a higher null; a lower null beats a higher fault', async () => {
  const states = (r2, r3) => [
    { fields: FIELDS(), body: BODY },
    { fields: FROM_LIST, body: 'new\r\n', recipe: r2 },
    { fields: FROM_LIST, body: 'newer\r\n', recipe: r3 },
  ];
  const hops = [toList(), two({ rt: ['<fwd@example.com>'] }), three()];
  assertPrimary(await verify(await signChain(states({ b: [{ c: [2, 1] }] }, { b: null }), hops)),
    'permerror', 'PERMERROR: Message-Instance m=2 recipe b[0] is invalid');
  assertPrimary(await verify(await signChain(states({ b: null }, { b: [{ c: [2, 1] }] }), hops)),
    'permerror', nullAt(2));
});

test('E2: the same instance\'s whole-document and step checks come first', async () => {
  const states = (r) => [{ fields: FIELDS(), body: BODY }, { fields: FROM_LIST, body: 'new\r\n', recipe: r }];
  assertPrimary(await verify(await signChain(states({ h: { subject: [{ x: 1 }] }, b: null }), [toList(), two()])),
    'permerror', 'PERMERROR: Message-Instance m=2 recipe h.subject[0] is invalid');
  assertPrimary(await verify(await signChain(states('{"h":{"subject":[{"d":["hi"]}]},"b":null,"b":null}'), [toList(), two()])),
    'permerror', 'PERMERROR: Message-Instance m=2 contains invalid JSON');
});

test('E2: a structure error still wins over a null', async () => {
  // m=2 holds the null and no signature covers it.
  const msg = await signChain([
    { fields: FIELDS(), body: BODY },
    { fields: FROM_LIST, body: 'new\r\n', recipe: NULL },
  ], [one()]);
  assertPrimary(await verify(msg), 'permerror', 'PERMERROR: Message-Instance m=2 is not signed');
});

test('E2: fullyVerified is true exactly for a pass', async () => {
  const rep = await verify(await oneHop());
  assertPass(rep);
  assert.equal(rep.fullyVerified, true);
});

// --- E3: Authentic From, up and down, and the Domain Policy Record -------------

const forbids = (dom) => `FAIL: DKIM2-Signature i=1 From ${dom} forbids subdomain signing`;
const NOT_AUTHENTIC = 'FAIL: DKIM2-Signature i=1 matching From is not authentic';

test('E3: the downward match (d= at or above the From domain) needs no lookup', async () => {
  policies = { 'sub.example.com': ['v=DKIM1; f=strict'], 'example.com': ['v=DKIM1; f=strict'] };
  assertPass(await verify(await fromHop('a@sub.example.com', 'example.com')));
  assertPass(await verify(await fromHop('a@example.com', 'example.com')));
  assert.deepEqual(policyLookups, []);
});

test('E3: d= below the From domain with no policy record passes, after one lookup', async () => {
  policies = {};
  const rep = await verify(await fromHop('a@example.com', 'mail.example.com'));
  assertPass(rep);
  assert.deepEqual(policyLookups, ['example.com']);
  assert.equal(rep.levels.find((l) => l.kind === 'signature').from.ok, true);
});

test('E3: neither match is "matching From is not authentic", with no lookup', async () => {
  policies = {};
  assertPrimary(await verify(await fromHop('a@sub.example.com', 'other.example.com')), 'fail', NOT_AUTHENTIC);
  assert.deepEqual(policyLookups, []);
});

for (const [records, want, what] of [
  [['v=DKIM1; f=strict'], 'strict', 'f=strict'],
  [['v=DKIM1; f=foo : strict'], 'strict', 'strict among other flags, FWS around ":"'],
  [['v=DKIM1; f=strict; f=foo'], 'strict', 'a record that does not parse (f= twice)'],
  [['v=DKIM1; f=strict:'], 'strict', 'an empty flag'],
  [['v=DKIM1; f=a::b'], 'strict', 'an empty flag in the middle'],
  [['v=DKIM1; f=-x'], 'strict', 'a flag that is not a hyphenated-word'],
  [['v=DKIM1; f=foo bar'], 'strict', 'WSP inside a flag'],
  [['v=DKIM1; garbage'], 'strict', 'a spec that is not a tag'],
  [[' v = DKIM1 ;f=strict'], 'strict', 'WSP before the first tag and around "="'],
  [['v=DKIM1'], 'pass', 'no f='],
  [['v=DKIM1; f='], 'pass', 'an empty f='],
  [['v=DKIM1; f=foo'], 'pass', 'an unknown flag'],
  [['v=DKIM1; f=Strict'], 'pass', 'flags are case sensitive'],
  [['v=DKIM1; F=strict'], 'pass', 'tag names are case sensitive (F= is unknown)'],
  [['v=spf1 -all', 'f=strict'], 'pass', 'only records that are not v=DKIM1'],
  [['V=DKIM1; f=strict'], 'pass', 'V=DKIM1 is not v=DKIM1'],
  [['v=DKIM10; f=strict'], 'pass', 'v=DKIM10 is not v=DKIM1'],
  [['v=spf1 -all', 'v=DKIM1; f=strict'], 'strict', 'one v=DKIM1 record among others'],
  [['v=DKIM1', 'v=DKIM1; f=strict'], 'multiple', 'two v=DKIM1 records'],
  [['v=DKIM1', 'v=DKIM1'], 'multiple', 'two identical v=DKIM1 records'],
]) {
  test(`E3.2: ${what}: ${JSON.stringify(records)} is ${want}`, async () => {
    policies = { 'example.com': records };
    const rep = await verify(await fromHop('a@example.com', 'mail.example.com'));
    if (want === 'pass') assertPass(rep);
    else if (want === 'strict') assertPrimary(rep, 'fail', forbids('example.com'));
    else assertPrimary(rep, 'permerror', 'PERMERROR: DKIM2-Signature i=1 multiple records for example.com policy');
    assert.deepEqual(policyLookups, ['example.com']);
  });
}

test('E3: a temporary failure is TEMPERROR "policy for <dom> unavailable"', async () => {
  policies = { 'example.com': () => { throw new Error('policy-temperror'); } };
  assertPrimary(await verify(await fromHop('a@example.com', 'mail.example.com')), 'temperror',
    'TEMPERROR: DKIM2-Signature i=1 policy for example.com unavailable');
});

test('E3: <dom> is the From domain lowercased, with no trailing dot, as A-labels', async () => {
  policies = { 'example.com': ['v=DKIM1; f=strict'], 'xn--bcher-kva.example': ['v=DKIM1; f=strict'] };
  assertPrimary(await verify(await fromHop('a@EXAMPLE.Com.', 'mail.example.com')), 'fail', forbids('example.com'));
  assert.deepEqual(policyLookups, ['example.com']);
  assertPrimary(await verify(await fromHop('u@BÜCHER.example', 'mail.xn--bcher-kva.example')), 'fail', forbids('xn--bcher-kva.example'));
  assert.deepEqual(policyLookups, ['xn--bcher-kva.example']);
});

test('E3: the exact From domain only, no walk up the tree', async () => {
  policies = { 'example.com': ['v=DKIM1; f=strict'] };
  assertPass(await verify(await fromHop('a@sub.example.com', 'mail.sub.example.com')));
  assert.deepEqual(policyLookups, ['sub.example.com']);
});

test('E3: no lookup when the message already has an error (first error wins)', async () => {
  policies = { 'example.com': ['v=DKIM1; f=strict'] };
  const msg = await fromHop('a@example.com', 'mail.example.com');
  // Expired.
  const rep = await verify(msg, { now: T + 30 * 86400 });
  assertPrimary(rep, 'fail', 'FAIL: DKIM2-Signature i=1 signature expired');
  assert.deepEqual(policyLookups, []);
  // A key that does not exist.
  const noKey = await verify(msg, { fetchKey: async () => { throw new Error('key-notfound'); } });
  assertPrimary(noKey, 'permerror', 'PERMERROR: DKIM2-Signature i=1 public key sel does not exist');
  assert.deepEqual(policyLookups, []);
});

// i=1 a.example.com over From x@example.com; a list at b.example.com
// rewrites From to y@example.com at m=2 and signs i=2. Both pairs need the
// policy of example.com.
const twoUpward = () => signChain([
  { fields: FIELDS('x@example.com'), body: BODY },
  { fields: FIELDS('y@example.com'), body: BODY, recipe: { h: { from: [{ d: ['x@example.com'] }] } } },
], [one({ d: 'a.example.com', mf: '<x@a.example.com>', rt: ['<list@b.example.com>'] }),
  two({ d: 'b.example.com', mf: '<list@b.example.com>' })]);

test('E3: one lookup per From domain per verification', async () => {
  policies = {};
  assertPass(await verify(await twoUpward()));
  assert.deepEqual(policyLookups, ['example.com']);
});

test('E3: pairs are checked in i order, the first that fails is the result', async () => {
  policies = { 'example.com': ['v=DKIM1; f=strict'] };
  const rep = await verify(await twoUpward());
  assertPrimary(rep, 'fail', forbids('example.com'));
  assert.equal(rep.errors.length, 1);
  assert.deepEqual(policyLookups, ['example.com']);
});

test('E3.1: more than one address, and a domain literal, have strings of their own', async () => {
  policies = {};
  for (const [from, want] of [
    ['a@example.com, b@example.com', 'FAIL: DKIM2-Signature i=1 From has more than one address'],
    ['list: a@example.com, b@example.com;', 'FAIL: DKIM2-Signature i=1 From has more than one address'],
    ['"a, b" <a@example.com>', null],
    ['list: a@example.com;', NOT_AUTHENTIC],
    ['undisclosed:;', NOT_AUTHENTIC],
    ['no address', NOT_AUTHENTIC],
    ['a@[192.0.2.1]', 'FAIL: DKIM2-Signature i=1 From uses a domain literal'],
    ['A <a@[IPv6:2001:db8::1]>', 'FAIL: DKIM2-Signature i=1 From uses a domain literal'],
  ]) {
    const rep = await verify(await fromHop(from, 'example.com'));
    if (want) assertPrimary(rep, 'fail', want); else assertPass(rep);
  }
  assert.deepEqual(policyLookups, []);
});

test('E3.2: a 64 KB record of WSP is judged quickly (linear-time trimming)', () => {
  const ws = ' \t'.repeat(32 * 1024);
  for (const rec of [`v=DKIM1; f=a${ws}\x01`, `v=DKIM1;${ws}f=strict${ws}`, `${ws}v=DKIM1${ws}`, `v=DKIM1; x=a${ws}b`]) {
    const t0 = process.hrtime.bigint();
    evaluatePolicy([rec]);
    // Not a timing test of the result: a quadratic trim takes seconds here.
    assert.ok(process.hrtime.bigint() - t0 < 2_000_000_000n);
  }
  assert.equal(evaluatePolicy([`v=DKIM1;${ws}f=strict${ws}`]), 'strict');
  assert.equal(evaluatePolicy([`${ws}v=DKIM1${ws}`]), 'open');
});

// --- E3 over DoH ----------------------------------------------------------------

const dohJson = (obj) => ({ ok: true, status: 200, json: async () => obj });
const txt = (name, ...data) => dohJson({ Status: 0, Answer: data.map((d) => ({ name, type: 16, data: d })) });

test('E3: fetchPolicy asks DoH for TXT at _domainkey.<dom>, and joins each RR\'s strings', async () => {
  const urls = [];
  const fetch = async (url) => { urls.push(String(url)); return txt('_domainkey.example.com', '"v=DKIM1; " "f=strict"', '"v=spf1 -all"'); };
  assert.deepEqual(await fetchPolicy('example.com', { fetch }), ['v=DKIM1; f=strict', 'v=spf1 -all']);
  const u = new URL(urls[0]);
  assert.equal(u.searchParams.get('name'), '_domainkey.example.com');
  assert.equal(u.searchParams.get('type'), 'TXT');
});

test('E3: fetchPolicy: NXDOMAIN or no TXT is none; SERVFAIL, other RCODEs, TC, 5xx, network errors are temporary', async () => {
  assert.deepEqual(await fetchPolicy('example.com', { fetch: async () => dohJson({ Status: 3 }) }), []);
  assert.deepEqual(await fetchPolicy('example.com', { fetch: async () => dohJson({ Status: 0 }) }), []);
  assert.deepEqual(await fetchPolicy('example.com', { fetch: async () => dohJson({ Status: 0, Answer: [{ type: 5, data: 'x.' }] }) }), []);
  for (const fetch of [
    async () => dohJson({ Status: 2 }),
    async () => dohJson({ Status: 5 }),
    async () => dohJson({ Status: 0, TC: true }),
    async () => ({ ok: false, status: 502, json: async () => ({}) }),
    async () => { throw new TypeError('network'); },
    async () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError('not JSON'); } }),
  ]) {
    await assert.rejects(fetchPolicy('example.com', { fetch }), /policy-temperror/);
  }
});

test('E3: over DoH, the policy is looked up lazily and never prefetched with the keys', async () => {
  const pub = await publicKeyB64(keyPair);
  const names = [];
  const answers = (records) => async (url) => {
    const name = new URL(url).searchParams.get('name');
    names.push(name);
    if (name === 'sel._domainkey.mail.example.com') return txt(name, `"v=DKIM1; k=ed25519; p=${pub}"`);
    if (name === '_domainkey.example.com') return records;
    return dohJson({ Status: 3 });
  };
  const msg = await fromHop('a@example.com', 'mail.example.com');
  const run = (records, opts = {}) => {
    names.length = 0;
    return verifyMessage(msg, { now: T + 10, dohFetch: answers(records), ...opts });
  };
  assertPrimary(await run(txt('_domainkey.example.com', '"v=DKIM1; f=strict"')), 'fail', forbids('example.com'));
  assert.deepEqual(names, ['sel._domainkey.mail.example.com', '_domainkey.example.com']);
  assertPass(await run(dohJson({ Status: 3 })));
  assertPrimary(await run(dohJson({ Status: 2 })), 'temperror', 'TEMPERROR: DKIM2-Signature i=1 policy for example.com unavailable');
  // Expired: the key is still prefetched, the policy never asked for.
  assertPrimary(await run(txt('_domainkey.example.com', '"v=DKIM1; f=strict"'), { now: T + 30 * 86400 }),
    'fail', 'FAIL: DKIM2-Signature i=1 signature expired');
  assert.deepEqual(names, ['sel._domainkey.mail.example.com']);
});

// --- E4: key records next to foreign TXT records ---------------------------------

test('E4: a record whose first tag is v= other than DKIM1 is ignored before counting', () => {
  const key = 'v=DKIM1; k=ed25519; p=AAAA';
  assert.deepEqual(selectKeyRecord(['v=spf1 -all', key]), { k: 'ed25519', p: 'AAAA' });
  assert.deepEqual(selectKeyRecord([key, 'v=DKIM2; p=BBBB', ' v = STSv1; id=1']), { k: 'ed25519', p: 'AAAA' });
  assert.deepEqual(selectKeyRecord(['k=ed25519; p=AAAA', 'v=spf1']), { k: 'ed25519', p: 'AAAA' });
  assert.throws(() => selectKeyRecord(['v=spf1 -all']), /key-notfound/);
  assert.throws(() => selectKeyRecord([]), /key-notfound/);
  // A record with no v=, or one that starts with something unparseable, is kept.
  assert.throws(() => selectKeyRecord(['k=rsa; p=BBBB', key]), /key-multiple/);
  assert.throws(() => selectKeyRecord(['garbage', key]), /key-multiple/);
  assert.throws(() => selectKeyRecord(['V=spf1', key]), /key-multiple/);
  assert.throws(() => selectKeyRecord(['garbage']), /key-syntax/);
  assert.throws(() => selectKeyRecord([key, key]), /key-multiple/);
});

test('E4: over DoH, a key next to a v=spf1 record verifies', async () => {
  const pub = await publicKeyB64(keyPair);
  const fetch = async (url) => {
    const name = new URL(url).searchParams.get('name');
    return name === 'sel._domainkey.example.com'
      ? txt(name, '"v=spf1 -all"', `"v=DKIM1; k=ed25519; p=${pub}"`) : dohJson({ Status: 3 });
  };
  assert.deepEqual(await dohFetchKey('sel', 'example.com', { fetch }), { k: 'ed25519', p: pub });
  assertPass(await verifyMessage(await oneHop(), { now: T + 10, dohFetch: fetch }));
});

// --- E5: an RSA key under 1024 bits is "too short" --------------------------------

test('E5: an RSA key under 1024 bits is "public key <s> too short"', async () => {
  const { subtle } = globalThis.crypto;
  const rsa512 = await subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 512,
    publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const p = Buffer.from(await subtle.exportKey('spki', rsa512.publicKey)).toString('base64');
  const msg = Buffer.from(await oneHop()).toString('latin1').replace(':ed25519-sha256:', ':rsa-sha256:');
  const rep = await verify(msg, { fetchKey: async () => ({ k: 'rsa', p }) });
  assertPrimary(rep, 'permerror', 'PERMERROR: DKIM2-Signature i=1 public key sel too short');
  // Base64 that is no RSA key at all stays "is malformed".
  assertPrimary(await verify(msg, { fetchKey: async () => ({ k: 'rsa', p: 'AAAAAAAA' }) }), 'permerror',
    'PERMERROR: DKIM2-Signature i=1 public key sel is malformed');
});

// --- E6: strings, and the i=1 exploded flag ---------------------------------------

test('E6: an exploded flag at i=1 is a PERMERROR, before any key is fetched', async () => {
  for (const f of ['exploded', 'feedback,exploded', 'feedback , exploded']) {
    const rep = await verify(await oneHop({ f }));
    assertPrimary(rep, 'permerror', 'PERMERROR: DKIM2-Signature i=1 has an exploded flag');
    assert.deepEqual(keyLookups, []);
  }
});

test('E6: "exploded" is matched exactly, and only i=1 is barred from it', async () => {
  assertPass(await verify(await oneHop({ f: 'feedback' })));
  assertPass(await verify(await oneHop({ f: 'Exploded' })));
  assertPass(await verify(await oneHop({ f: 'explodedx' })));
  const msg = await signChain([
    { fields: FIELDS(), body: BODY },
    { fields: FROM_LIST, body: BODY, recipe: { h: { subject: [{ d: ['hi'] }] } } },
  ], [toList(), two({ f: 'exploded' })]);
  assertPass(await verify(msg));
});

test('E6: the exploded check comes after tag syntax and before duplicate selectors', async () => {
  // A t= that is not 1*DIGIT is a syntax error first.
  assertPrimary(await verify(await oneHop({ f: 'exploded', t: '12a' })), 'permerror', 'PERMERROR: DKIM2-Signature i=1 syntax error');
  assertPrimary(await verify(await oneHop({ f: 'exploded', sets: [{ sel: 'sel1' }, { sel: 'sel1' }] })),
    'permerror', 'PERMERROR: DKIM2-Signature i=1 has an exploded flag');
  // A tag missing comes first too.
  const msg = Buffer.from(await oneHop({ f: 'exploded' })).toString('latin1').replace(/; t=\d+/, '');
  assertPrimary(await verify(msg), 'permerror', 'PERMERROR: DKIM2-Signature i=1 tag=t missing');
});

test('E6: "is duplicated", lower-case "recipe ... is invalid", "mf= and d= do not match"', async () => {
  const msg = Buffer.from(await oneHop()).toString('latin1');
  const mi = /^Message-Instance:[^\r]*\r\n/m.exec(msg)[0];
  assertPrimary(await verify(msg.replace(mi, mi + mi)), 'permerror', 'PERMERROR: Message-Instance m=1 is duplicated');
  const sig = /^DKIM2-Signature:[^\r]*\r\n/m.exec(msg)[0];
  assertPrimary(await verify(msg.replace(sig, sig + sig)), 'permerror', 'PERMERROR: DKIM2-Signature i=1 is duplicated');
  const bad = await signChain([
    { fields: FIELDS(), body: BODY },
    { fields: FROM_LIST, body: BODY, recipe: { b: [{ c: [2, 1] }] } },
  ], [toList(), two()]);
  assertPrimary(await verify(bad), 'permerror', 'PERMERROR: Message-Instance m=2 recipe b[0] is invalid');
  assertPrimary(await verify(await oneHop({ mf: '<a@example.net>' })), 'fail', 'FAIL: DKIM2-Signature i=1 mf= and d= do not match');
});
