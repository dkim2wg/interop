// draft-ietf-dkim-dkim2-spec-08: the verifier behaviour the -08 contract
// (docs/superpowers/specs/2026-10-28-dkim2-spec-08-design.md, D1-D13)
// changes, through the REAL verifyMessage() entry point on genuinely
// Ed25519-signed chains.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyMessage } from '../verify.js';
import { parseTagList } from '../parse.js';
import { signChain as sign, newKeyPair, publicKeyB64, T } from './sign-chain.mjs';

// Fake DNS: every "sel*" Selector at example.com publishes the one key;
// "tmp" cannot be fetched; anything else does not exist. Every lookup is
// recorded in `lookups`.
const keyPair = newKeyPair();
const lookups = [];
async function fetchKey(selector, domain) {
  lookups.push(selector);
  if (selector === 'tmp') throw new Error('key-temperror');
  if (!/^sel/.test(selector) || domain.toLowerCase() !== 'example.com') throw new Error('key-notfound');
  return { k: 'ed25519', p: await publicKeyB64(keyPair) };
}
const signChain = (states, hops) => sign(states, hops, keyPair);
const verify = (msg, opts = {}) => verifyMessage(msg, { now: T + 10, fetchKey, ...opts });

const FIELDS = [['From', 'a@example.com'], ['Subject', 'hi']];
const BODY = 'hello\r\n';
const one = (over = {}) => ({ d: 'example.com', m: 1, mf: '<a@example.com>', rt: ['<b@example.net>'], ...over });
const oneHop = (hop = {}, state = {}) => signChain([{ fields: FIELDS, body: BODY, ...state }], [one(hop)]);

// msg with every `from` replaced by `to` (binary strings), after signing.
const edit = (msg, from, to) => {
  const text = Buffer.from(msg).toString('latin1');
  assert.ok(text.includes(from), `no ${from}`);
  return new Uint8Array(Buffer.from(text.split(from).join(to), 'latin1'));
};

function assertPass(rep) { assert.equal(rep.overall, 'pass', rep.summary); }
function assertPrimary(rep, overall, text) {
  assert.equal(rep.errors[0], text, rep.summary);
  assert.equal(rep.overall, overall, rep.summary);
}

// --- D10: tag names are strictly lowercase ----------------------------------

test('D10: parseTagList keeps tag names as written', () => {
  const { map, tags } = parseTagList('i=1; M=2; m=1');
  assert.equal(map.m, '1');
  assert.equal(map.M, '2');
  assert.deepEqual(tags.map((t) => t.tag), ['i', 'M', 'm']);
});

test('D10: an uppercase tag name is an unknown tag, so D= alone is "tag=d missing"', async () => {
  const msg = edit(await oneHop(), '; d=example.com', '; D=example.com');
  assertPrimary(await verify(msg), 'permerror', 'PERMERROR: DKIM2-Signature i=1 tag=d missing');
});

test('D10: an uppercase twin of a tag is not a duplicate, and is ignored', async () => {
  assertPass(await verify(await oneHop({ extra: '; N=x; n=y' })));
  assertPass(await verify(await oneHop({}, { extra: '; M=2' })));
});

test('D10: a Message-Instance with only M= is "tag=m missing"', async () => {
  const msg = edit(await oneHop(), 'Message-Instance: m=1;', 'Message-Instance: M=1;');
  assertPrimary(await verify(msg), 'permerror', 'PERMERROR: Message-Instance m= tag=m missing');
});

// --- D2, D3, D8: "|" groups of "," lists of signatures ------------------------

// s= from a compact layout: "sel1 | sel2!, x:mldsa44" -- "!" a corrupted
// value, ":alg" another algorithm (with a valid-looking base64 value).
const sLayout = (layout) => {
  const sets = [];
  for (const m of layout.matchAll(/([|,]?)\s*([\w.-]+)(!?)(?::([\w-]+))?\s*/g)) {
    sets.push({ sep: m[1] || ',', sel: m[2], bad: m[3] === '!', ...(m[4] ? { alg: m[4], sig: 'AAAA' } : {}) });
  }
  return oneHop({ sets });
};
const SIG = 'DKIM2-Signature i=1';

for (const layout of ['sel1! | sel2', 'sel1 | sel2!', 'sel1, sel2', 'sel1 | x:mldsa44', 'x:mldsa44 | sel1',
  'x:mldsa44-ed25519-sha512 | sel1', 'nokey | sel1', 'tmp | sel1', 'sel1, sel2 | sel3!', 'sel1 , sel2, sel3',
  'sel1,sel2,sel3,sel4,sel5,sel6,sel7,sel8']) {
  test(`D3: s= ${layout} passes`, async () => assertPass(await verify(await sLayout(layout))));
}

for (const [layout, state, text] of [
  ['sel1! | sel2!', 'fail', `FAIL: ${SIG} no group of signatures passed`],
  ['sel1, sel2!', 'fail', `FAIL: ${SIG} selector sel2 incorrect signature`],
  ['sel1!, sel2!', 'fail', `FAIL: ${SIG} selector sel1 incorrect signature`],
  ['sel1, x:mldsa44', 'permerror', `PERMERROR: ${SIG} selector x algorithm unknown`],
  ['x:mldsa44', 'permerror', `PERMERROR: ${SIG} selector x algorithm unknown`],
  ['x:mldsa44-ed25519-sha512', 'permerror', `PERMERROR: ${SIG} selector x algorithm unknown`],
  ['sel1:RSA-SHA256', 'permerror', `PERMERROR: ${SIG} selector sel1 algorithm unknown`],
  ['nokey, sel1', 'permerror', `PERMERROR: ${SIG} public key nokey does not exist`],
  ['nokey | x:mldsa44', 'permerror', `PERMERROR: ${SIG} public key nokey does not exist`],
  ['x:mldsa44 | nokey', 'permerror', `PERMERROR: ${SIG} selector x algorithm unknown`],
  ['x:mldsa44, sel1!', 'fail', `FAIL: ${SIG} selector sel1 incorrect signature`],
  ['sel1, tmp', 'temperror', `TEMPERROR: ${SIG} public key tmp could not be fetched`],
  ['sel1!, tmp', 'fail', `FAIL: ${SIG} selector sel1 incorrect signature`],
  ['tmp | sel1!', 'temperror', `TEMPERROR: ${SIG} public key tmp could not be fetched`],
  ['sel1! | tmp', 'temperror', `TEMPERROR: ${SIG} public key tmp could not be fetched`],
  ['sel1! | nokey', 'fail', `FAIL: ${SIG} no group of signatures passed`],
]) {
  test(`D3: s= ${layout} is ${text}`, async () => assertPrimary(await verify(await sLayout(layout)), state, text));
}

test('D3, D8: no key is fetched for an algorithm that is not implemented', async () => {
  lookups.length = 0;
  assertPass(await verify(await sLayout('x:mldsa44 | sel1')));
  assert.deepEqual(lookups, ['sel1']);
});

test('D3: every sig-set is verified, a "|" alternative that passes included', async () => {
  lookups.length = 0;
  assertPass(await verify(await sLayout('sel1 | sel2')));
  assert.deepEqual(lookups.sort(), ['sel1', 'sel2']);
});

for (const [layout, text] of [
  ['sel1 || sel2', 'syntax error'],
  ['|sel1', 'syntax error'],
  ['sel1 |', 'syntax error'],
  ['sel1 ,', 'syntax error'],
  ['sel1 ,| sel2', 'syntax error'],
  ['sel1 | sel1', 'has a duplicate selector'],
  ['sel1, sel2 | SEL1', 'has a duplicate selector'],
  ['sel1,sel2,sel3,sel4,sel5,sel6,sel7,sel8 | sel9', 'has more than 8 signatures'],
  ['sel1,x1:a,x2:b,x3:c,x4:d,x5:e,x6:f,x7:g,x8:h', 'has more than 8 signatures'],
]) {
  test(`D2, D3: s= ${layout} is "${text}", before any key is fetched`, async () => {
    // The s= value written as given (each name as name:alg:AAAA), after
    // signing: the error is found before the signature is checked.
    const s = layout.replace(/([\w.-]+)(?::([\w-]+))?/g, (_m, sel, alg) => `${sel}:${alg || 'ed25519-sha256'}:AAAA`);
    const text0 = Buffer.from(await oneHop()).toString('latin1');
    const msg = new Uint8Array(Buffer.from(text0.replace(/; s=[^\r\n]*/, `; s=${s}`), 'latin1'));
    lookups.length = 0;
    assertPrimary(await verify(msg), 'permerror', `PERMERROR: ${SIG} ${text}`);
    assert.deepEqual(lookups, []);
  });
}

test('D3: a value that is not a base64string is a syntax error whatever its algorithm', async () => {
  const msg = await oneHop({ sets: [{ sel: 'sel1' }, { sep: '|', sel: 'x', alg: 'future', sig: '@@@@' }] });
  assertPrimary(await verify(msg), 'permerror', `PERMERROR: ${SIG} syntax error`);
  const empty = await oneHop({ sets: [{ sel: 'sel1' }, { sep: '|', sel: 'x', alg: 'future', sig: '' }] });
  assertPrimary(await verify(empty), 'permerror', `PERMERROR: ${SIG} syntax error`);
});

// The contract does not order these; syntax first (as h=, and C9's "tag-list
// syntax, then ... duplicate selector") -- see the report.
test('D3: a value that is not base64 is a syntax error before a duplicate selector or the limit', async () => {
  const text0 = Buffer.from(await oneHop()).toString('latin1');
  const withS = (s) => new Uint8Array(Buffer.from(text0.replace(/; s=[^\r\n]*/, `; s=${s}`), 'latin1'));
  const nine = [1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => `sel${n}:ed25519-sha256:${n === 9 ? '@@@@' : 'AAAA'}`).join(',');
  for (const s of ['sel1:ed25519-sha256:AAAA|sel1:ed25519-sha256:@@@@', 'sel1:ed25519-sha256:|sel1:ed25519-sha256:AAAA', nine]) {
    assertPrimary(await verify(withS(s)), 'permerror', `PERMERROR: ${SIG} syntax error`);
  }
});

test('D3 amends C9: a bad signature at i=1 is primary over a key error at i=2', async () => {
  const msg = await signChain([{ fields: FIELDS, body: BODY }], [
    one({ rt: ['<list@example.com>'], sets: [{ sel: 'sel1', bad: true }] }),
    { d: 'example.com', m: 1, mf: '<list@example.com>', rt: ['<c@example.net>'], sel: 'nokey' },
  ]);
  const rep = await verify(msg);
  assertPrimary(rep, 'fail', `FAIL: ${SIG} selector sel1 incorrect signature`);
  assert.ok(rep.errors.includes('PERMERROR: DKIM2-Signature i=2 public key nokey does not exist'), rep.summary);
});

// --- D2, D4: "|" groups of "," lists of hash-sets ------------------------------

// A one-hop message whose h= is layout(sha256, sha512, bad): each a
// "name:header:body" set; bad(set, 'h'|'b') corrupts one hash of it.
const flip = (v) => (v[0] === 'A' ? 'B' : 'A') + v.slice(1);
const hLayout = (layout) => oneHop({}, { h: (hh, bh, s512) => layout({
  s256: `sha256:${hh}:${bh}`, s512: `sha512:${s512.hh}:${s512.bh}`,
  bad256: (w) => `sha256:${w === 'h' ? flip(hh) : hh}:${w === 'b' ? flip(bh) : bh}`,
  bad512: (w) => `sha512:${w === 'h' ? flip(s512.hh) : s512.hh}:${w === 'b' ? flip(s512.bh) : s512.bh}`,
}) });
const X_HASH = 'x-hash:AAAA:AAAA';

for (const [what, layout] of [
  ['"," of two good sets', (h) => `${h.s256},${h.s512}`],
  ['a bad set "|" a good one', (h) => `${h.bad256('b')} | ${h.s512}`],
  ['a good set "|" a bad one', (h) => `${h.s256}|${h.bad512('h')}`],
  ['a good set "|" an unknown algorithm', (h) => `${h.s256} |\r\n ${X_HASH}`],
  ['an unknown algorithm "|" a good set', (h) => `${X_HASH}|${h.s256}`],
  ['"," groups either side of "|"', (h) => `${X_HASH},${h.s512}|${h.s256}`],
]) {
  test(`D4: h= ${what} passes`, async () => assertPass(await verify(await hLayout(layout))));
}

for (const [what, layout, state, text] of [
  ['a bad body "|" a bad header', (h) => `${h.bad256('b')}|${h.bad512('h')}`, 'fail', 'FAIL: Message-Instance m=1 no group of hashes passed'],
  ['an unknown algorithm alone', () => X_HASH, 'permerror', 'PERMERROR: Message-Instance m=1 algorithm x-hash unknown'],
  ['a good set "," an unknown algorithm', (h) => `${h.s256},${X_HASH}`, 'permerror', 'PERMERROR: Message-Instance m=1 algorithm x-hash unknown'],
  ['an unknown algorithm "|" a bad set', (h) => `${X_HASH}|${h.bad256('h')}`, 'fail', 'FAIL: Message-Instance m=1 no group of hashes passed'],
  ['an unknown algorithm "," a bad set: FAIL wins', (h) => `${X_HASH},${h.bad256('b')}`, 'fail', 'FAIL: Message-Instance m=1 body hash sha256 mismatch'],
  ['a bad sha512 header "," a bad sha256 body: h= order', (h) => `${h.bad512('h')},${h.bad256('b')}`, 'fail', 'FAIL: Message-Instance m=1 header hash sha512 mismatch'],
  ['a bad sha256 body "," a bad sha512 header: h= order', (h) => `${h.bad256('b')},${h.bad512('h')}`, 'fail', 'FAIL: Message-Instance m=1 body hash sha256 mismatch'],
  ['two unknown groups', () => `${X_HASH}|y-hash:AAAA:AAAA`, 'permerror', 'PERMERROR: Message-Instance m=1 algorithm x-hash unknown'],
]) {
  test(`D4: h= ${what}`, async () => assertPrimary(await verify(await hLayout(layout)), state, text));
}

for (const [what, layout, text] of [
  ['a leading "|"', (h) => `|${h.s256}`, 'syntax error'],
  ['a trailing ","', (h) => `${h.s256},`, 'syntax error'],
  ['a doubled "|"', (h) => `${h.s256}||${h.s512}`, 'syntax error'],
  ['",|"', (h) => `${h.s256},|${h.s512}`, 'syntax error'],
  ['a hash that is not base64', (h) => `${h.s256}|x-hash:AAA:AAAA`, 'syntax error'],
  ['the same algorithm in two groups', (h) => `${h.s256}|${h.s256}`, 'has a duplicate hash algorithm'],
]) {
  test(`D2: h= with ${what} is "${text}"`, async () => {
    assertPrimary(await verify(await hLayout(layout)), 'permerror', `PERMERROR: Message-Instance m=1 ${text}`);
  });
}

// --- D7: a key that is not one of its type is "is malformed" ----------------

const { subtle } = globalThis.crypto;
const spki = async (kp) => Buffer.from(await subtle.exportKey('spki', (await kp).publicKey)).toString('base64');
const withKey = (key) => async () => key;

test('D7: an Ed25519 p= that is not exactly 32 octets is malformed', async () => {
  const msg = await oneHop();
  const raw = Buffer.from(await publicKeyB64(keyPair), 'base64');
  for (const p of [raw.subarray(0, 31).toString('base64'), Buffer.concat([raw, Buffer.from([0])]).toString('base64'), await spki(keyPair)]) {
    assertPrimary(await verify(msg, { fetchKey: withKey({ k: 'ed25519', p }) }), 'permerror',
      'PERMERROR: DKIM2-Signature i=1 public key sel is malformed');
  }
});

test('D7: an RSA key shorter than 1024 bits, or base64 that is no RSA key, is malformed', async () => {
  const rsa512 = subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 512,
    publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const msg = edit(await oneHop(), ':ed25519-sha256:', ':rsa-sha256:');
  for (const p of [await spki(rsa512), 'AAAAAAAA']) {
    assertPrimary(await verify(msg, { fetchKey: withKey({ k: 'rsa', p }) }), 'permerror',
      'PERMERROR: DKIM2-Signature i=1 public key sel is malformed');
  }
});

// --- D6, D10: Recipe errors ---------------------------------------------------

const two = (over = {}) => ({ d: 'example.com', m: 2, mf: '<a@example.com>', rt: ['<c@example.net>'], ...over });
const oneTo = (over = {}) => one({ rt: ['<list@example.com>'], ...over });
// i=1 example.com to a list at example.com; i=2 the list on. recipe is an
// object, or a string of JSON text used as it is.
const twoHop = (recipe) => signChain([
  { fields: FIELDS, body: BODY },
  { fields: FIELDS, body: BODY, recipe },
], [oneTo(), two()]);
const INVALID_JSON = 'PERMERROR: Message-Instance m=2 contains invalid JSON';
const stepInvalid = (path) => `PERMERROR: Message-Instance m=2 Recipe ${path} is invalid`;

test('control: the two-hop canvas passes', async () => {
  assertPass(await verify(await twoHop({ h: { subject: [{ c: [1, 1] }] }, b: [{ c: [1, 1] }] })));
});

for (const [recipe, path] of [
  [{ b: ['x'] }, 'b[0]'],
  [{ b: [{}] }, 'b[0]'],
  [{ b: [{ x: [1] }] }, 'b[0]'],
  [{ b: [{ c: [1, 1], d: ['x'] }] }, 'b[0]'],
  [{ b: [{ c: [2, 1] }] }, 'b[0]'],
  [{ b: [{ c: [0, 1] }] }, 'b[0]'],
  [{ b: [{ c: [1] }] }, 'b[0]'],
  [{ b: [{ c: [1, '1'] }] }, 'b[0]'],
  [{ b: [{ c: [1, 1] }, { c: [1, 1] }] }, 'b[1]'],
  [{ b: [{ c: [1, 1] }, { d: [] }] }, 'b[1]'],
  [{ b: [{ d: [1] }] }, 'b[0]'],
  [{ b: [{ d: ['a\rb'] }] }, 'b[0]'],
  [{ b: [{ u: ['QR=='] }] }, 'b[0]'],
  [{ b: [{ u: ['DQo='] }] }, 'b[0]'],
  [{ h: { subject: [{ c: [1, 1] }, { x: 1 }] } }, 'h.subject[1]'],
  [{ h: { subject: 'x' } }, 'h.subject'],
  [{ h: { 'x café': [{ q: 1 }] } }, 'h.x\\x20caf\\xC3\\xA9[0]'],
  [{ h: { subject: [{ e: 1 }] }, b: [{ c: [1, 1] }, { d: [] }] }, 'b[1]'],
  [{ h: { to: [{ x: 1 }], subject: [{ x: 1 }] } }, 'h.subject[0]'],
]) {
  test(`D6: ${JSON.stringify(recipe)} is "Recipe ${path} is invalid"`, async () => {
    assertPrimary(await verify(await twoHop(recipe)), 'permerror', stepInvalid(path));
  });
}

for (const [what, json] of [
  ['not JSON', '{"b":'],
  ['not an object', '[1]'],
  ['neither h nor b', '{"x":1}'],
  ['h empty', '{"h":{}}'],
  ['h an array, with a bad step too', '{"b":[{"x":1}],"h":[]}'],
  ['b neither array nor null', '{"b":{}}'],
  ['a duplicate key', '{"b":null,"b":[{"c":[1,1]}]}'],
  ['an uppercase top-level key', '{"H":{"subject":[{"c":[1,1]}]}}'],
  ['an uppercase header name', '{"h":{"Subject":[{"c":[1,1]}]}}'],
  ['an uppercase step key', '{"b":[{"C":[1,1]}]}'],
  ['an escaped uppercase key', '{"b":[{"\\u0043":[1,1]}]}'],
  ['a number with an exponent, unused', '{"b":[{"c":[1,1]}],"n":1e0}'],
  ['a number with a fraction', '{"b":[{"c":[1.0,1]}]}'],
  ['a lone surrogate in a "d" string', '{"b":[{"d":["\\udc80"]}]}'],
  ['a lone surrogate in an unused key', '{"b":[{"c":[1,1]}],"x\\ud800":1}'],
  ['a copy past the end', '{"b":[{"c":[1,2]}]}'],
]) {
  test(`D6/D10: ${what} is "contains invalid JSON"`, async () => {
    assertPrimary(await verify(await twoHop(json)), 'permerror', INVALID_JSON);
  });
}

test('D10: Recipe octets that are not UTF-8 are "contains invalid JSON"', async () => {
  const good = Buffer.from('{"b":[{"d":["café"]}]}').toString('base64');
  const bad = Buffer.from([...Buffer.from('{"b":[{"d":["caf'), 0xe9, ...Buffer.from('"]}]}')]).toString('base64');
  const msg = edit(await twoHop('{"b":[{"d":["café"]}]}'), good, bad);
  assertPrimary(await verify(msg), 'permerror', INVALID_JSON);
});

test('D10: non-ASCII letters in keys are not judged', async () => {
  assertPass(await verify(await signChain([
    { fields: FIELDS, body: BODY },
    { fields: [...FIELDS, ['X-Été', 'x']], body: BODY, recipe: { h: { 'x-été': [] } } },
  ], [oneTo(), two()])));
});
