// draft-ietf-dkim-dkim2-spec-08: the verifier behaviour the -08 contract
// (docs/superpowers/specs/2026-10-28-dkim2-spec-08-design.md, D1-D13)
// changes, through the REAL verifyMessage() entry point on genuinely
// Ed25519-signed chains.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyMessage } from '../verify.js';
import { parseTagList } from '../parse.js';
import { signChain as sign, newKeyPair, publicKeyB64, T } from './sign-chain.mjs';

const keyPair = newKeyPair();
async function fetchKey(selector, domain) {
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
