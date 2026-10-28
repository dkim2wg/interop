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
