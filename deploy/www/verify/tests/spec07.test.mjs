// draft-ietf-dkim-dkim2-spec-07: the verifier-side shared behaviour tests
// (U3-U5, K1-K2, F1, C1-C6, A1, A2, A4, T1) and the Review Focus extras,
// through the REAL verifyMessage() entry point on genuinely Ed25519-signed
// chains. The signer-side tests (U1, F2, A3, D1) do not apply: this is a
// verify-only implementation.
//
// Fake DNS: one Ed25519 key, published under every domain the shared table
// names (and nowhere else).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyMessage } from '../verify.js';
import { domainOf, toALabel, relaxedMatch } from '../domain.js';
import { signChain as sign, newKeyPair, publicKeyB64, b64text, T } from './sign-chain.mjs';

const keyPair = newKeyPair();
const DOMAINS = new Set(['example.com', 'example.org', 'example.net', 'other.net',
  'fwd.example.net', 'mail.example.org', 'other.example', 'elsewhere.net',
  'lists.example.org', 'sub.example.com', 'xn--bcher-kva.example']);
async function fetchKey(selector, domain) {
  if (selector !== 'sel' || !DOMAINS.has(domain.toLowerCase())) throw new Error('key-notfound');
  return { k: 'ed25519', p: await publicKeyB64(keyPair) };
}

// See sign-chain.mjs: states[k - 1] is the message at m=k, hops[n - 1] is i=n.
const signChain = (states, hops) => sign(states, hops, keyPair);

const verify = (msg, opts = {}) => verifyMessage(msg, { now: T + 10, fetchKey, ...opts });

const FIELDS = [['From', 'a@example.com'], ['Subject', 'hi']];
const BODY = 'hello\r\n';
const one = (over = {}) => ({ d: 'example.com', m: 1, mf: '<a@example.com>', rt: ['<list@lists.example.org>'], ...over });
const two = (over = {}) => ({ d: 'example.org', m: 2, mf: '<list@lists.example.org>', rt: ['<b@example.net>'], ...over });

// The standard two-hop canvas: i=1 example.com to a list at
// lists.example.org; i=2 the list (example.org) on to b@example.net.
async function twoHop(recipe, { prev = {}, cur = {}, hop1 = {}, hop2 = {} } = {}) {
  return signChain([
    { fields: FIELDS, body: BODY, ...prev },
    { fields: FIELDS, body: BODY, ...cur, recipe },
  ], [one(hop1), two(hop2)]);
}

function assertPass(rep) { assert.equal(rep.overall, 'pass', rep.summary); }
function assertPerm(rep, text) {
  assert.equal(rep.overall, 'permerror', rep.summary);
  assert.ok(rep.summary.includes(text), `summary ${JSON.stringify(rep.summary)} lacks ${JSON.stringify(text)}`);
}
const INVALID_JSON = 'PERMERROR: Message-Instance m=2 contains invalid JSON';

// --- domain.js -----------------------------------------------------------

test('domainOf: text after the last @, lowercased, one trailing dot gone; literals marked', () => {
  assert.deepEqual(domainOf('<A@Example.COM.>'), { domain: 'example.com', literal: false });
  assert.deepEqual(domainOf('<"x@y"@b.example>'), { domain: 'b.example', literal: false });
  assert.deepEqual(domainOf('<x@[192.0.2.1]>'), { domain: '[192.0.2.1]', literal: true });
  assert.deepEqual(domainOf('<>'), { domain: '', literal: false });
});

test('toALabel maps only labels with non-ASCII, via the URL host parser', () => {
  assert.equal(toALabel('bücher.example'), 'xn--bcher-kva.example');
  assert.equal(toALabel('BÜCHER.example'), 'xn--bcher-kva.example');
  assert.equal(toALabel('example.com'), 'example.com');
});

test('relaxedMatch shortens only Parameter1, and a literal never matches', () => {
  assert.equal(relaxedMatch('bounce.a.example.com', 'example.com'), true);
  assert.equal(relaxedMatch('example.com', 'EXAMPLE.com'), true);
  assert.equal(relaxedMatch('example.com', 'a.example.com'), false);
  assert.equal(relaxedMatch('com', 'example.com'), false);
  assert.equal(relaxedMatch('[192.0.2.1]', '[192.0.2.1]'), false);
  assert.equal(relaxedMatch('', ''), false);
});

// --- controls ---------------------------------------------------------------

test('control: the one-hop and two-hop canvases pass', async () => {
  assertPass(await verify(await signChain([{ fields: FIELDS, body: BODY }], [one()])));
  assertPass(await verify(await twoHop({ h: { subject: [{ c: [1, 1] }] } })));
});

// --- U: the "u" Recipe step (C1) --------------------------------------------

// §9/§12.1: r= is optional. A Message-Instance with no Recipes says the
// previous instance is the same message; any difference shows as a hash
// mismatch on the lower instance.
test('a Message-Instance with no r= over an unchanged message passes', async () => {
  const msg = await signChain([{ fields: FIELDS, body: BODY }, { fields: FIELDS, body: BODY }], [one(), two()]);
  assertPass(await verify(msg));
  assertPass(await verify(msg, { undoWalk: true }));
});

test('a Message-Instance with no r= over a changed message is a hash mismatch below it', async () => {
  for (const [cur, want] of [
    [{ fields: [['From', 'a@example.com'], ['Subject', '[list] hi']], body: BODY }, 'FAIL: Message-Instance m=1 header hash sha256 mismatch'],
    [{ fields: FIELDS, body: 'hello\r\n-- footer\r\n' }, 'FAIL: Message-Instance m=1 body hash sha256 mismatch'],
  ]) {
    const msg = await signChain([{ fields: FIELDS, body: BODY }, cur], [one(), two()]);
    for (const undoWalk of [false, true]) {
      const rep = await verify(msg, { undoWalk });
      assert.equal(rep.overall, 'fail', rep.summary);
      assert.equal(rep.summary, want);
    }
  }
});

test('"c" ranges that do not fit the message are "contains invalid JSON" too', async () => {
  for (const recipe of [{ b: [{ c: [1, 2] }] }, { b: [{ c: [1, 1] }, { c: [1, 1] }] }, { b: [{ c: [2, 1] }] },
    { h: { subject: [{ c: [1, 2] }] } }]) {
    assertPerm(await verify(await twoHop(recipe)), INVALID_JSON);
  }
});

test('U2 (verify side): a "u" step restores a body line of octets 63 61 66 E9', async () => {
  const msg = await twoHop({ b: [{ u: ['Y2Fm6Q=='] }] }, {
    prev: { body: { bin: 'caf\xe9\r\n' } }, cur: { body: 'x\r\n' },
  });
  assertPass(await verify(msg));
});

test('Review: a "d" step with valid UTF-8 non-ASCII restores a header and a body line byte-exactly', async () => {
  const msg = await twoHop({ h: { subject: [{ d: ['naïve'] }] }, b: [{ d: ['naïve café'] }] }, {
    prev: { fields: [['From', 'a@example.com'], ['Subject', 'naïve']], body: 'naïve café\r\n' },
    cur: { body: 'x\r\n' },
  });
  assertPass(await verify(msg));
});

test('U3: "u" with non-zero pad bits (QR==) is invalid JSON', async () => {
  assertPerm(await verify(await twoHop({ b: [{ u: ['QR=='] }] })), INVALID_JSON);
});

for (const [label, recipe] of [
  ['U4 old "b" step key', { b: [{ b: ['eA=='] }] }],
  ['U4 step with two keys', { b: [{ c: [1, 1], d: ['x'] }] }],
  ['U4 empty step', { b: [{}] }],
  ['U5 "u" decoding to a CR', { b: [{ u: ['YQ1i'] }] }],
  ['U5 empty "h"', { h: {} }],
  ['U5 neither "h" nor "b"', { x: 1 }],
  ['"u" not padded', { b: [{ u: ['YQ'] }] }],
  ['"u" outside the alphabet', { b: [{ u: ['YQ-='] }] }],
  ['"u" with whitespace', { b: [{ u: ['YW Jj'] }] }],
  ['"d" with a lone surrogate', '{"b":[{"d":["caf\\udce9"]}]}'],
  ['"c" start of 0', { b: [{ c: [0, 1] }] }],
  ['"c" as strings', { b: [{ c: ['1', '1'] }] }],
  ['Recipe is an array', [{ c: [1, 1] }]],
]) {
  test(`${label} is "contains invalid JSON"`, async () => {
    assertPerm(await verify(await twoHop(recipe)), INVALID_JSON);
  });
}

// --- K: JSON key case (decision 2) ------------------------------------------

test('K1: upper-case keys verify the same as the lower-case form', async () => {
  assertPass(await verify(await twoHop({ H: { Subject: [{ C: [1, 1] }] } })));
  // and an upper-case "D" and "U" step that really restore something
  const opts = { prev: { fields: [['From', 'a@example.com'], ['Subject', 'old']], body: { bin: 'caf\xe9\r\n' } }, cur: { body: 'x\r\n' } };
  assertPass(await verify(await twoHop({ H: { SUBJECT: [{ D: ['old'] }] }, B: [{ U: ['Y2Fm6Q=='] }] }, opts)));
});

for (const [label, json] of [
  ['K2 header names differing only in case', '{"h":{"Subject":[],"subject":[]}}'],
  ['top-level keys differing only in case', '{"b":[{"c":[1,1]}],"B":[{"c":[1,1]}]}'],
  ['step keys differing only in case', '{"b":[{"c":[1,1],"C":[1,1]}]}'],
]) {
  test(`${label} are a duplicate: "contains invalid JSON"`, async () => {
    assertPerm(await verify(await twoHop(json)), INVALID_JSON);
  });
}

// --- F1: f= is a generic flag list (C2) ----------------------------------

test('F1: i=1 f=donotmodify, then a later hop modifies validly: PASS', async () => {
  const msg = await twoHop({ h: { subject: [{ d: ['hi'] }] } }, {
    cur: { fields: [['From', 'a@example.com'], ['Subject', '[list] hi']] },
    hop1: { f: 'donotmodify' },
  });
  assertPass(await verify(msg));
});

// --- C: Chain of Custody (C3/C4) -------------------------------------------

const c1hops = (rt1 = '<list@lists.example.org>', d2 = 'example.org') => [
  one({ rt: [rt1] }), two({ d: d2, mf: '<>', rt: ['<a@example.com>'] })];
const twoStates = [{ fields: FIELDS, body: BODY }, { fields: FIELDS, body: BODY, recipe: { h: { subject: [{ c: [1, 1] }] } } }];

test('C1: an mf=<> hop whose d= relaxed-matches the previous rt= passes', async () => {
  const rep = await verify(await signChain(twoStates, c1hops()));
  assertPass(rep);
  assert.doesNotMatch(rep.summary, /does not match/);
});

test('C1 (Review): an rt= in upper case with a trailing dot still matches', async () => {
  assertPass(await verify(await signChain(twoStates, c1hops('<list@Lists.Example.ORG.>'))));
});

test('C2: an mf=<> hop whose d= is not in the previous rt= fails', async () => {
  assertPerm(await verify(await signChain(twoStates, c1hops(undefined, 'other.net'))),
    'PERMERROR: DKIM2-Signature i=2 d= does not match the rt= of i=1');
});

const c3 = (rt1, d2, d3) => signChain([{ fields: FIELDS, body: BODY }], [
  one({ rt: [rt1] }),
  { d: d2, m: 1, nd: 'fwd.example.net' },
  { d: d3, m: 1, mf: `<b@${d3}>`, rt: ['<c@example.net>'] },
]);

test('C3: an nd= hop matches the previous rt=, and the next d= equals nd=', async () => {
  assertPass(await verify(await c3('<x@mail.example.org>', 'example.org', 'fwd.example.net')));
});

test('C3 swapped: the nd= hop d= is a subdomain of the previous rt=, which never matches', async () => {
  assertPerm(await verify(await c3('<x@example.org>', 'mail.example.org', 'fwd.example.net')),
    'PERMERROR: DKIM2-Signature i=2 d= does not match the rt= of i=1');
});

test('C4: the hop after nd= has a different d=', async () => {
  assertPerm(await verify(await c3('<x@mail.example.org>', 'example.org', 'other.example')),
    'PERMERROR: DKIM2-Signature i=2 nd= does not match');
});

test('C5: a domain literal never matches', async () => {
  const rep = await verify(await signChain(twoStates, [
    one({ rt: ['<x@[192.0.2.1]>'] }), two({ mf: '<y@[192.0.2.1]>' })]));
  assertPerm(rep, 'PERMERROR: DKIM2-Signature i=2 mf= does not match the rt= of i=1');
  assertPerm(rep, 'PERMERROR: DKIM2-Signature i=2 MAIL FROM and d= do not match');
});

test('C6: i=1 MAIL FROM and d= do not match', async () => {
  const rep = await verify(await signChain([{ fields: FIELDS, body: BODY }], [one({ mf: '<a@example.net>' })]));
  assertPerm(rep, 'PERMERROR: DKIM2-Signature i=1 MAIL FROM and d= do not match');
});

test('a non-null mf= that does not relaxed-match the previous rt= fails', async () => {
  assertPerm(await verify(await twoHop({ h: { subject: [{ c: [1, 1] }] } }, { hop2: { d: 'example.net', mf: '<x@example.net>' } })),
    'PERMERROR: DKIM2-Signature i=2 mf= does not match the rt= of i=1');
});

test('Review: an nd= tag on the top signature, verified inbound, is "unexpected nd= tag"', async () => {
  const rep = await verify(await signChain([{ fields: FIELDS, body: BODY }], [{ d: 'example.com', m: 1, nd: 'example.net' }]));
  assertPerm(rep, 'PERMERROR: DKIM2-Signature i=1 unexpected nd= tag');
});

test('nd= together with mf= or rt= is "tag=mf was unexpected"', async () => {
  const msg = await signChain([{ fields: FIELDS, body: BODY }], [{ d: 'example.com', m: 1, nd: 'example.net', extra: `; mf=${b64text('<a@example.com>')}` }]);
  assertPerm(await verify(msg), 'PERMERROR: DKIM2-Signature i=1 tag=mf was unexpected');
});

// --- A: From is Authentic (C5) ---------------------------------------------

const oneHopFrom = (from, hop = {}) => signChain([{ fields: [['From', from], ['Subject', 'hi']], body: BODY }], [one(hop)]);
const NOT_AUTHENTIC_1 = 'PERMERROR: DKIM2-Signature i=1 matching From is not authentic';

test('A1: From "A <a@example.com>" with d=example.com passes', async () => {
  assertPass(await verify(await oneHopFrom('A <a@example.com>')));
});

test('A1: the same From with d=example.net is not authentic', async () => {
  assertPerm(await verify(await oneHopFrom('A <a@example.com>', { d: 'example.net', mf: '<a@example.net>' })), NOT_AUTHENTIC_1);
});

test('A1: From a@sub.example.com with d=example.com passes', async () => {
  assertPass(await verify(await oneHopFrom('a@sub.example.com')));
});

for (const from of ['a@example.com, b@example.com', 'a@[192.0.2.1]', 'group: a@example.com;', 'not an address']) {
  test(`A1: From "${from}" is not authentic`, async () => {
    assertPerm(await verify(await oneHopFrom(from)), NOT_AUTHENTIC_1);
  });
}

test('A1: two From fields are not authentic', async () => {
  const msg = await signChain([{ fields: [['From', 'a@example.com'], ['From', 'b@example.com'], ['Subject', 'hi']], body: BODY }], [one()]);
  assertPerm(await verify(msg), NOT_AUTHENTIC_1);
});

test('A1 (Review): a folded From with an RFC 2047 display name and angle-addr passes', async () => {
  assertPass(await verify(await oneHopFrom('=?utf-8?q?Caf=C3=A9?=\r\n <a@example.com>')));
  assertPass(await verify(await oneHopFrom('"Smith, A" (comment) <a@example.com>')));
});

test('A2: a list rewrites From to its own domain at m=2 and signs i=2 as example.org: PASS', async () => {
  const msg = await twoHop({ h: { from: [{ d: ['a@example.com'] }] } }, {
    cur: { fields: [['From', 'list@lists.example.org'], ['Subject', 'hi']] },
  });
  assertPass(await verify(msg));
});

test('A2: a From rewritten to a domain the m=2 signer does not hold is not authentic', async () => {
  const msg = await twoHop({ h: { From: [{ d: ['a@example.com'] }] } }, {
    cur: { fields: [['From', 'x@elsewhere.net'], ['Subject', 'hi']] },
  });
  assertPerm(await verify(msg), 'PERMERROR: DKIM2-Signature i=2 matching From is not authentic');
});

test('A2: the original From is still checked against i=1', async () => {
  const msg = await twoHop({ h: { from: [{ d: ['a@elsewhere.net'] }] } }, {
    prev: { fields: [['From', 'a@elsewhere.net'], ['Subject', 'hi']] },
    cur: { fields: [['From', 'list@lists.example.org'], ['Subject', 'hi']] },
  });
  assertPerm(await verify(msg), NOT_AUTHENTIC_1);
});

// Ruling 19: i=1 is checked against the From at state m(i=1). An author's
// From in an unsigned ingress m=1, rewritten by the list in m=2 before it
// signed i=1 over m=2, was never covered by a signature.
test('Ruling 19: a From replaced before the first signature is not checked', async () => {
  const msg = await signChain([
    { fields: [['From', 'a@elsewhere.net'], ['Subject', 'hi']], body: BODY },
    { fields: [['From', 'list@lists.example.org'], ['Subject', 'hi']], body: BODY, recipe: { h: { from: [{ d: ['a@elsewhere.net'] }] } } },
  ], [two({ m: 2 })]);
  assertPass(await verify(msg));
});

test('Ruling 19: the From at state m(i=1) is checked against i=1', async () => {
  const msg = await signChain([
    { fields: [['From', 'a@example.com'], ['Subject', 'hi']], body: BODY },
    { fields: [['From', 'a@example.com'], ['Subject', '[list] hi']], body: BODY, recipe: { h: { subject: [{ d: ['hi'] }] } } },
  ], [two({ m: 2 })]);
  assertPerm(await verify(msg), NOT_AUTHENTIC_1);
});

test('A4: From u@bücher.example (UTF-8) with d=xn--bcher-kva.example passes', async () => {
  const msg = await oneHopFrom('u@bücher.example', { d: 'xn--bcher-kva.example', mf: '<u@xn--bcher-kva.example>' });
  assertPass(await verify(msg));
});

// --- T1: timestamps against the current time -------------------------------

test('T1: t two hours ahead passes; two days ahead is from the future', async () => {
  const msg = await signChain([{ fields: FIELDS, body: BODY }], [one()]);
  assertPass(await verify(msg, { now: T - 7200 }));
  assertPerm(await verify(msg, { now: T - 172800 }), 'PERMERROR: DKIM2-Signature i=1 signature is from the future');
});

test('T1: a signature more than 14 days old is expired (PERMERROR, not a warning)', async () => {
  const msg = await signChain([{ fields: FIELDS, body: BODY }], [one()]);
  assertPass(await verify(msg, { now: T + 1209600 }));
  const rep = await verify(msg, { now: T + 1209601 });
  assertPerm(rep, 'PERMERROR: DKIM2-Signature i=1 signature expired');
  // the signature itself still verified, and the report says so
  const sig = rep.levels.find((l) => l.kind === 'signature' && l.i === 1);
  assert.equal(sig.items[0].result, 'pass');
});

test('T1: with no clock given, the current time is used', async () => {
  const msg = await signChain([{ fields: FIELDS, body: BODY }], [one()]);
  const rep = await verifyMessage(msg, { fetchKey });
  assertPerm(rep, 'PERMERROR: DKIM2-Signature i=1 signature expired');
});

// --- C6: error strings ------------------------------------------------------

test('no DKIM2 header fields at all: none, with no error string', async () => {
  const rep = await verify('From: a@example.com\r\n\r\nhi\r\n');
  assert.equal(rep.overall, 'none');
  assert.doesNotMatch(rep.summary, /PERMERROR|FAIL|TEMPERROR/);
});

test('Message-Instance fields but no signature: "is not signed"', async () => {
  assertPerm(await verify('Message-Instance: m=1; h=sha256:AAAA:AAAA\r\nFrom: a@example.com\r\n\r\nhi\r\n'),
    'PERMERROR: Message-Instance m=1 is not signed');
});

test('a duplicate hash algorithm is PERMERROR', async () => {
  const msg = await signChain([{ fields: FIELDS, body: BODY, h: (hh, bh) => `sha256:${hh}:${bh},sha256:${hh}:${bh}` }], [one()]);
  assertPerm(await verify(msg), 'PERMERROR: Message-Instance m=1 has a duplicate hash algorithm');
});

test('a header and a body hash mismatch name the algorithm', async () => {
  const msg = await signChain([{ fields: FIELDS, body: BODY }], [one()]);
  const text = new TextDecoder().decode(msg);
  let rep = await verify(text.replace('Subject: hi', 'Subject: ho'));
  assert.equal(rep.overall, 'fail', rep.summary);
  assert.match(rep.summary, /FAIL: Message-Instance m=1 header hash sha256 mismatch/);
  rep = await verify(text.replace(/hello\r\n$/, 'hullo\r\n'));
  assert.match(rep.summary, /FAIL: Message-Instance m=1 body hash sha256 mismatch/);
});

test('a broken signature: "selector <s1> incorrect signature"', async () => {
  const text = new TextDecoder().decode(await signChain([{ fields: FIELDS, body: BODY }], [one()]));
  const broken = text.replace(/(s=sel:ed25519-sha256:)(.)/, (_m, pre, c) => pre + (c === 'A' ? 'B' : 'A'));
  const rep = await verify(broken);
  assert.equal(rep.overall, 'fail');
  assert.match(rep.summary, /FAIL: DKIM2-Signature i=1 selector sel incorrect signature/);
});

test('one of two signatures fails: "signature <s1> signature <s2> failed"', async () => {
  // a second Selector for the same key, carrying a corrupted value
  const msg = await signChain([{ fields: FIELDS, body: BODY }], [one({ sets: [{ sel: 'sel' }, { sel: 'sel2', bad: true }] })]);
  const rep = await verify(msg, { fetchKey: async (s, d) => fetchKey('sel', d) });
  assert.equal(rep.overall, 'fail');
  assert.match(rep.summary, /FAIL: DKIM2-Signature i=1 signature sel signature sel2 failed/);
});

test('an absent key: "public key <s1> does not exist"', async () => {
  const msg = await signChain([{ fields: FIELDS, body: BODY }], [one()]);
  assertPerm(await verify(msg, { fetchKey: async () => { throw new Error('key-notfound'); } }),
    'PERMERROR: DKIM2-Signature i=1 public key sel does not exist');
});

test('a DNS failure: "TEMPERROR: ... public key <s1> could not be fetched"', async () => {
  const msg = await signChain([{ fields: FIELDS, body: BODY }], [one()]);
  const rep = await verify(msg, { fetchKey: async () => { throw new Error('key-temperror'); } });
  assert.equal(rep.overall, 'temperror');
  assert.match(rep.summary, /TEMPERROR: DKIM2-Signature i=1 public key sel could not be fetched/);
});

test('a duplicate tag, in any case, is a syntax error', async () => {
  const msg = await signChain([{ fields: FIELDS, body: BODY }], [one({ extra: '; N=x; n=y' })]);
  assertPerm(await verify(msg), 'PERMERROR: DKIM2-Signature i=1 syntax error');
});

test('an mf= without angle brackets is a syntax error', async () => {
  const msg = await signChain([{ fields: FIELDS, body: BODY }], [one({ mf: 'a@example.com' })]);
  assertPerm(await verify(msg), 'PERMERROR: DKIM2-Signature i=1 syntax error');
});

test('a missing required tag: "tag=<y> missing"', async () => {
  const text = new TextDecoder().decode(await signChain([{ fields: FIELDS, body: BODY }], [one()]));
  assertPerm(await verify(text.replace(/; rt=[^;]+/, '')), 'PERMERROR: DKIM2-Signature i=1 tag=rt missing');
});
