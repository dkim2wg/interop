import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyMessage } from '../verify.js';
import { parseMessage, collectLevels } from '../parse.js';
import { canonHeaderHash, canonBody, signingInput } from '../canon.js';
import { hashB64, sha256Bytes } from '../crypto.js';
import { stringToBytes, bytesToB64, binaryToBytes } from '../b64.js';

// Recipe validation (§5, with the proposed "b" step) through the REAL
// verifyMessage() entry point, on genuinely Ed25519-signed two-hop messages.
// Every message here is built as a binary string (one code unit per byte,
// see b64.js) and handed over as bytes, so a Subject or body line can carry
// octets that are not UTF-8 -- the whole reason the "b" step exists.
//
// Hop 1 (m=1, i=1) signs the "previous" message; hop 2 (m=2, i=2) changes
// it and records the change in an r= Recipe. Content and chain of custody
// are otherwise valid, so the Recipe is the only thing under test.

const { subtle } = globalThis.crypto;
const keyPromise = subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
async function keyFetcher() {
  const kp = await keyPromise;
  const p = bytesToB64(new Uint8Array(await subtle.exportKey('raw', kp.publicKey)));
  return async () => ({ k: 'ed25519', p });
}

// base64 of a binary string's octets (what a "b" item carries).
const b64bin = (bin) => bytesToB64(binaryToBytes(bin));
const b64text = (text) => bytesToB64(stringToBytes(text));
const recipeTag = (recipe) => b64text(JSON.stringify(recipe));

const T = 1740000000;
const mf1 = b64text('<sender@example.com>');
const rt1 = b64text('<mid@example.com>');
const mf2 = b64text('<mid@example.com>');
const rt2 = b64text('<final@example.com>');

async function sign(kp, draftBin, miFields, sigFields, target) {
  const input = binaryToBytes(signingInput([...miFields, ...sigFields], target));
  return bytesToB64(new Uint8Array(await subtle.sign({ name: 'Ed25519' }, kp.privateKey, await sha256Bytes(input))));
}

// fields: [{name, value}] with values as binary strings (value includes the
// leading space, as parsed); body: binary string. Returns the message bytes.
async function twoHop({ prevFields, prevBody, curFields, curBody, recipe, rTag }) {
  const kp = await keyPromise;
  const hash = async (fields, body) => [
    await hashB64(binaryToBytes(canonHeaderHash(fields)), 'sha256'),
    await hashB64(binaryToBytes(canonBody(body)), 'sha256'),
  ];
  const [hh1, bh1] = await hash(prevFields, prevBody);
  const [hh2, bh2] = await hash(curFields, curBody);
  const content = (fields, body) => fields.map((f) => `${f.name}:${f.value}\r\n`).join('') + '\r\n' + body;
  const r = rTag !== undefined ? rTag : recipeTag(recipe);

  const sig1Line = (sig) => `DKIM2-Signature: i=1; m=1; t=${T}; d=example.com; mf=${mf1}; rt=${rt1}; s=sel:ed25519-sha256:${sig};\r\n`;
  const sig2Line = (sig) => `DKIM2-Signature: i=2; m=2; t=${T}; d=example.com; mf=${mf2}; rt=${rt2}; s=sel:ed25519-sha256:${sig};\r\n`;
  const mi1Line = `Message-Instance: m=1; h=sha256:${hh1}:${bh1};\r\n`;
  const mi2Line = `Message-Instance: m=2; h=sha256:${hh2}:${bh2}; r=${r};\r\n`;

  // Hop 1 signs on its own, before hop 2 exists.
  const draft1 = sig1Line('') + mi1Line + content(prevFields, prevBody);
  const { headers: h1 } = parseMessage(draft1);
  const l1 = collectLevels(h1);
  const sig1 = await sign(kp, draft1, [l1.instances[1].field], [l1.signatures[1].field], l1.signatures[1].field);

  // Hop 2 signs over hop 1's finished signature plus its own blank target.
  const draft2 = sig2Line('') + sig1Line(sig1) + mi2Line + mi1Line + content(curFields, curBody);
  const { headers: h2 } = parseMessage(draft2);
  const l2 = collectLevels(h2);
  const sig2 = await sign(kp, draft2,
    [l2.instances[1].field, l2.instances[2].field],
    [l2.signatures[1].field, l2.signatures[2].field], l2.signatures[2].field);

  const raw = sig2Line(sig2) + sig1Line(sig1) + mi2Line + mi1Line + content(curFields, curBody);
  return binaryToBytes(raw);
}

async function verify(msg) {
  return verifyMessage(msg, { now: T + 10, fetchKey: await keyFetcher() });
}

// Unchanged content between hops, two body lines: the canvas for the
// malformed-"c" cases (a correct Recipe would be {"b":[{"c":[1,2]}]}).
const twoLineFields = [{ name: 'From', value: ' a@b' }, { name: 'Subject', value: ' hi' }];
const twoLineBody = 'hello\r\nworld\r\n';
const unchanged = (recipe) => twoHop({
  prevFields: twoLineFields, prevBody: twoLineBody,
  curFields: twoLineFields, curBody: twoLineBody, recipe,
});

test('control: a well-formed copy Recipe over unchanged content passes end to end', async () => {
  const rep = await verify(await unchanged({ b: [{ c: [1, 2] }] }));
  assert.equal(rep.overall, 'pass', rep.summary);
});

const MALFORMED = /PERMERROR Message-Instance m=2 has a malformed Recipe/;

function rejects(name, recipe) {
  test(`malformed Recipe rejected through verifyMessage(): ${name}`, async () => {
    const rep = await verify(await unchanged(recipe));
    assert.notEqual(rep.overall, 'pass');
    assert.equal(rep.overall, 'permerror', rep.summary);
    assert.match(rep.summary, MALFORMED);
    const mi1 = rep.levels.find((l) => l.kind === 'instance' && l.m === 1);
    assert.equal(mi1.detail, 'PERMERROR Message-Instance m=2 has a malformed Recipe');
    const mi2 = rep.levels.find((l) => l.kind === 'instance' && l.m === 2);
    assert.equal(mi2.undo, 'failed');
  });
}

rejects('descending "c" ranges', { b: [{ c: [2, 2] }, { c: [1, 1] }] });
rejects('overlapping "c" ranges', { b: [{ c: [1, 2] }, { c: [2, 2] }] });
rejects('"c" start of 0', { b: [{ c: [0, 1] }] });
rejects('"c" end beyond the line count', { b: [{ c: [1, 3] }] });
rejects('"c" bounds as strings', { b: [{ c: ['1', '2'] }] });
rejects('"c" bound 1.5', { b: [{ c: [1, 1.5] }] });
rejects('"c" end beyond the header instance count', { h: { subject: [{ c: [1, 2] }] } });
rejects('invalid base64 in "b"', { b: [{ b: ['!!!!'] }] });
rejects('"b" item outside the base64 alphabet', { b: [{ b: ['QUJD-QUJD'] }] });
rejects('unpadded "b" item (not canonical RFC 4648 §4)', { b: [{ b: ['QUI'] }] });
rejects('empty "d" array', { b: [{ d: [] }] });
rejects('CR LF inside a decoded "b" item', { b: [{ b: [b64bin('a\r\nb')] }] });
rejects('LF inside a decoded header "b" item', { h: { subject: [{ b: [b64bin('x\ny')] }] } });
rejects('unknown step kind', { b: [{ z: [1, 2] }] });
rejects('Recipe is a JSON array, not an object', [{ c: [1, 2] }]);

test('a malformed Recipe never escapes as an exception, whatever the JSON shape', async () => {
  for (const recipe of [null, 7, 'x', { b: 'lines' }, { h: null }, { h: { subject: null } }, { b: [null] }, { b: [{ c: null }] }]) {
    const rep = await verify(await unchanged(recipe));
    assert.notEqual(rep.overall, 'pass', JSON.stringify(recipe));
  }
});

test('"b" steps restore a Subject and a body line of non-UTF-8 octets and the chain verifies', async () => {
  // At m=1 the Subject is Latin-1 "café" and the body has a Big5 line and
  // a Latin-1 line -- none of it valid UTF-8, so no "d" step could carry it.
  const prevFields = [{ name: 'From', value: ' a@b' }, { name: 'Subject', value: ' caf\xe9' }];
  const prevBody = '\xb1\xa4 line one\r\ncaf\xe9 au lait\r\n';
  // Hop 2 tags the Subject, edits line two and appends a footer.
  const curFields = [{ name: 'From', value: ' a@b' }, { name: 'Subject', value: ' [list] hello' }];
  const curBody = '\xb1\xa4 line one\r\n[list] edited\r\n-- footer\r\n';
  const recipe = {
    h: { subject: [{ b: [b64bin('caf\xe9')] }] },
    b: [{ c: [1, 1] }, { b: [b64bin('caf\xe9 au lait')] }],
  };
  const msg = await twoHop({ prevFields, prevBody, curFields, curBody, recipe });
  const rep = await verify(msg);
  assert.equal(rep.overall, 'pass', rep.summary);
  const mi2 = rep.levels.find((l) => l.kind === 'instance' && l.m === 2);
  assert.equal(mi2.undo, 'clean');
  // The report shows the Recipe as decoded text: U+FFFD for the stray byte,
  // never a crash, and the "b" item stays base64 in the decoded JSON.
  const subj = mi2.header_recipes.find((r) => r.name === 'subject');
  assert.equal(subj.current, '[list] hello');
  assert.equal(subj.previous, 'caf�');
  assert.equal(mi2.recipe_json.h.subject[0].b[0], b64bin('caf\xe9'));
});

test('the same restoration with "d" instead of "b" cannot verify (why "b" exists)', async () => {
  const prevFields = [{ name: 'From', value: ' a@b' }, { name: 'Subject', value: ' caf\xe9' }];
  const prevBody = 'line one\r\n';
  const curFields = [{ name: 'From', value: ' a@b' }, { name: 'Subject', value: ' [list] hello' }];
  // "d" is JSON text: the best it can say is U+00E9, which UTF-8 encodes as
  // two bytes, not the single 0xE9 that was hashed at m=1.
  const recipe = { h: { subject: [{ d: ['café'] }] } };
  const rep = await verify(await twoHop({ prevFields, prevBody, curFields, curBody: prevBody, recipe }));
  assert.notEqual(rep.overall, 'pass');
  assert.equal(rep.overall, 'fail');
});
