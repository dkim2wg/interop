import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyMessage, relaxedDomainMatch, domainOf } from '../verify.js';
import { parseKeyRecord } from '../doh.js';
import { parseMessage, collectLevels } from '../parse.js';
import { canonHeaderHash, canonBody, signingInput } from '../canon.js';
import { hashB64, sha256Bytes } from '../crypto.js';
import { stringToBytes, bytesToB64 } from '../b64.js';

// A real, single-hop signed sample (mailfrom_case vector) whose Message-Instance
// sha256 hashes and RSA signature genuinely verify against the shared dns.json
// key. Using it lets the §11.4 envelope / §11.3 timestamp checks be the sole
// determinant of the outcome (MI + crypto both pass on their own).
const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..', '..');
const SIGNED_SAMPLE = readFileSync(join(repoRoot, 'dkim2tests', 'tests', 'mailfrom_case.signed'), 'utf8');
const dns = JSON.parse(readFileSync(join(repoRoot, 'dkim2tests', 'dns.json'), 'utf8'));
const realFetchKey = async (selector, domain) => {
  const rec = dns[`${selector}._domainkey.${domain}`];
  if (rec === undefined) throw new Error('key-notfound');
  return parseKeyRecord(rec);
};
const SAMPLE_T = 1782394336;      // t= in the sample
const FRESH_NOW = SAMPLE_T + 3600; // well within the §11.3 14-day window

test('relaxedDomainMatch strips labels from the left of the from-domain', () => {
  assert.equal(relaxedDomainMatch('bounce.a.example.com', 'example.com'), true);
  assert.equal(relaxedDomainMatch('example.com', 'example.com'), true);
  assert.equal(relaxedDomainMatch('example.com', 'other.com'), false);
});

test('domainOf extracts the domain from a reverse/forward path', () => {
  assert.equal(domainOf('<bob@Sub.Example.COM>'), 'sub.example.com');
  assert.equal(domainOf('<>'), '');
});

test('no DKIM2-Signature yields overall=none', async () => {
  const rep = await verifyMessage('From: a@b\r\nSubject: x\r\n\r\nhi\r\n');
  assert.equal(rep.overall, 'none');
});

test('verifyMessage returns a levels array (shape contract)', async () => {
  // Real crypto verification of signed messages is covered end-to-end in
  // Task 9's vectors.test.mjs conformance harness. Here we only assert the
  // report shape contract: `levels` is always an array.
  const rep = await verifyMessage('From: a@b\r\nSubject: x\r\n\r\nhi\r\n');
  assert.ok(Array.isArray(rep.levels));
});

// A stub key so the algorithm/custody paths never hit real DoH/crypto.
const stubKey = async () => ({ k: 'rsa', p: 'AAAA' });

test('DKIM2-Signature with NO Message-Instance yields permerror (fix #3)', async () => {
  // sigNums=[1] but miNums=[]. The DKIM2-Signature header below is fully
  // valid structurally (i=, m=, t=, d=, s=, and mf=+rt= all present), so the
  // pre-existing per-tag presence check does NOT fire here. Only the
  // dedicated zero-MI guard (miNums.length === 0) can catch the missing
  // Message-Instance header, so this test would regress to a non-permerror
  // (or wrong-reason) result if that guard were removed.
  const raw =
    'From: a@b\r\n' +
    'DKIM2-Signature: i=1; m=1; t=1000000; d=test.dkim2.eu; ' +
    's=sel:rsa-sha256:AAAA; mf=PHNlbmRlckB0ZXN0LmRraW0yLmV1Pg==; rt=PHJlY2lwaWVudEBleGFtcGxlLmNvbT4=\r\n' +
    '\r\nhi\r\n';
  const rep = await verifyMessage(raw, { now: 1000000, fetchKey: stubKey });
  assert.equal(rep.overall, 'permerror');
  assert.match(rep.summary, /Message-Instance/);
});

test('signature with only an unsupported algorithm fails, overall=fail (fix #2a)', async () => {
  // Isolate the algorithm path: use a non-sha256 MI hash-set (so the MI hash
  // check is skipped and stays pass), nd= for trivially-ok top-hop custody,
  // a fresh timestamp, and an s= whose only sig-set uses `banana`.
  const raw =
    'From: a@b\r\n' +
    'Message-Instance: m=1; h=blake:xxx:yyy\r\n' +
    'DKIM2-Signature: i=1; m=1; t=1000000; d=example.com; s=sel:banana:AAA; nd=example.net\r\n' +
    '\r\nhi\r\n';
  const rep = await verifyMessage(raw, { now: 1000000, fetchKey: stubKey });
  const sig = rep.levels.find((l) => l.kind === 'signature' && l.i === 1);
  assert.ok(sig, 'signature level present');
  assert.equal(sig.result, 'fail');
  assert.equal(rep.overall, 'fail');
});

test('present but invalid-base64 mf= does not throw; custody fails (fix #5a)', async () => {
  // `@@@` is not valid base64; b64ToString throws a DOMException. The
  // orchestrator must catch it and fail the custody check, not propagate.
  const raw =
    'From: a@b\r\n' +
    'Message-Instance: m=1; h=blake:xxx:yyy\r\n' +
    'DKIM2-Signature: i=1; m=1; t=1000000; d=example.com; s=sel:banana:AAA; mf=@@@; rt=AAAA\r\n' +
    '\r\nhi\r\n';
  let rep;
  await assert.doesNotReject(async () => { rep = await verifyMessage(raw, { now: 1000000, fetchKey: stubKey }); });
  const sig = rep.levels.find((l) => l.kind === 'signature' && l.i === 1);
  assert.ok(sig, 'signature level present');
  assert.equal(sig.custody.ok, false);
  // fix #4: a custody failure must surface into level.detail (and hence the
  // top-level summary), not just level.custody.detail.
  assert.match(sig.detail, /mf\/rt malformed/);
  assert.match(rep.summary, /mf\/rt malformed/);
});

// --- §11.3 expired signature is PERMERROR, not fail --------------------
test('an old-but-otherwise-valid signature (>14 days) is a soft WARN, not a failure (§11.3/§8.4)', async () => {
  const rep = await verifyMessage(SIGNED_SAMPLE, {
    fetchKey: realFetchKey,
    mailFrom: '<sender@test.dkim2.eu>',
    rcptTo: ['<recipient@example.com>'],
    now: SAMPLE_T + 20 * 86400, // 20 days after the signature timestamp
  });
  // Crypto/hashes are fine; only the age is stale — overall must be 'warn'
  // (the reference /validate/ grades age as a soft warning), NOT a hard error.
  assert.equal(rep.overall, 'warn');
  assert.match(rep.summary, /more than 14 days old/);
  const sig = rep.levels.find((l) => l.kind === 'signature' && l.i === 1);
  assert.equal(sig.result, 'warn');
  assert.equal(sig.timestamp.ok, false);
  assert.equal(sig.timestamp.status, 'expired');
});

test('a signature within 14 days is a clean pass (no age warning)', async () => {
  const rep = await verifyMessage(SIGNED_SAMPLE, {
    fetchKey: realFetchKey,
    mailFrom: '<sender@test.dkim2.eu>',
    rcptTo: ['<recipient@example.com>'],
    now: SAMPLE_T + 3600, // an hour after signing
  });
  assert.equal(rep.overall, 'pass');
  const sig = rep.levels.find((l) => l.kind === 'signature' && l.i === 1);
  assert.equal(sig.result, 'pass');
  assert.equal(sig.timestamp.ok, true);
});

// --- §11.7 MI hash fails closed when no supported hash algorithm ---------
test('MI with no supported hash algorithm fails closed (§11.7)', async () => {
  // h= names only `blake` (no sha256). The instance MUST NOT stay at pass.
  const raw =
    'From: a@b\r\n' +
    'Message-Instance: m=1; h=blake:xxx:yyy\r\n' +
    'DKIM2-Signature: i=1; m=1; t=1000000; d=example.com; s=sel:rsa-sha256:AAA; nd=example.net\r\n' +
    '\r\nhi\r\n';
  const rep = await verifyMessage(raw, { now: 1000000, fetchKey: stubKey });
  const mi = rep.levels.find((l) => l.kind === 'instance' && l.m === 1);
  assert.ok(mi, 'instance level present');
  assert.equal(mi.result, 'fail');
  assert.match(mi.detail, /no supported hash algorithm/);
});

// --- §11.4 top-hop envelope exact-match ---------------------------------
test('envelope match with differing domain case is not a permerror (§11.4)', async () => {
  // mf/rt domains are lower-cased before comparison, so an upper-case delivery
  // domain must still match. With the real key the whole message verifies.
  const rep = await verifyMessage(SIGNED_SAMPLE, {
    fetchKey: realFetchKey,
    mailFrom: '<sender@TEST.DKIM2.EU>',
    rcptTo: ['<recipient@EXAMPLE.com>'],
    now: FRESH_NOW,
  });
  assert.equal(rep.overall, 'pass');
  assert.doesNotMatch(rep.summary, /did not match/);
  const sig = rep.levels.find((l) => l.kind === 'signature' && l.i === 1);
  assert.equal(sig.custody.ok, true);
});

test('wrong MAIL FROM is PERMERROR with a MAIL FROM detail (§11.4)', async () => {
  const rep = await verifyMessage(SIGNED_SAMPLE, {
    fetchKey: realFetchKey,
    mailFrom: '<attacker@evil.example>',
    rcptTo: ['<recipient@example.com>'],
    now: FRESH_NOW,
  });
  assert.equal(rep.overall, 'permerror');
  assert.match(rep.summary, /MAIL FROM .*did not match/);
  const sig = rep.levels.find((l) => l.kind === 'signature' && l.i === 1);
  assert.equal(sig.result, 'permerror');
});

test('a used RCPT TO absent from rt= is PERMERROR (§11.4)', async () => {
  const rep = await verifyMessage(SIGNED_SAMPLE, {
    fetchKey: realFetchKey,
    mailFrom: '<sender@test.dkim2.eu>',
    rcptTo: ['<nobody@example.com>'],
    now: FRESH_NOW,
  });
  assert.equal(rep.overall, 'permerror');
  assert.match(rep.summary, /RCPT TO .*did not match/);
});

test('local-part case is significant in the envelope match (§11.4)', async () => {
  // rt= carries recipient@example.com; a differently-cased local part must NOT
  // match (only the domain is lower-cased).
  const rep = await verifyMessage(SIGNED_SAMPLE, {
    fetchKey: realFetchKey,
    mailFrom: '<sender@test.dkim2.eu>',
    rcptTo: ['<RECIPIENT@example.com>'],
    now: FRESH_NOW,
  });
  assert.equal(rep.overall, 'permerror');
  assert.match(rep.summary, /RCPT TO .*did not match/);
});

test('omitting the envelope skips the §11.4 check (browser paste case)', async () => {
  // No mailFrom/rcptTo: the envelope check must not fire, so no envelope-based
  // permerror; the message otherwise verifies cleanly.
  const rep = await verifyMessage(SIGNED_SAMPLE, { fetchKey: realFetchKey, now: FRESH_NOW });
  assert.equal(rep.overall, 'pass');
  assert.doesNotMatch(rep.summary, /did not match/);
});

test('custody-only failure (mf=/d= mismatch) surfaces its reason in the summary (fix #4)', async () => {
  // mf= decodes to a domain that does not relaxed-match d=, so custodyCheck's
  // normal (non-exception) `if (!level.custody.ok)` branch fires. Timestamp
  // is fresh and the MI hash-set uses a non-sha256 alg so the MI check is
  // skipped (stays pass); the sig-set alg is unsupported so no real crypto
  // is needed. custody is the only reason this signature is unusable, so its
  // detail must be the one that reaches the summary.
  const raw =
    'From: a@b\r\n' +
    'Message-Instance: m=1; h=blake:xxx:yyy\r\n' +
    'DKIM2-Signature: i=1; m=1; t=1000000; d=example.com; ' +
    's=sel:banana:AAA; mf=PHNlbmRlckB3cm9uZy5leGFtcGxlPg==; rt=AAAA\r\n' +
    '\r\nhi\r\n';
  const rep = await verifyMessage(raw, { now: 1000000, fetchKey: stubKey });
  const sig = rep.levels.find((l) => l.kind === 'signature' && l.i === 1);
  assert.ok(sig, 'signature level present');
  assert.equal(sig.custody.ok, false);
  assert.match(sig.detail, /MAIL FROM and d= do not match/);
  assert.match(rep.summary, /MAIL FROM and d= do not match/);
});

// --- recipe breakdown display (§5/§7.2): per-header current<-previous + JSON ---
test('MI levels expose the decoded recipe breakdown (header current<-previous, summary, JSON)', async () => {
  // A real 6-hop chain message (m=1..5) with header + body recipes at each hop.
  // Keys are irrelevant to the recipe breakdown, so use a stub resolver.
  const chain = readFileSync(
    join(repoRoot, 'perl', 'tests', 'expected', 'chain-hop6-unchanged-re-sign.eml'), 'utf8');
  const rep = await verifyMessage(chain, {
    fetchKey: async () => { throw new Error('key-notfound'); },
    skipTimestamp: true,
  });
  // m=4 adds an Extra-Header and body text; its recipe reconstructs the prior
  // state (Extra-Header absent). This is exactly what the breakdown must show.
  const m4 = rep.levels.find((l) => l.kind === 'instance' && l.m === 4);
  assert.ok(m4, 'm=4 instance level present');
  assert.equal(m4.recipe, 'diff');
  assert.equal(m4.body_recipe, 'diff');
  const eh = (m4.header_recipes || []).find((r) => r.name === 'extra-header');
  assert.ok(eh, 'm=4 has an extra-header recipe');
  assert.equal(eh.current, '(absent)');   // Extra-Header not present at m=4's prior state...
  assert.equal(eh.previous, 'yes');        // ...it existed one hop earlier
  // The decoded recipe JSON is exposed for display.
  assert.ok(m4.recipe_json && Array.isArray(m4.recipe_json.b), 'recipe_json has a body step array');
  assert.ok(m4.recipe_json.h && 'extra-header' in m4.recipe_json.h, 'recipe_json names the header change');
  // The r= tag is shown as a readable summary, not raw base64.
  const rtag = m4.tags.find((t) => t.tag === 'r');
  assert.ok(rtag && /headers:|body:/.test(rtag.value), 'r= tag shows a decoded summary');
  assert.ok(!/^[A-Za-z0-9+/=]{40,}$/.test(rtag.value), 'r= tag is not raw base64');
});

test('an instance with no r= recipe has no recipe_json', async () => {
  const rep = await verifyMessage(SIGNED_SAMPLE, { fetchKey: realFetchKey, skipTimestamp: true });
  const m1 = rep.levels.find((l) => l.kind === 'instance' && l.m === 1);
  assert.ok(m1);
  assert.equal(m1.recipe_json, undefined);
  assert.deepEqual(m1.header_recipes, []);
});

// --- Received-SPF added by the receiving MTA ----------------------------
// spec-06 §4 added a "Received-*" prefix rule, so Received-SPF is excluded
// from the Message-Instance header hash directly (via isUnsignedHeader) and
// never pollutes verification. verifyMessage() no longer has any
// strip-and-retry mechanism for this (removed: it was hardcoded to the
// literal name Received-SPF, and stripping a header excluded from the hash
// cannot change the hash, so it was provably a no-op once §4 landed; same
// removal in Mail::DKIM2::Validate::report()).
test('a Received-SPF prepended by the receiver verifies cleanly (spec-06 §4)', async () => {
  const polluted = 'Received-SPF: pass\r\n (test.example: 1.2.3.4 authorized)\r\n' + SIGNED_SAMPLE;
  const rep = await verifyMessage(polluted, {
    fetchKey: realFetchKey,
    mailFrom: '<sender@test.dkim2.eu>',
    rcptTo: ['<recipient@example.com>'],
    now: FRESH_NOW,
  });
  assert.equal(rep.overall, 'pass');
});

test('a genuinely broken message with Received-SPF present still fails', async () => {
  // Body tampering is unaffected by the header exclusion: the verdict stays fail.
  const broken = 'Received-SPF: pass\r\n' + SIGNED_SAMPLE.replace(/\r\n\r\n/, '\r\n\r\ntampered\r\n');
  const rep = await verifyMessage(broken, { fetchKey: realFetchKey, now: FRESH_NOW });
  assert.equal(rep.overall, 'fail');
});

test('Received-SPF on an LF-only paste (browser textarea) also verifies cleanly', async () => {
  // A <textarea> hands us bare LF line endings; parseMessage normalizes to
  // CRLF internally, so the exclusion must tolerate either form.
  const polluted = 'Received-SPF: pass\n (test.example: 1.2.3.4 authorized)\n'
    + SIGNED_SAMPLE.replace(/\r\n/g, '\n');
  const rep = await verifyMessage(polluted, { fetchKey: realFetchKey, now: FRESH_NOW });
  assert.equal(rep.overall, 'pass');
});

// --- spec-06 §11.2: malformed r= JSON is a specific PERMERROR ------------
//
// This builds a REAL, validly Ed25519-signed two-hop message (genuine
// crypto over the actual canonicalized signing input, using this module's
// own signingInput()/canon*() helpers, exactly as the real verifier would
// compute it) whose m=2 Message-Instance carries an r= tag that
// base64-decodes to truncated/malformed JSON. It is fed through
// verifyMessage(), the same real entry point the /verify/ page itself
// calls -- not decodeRecipe()/JSON.parse() in isolation -- so this proves
// the PERMERROR is actually reachable end to end, not just detectable by
// the parser. Before this fix, the catch around decodeRecipe() in the
// state-reconstruction loop lumped a JSON syntax error in with every other
// "undo broke" cause, producing a generic "state unavailable" fail instead
// of the specific §11.2 PERMERROR text.
test('spec-06 §11.2: malformed r= JSON is reported as the specific PERMERROR through the real verifier entry point', async () => {
  const { subtle } = globalThis.crypto;
  const kp = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pubB64 = bytesToB64(new Uint8Array(await subtle.exportKey('raw', kp.publicKey)));
  const stubEd25519Key = async () => ({ k: 'ed25519', p: pubB64 });

  // Content is identical between hops (a legal, recipe-less/unchanged MI is
  // accepted everywhere), so m=1 and m=2 share the same genuinely correct
  // header/body hashes; only m=2 additionally carries the malformed r=.
  const contentFields = [{ name: 'From', value: ' a@b' }, { name: 'Subject', value: ' hi' }];
  const body = 'hello\r\n';
  const hh = await hashB64(stringToBytes(canonHeaderHash(contentFields)), 'sha256');
  const bh = await hashB64(stringToBytes(canonBody(body)), 'sha256');

  // "eyJoIjog" is base64 of `{"h": `, truncated so it decodes to invalid
  // (incomplete) JSON, not merely a semantic rejection like a null header
  // recipe.
  const badR = 'eyJoIjog';
  const t = 1740000000;
  const mf1 = bytesToB64(stringToBytes('<sender@example.com>'));
  const rt1 = bytesToB64(stringToBytes('<mid@example.com>'));
  const mf2 = bytesToB64(stringToBytes('<mid@example.com>')); // matches hop1's rt= domain
  const rt2 = bytesToB64(stringToBytes('<final@example.com>'));

  // Hop 1 is signed first, on its own (only m=1 / i=1 exist yet) -- exactly
  // as a real signer would produce it before hop 2 ever sees the message.
  const draft1 =
    `DKIM2-Signature: i=1; m=1; t=${t}; d=example.com; mf=${mf1}; rt=${rt1}; s=sel:ed25519-sha256:;\r\n` +
    `Message-Instance: m=1; h=sha256:${hh}:${bh};\r\n` +
    `From: a@b\r\nSubject: hi\r\n\r\n${body}`;
  const { headers: headers1 } = parseMessage(draft1);
  const { instances: mi1map, signatures: sig1map } = collectLevels(headers1);
  const input1 = stringToBytes(signingInput(
    [mi1map[1].field, sig1map[1].field], sig1map[1].field));
  const sig1 = bytesToB64(new Uint8Array(
    await subtle.sign({ name: 'Ed25519' }, kp.privateKey, await sha256Bytes(input1))));

  // Hop 2 signs with hop 1's REAL (already-finalized) signature already in
  // place, plus a still-blank i=2 target -- matching what every real signer
  // covers: existing DKIM2-Signature headers at their true, complete value.
  const draft2 =
    `DKIM2-Signature: i=2; m=2; t=${t}; d=example.com; mf=${mf2}; rt=${rt2}; s=sel:ed25519-sha256:;\r\n` +
    `DKIM2-Signature: i=1; m=1; t=${t}; d=example.com; mf=${mf1}; rt=${rt1}; s=sel:ed25519-sha256:${sig1};\r\n` +
    `Message-Instance: m=2; h=sha256:${hh}:${bh}; r=${badR};\r\n` +
    `Message-Instance: m=1; h=sha256:${hh}:${bh};\r\n` +
    `From: a@b\r\nSubject: hi\r\n\r\n${body}`;
  const { headers: headers2 } = parseMessage(draft2);
  const { instances, signatures } = collectLevels(headers2);
  const input2 = stringToBytes(signingInput(
    [instances[1].field, instances[2].field, signatures[1].field, signatures[2].field],
    signatures[2].field));
  const sig2 = bytesToB64(new Uint8Array(
    await subtle.sign({ name: 'Ed25519' }, kp.privateKey, await sha256Bytes(input2))));

  const raw =
    `DKIM2-Signature: i=2; m=2; t=${t}; d=example.com; mf=${mf2}; rt=${rt2}; s=sel:ed25519-sha256:${sig2};\r\n` +
    `DKIM2-Signature: i=1; m=1; t=${t}; d=example.com; mf=${mf1}; rt=${rt1}; s=sel:ed25519-sha256:${sig1};\r\n` +
    `Message-Instance: m=2; h=sha256:${hh}:${bh}; r=${badR};\r\n` +
    `Message-Instance: m=1; h=sha256:${hh}:${bh};\r\n` +
    `From: a@b\r\nSubject: hi\r\n\r\n${body}`;

  const rep = await verifyMessage(raw, { now: t + 10, fetchKey: stubEd25519Key });

  assert.equal(rep.overall, 'permerror');
  assert.match(rep.summary, /PERMERROR Message-Instance m=2 contains invalid JSON/);
  const mi1 = rep.levels.find((l) => l.kind === 'instance' && l.m === 1);
  assert.ok(mi1, 'm=1 instance level present');
  // Exact match (not just Contains/match): proves the text reaching this
  // level is the verbatim §11.2 string, with no extra decoration.
  assert.equal(mi1.detail, 'PERMERROR Message-Instance m=2 contains invalid JSON');
});

// spec-06 §11.2 ruling: a bad-base64 r= value is a DIFFERENT error from a
// post-decode JSON parse failure, and must stay distinct: base64 failure ->
// "syntax error" (§11.2 lists this explicitly for malformed field content),
// never "contains invalid JSON" (the payload here never even reaches JSON
// parsing). Same real two-hop construction as the test above, "!!!!" (not
// valid base64) in place of the truncated-JSON r= value.
test('spec-06 §11.2: a bad-base64 r= value is reported as "syntax error", distinct from "contains invalid JSON"', async () => {
  const { subtle } = globalThis.crypto;
  const kp = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pubB64 = bytesToB64(new Uint8Array(await subtle.exportKey('raw', kp.publicKey)));
  const stubEd25519Key = async () => ({ k: 'ed25519', p: pubB64 });

  const contentFields = [{ name: 'From', value: ' a@b' }, { name: 'Subject', value: ' hi' }];
  const body = 'hello\r\n';
  const hh = await hashB64(stringToBytes(canonHeaderHash(contentFields)), 'sha256');
  const bh = await hashB64(stringToBytes(canonBody(body)), 'sha256');

  const badR = '!!!!';
  const t = 1740000000;
  const mf1 = bytesToB64(stringToBytes('<sender@example.com>'));
  const rt1 = bytesToB64(stringToBytes('<mid@example.com>'));
  const mf2 = bytesToB64(stringToBytes('<mid@example.com>'));
  const rt2 = bytesToB64(stringToBytes('<final@example.com>'));

  const draft1 =
    `DKIM2-Signature: i=1; m=1; t=${t}; d=example.com; mf=${mf1}; rt=${rt1}; s=sel:ed25519-sha256:;\r\n` +
    `Message-Instance: m=1; h=sha256:${hh}:${bh};\r\n` +
    `From: a@b\r\nSubject: hi\r\n\r\n${body}`;
  const { headers: headers1 } = parseMessage(draft1);
  const { instances: mi1map, signatures: sig1map } = collectLevels(headers1);
  const input1 = stringToBytes(signingInput(
    [mi1map[1].field, sig1map[1].field], sig1map[1].field));
  const sig1 = bytesToB64(new Uint8Array(
    await subtle.sign({ name: 'Ed25519' }, kp.privateKey, await sha256Bytes(input1))));

  const draft2 =
    `DKIM2-Signature: i=2; m=2; t=${t}; d=example.com; mf=${mf2}; rt=${rt2}; s=sel:ed25519-sha256:;\r\n` +
    `DKIM2-Signature: i=1; m=1; t=${t}; d=example.com; mf=${mf1}; rt=${rt1}; s=sel:ed25519-sha256:${sig1};\r\n` +
    `Message-Instance: m=2; h=sha256:${hh}:${bh}; r=${badR};\r\n` +
    `Message-Instance: m=1; h=sha256:${hh}:${bh};\r\n` +
    `From: a@b\r\nSubject: hi\r\n\r\n${body}`;
  const { headers: headers2 } = parseMessage(draft2);
  const { instances, signatures } = collectLevels(headers2);
  const input2 = stringToBytes(signingInput(
    [instances[1].field, instances[2].field, signatures[1].field, signatures[2].field],
    signatures[2].field));
  const sig2 = bytesToB64(new Uint8Array(
    await subtle.sign({ name: 'Ed25519' }, kp.privateKey, await sha256Bytes(input2))));

  const raw =
    `DKIM2-Signature: i=2; m=2; t=${t}; d=example.com; mf=${mf2}; rt=${rt2}; s=sel:ed25519-sha256:${sig2};\r\n` +
    `DKIM2-Signature: i=1; m=1; t=${t}; d=example.com; mf=${mf1}; rt=${rt1}; s=sel:ed25519-sha256:${sig1};\r\n` +
    `Message-Instance: m=2; h=sha256:${hh}:${bh}; r=${badR};\r\n` +
    `Message-Instance: m=1; h=sha256:${hh}:${bh};\r\n` +
    `From: a@b\r\nSubject: hi\r\n\r\n${body}`;

  const rep = await verifyMessage(raw, { now: t + 10, fetchKey: stubEd25519Key });

  assert.equal(rep.overall, 'permerror');
  const mi1 = rep.levels.find((l) => l.kind === 'instance' && l.m === 1);
  assert.ok(mi1, 'm=1 instance level present');
  assert.equal(mi1.detail, 'PERMERROR Message-Instance m=2 syntax error');
  assert.doesNotMatch(mi1.detail, /invalid JSON/);
});

// spec-06 §9.1: the BOTTOM (m=1) instance MAY carry Recipes too ("if it is
// wished to record any changes made to a message as it enters the DKIM2
// ecosystem"). It never participates in the reconstruction loop (there is
// no earlier state to undo to), so before this fix it was never checked at
// all -- a single-instance (m=1 only) message, so m=1 is both the topmost
// AND the bottom instance, hand-signed so its own signature legitimately
// covers the malformed r=.
test('spec-06 §9.1/§11.2: a malformed r= on the BOTTOM (m=1) instance is rejected too, not silently ignored', async () => {
  const { subtle } = globalThis.crypto;
  const kp = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pubB64 = bytesToB64(new Uint8Array(await subtle.exportKey('raw', kp.publicKey)));
  const stubEd25519Key = async () => ({ k: 'ed25519', p: pubB64 });

  const contentFields = [{ name: 'From', value: ' a@b' }, { name: 'Subject', value: ' hi' }];
  const body = 'hello\r\n';
  const hh = await hashB64(stringToBytes(canonHeaderHash(contentFields)), 'sha256');
  const bh = await hashB64(stringToBytes(canonBody(body)), 'sha256');

  const badR = 'eyJoIjog'; // base64 of `{"h": `, truncated/invalid JSON
  const t = 1740000000;
  const mf1 = bytesToB64(stringToBytes('<sender@example.com>'));
  const rt1 = bytesToB64(stringToBytes('<rcpt@example.com>'));

  const draft =
    `DKIM2-Signature: i=1; m=1; t=${t}; d=example.com; mf=${mf1}; rt=${rt1}; s=sel:ed25519-sha256:;\r\n` +
    `Message-Instance: m=1; h=sha256:${hh}:${bh}; r=${badR};\r\n` +
    `From: a@b\r\nSubject: hi\r\n\r\n${body}`;
  const { headers } = parseMessage(draft);
  const { instances, signatures } = collectLevels(headers);
  const input = stringToBytes(signingInput(
    [instances[1].field, signatures[1].field], signatures[1].field));
  const sig = bytesToB64(new Uint8Array(
    await subtle.sign({ name: 'Ed25519' }, kp.privateKey, await sha256Bytes(input))));

  const raw =
    `DKIM2-Signature: i=1; m=1; t=${t}; d=example.com; mf=${mf1}; rt=${rt1}; s=sel:ed25519-sha256:${sig};\r\n` +
    `Message-Instance: m=1; h=sha256:${hh}:${bh}; r=${badR};\r\n` +
    `From: a@b\r\nSubject: hi\r\n\r\n${body}`;

  const rep = await verifyMessage(raw, { now: t + 10, fetchKey: stubEd25519Key });

  assert.equal(rep.overall, 'permerror');
  const mi1 = rep.levels.find((l) => l.kind === 'instance' && l.m === 1);
  assert.ok(mi1, 'm=1 instance level present');
  assert.equal(mi1.detail, 'PERMERROR Message-Instance m=1 contains invalid JSON');
});

// --- §11.6 signature-failure strings name the Selector -------------------
// draft-06 replaced the algorithm-based failure text with Selector-based
// wording: "<selector> incorrect signature", and a two-Selector variant for
// when some signatures pass and others fail.
test('spec-06 §11.6: a broken signature names the failing Selector', async () => {
  // Corrupt one base64 character inside the s= signature value. The value stays
  // valid base64, so RSA verification returns false rather than throwing — that
  // is the plain-FAIL branch, not the key-permerror branch.
  const broken = SIGNED_SAMPLE.replace(
    /(s=rsa2048:rsa-sha256:)(.)/,
    (_m, pre, c) => pre + (c === 'A' ? 'B' : 'A'),
  );
  assert.notEqual(broken, SIGNED_SAMPLE, 'sample was actually corrupted');
  const rep = await verifyMessage(broken, {
    fetchKey: realFetchKey,
    mailFrom: '<sender@test.dkim2.eu>',
    rcptTo: ['<recipient@example.com>'],
    now: FRESH_NOW,
  });
  const sig = rep.levels.find((l) => l.kind === 'signature' && l.i === 1);
  assert.equal(sig.result, 'fail');
  assert.equal(sig.detail, 'DKIM2-Signature i=1 rsa2048 incorrect signature');
});
