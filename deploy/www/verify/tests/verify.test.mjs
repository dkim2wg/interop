import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyMessage, relaxedDomainMatch, domainOf } from '../verify.js';
import { parseKeyRecord } from '../doh.js';

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
test('expired signature (>14 days) is PERMERROR (§11.3)', async () => {
  const rep = await verifyMessage(SIGNED_SAMPLE, {
    fetchKey: realFetchKey,
    mailFrom: '<sender@test.dkim2.eu>',
    rcptTo: ['<recipient@example.com>'],
    now: SAMPLE_T + 20 * 86400, // 20 days after the signature timestamp
  });
  assert.equal(rep.overall, 'permerror');
  assert.match(rep.summary, /signature expired/);
  const sig = rep.levels.find((l) => l.kind === 'signature' && l.i === 1);
  assert.equal(sig.result, 'permerror');
  assert.equal(sig.timestamp.ok, false);
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
