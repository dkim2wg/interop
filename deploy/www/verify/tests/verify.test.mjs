import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyMessage, relaxedDomainMatch, domainOf } from '../verify.js';

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
