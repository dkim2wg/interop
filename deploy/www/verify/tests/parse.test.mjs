import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseMessage, parseTagList, collectLevels, MAX_CHAIN_LENGTH, MAX_CHAIN_NUMBER, chainNumberError } from '../parse.js';

const MSG =
  'Message-Instance: m=1; h=sha256:AA=:BB=\r\n' +
  'DKIM2-Signature: i=1; m=1;\r\n' +
  ' d=test.dkim2.eu; s=sel:ed25519-sha256:ZZ\r\n' +
  'From: a@b\r\n' +
  'Subject: hi\r\n' +
  '\r\n' +
  'body line\r\n';

test('parseMessage splits headers and body, unfolds', () => {
  const { headers, body } = parseMessage(MSG);
  assert.equal(headers.length, 4);
  assert.equal(headers[0].name, 'Message-Instance');
  assert.equal(headers[2].name, 'From');
  // Folded DKIM2-Signature value is unfolded: the fold CRLF is removed but
  // the continuation line's leading whitespace survives (no literal \r\n).
  assert.equal(
    headers[1].value,
    ' i=1; m=1; d=test.dkim2.eu; s=sel:ed25519-sha256:ZZ'
  );
  assert.equal(body, 'body line\r\n');
});

test('parseMessage normalizes bare LF to CRLF', () => {
  const { headers, body } = parseMessage('From: a@b\nSubject: x\n\nhi\n');
  assert.equal(headers.length, 2);
  assert.equal(body, 'hi\r\n');
});

test('parseTagList parses tags case-insensitively, values case-significant', () => {
  const { map, tags } = parseTagList('i=1; M=1; d=Test.DKIM2.eu;');
  assert.equal(map.i, '1');
  assert.equal(map.m, '1');       // tag name lowercased
  assert.equal(map.d, 'Test.DKIM2.eu'); // value preserved
  assert.equal(tags.length, 3);   // trailing empty segment dropped
});

test('parseTagList strips fold whitespace embedded inside a value', () => {
  // A base64 value split across a header fold: continuation-line WSP lands in
  // the middle of the token. It MUST be removed so the reassembled value is the
  // intact base64 (otherwise hash-string comparison fails — the folded-list bug).
  const { map } = parseTagList('h=sha256:AAAA=:4olUkMUi2b\tCCfVrAOg==');
  assert.equal(map.h, 'sha256:AAAA=:4olUkMUi2bCCfVrAOg==');
  assert.ok(!/[ \t]/.test(map.h));
});

test('collectLevels reassembles a folded Message-Instance h= base64 intact', () => {
  // The Message-Instance header is folded mid-base64 (as real MTAs emit).
  const raw =
    'Message-Instance: m=1;\r\n' +
    '\th=sha256:hixqBKGSX/pbmi3l0M1YQzc8Ad5BVkkHhRl4fNWkqjs=:4olUkMUi2b\r\n' +
    '\tCCfVrAOg4rSNpPMBWnWoKd71+94zpiUqo=\r\n' +
    'From: a@b\r\n\r\nbody\r\n';
  const { headers } = parseMessage(raw);
  const { instances } = collectLevels(headers);
  const bodyHash = instances[1].map.h.split(',')[0].split(':')[2];
  assert.equal(bodyHash, '4olUkMUi2bCCfVrAOg4rSNpPMBWnWoKd71+94zpiUqo=');
  assert.ok(!/[ \t]/.test(instances[1].map.h));
});

test('collectLevels indexes instances and signatures', () => {
  const { headers } = parseMessage(MSG);
  const { instances, signatures } = collectLevels(headers);
  assert.equal(instances[1].map.m, '1');
  assert.equal(signatures[1].map.d, 'test.dkim2.eu');
});

test('collectLevels does not create NaN-keyed entries for malformed headers', () => {
  const malformed =
    'Message-Instance: h=sha256:AA=:BB=\r\n' +
    'DKIM2-Signature: d=test.dkim2.eu; s=sel:ed25519-sha256:ZZ\r\n' +
    'From: a@b\r\n' +
    '\r\n' +
    'body\r\n';
  const { headers } = parseMessage(malformed);
  const { instances, signatures, miFields, sigFields } = collectLevels(headers);
  assert.equal(Object.keys(instances).length, 0);
  assert.equal(Object.keys(signatures).length, 0);
  assert.ok(!Object.prototype.hasOwnProperty.call(instances, 'NaN'));
  assert.ok(!Object.prototype.hasOwnProperty.call(signatures, 'NaN'));
  // The malformed headers must still be retained for downstream count checks.
  assert.equal(miFields.length, 1);
  assert.equal(sigFields.length, 1);
});

test('collectLevels counts DKIM2-Signatures with no valid i= as unkeyable', () => {
  const msg =
    'DKIM2-Signature: m=2; d=evil.example\r\n' +
    'DKIM2-Signature: i=0; m=2; d=evil.example\r\n' +
    'DKIM2-Signature: i=abc; m=2; d=evil.example\r\n' +
    'DKIM2-Signature: i=1; m=1; d=good.example\r\n' +
    'From: a@b\r\n\r\nbody\r\n';
  const { headers } = parseMessage(msg);
  const { signatures, unkeyableSignatures } = collectLevels(headers);
  assert.equal(unkeyableSignatures, 3);
  assert.deepEqual(Object.keys(signatures), ['1']);
});

test('chainNumberError: i=/m= is 1*DIGIT, at most 3 digits and 1..100, then at most 32', () => {
  assert.equal(MAX_CHAIN_LENGTH, 32);
  assert.equal(MAX_CHAIN_NUMBER, 100);
  for (const v of ['1', '9', '32', '01', '001', '032']) assert.equal(chainNumberError('DKIM2-Signature', 'm', v), null, v);
  for (const v of ['33', '99', '100', '099'])
    assert.equal(chainNumberError('DKIM2-Signature', 'm', v), 'DKIM2-Signature m= exceeds the maximum chain length of 32', v);
  for (const v of ['101', '999', '0001', '4294967297', '99999999999999999999'])
    assert.equal(chainNumberError('Message-Instance', 'm', v), 'Message-Instance m= exceeds the maximum chain number of 100', v);
  for (const v of ['', '0', '00', '000', 'abc', '1x', '4294967297x', '30000000x', '0_1', '\uFF11', '+1', '-1', ' 1'])
    assert.equal(chainNumberError('Message-Instance', 'm', v), 'Message-Instance has a malformed m= tag', JSON.stringify(v));
  assert.equal(chainNumberError('DKIM2-Signature', 'i', 'abc'), 'DKIM2-Signature has a missing or malformed i= tag');
  assert.equal(chainNumberError('DKIM2-Signature', 'm', undefined), null, 'missing is left to the callers');
});

test('collectLevels keys i=/m= numerically (01 and 001 are 1)', () => {
  const msg = 'Message-Instance: m=001; h=x\r\nDKIM2-Signature: i=01; m=001; d=a.example\r\nFrom: a@b\r\n\r\nbody\r\n';
  const { instances, signatures, rangeError } = collectLevels(parseMessage(msg).headers);
  assert.equal(rangeError, null);
  assert.deepEqual(Object.keys(instances), ['1']);
  assert.deepEqual(Object.keys(signatures), ['1']);
});
