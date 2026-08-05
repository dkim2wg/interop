import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseMessage, parseTagList, collectLevels } from '../parse.js';

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
