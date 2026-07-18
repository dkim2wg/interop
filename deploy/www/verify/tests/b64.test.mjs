import { test } from 'node:test';
import assert from 'node:assert/strict';
import { b64ToBytes, bytesToB64, b64ToString, stringToBytes, bytesToString } from '../b64.js';

test('bytesToB64 round-trips b64ToBytes', () => {
  const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
  assert.equal(bytesToB64(bytes), 'AAEC/f7/');
  assert.deepEqual(b64ToBytes('AAEC/f7/'), bytes);
});

test('b64ToString decodes base64 of a reverse-path', () => {
  // base64('<sender@test.dkim2.eu>')
  assert.equal(b64ToString('PHNlbmRlckB0ZXN0LmRraW0yLmV1Pg=='), '<sender@test.dkim2.eu>');
});

test('stringToBytes/bytesToString round-trip UTF-8', () => {
  const s = 'Subject: héllo';
  assert.equal(bytesToString(stringToBytes(s)), s);
});
