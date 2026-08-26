import { test } from 'node:test';
import assert from 'node:assert';
import { HASH_ALGS, hashB64 } from '../crypto.js';
import { parseHashSets } from '../parse.js';

test('spec-05 §3: both hashing algorithms are implemented', () => {
  assert.deepEqual(Object.keys(HASH_ALGS).sort(), ['sha256', 'sha512']);
});

test('spec-05 §7.3: h= parses as a list of hash-sets', () => {
  const sets = parseHashSets('sha256:AAA:BBB,sha512:CCC:DDD');
  assert.equal(sets.length, 2);
  assert.deepEqual(sets[0], { alg: 'sha256', headerHash: 'AAA', bodyHash: 'BBB' });
  assert.equal(sets[1].alg, 'sha512');
});

test('hash-name matching is case-insensitive (RFC 5234)', () => {
  assert.equal(parseHashSets('SHA512:AAA:BBB')[0].alg, 'sha512');
});

test('sha512 digest is 64 bytes (88 base64 chars)', async () => {
  const b = new TextEncoder().encode('Hello\r\n');
  assert.equal((await hashB64(b, 'sha512')).length, 88);
  assert.equal((await hashB64(b, 'sha256')).length, 44);
});
