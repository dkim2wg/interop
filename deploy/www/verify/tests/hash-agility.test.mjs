import { test } from 'node:test';
import assert from 'node:assert';
import { HASH_ALGS, hashB64 } from '../crypto.js';
import { parseHashSets } from '../parse.js';

test('§3: both hashing algorithms are implemented', () => {
  assert.deepEqual(Object.keys(HASH_ALGS).sort(), ['sha256', 'sha512']);
});

test('§9.3: h= parses as a list of hash-sets', () => {
  const sets = parseHashSets('sha256:AAAA:BBBB,sha512:CCCC:DDDD');
  assert.equal(sets.length, 2);
  assert.deepEqual(sets[0], { alg: 'sha256', headerHash: 'AAAA', bodyHash: 'BBBB', group: 0 });
  assert.equal(sets[1].alg, 'sha512');
});

test('-08 §9.3: "|" separates groups of "," lists, FWS either side', () => {
  const sets = parseHashSets('sha256:AAAA:BBBB , x:CCCC:DDDD\r\n | sha512:EEEE:FFFF');
  assert.deepEqual(sets.map((s) => [s.alg, s.group]), [['sha256', 0], ['x', 0], ['sha512', 1]]);
  for (const bad of ['|sha256:AAAA:BBBB', 'sha256:AAAA:BBBB|', 'sha256:AAAA:BBBB||x:AAAA:AAAA',
    'sha256:AAAA:BBBB,', 'sha256:AAAA:BBBB, |x:AAAA:AAAA', 'sha256:AAA:BBBB', 'x:AAAA:']) {
    assert.throws(() => parseHashSets(bad), /h-syntax/, bad);
  }
});

test('hash-name matching is case-insensitive (RFC 5234)', () => {
  assert.equal(parseHashSets('SHA512:AAAA:BBBB')[0].alg, 'sha512');
});

test('sha512 digest is 64 bytes (88 base64 chars)', async () => {
  const b = new TextEncoder().encode('Hello\r\n');
  assert.equal((await hashB64(b, 'sha512')).length, 88);
  assert.equal((await hashB64(b, 'sha256')).length, 44);
});
