import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseKeyRecord, keyName } from '../doh.js';

test('keyName builds the _domainkey query name', () => {
  assert.equal(keyName('ed25519', 'test.dkim2.eu'), 'ed25519._domainkey.test.dkim2.eu');
});

test('parseKeyRecord reads k and p, defaults k to rsa', () => {
  assert.deepEqual(parseKeyRecord('v=DKIM1; k=ed25519; p=abc='), { k: 'ed25519', p: 'abc=' });
  assert.deepEqual(parseKeyRecord('v=DKIM1; p=xyz='), { k: 'rsa', p: 'xyz=' });
});

test('parseKeyRecord throws on empty p (revoked) and on missing p', () => {
  assert.throws(() => parseKeyRecord('v=DKIM1; k=rsa; p='), /key-revoked/);
  assert.throws(() => parseKeyRecord('v=DKIM1; k=rsa'), /key-syntax/);
});
