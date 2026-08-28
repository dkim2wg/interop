import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkSignatureDuplicates } from '../verify.js';
import { parseHashSets } from '../parse.js';

test('clean signature list has no errors', () => {
  const items = [{ selector: 'sel1', alg: 'rsa-sha256' }, { selector: 'sel2', alg: 'ed25519-sha256' }];
  assert.deepEqual(checkSignatureDuplicates(items, 1), []);
});

test('duplicate selector is permerror', () => {
  // spec-06 §8.9: a Selector MUST NOT be present more than once
  const items = [{ selector: 'sel1', alg: 'rsa-sha256' }, { selector: 'sel1', alg: 'ed25519-sha256' }];
  assert.deepEqual(checkSignatureDuplicates(items, 3),
    ['PERMERROR DKIM2-Signature i=3 has a duplicate selector']);
});

test('duplicate selector is case-insensitive', () => {
  // Selector is a Domain (§3.5); DNS names are case-insensitive
  const items = [{ selector: 'Sel1', alg: 'rsa-sha256' }, { selector: 'sel1', alg: 'ed25519-sha256' }];
  const errs = checkSignatureDuplicates(items, 1);
  assert.equal(errs.length, 1);
  assert.match(errs[0], /has a duplicate selector/);
});

test('same algorithm twice with distinct selectors is allowed', () => {
  // spec-06 §8.9: one additional signature using the same algorithm MAY be
  // present provided a different Selector is used
  const items = [{ selector: 'sel1', alg: 'rsa-sha256' }, { selector: 'sel2', alg: 'rsa-sha256' }];
  assert.deepEqual(checkSignatureDuplicates(items, 1), []);
});

test('same algorithm three times has excess selectors', () => {
  const items = [
    { selector: 'sel1', alg: 'rsa-sha256' },
    { selector: 'sel2', alg: 'rsa-sha256' },
    { selector: 'sel3', alg: 'rsa-sha256' },
  ];
  assert.deepEqual(checkSignatureDuplicates(items, 2),
    ['PERMERROR DKIM2-Signature i=2 has more selectors than allowed']);
});

test('duplicate selector and excess-selector are independent', () => {
  // two sigs sharing an algorithm AND a selector is a duplicate-selector
  // error but NOT an excess-selector error (the count is 2, not 3+)
  const items = [{ selector: 'sel1', alg: 'rsa-sha256' }, { selector: 'sel1', alg: 'rsa-sha256' }];
  const errs = checkSignatureDuplicates(items, 1);
  assert.ok(errs.some((e) => e.includes('duplicate selector')));
  assert.ok(!errs.some((e) => e.includes('more selectors than allowed')));
});

test('parseHashSets keeps duplicate algorithms visible as a list', () => {
  // spec-06 §7.3: h= duplicate-algorithm detection must run over the parsed
  // LIST, never a deduplicated map (a map would silently overwrite the
  // second occurrence and make the duplicate undetectable).
  const sets = parseHashSets('sha256:AAA:BBB,sha256:CCC:DDD');
  assert.equal(sets.length, 2);
  assert.equal(sets[0].alg, 'sha256');
  assert.equal(sets[1].alg, 'sha256');
});
