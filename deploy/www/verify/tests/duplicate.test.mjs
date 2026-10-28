import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkSignatureDuplicates } from '../verify.js';
import { parseHashSets } from '../parse.js';

test('clean signature list has no errors', () => {
  const items = [{ selector: 'sel1', alg: 'rsa-sha256' }, { selector: 'sel2', alg: 'ed25519-sha256' }];
  assert.deepEqual(checkSignatureDuplicates(items, 1), []);
});

test('duplicate selector is permerror', () => {
  // §10.9: a Selector MUST NOT be present more than once
  const items = [{ selector: 'sel1', alg: 'rsa-sha256' }, { selector: 'sel1', alg: 'ed25519-sha256' }];
  assert.deepEqual(checkSignatureDuplicates(items, 3),
    ['PERMERROR: DKIM2-Signature i=3 has a duplicate selector']);
});

test('duplicate selector is case-insensitive', () => {
  // Selector is a Domain (§3.6); DNS names are case-insensitive
  const items = [{ selector: 'Sel1', alg: 'rsa-sha256' }, { selector: 'sel1', alg: 'ed25519-sha256' }];
  const errs = checkSignatureDuplicates(items, 1);
  assert.equal(errs.length, 1);
  assert.match(errs[0], /has a duplicate selector/);
});

test('the same algorithm any number of times with distinct selectors is allowed', () => {
  // -08 §10.9: more than one signature using the same algorithm MAY be
  // present provided a different Selector is used for each
  const items = [1, 2, 3, 4, 5, 6, 7, 8].map((n) => ({ selector: `sel${n}`, alg: 'rsa-sha256' }));
  assert.deepEqual(checkSignatureDuplicates(items, 1), []);
});

test('more than 8 items is the local limit (contract D3)', () => {
  const items = [1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => ({ selector: `sel${n}`, alg: `alg${n}` }));
  assert.deepEqual(checkSignatureDuplicates(items, 2),
    ['PERMERROR: DKIM2-Signature i=2 has more than 8 signatures']);
});

test('a duplicate selector is reported before the limit', () => {
  const items = [1, 2, 3, 4, 5, 6, 7, 8, 1].map((n) => ({ selector: `sel${n}`, alg: 'rsa-sha256' }));
  assert.deepEqual(checkSignatureDuplicates(items, 1), [
    'PERMERROR: DKIM2-Signature i=1 has a duplicate selector',
    'PERMERROR: DKIM2-Signature i=1 has more than 8 signatures']);
});

test('parseHashSets keeps duplicate algorithms visible as a list', () => {
  // §9.3: h= duplicate-algorithm detection must run over the parsed
  // LIST, never a deduplicated map (a map would silently overwrite the
  // second occurrence and make the duplicate undetectable).
  const sets = parseHashSets('sha256:AAAA:BBBB,sha256:CCCC:DDDD');
  assert.equal(sets.length, 2);
  assert.equal(sets[0].alg, 'sha256');
  assert.equal(sets[1].alg, 'sha256');
});

import { verifyMessage } from '../verify.js';

test('duplicate Message-Instance m= is permerror', async () => {
  // Exactly one Message-Instance per m= value
  const raw = 'From: a@example.com\r\nTo: b@example.com\r\n' +
    'Message-Instance: m=1; h=sha256:AAAA:BBBB\r\n' +
    'Message-Instance: m=1; h=sha256:AAAA:BBBB\r\n' +
    'DKIM2-Signature: i=1; m=1; t=1; d=example.com; s=a:rsa-sha256:sel; mf=<a@example.com>; rt=<b@example.com>; b=AAAA\r\n' +
    '\r\nhi\r\n';
  const r = await verifyMessage(raw);
  assert.equal(r.overall, 'permerror');
  assert.match(r.summary, /Message-Instance m=1 appears more than once/);
});

test('duplicate DKIM2-Signature i= is permerror', async () => {
  const sig = 'DKIM2-Signature: i=1; m=1; t=1; d=example.com; s=a:rsa-sha256:sel; mf=<a@example.com>; rt=<b@example.com>; b=AAAA\r\n';
  const raw = 'From: a@example.com\r\nMessage-Instance: m=1; h=sha256:AAAA:BBBB\r\n' + sig + sig + '\r\nhi\r\n';
  const r = await verifyMessage(raw);
  assert.equal(r.overall, 'permerror');
  assert.match(r.summary, /DKIM2-Signature i=1 appears more than once/);
});
