import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseToml } from './toml.mjs';

test('parses scalars, arrays, multiline, and tables', () => {
  const t = parseToml([
    "Name = 'algorithm_with_future'",
    'ExpectedState = \'pass\'',
    "RcptTo = ['<recipient@example.com>']",
    'ExpectedFlags = []',
    'SignedMessage = """',
    'Message-Instance: m=1\r',
    'From: a@b\r',
    '"""',
    '',
    '[DNS]',
    "'ed25519._domainkey.test.dkim2.eu' = 'v=DKIM1; k=ed25519; p=abc'",
  ].join('\n'));
  assert.equal(t.Name, 'algorithm_with_future');
  assert.equal(t.ExpectedState, 'pass');
  assert.deepEqual(t.RcptTo, ['<recipient@example.com>']);
  assert.deepEqual(t.ExpectedFlags, []);
  assert.equal(t.SignedMessage, 'Message-Instance: m=1\r\nFrom: a@b\r\n');
  assert.equal(t.DNS['ed25519._domainkey.test.dkim2.eu'], 'v=DKIM1; k=ed25519; p=abc');
});
