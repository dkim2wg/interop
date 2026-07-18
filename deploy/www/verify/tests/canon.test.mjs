import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonBody, canonHeaderHash, isUnsignedHeader, signingInput, blankSignatureValues } from '../canon.js';

test('canonBody reduces trailing empty lines to one CRLF', () => {
  assert.equal(canonBody('a\r\nb\r\n\r\n\r\n'), 'a\r\nb\r\n');
  assert.equal(canonBody('a\r\nb'), 'a\r\nb\r\n');
  assert.equal(canonBody(''), '\r\n');
});

test('isUnsignedHeader matches the §4 list', () => {
  for (const n of ['Received', 'Return-Path', 'Delivered-To', 'DKIM-Signature',
    'ARC-Seal', 'Authentication-Results', 'X-Spam'])
    assert.equal(isUnsignedHeader(n), true, n);
  for (const n of ['From', 'Subject', 'To', 'Message-Instance', 'DKIM2-Signature'])
    assert.equal(isUnsignedHeader(n), false, n);
});

test('canonHeaderHash lowercases names, collapses WSP, sorts, orders dups bottom-up', () => {
  const fields = [
    { name: 'Received', value: ' from x' },   // ignored (§4)
    { name: 'SUBJect', value: '  AbC  ' },
    { name: 'From', value: ' a@b' },
    { name: 'From', value: ' c@d' },           // duplicate; bottom-up => c@d first
  ].filter((f) => !isUnsignedHeader(f.name));
  assert.equal(canonHeaderHash(fields),
    'from:c@d\r\nfrom:a@b\r\nsubject:AbC\r\n');
});

test('blankSignatureValues empties message-sig, keeps selector:alg:', () => {
  const raw = 'i=1;m=1;s=banana:banana:YmFuYW5h,ed25519:ed25519-sha256:8SDP==';
  assert.match(blankSignatureValues(raw), /s=banana:banana:,ed25519:ed25519-sha256:/);
});

test('signingInput removes all WSP, keeps colon and CRLF, blanks target s=', () => {
  const mi = { name: 'Message-Instance', value: ' m=1; h=sha256:AA=:BB=' };
  const sig = { name: 'DKIM2-Signature', value: ' i=1; s=sel:ed25519-sha256:ZZ' };
  const out = signingInput([mi, sig], sig);
  assert.equal(out,
    'message-instance:m=1;h=sha256:AA=:BB=\r\n' +
    'dkim2-signature:i=1;s=sel:ed25519-sha256:\r\n');
});
