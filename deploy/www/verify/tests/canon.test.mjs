import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonBody, canonHeaderHash, isUnsignedHeader, signingInput, blankSignatureValues } from '../canon.js';

test('canonBody reduces trailing empty lines to one CRLF', () => {
  assert.equal(canonBody('a\r\nb\r\n\r\n\r\n'), 'a\r\nb\r\n');
  assert.equal(canonBody('a\r\nb'), 'a\r\nb\r\n');
  assert.equal(canonBody(''), '\r\n');
});

test('isUnsignedHeader matches the §4 list', () => {
  // Message-Instance and DKIM2-Signature are unsigned here for parity with
  // the other five implementations (see the comment in canon.js); the
  // verifier also filters them upstream in signedFields().
  for (const n of ['Received', 'Return-Path', 'Delivered-To', 'DKIM-Signature',
    'ARC-Seal', 'Authentication-Results', 'X-Spam', 'Message-Instance',
    'DKIM2-Signature'])
    assert.equal(isUnsignedHeader(n), true, n);
  for (const n of ['From', 'Subject', 'To'])
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

test('canonHeaderHash collapses an interior WSP run to a single SP, not deletes it', () => {
  // §6.2 collapses runs of WSP to one SP; it must NOT delete them entirely
  // (that is the §9.6 signing-input rule). This would fail if hashLine were
  // ever changed to delete-all-WSP instead of collapse-to-one-SP.
  const fields = [{ name: 'Subject', value: 'a  b' }];
  assert.equal(canonHeaderHash(fields), 'subject:a b\r\n');
});

test('canonHeaderHash unfolds a header value with an embedded CRLF+WSP fold', () => {
  // The fold (CRLF followed by WSP) must be removed entirely by unfold(),
  // then the single remaining space is left as-is by the WSP-collapse step.
  const fields = [{ name: 'Subject', value: 'a\r\n b' }];
  assert.equal(canonHeaderHash(fields), 'subject:a b\r\n');
});

test('signingInput unfolds a header value with an embedded CRLF+WSP fold', () => {
  // unfold() strips the CRLF of the fold; the WSP that follows (and any
  // other WSP in the value) is then deleted entirely per §9.6.
  const mi = { name: 'Message-Instance', value: ' m=1;\r\n h=sha256:AA=:BB=' };
  const sig = { name: 'DKIM2-Signature', value: ' i=1; s=sel:ed25519-sha256:ZZ' };
  const out = signingInput([mi, sig], sig);
  assert.equal(out,
    'message-instance:m=1;h=sha256:AA=:BB=\r\n' +
    'dkim2-signature:i=1;s=sel:ed25519-sha256:\r\n');
});

test('canonHeaderHash orders duplicates bottom-up by document index, not array adjacency', () => {
  const fields = [
    { name: 'From', value: 'a' },
    { name: 'To', value: 'x' },
    { name: 'From', value: 'b' },
    { name: 'From', value: 'c' },
  ];
  assert.equal(canonHeaderHash(fields),
    'from:c\r\nfrom:b\r\nfrom:a\r\nto:x\r\n');
});

test('spec-06 §4: HDRMAINT-survey names are unsigned', () => {
  for (const n of ['Apparently-To', 'Auto-Submitted', 'DL-Expansion-History',
                   'Original-Recipient', 'SIO-Label-History', 'VBR-Info',
                   'X400-Received', 'X400-Trace']) {
    assert.ok(isUnsignedHeader(n), `${n} must be unsigned`);
  }
});

test('spec-06 §4: any Received-* is unsigned', () => {
  assert.ok(isUnsignedHeader('Received-SPF'));
  assert.ok(isUnsignedHeader('Received-Anything'));
});

test('spec-05 §4: the ARC- prefix narrowed to three names', () => {
  assert.ok(isUnsignedHeader('ARC-Seal'));
  assert.ok(isUnsignedHeader('ARC-Message-Signature'));
  assert.ok(isUnsignedHeader('ARC-Authentication-Results'));
  assert.ok(!isUnsignedHeader('ARC-Something-Else'));
});

test('MI and DKIM2-Signature are in the list for parity with the other five impls', () => {
  assert.ok(isUnsignedHeader('Message-Instance'));
  assert.ok(isUnsignedHeader('DKIM2-Signature'));
});
