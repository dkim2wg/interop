import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyMessage, relaxedDomainMatch, domainOf } from '../verify.js';

test('relaxedDomainMatch strips labels from the left of the from-domain', () => {
  assert.equal(relaxedDomainMatch('bounce.a.example.com', 'example.com'), true);
  assert.equal(relaxedDomainMatch('example.com', 'example.com'), true);
  assert.equal(relaxedDomainMatch('example.com', 'other.com'), false);
});

test('domainOf extracts the domain from a reverse/forward path', () => {
  assert.equal(domainOf('<bob@Sub.Example.COM>'), 'sub.example.com');
  assert.equal(domainOf('<>'), '');
});

test('no DKIM2-Signature yields overall=none', async () => {
  const rep = await verifyMessage('From: a@b\r\nSubject: x\r\n\r\nhi\r\n');
  assert.equal(rep.overall, 'none');
});

test('verifyMessage returns a levels array (shape contract)', async () => {
  // Real crypto verification of signed messages is covered end-to-end in
  // Task 9's vectors.test.mjs conformance harness. Here we only assert the
  // report shape contract: `levels` is always an array.
  const rep = await verifyMessage('From: a@b\r\nSubject: x\r\n\r\nhi\r\n');
  assert.ok(Array.isArray(rep.levels));
});
