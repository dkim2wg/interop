import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bodyToLines, linesToBody, applyBodyRecipe, applyHeaderRecipe, decodeRecipe } from '../recipes.js';

test('bodyToLines / linesToBody round-trip', () => {
  assert.deepEqual(bodyToLines('a\r\nb\r\n'), ['a', 'b']);
  assert.deepEqual(bodyToLines('a\r\nb'), ['a', 'b']);
  assert.equal(linesToBody(['a', 'b']), 'a\r\nb\r\n');
});

test('applyBodyRecipe undoes an appended footer (copy first N lines)', () => {
  // current body = original 2 lines + a footer; recipe copies lines 1..2.
  const cur = ['Hello', 'world', '-- footer'];
  assert.deepEqual(applyBodyRecipe(cur, [{ c: [1, 2] }]), ['Hello', 'world']);
});

test('applyBodyRecipe restores a replaced line via d step', () => {
  const cur = ['NEW line', 'tail'];
  assert.deepEqual(applyBodyRecipe(cur, [{ d: ['OLD line'] }, { c: [2, 2] }]),
    ['OLD line', 'tail']);
});

test('applyHeaderRecipe restores a modified Subject (d step), retains others', () => {
  const fields = [
    { name: 'From', value: ' a@b', raw: 'From: a@b\r\n' },
    { name: 'Subject', value: ' [DKIM2] hi', raw: 'Subject: [DKIM2] hi\r\n' },
  ];
  const out = applyHeaderRecipe(fields, { subject: [{ d: ['hi'] }] });
  const subj = out.find((f) => f.name.toLowerCase() === 'subject');
  assert.equal(subj.value, 'hi');
  assert.ok(out.find((f) => f.name === 'From'));
});

test('applyHeaderRecipe empty array removes all instances of a name', () => {
  const fields = [
    { name: 'From', value: ' a@b', raw: '' },
    { name: 'List-Id', value: ' x', raw: '' },
  ];
  const out = applyHeaderRecipe(fields, { 'list-id': [] });
  assert.equal(out.find((f) => f.name.toLowerCase() === 'list-id'), undefined);
});

test('decodeRecipe base64-decodes JSON', () => {
  const b64 = Buffer.from(JSON.stringify({ b: [{ c: [1, 1] }] })).toString('base64');
  assert.deepEqual(decodeRecipe(b64), { b: [{ c: [1, 1] }] });
});
