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

test('applyHeaderRecipe c-step copies specific bottom-up-numbered instances (multi-instance)', () => {
  // Three Received instances in document order top->bottom: top, middle, bottom.
  // Bottom-up numbering (last in doc = #1): bottom=#1, middle=#2, top=#3.
  const fields = [
    { name: 'Received', value: ' top', raw: 'Received: top\r\n' },
    { name: 'Received', value: ' middle', raw: 'Received: middle\r\n' },
    { name: 'Received', value: ' bottom', raw: 'Received: bottom\r\n' },
    { name: 'From', value: ' a@b', raw: 'From: a@b\r\n' },
  ];
  // c:[2,3] selects #2 (middle) and #3 (top), dropping #1 (bottom).
  const out = applyHeaderRecipe(fields, { received: [{ c: [2, 3] }] });
  const received = out.filter((f) => f.name.toLowerCase() === 'received');
  assert.equal(received.length, 2);
  // Reconstructed doc order (top->bottom) must be: top, then middle.
  assert.deepEqual(received.map((f) => f.value), [' top', ' middle']);
  // Untouched header name is retained unchanged.
  const from = out.find((f) => f.name === 'From');
  assert.equal(from.value, ' a@b');
});

test('applyHeaderRecipe mixed d+c steps on a signed header order correctly under bottom-up processing', () => {
  // Two List-Id instances in document order top->bottom: first, second.
  // Bottom-up numbering: second=#1, first=#2.
  const fields = [
    { name: 'List-Id', value: ' <first.list>', raw: 'List-Id: <first.list>\r\n' },
    { name: 'List-Id', value: ' <second.list>', raw: 'List-Id: <second.list>\r\n' },
  ];
  // Recipe emits a literal 'd' value, then copies bottom-up instance #1 (second).
  // Processing (bottom-up) order is [restored, second]; reversing to get doc
  // order puts the c-copied instance (second) on top and the d-emitted value
  // last, even though 'd' was listed first in the recipe.
  const out = applyHeaderRecipe(fields, {
    'list-id': [{ d: [' restored'] }, { c: [1, 1] }],
  });
  const lids = out.filter((f) => f.name.toLowerCase() === 'list-id');
  assert.equal(lids.length, 2);
  assert.deepEqual(lids.map((f) => f.value), [' <second.list>', ' restored']);
  assert.equal(lids[1].name, 'list-id');
});

test('decodeRecipe base64-decodes JSON', () => {
  const b64 = Buffer.from(JSON.stringify({ b: [{ c: [1, 1] }] })).toString('base64');
  assert.deepEqual(decodeRecipe(b64), { b: [{ c: [1, 1] }] });
});
