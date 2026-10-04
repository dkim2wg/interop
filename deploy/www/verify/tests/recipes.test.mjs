import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bodyToLines, linesToBody, applyBodyRecipe, applyHeaderRecipe, applyRecipe, decodeRecipe, MalformedRecipe } from '../recipes.js';

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

// --- "b" steps: base64 literals for octets that are not JSON text ----------
// The message is a binary string (b64.js); a "b" item must land in it as
// exactly the decoded octets, like a "d" item does after UTF-8 encoding.
const b64 = (bin) => Buffer.from(bin, 'latin1').toString('base64');

test('applyBodyRecipe "b" step emits the decoded octets as a binary-string line', () => {
  const cur = ['[list] edited', '-- footer'];
  const out = applyBodyRecipe(cur, [{ b: [b64('\xb1\xa4 line'), b64('caf\xe9')] }, { c: [2, 2] }]);
  assert.deepEqual(out, ['\xb1\xa4 line', 'caf\xe9', '-- footer']);
  assert.equal(out[0].charCodeAt(0), 0xb1);
  assert.equal(out[0].charCodeAt(1), 0xa4);
  assert.equal(out[1].charCodeAt(3), 0xe9);
});

test('applyHeaderRecipe "b" step restores a header value with non-UTF-8 octets', () => {
  const fields = [
    { name: 'From', value: ' a@b', raw: 'From: a@b\r\n' },
    { name: 'Subject', value: ' [list] hello', raw: 'Subject: [list] hello\r\n' },
  ];
  const out = applyHeaderRecipe(fields, { subject: [{ b: [b64('caf\xe9 \xb1\xa4')] }] });
  const subj = out.find((f) => f.name.toLowerCase() === 'subject');
  assert.equal(subj.value, 'caf\xe9 \xb1\xa4');
  assert.equal(subj.value.length, 7);
});

test('"d" and "b" steps for the same text agree once both are binary strings', () => {
  const viaD = applyBodyRecipe([], [{ d: ['café'] }]);
  const viaB = applyBodyRecipe([], [{ b: [Buffer.from('café', 'utf8').toString('base64')] }]);
  assert.deepEqual(viaD, viaB);
});

// --- malformed Recipes throw MalformedRecipe (§5 rules) ---------------------
const malformed = (fn) => assert.throws(fn, (e) => e instanceof MalformedRecipe && e.name === 'MalformedRecipe');

test('"c" ranges: bounds, ordering and integer-ness are enforced', () => {
  const cur = ['a', 'b', 'c'];
  assert.deepEqual(applyBodyRecipe(cur, [{ c: [1, 1] }, { c: [3, 3] }]), ['a', 'c']);
  malformed(() => applyBodyRecipe(cur, [{ c: [0, 1] }]));            // start 0
  malformed(() => applyBodyRecipe(cur, [{ c: [1, 4] }]));            // end beyond count
  malformed(() => applyBodyRecipe(cur, [{ c: [2, 1] }]));            // end < start
  malformed(() => applyBodyRecipe(cur, [{ c: [2, 2] }, { c: [1, 1] }])); // descending
  malformed(() => applyBodyRecipe(cur, [{ c: [1, 2] }, { c: [2, 3] }])); // overlapping
  malformed(() => applyBodyRecipe(cur, [{ c: ['1', '2'] }]));        // strings
  malformed(() => applyBodyRecipe(cur, [{ c: [1, 1.5] }]));          // fraction
  malformed(() => applyBodyRecipe(cur, [{ c: [1] }]));               // one bound
  malformed(() => applyBodyRecipe(cur, [{ c: [1, 2, 3] }]));         // three bounds
  malformed(() => applyHeaderRecipe([{ name: 'Subject', value: ' x', raw: '' }], { subject: [{ c: [1, 2] }] }));
});

test('literal steps: bad base64, CR/LF, non-strings and unknown steps are malformed', () => {
  malformed(() => applyBodyRecipe([], [{ b: ['!!!!'] }]));
  malformed(() => applyBodyRecipe([], [{ b: ['QUJD QUJD'] }]));           // whitespace is outside the alphabet
  malformed(() => applyBodyRecipe([], [{ b: ['QUI'] }]));                 // unpadded: not canonical RFC 4648 §4
  malformed(() => applyBodyRecipe([], [{ b: ['QUJDQQ'] }]));              // length not a multiple of 4
  assert.deepEqual(applyBodyRecipe([], [{ b: ['QUI='] }]), ['AB']);       // padded form of the same octets
  malformed(() => applyBodyRecipe([], [{ d: [] }]));                      // schema minItems 1
  malformed(() => applyBodyRecipe([], [{ b: [] }]));
  malformed(() => applyHeaderRecipe([], { subject: [{ d: [] }] }));
  malformed(() => applyBodyRecipe([], [{ b: [b64('a\r\nb')] }]));
  malformed(() => applyBodyRecipe([], [{ b: [b64('a\nb')] }]));
  malformed(() => applyBodyRecipe([], [{ b: [42] }]));
  malformed(() => applyBodyRecipe([], [{ d: ['a\r\nb'] }]));
  malformed(() => applyBodyRecipe([], [{ d: [42] }]));
  malformed(() => applyBodyRecipe([], [{ x: [] }]));
  malformed(() => applyBodyRecipe([], [{ c: [1, 1], d: [] }]));
  malformed(() => applyBodyRecipe([], ['c']));
  malformed(() => applyBodyRecipe([], 'not an array'));
  malformed(() => applyHeaderRecipe([], ['subject']));
});

test('applyRecipe validates the top level and leaves a null "b" body alone', () => {
  const state = { fields: [{ name: 'Subject', value: ' x', raw: '' }], bodyLines: ['l1'] };
  const prev = applyRecipe({ h: { subject: [{ d: ['y'] }] }, b: null }, state);
  assert.equal(prev.fields[0].value, 'y');
  assert.deepEqual(prev.bodyLines, ['l1']);
  malformed(() => applyRecipe(5, state));
  malformed(() => applyRecipe([], state));
  malformed(() => applyRecipe({}, state));
  malformed(() => applyRecipe({ b: 'lines' }, state));
  malformed(() => applyRecipe({ h: [] }, state));
});
