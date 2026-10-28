import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bodyToLines, linesToBody, applyBodyRecipe, applyHeaderRecipe, applyRecipe, decodeRecipe, validateRecipeSteps, InvalidRecipe, InvalidStep } from '../recipes.js';

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

// --- "u" steps: base64 literals for octets that are not UTF-8 -------------
// The message is a binary string (b64.js); a "u" item must land in it as
// exactly the decoded octets, like a "d" item does after UTF-8 encoding.
const b64 = (bin) => Buffer.from(bin, 'latin1').toString('base64');

test('applyBodyRecipe "u" step emits the decoded octets as a binary-string line', () => {
  const cur = ['[list] edited', '-- footer'];
  const out = applyBodyRecipe(cur, [{ u: [b64('\xb1\xa4 line'), b64('caf\xe9')] }, { c: [2, 2] }]);
  assert.deepEqual(out, ['\xb1\xa4 line', 'caf\xe9', '-- footer']);
  assert.equal(out[0].charCodeAt(0), 0xb1);
  assert.equal(out[0].charCodeAt(1), 0xa4);
  assert.equal(out[1].charCodeAt(3), 0xe9);
});

test('applyHeaderRecipe "u" step restores a header value with non-UTF-8 octets', () => {
  const fields = [
    { name: 'From', value: ' a@b', raw: 'From: a@b\r\n' },
    { name: 'Subject', value: ' [list] hello', raw: 'Subject: [list] hello\r\n' },
  ];
  const out = applyHeaderRecipe(fields, { subject: [{ u: [b64('caf\xe9 \xb1\xa4')] }] });
  const subj = out.find((f) => f.name.toLowerCase() === 'subject');
  assert.equal(subj.value, 'caf\xe9 \xb1\xa4');
  assert.equal(subj.value.length, 7);
});

test('"d" and "u" steps for the same text agree once both are binary strings', () => {
  const viaD = applyBodyRecipe([], [{ d: ['café'] }]);
  const viaU = applyBodyRecipe([], [{ u: [Buffer.from('café', 'utf8').toString('base64')] }]);
  assert.deepEqual(viaD, viaU);
});

// --- bad Recipes: InvalidRecipe (the §5 schema, or a "c" range that does
// not fit) -------------------------------------------------------------------
// (InvalidStep, one step the schema refuses, is an InvalidRecipe too.)
const invalid = (fn) => assert.throws(fn, (e) => e instanceof InvalidRecipe);

test('"c" ranges: integers of at least 1 (schema), then bounds and ordering', () => {
  const cur = ['a', 'b', 'c'];
  assert.deepEqual(applyBodyRecipe(cur, [{ c: [1, 1] }, { c: [3, 3] }]), ['a', 'c']);
  invalid(() => applyBodyRecipe(cur, [{ c: [0, 1] }]));            // start 0
  invalid(() => applyBodyRecipe(cur, [{ c: [1, 4] }]));          // end beyond count
  invalid(() => applyBodyRecipe(cur, [{ c: [2, 1] }]));          // end < start
  invalid(() => applyBodyRecipe(cur, [{ c: [2, 2] }, { c: [1, 1] }])); // descending
  invalid(() => applyBodyRecipe(cur, [{ c: [1, 2] }, { c: [2, 3] }])); // overlapping
  invalid(() => applyBodyRecipe(cur, [{ c: ['1', '2'] }]));        // strings
  invalid(() => applyBodyRecipe(cur, [{ c: [1, 1.5] }]));          // fraction
  invalid(() => applyBodyRecipe(cur, [{ c: [1] }]));               // one bound
  invalid(() => applyBodyRecipe(cur, [{ c: [1, 2, 3] }]));         // three bounds
  invalid(() => applyHeaderRecipe([{ name: 'Subject', value: ' x', raw: '' }], { subject: [{ c: [1, 2] }] }));
});

test('literal steps: bad base64, CR/LF, non-strings and unknown steps are invalid', () => {
  invalid(() => applyBodyRecipe([], [{ u: ['!!!!'] }]));
  invalid(() => applyBodyRecipe([], [{ u: ['QUJD QUJD'] }]));           // whitespace is outside the alphabet
  invalid(() => applyBodyRecipe([], [{ u: ['QUI'] }]));                 // unpadded
  invalid(() => applyBodyRecipe([], [{ u: ['QUJDQQ'] }]));              // length not a multiple of 4
  invalid(() => applyBodyRecipe([], [{ u: ['QUJ='] }]));                // non-zero pad bits
  invalid(() => applyBodyRecipe([], [{ u: ['QR=='] }]));
  assert.deepEqual(applyBodyRecipe([], [{ u: ['QUI='] }]), ['AB']);     // canonical form of the same octets
  assert.deepEqual(applyBodyRecipe([], [{ u: ['QQ=='] }]), ['A']);
  assert.deepEqual(applyBodyRecipe([], [{ u: [''] }]), ['']);
  invalid(() => applyBodyRecipe([], [{ d: [] }]));                      // schema minItems 1
  invalid(() => applyBodyRecipe([], [{ u: [] }]));
  invalid(() => applyHeaderRecipe([], { subject: [{ d: [] }] }));
  invalid(() => applyBodyRecipe([], [{ u: [b64('a\r\nb')] }]));
  invalid(() => applyBodyRecipe([], [{ u: [b64('a\nb')] }]));
  invalid(() => applyBodyRecipe([], [{ u: [b64('a\rb')] }]));
  invalid(() => applyBodyRecipe([], [{ u: [42] }]));
  invalid(() => applyBodyRecipe([], [{ d: ['a\r\nb'] }]));
  invalid(() => applyBodyRecipe([], [{ d: [42] }]));
  invalid(() => applyBodyRecipe([], [{ d: ['caf\udce9'] }]));           // lone low surrogate
  invalid(() => applyBodyRecipe([], [{ d: ['\ud800x'] }]));             // lone high surrogate
  assert.deepEqual(applyBodyRecipe([], [{ d: ['\u{10080}'] }]), ['\xf0\x90\x82\x80']); // a pair is a character
  invalid(() => applyBodyRecipe([], [{ b: ['eA=='] }]));                // the old "b" step is unknown
  invalid(() => applyBodyRecipe([], [{ x: [] }]));
  invalid(() => applyBodyRecipe([], [{}]));
  invalid(() => applyBodyRecipe([], [{ c: [1, 1], d: [] }]));
  invalid(() => applyBodyRecipe([], ['c']));
  invalid(() => applyBodyRecipe([], 'not an array'));
  invalid(() => applyHeaderRecipe([], ['subject']));
});

test('applyRecipe validates the top level and leaves a null "b" body alone', () => {
  const state = { fields: [{ name: 'Subject', value: ' x', raw: '' }], bodyLines: ['l1'] };
  const prev = applyRecipe({ h: { subject: [{ d: ['y'] }] }, b: null }, state);
  assert.equal(prev.fields[0].value, 'y');
  assert.deepEqual(prev.bodyLines, ['l1']);
  invalid(() => applyRecipe(5, state));
  invalid(() => applyRecipe([], state));
  invalid(() => applyRecipe({}, state));
  invalid(() => applyRecipe({ b: 'lines' }, state));
  invalid(() => applyRecipe({ h: [] }, state));
});

const r64 = (raw) => Buffer.from(raw).toString('base64');

// A duplicate key anywhere in the Recipe JSON is invalid JSON: parsers
// disagree on which value wins (C's took the first, JSON.parse the last), so
// {"b":[...],"b":null} was a null body Recipe to some verifiers and a real
// one to others. (Two that differ only in case hold a capital: invalid too.)
test('decodeRecipe: a duplicate key is a SyntaxError (invalid JSON)', () => {
  for (const raw of ['{"b":[{"c":[1,1]}],"b":null}', '{"b":null,"b":[{"c":[1,1]}]}',
    '{"h":{"subject":[],"subject":[]}}', '{"h":{"subject":[]},"h":{}}',
    '{"h":{"subject":[],"subj\\u0065ct":[]}}', '{"h":{"Subject":[],"subject":[]}}',
    '{"b":null,"B":null}', '{"b":[{"c":[1,1],"C":[1,1]}]}', '{"b":null,"x":{"k":1,"K":2}}']) {
    assert.throws(() => decodeRecipe(r64(raw)), SyntaxError, raw);
  }
  assert.deepEqual(decodeRecipe(r64('{"h":{"subject":[{"d":["b"]}],"to":[]},"b":[{"d":["b"]}]}')).b, [{ d: ['b'] }]);
});

test('decodeRecipe: a key holding an ASCII capital, at any level, is a SyntaxError (-08 D10)', () => {
  for (const raw of ['{"H":{"subject":[]}}', '{"h":{"Subject":[]}}', '{"b":[{"C":[1,1]}]}',
    '{"b":null,"x":{"K":1}}', '{"h":{"subj\\u0045ct":[]}}']) {
    assert.throws(() => decodeRecipe(r64(raw)), SyntaxError, raw);
  }
  // a "__proto__" header name stays an ordinary key
  assert.deepEqual(Object.keys(decodeRecipe(r64('{"h":{"__proto__":[]}}')).h), ['__proto__']);
});

test('decodeRecipe: a number with a fraction or an exponent, or a lone surrogate, is a SyntaxError', () => {
  for (const raw of ['{"b":[{"c":[1,1]}],"n":1e0}', '{"b":[{"c":[1.0,1]}]}', '{"b":null,"n":-2E3}',
    '{"b":[{"d":["\\udc80"]}]}', '{"b":null,"\\ud800":1}']) {
    assert.throws(() => decodeRecipe(r64(raw)), SyntaxError, raw);
  }
  assert.deepEqual(decodeRecipe(r64('{"b":[{"c":[1,10]}],"n":-0}')).b, [{ c: [1, 10] }]);
});

test('decodeRecipe: what the §5 schema refuses of the whole document is an InvalidRecipe', () => {
  for (const raw of ['[]', 'null', '7', '{}', '{"x":1}', '{"h":{}}', '{"h":[]}', '{"b":5}', '{"b":{}}']) {
    invalid(() => decodeRecipe(r64(raw)));
  }
  // an unknown top-level key next to "h" or "b" is ignored
  assert.deepEqual(decodeRecipe(r64('{"b":null,"x":1}')), { b: null, x: 1 });
});

test('validateRecipeSteps: the first invalid step, "b" first, then "h" by name', () => {
  const path = (raw) => {
    try { validateRecipeSteps(decodeRecipe(r64(raw))); } catch (e) { assert.ok(e instanceof InvalidStep, raw); return e.path; }
    return null;
  };
  assert.equal(path('{"b":[{}]}'), 'b[0]');
  assert.equal(path('{"b":[{"c":[1,1]},{"b":["eA=="]}]}'), 'b[1]');
  assert.equal(path('{"b":[{"u":["QR=="]}]}'), 'b[0]');
  assert.equal(path('{"b":[{"u":["YQ1i"]}]}'), 'b[0]');
  assert.equal(path('{"h":{"subject":null}}'), 'h.subject');
  assert.equal(path('{"h":{"subject":[{"x":1}]},"b":[{"c":[0,1]}]}'), 'b[0]');
  assert.equal(path('{"h":{"to":[{"x":1}],"subject":[{"c":[1,1]},{"x":1}]}}'), 'h.subject[1]');
  assert.equal(path('{"h":{"x café":[1]}}'), 'h.x\\x20caf\\xC3\\xA9[0]');
  assert.equal(path('{"h":{"subject":[{"c":[1,9]}]},"b":[{"c":[1,1]}]}'), null);
});
