// Parity of the planned chain walk (plan.js) with the undo walk: per-instance
// header/body hashes, Recipe errors, displayed header values, and the whole
// report, on hand-built cases.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkMsg, selfConsistent, compareChains, compareReports } from './plan-helpers.mjs';

const H = [['From', 'a@example.com'], ['Subject', '[list] hi'], ['To', 'b@example.com']];
const b64 = (s) => Buffer.from(s, 'latin1').toString('base64');

// name -> spec for mkMsg; `expect` checks the undo-walk outcome so each case
// exercises what it says (an error where one is meant, none elsewhere).
const cases = {
  'no Recipe, one instance': { body: 'a\r\nb\r\n' },
  'no body Recipe (header only)': { maxM: 2, recipes: { 2: { h: { subject: [{ d: ['hi'] }] } } } },
  'footer append': { maxM: 2, body: 'a\r\nb\r\n--\r\nfooter\r\n', recipes: { 2: { b: [{ c: [1, 2] }] } } },
  'MIME wrap: old body a middle range': {
    maxM: 2, body: 'pre\r\n--x\r\na\r\nb\r\n--x--\r\nepi\r\n', recipes: { 2: { b: [{ c: [3, 4] }] } } },
  'literals before/between/after copies': {
    maxM: 2, body: '1\r\n2\r\n3\r\n4\r\n5\r\n',
    recipes: { 2: { b: [{ d: ['x'] }, { c: [1, 2] }, { d: ['y', 'z'] }, { c: [4, 5] }, { d: ['w'] }] } } },
  '3 levels: lower copies a literal of the level above': {
    maxM: 3, body: 'a\r\nb\r\nc\r\nd\r\n',
    recipes: { 3: { b: [{ c: [1, 1] }, { d: ['L1', 'L2'] }, { c: [3, 4] }] }, 2: { b: [{ c: [2, 3] }, { d: ['q'] }, { c: [5, 5] }] } } },
  'trailing blank lines': { maxM: 2, body: 'a\r\n\r\n\r\n', recipes: { 2: { b: [{ c: [1, 1] }] } } },
  'blank run spanning a body line and a literal': {
    maxM: 2, body: 'a\r\n\r\nb\r\n', recipes: { 2: { b: [{ c: [1, 2] }, { d: ['', ''] }] } } },
  'blank run then a literal line': {
    maxM: 2, body: 'a\r\n\r\nb\r\n', recipes: { 2: { b: [{ c: [1, 2] }, { d: ['', 'x'] }] } } },
  'blank literals at the end': { maxM: 2, body: 'a\r\nb\r\nc\r\n', recipes: { 2: { b: [{ c: [1, 3] }, { d: ['', ''] }] } } },
  // The undo walk here counts trailing blank lines as body lines (bodyToLines),
  // so copying them is not an error in this implementation; parity is what
  // matters.
  'copy into trailing blanks': { maxM: 2, body: 'a\r\n\r\n\r\n', recipes: { 2: { b: [{ c: [1, 3] }] } } },
  'copy past end': { maxM: 2, body: 'a\r\n\r\n\r\n', recipes: { 2: { b: [{ c: [1, 4] }] } }, expect: 2 },
  'copy past end of a rebuilt body': {
    maxM: 3, body: 'a\r\nb\r\n', recipes: { 3: { b: [{ c: [1, 1] }, { d: ['x'] }] }, 2: { b: [{ c: [1, 3] }] } }, expect: 2 },
  'out-of-order copies': { maxM: 2, body: '1\r\n2\r\n3\r\n4\r\n', recipes: { 2: { b: [{ c: [3, 4] }, { c: [1, 2] }] } }, expect: 2 },
  'overlapping copies': { maxM: 2, body: '1\r\n2\r\n3\r\n4\r\n', recipes: { 2: { b: [{ c: [1, 3] }, { c: [3, 4] }] } }, expect: 2 },
  'non-integer copy': { maxM: 2, body: '1\r\n2\r\n', recipes: { 2: { b: [{ c: [1, 1.5] }] } }, expect: 2 },
  'null body Recipe': {
    maxM: 3, body: 'a\r\nb\r\n', recipes: { 3: { b: [{ c: [1, 1] }] }, 2: { h: { subject: [{ d: ['old'] }] }, b: null } } },
  'unterminated last line': { maxM: 2, body: 'a\r\nb', recipes: { 2: { b: [{ c: [2, 2] }, { d: ['x'] }] } } },
  'unterminated last line, copied whole': { maxM: 3, body: 'a\r\nb', recipes: { 3: { b: [{ d: ['x'] }, { c: [1, 2] }] }, 2: { b: [{ c: [2, 3] }] } } },
  'unterminated last line, top only': { body: 'a\r\nb' },
  'empty body': { maxM: 2, body: '', recipes: { 2: { b: [{ d: ['x'] }] } } },
  'no header/body separator': { maxM: 2, noSeparator: true, recipes: { 2: { b: [{ d: ['x'] }] } } },
  'body of only blank lines': { maxM: 2, body: '\r\n\r\n\r\n', recipes: { 2: { b: [{ c: [1, 2] }, { d: ['q'] }] } } },
  'body of only blank lines, copied': { maxM: 2, body: '\r\n\r\n', recipes: { 2: { b: [{ c: [1, 2] }] } } },
  'lone CR and bare LF in the body': { maxM: 2, body: 'a\rb\r\nc\nd\r\n', recipes: { 2: { b: [{ c: [2, 3] }] } } },
  'empty body Recipe []': { maxM: 2, body: 'a\r\n', recipes: { 2: { b: [] } } },
  '"u" step and a UTF-8 "d"': {
    maxM: 2, body: 'a\r\n', recipes: { 2: { b: [{ u: [b64('caf\xe9')] }, { d: ['x\u00e9y'] }, { c: [1, 1] }] } } },
  'a lone surrogate in "d"': { maxM: 2, body: 'a\r\n', recipes: { 2: '{"b":[{"d":["x\\udce9y"]}]}' }, expect: 2 },
  'upper-case step and top-level keys': { maxM: 2, body: 'a\r\nb\r\n', recipes: { 2: { B: [{ C: [1, 1] }, { U: [b64('caf\xe9')] }] } }, expect: 2 },
  // headers
  'subject tag removed': { maxM: 2, headers: H, recipes: { 2: { h: { subject: [{ d: ['hi'] }] } } } },
  'fields removed': { maxM: 2, headers: [...H, ['List-Id', '<l.example.com>']], recipes: { 2: { h: { 'list-id': [] } } } },
  'repeated fields with copies and literals': {
    maxM: 2, headers: [...H, ['Comments', 'one'], ['Comments', 'two'], ['Comments', 'three']],
    recipes: { 2: { h: { comments: [{ c: [1, 1] }, { d: ['new'] }, { c: [3, 3] }] } } } },
  'a field added': { maxM: 2, headers: H, recipes: { 2: { h: { keywords: [{ d: ['k'] }] } } } },
  '3 levels of headers': {
    maxM: 3, headers: [...H, ['Comments', 'c1'], ['Comments', 'c2']],
    recipes: { 3: { h: { subject: [{ d: ['[a] hi'] }], comments: [{ c: [2, 2] }] } }, 2: { h: { subject: [{ d: ['hi'] }], comments: [{ d: ['z'] }, { c: [1, 1] }] } } } },
  'folded values': {
    maxM: 2, headers: [['From', 'a@example.com'], ['Subject', ' a\r\n b\r\n\tc  '], ['Comments', '\t x \r\n  y']],
    recipes: { 2: { h: { comments: [{ d: [' x  y '] }] } } } },
  'mixed-case names': {
    maxM: 2, headers: [['From', 'a@example.com'], ['SUBJECT', 'one'], ['subject', 'two'], ['Subject', 'three']],
    recipes: { 2: { h: { subject: [{ c: [2, 3] }] } } } },
  'mixed-case Recipe keys (invalid JSON, -08 D10)': { maxM: 2, headers: H, recipes: { 2: { h: { Subject: [{ d: ['hi'] }], TO: [{ c: [1, 1] }] } } }, expect: 2 },
  'Recipe keys differing only in case': { maxM: 2, headers: H, recipes: { 2: { h: { Subject: [{ d: ['x'] }], SUBJECT: [{ d: ['y'] }] } } }, expect: 2 },
  'skipped fields with Recipes': {
    maxM: 2, headers: [...H, ['Received', 'from a'], ['Received', 'from b'], ['X-Mailer', 'm']],
    recipes: { 2: { h: { received: [{ c: [1, 1] }], 'x-mailer': [], 'dkim2-signature': [] } } } },
  'header copy past end': { maxM: 2, headers: H, recipes: { 2: { h: { subject: [{ c: [1, 2] }] } } }, expect: 2 },
  'header copy of a missing field': { maxM: 2, headers: H, recipes: { 2: { h: { keywords: [{ c: [1, 1] }] } } }, expect: 2 },
  'header copies out of order': {
    maxM: 2, headers: [...H, ['Comments', '1'], ['Comments', '2']], recipes: { 2: { h: { comments: [{ c: [2, 2] }, { c: [1, 1] }] } } }, expect: 2 },
  'first bad name in key order': {
    maxM: 2, headers: H, recipes: { 2: { h: { zzz: [{ c: [1, 9] }], aaa: ['bad'] } } }, expect: 2 },
  'body error and header error': {
    maxM: 2, headers: H, recipes: { 2: { h: { subject: [{ c: [5, 5] }] }, b: [{ c: [9, 9] }] } }, expect: 2 },
  'header Recipe checked below a null body Recipe (bad)': {
    maxM: 3, headers: H, recipes: { 3: { b: null }, 2: { h: { subject: [{ c: [1, 9] }] } } }, expect: 2 },
  'header Recipe applied below a null body Recipe': {
    maxM: 3, headers: H, recipes: { 3: { b: null }, 2: { h: { subject: [{ d: ['old'] }] }, b: [{ c: [1, 99] }] } } },
  'bad body Recipe structure below a null body Recipe': {
    maxM: 3, headers: H, recipes: { 3: { b: null }, 2: { b: [{ c: [2, 1] }] } }, expect: 2 },
  'm=01': { maxM: 2, mTag: { 1: '01', 2: '02' }, headers: H, recipes: { 2: { h: { subject: [{ d: ['hi'] }] } } } },
  'Recipe on m=1, good': { maxM: 1, body: 'a\r\nb\r\n', recipes: { 1: { b: [{ c: [1, 2] }], h: { subject: [{ c: [1, 1] }] } } } },
  'Recipe on m=1, body past end': { maxM: 2, body: 'a\r\nb\r\n', recipes: { 2: { b: [{ c: [1, 1] }] }, 1: { b: [{ c: [1, 2] }] } } },
  'Recipe on m=1 below a null body Recipe, against the stale body': {
    maxM: 2, body: 'a\r\nb\r\nc\r\n', recipes: { 2: { b: null }, 1: { b: [{ c: [1, 3] }] } } },
  'Recipe on m=1 below a null body Recipe, past the stale body': {
    maxM: 2, body: 'a\r\nb\r\nc\r\n', recipes: { 2: { b: null }, 1: { b: [{ c: [1, 4] }] } } },
  'Recipe on m=1 with a bad header range': { maxM: 1, headers: H, recipes: { 1: { h: { subject: [{ c: [1, 2] }] } } } },
  'r= missing (the same message)': { maxM: 2, recipes: {} },
  'r= missing over a body Recipe': { maxM: 3, body: 'a\r\nb\r\n', recipes: { 2: { b: [{ c: [1, 1] }] } } },
  'r= invalid JSON': { maxM: 2, recipes: { 2: '{"b":' }, expect: 2 },
  'r= not base64': { maxM: 2, rawR: { 2: '!!!' }, expect: 2 },
  'Recipe not an object': { maxM: 2, recipes: { 2: [1] }, expect: 2 },
  'Recipe with neither h nor b': { maxM: 2, recipes: { 2: {} }, expect: 2 },
  '"b" neither steps nor null': { maxM: 2, recipes: { 2: { b: 5 } }, expect: 2 },
  '"h" not an object': { maxM: 2, recipes: { 2: { h: [] } }, expect: 2 },
  'broken at the top of 3 levels': { maxM: 3, recipes: { 3: { b: [{ c: [9, 9] }] }, 2: { b: [] } }, expect: 3 },
  'message-instance named in a header Recipe (falls back)': {
    maxM: 2, headers: H, recipes: { 2: { h: { 'message-instance': [{ c: [1, 1] }], subject: [{ d: ['hi'] }] } } }, fallback: true },
};

for (const [name, spec] of Object.entries(cases)) {
  test(`planned walk matches the undo walk: ${name}`, async () => {
    const raw = await selfConsistent(mkMsg({ headers: H, ...spec }));
    const { undo, plan, fallback } = await compareChains(raw);
    assert.equal(fallback, !!spec.fallback, 'fallback to the undo walk');
    if (!fallback) assert.deepEqual(plan, undo);
    assert.equal(undo.undoBroken, spec.expect || null, 'case exercises what it says');
    const reps = await compareReports(raw);
    assert.deepEqual(reps.plan, reps.undo);
    // A tampered copy reports the same way through both walks.
    const tampered = raw.replace(/\r\n\r\n([\s\S])/, (m0, c) => '\r\n\r\n' + (c === 'Z' ? 'Y' : 'Z'));
    const t = await compareReports(tampered);
    assert.deepEqual(t.plan, t.undo);
  });
}

test('the self-consistent cases really pass their MI hashes', async () => {
  const raw = await selfConsistent(mkMsg({ headers: H, ...cases['3 levels: lower copies a literal of the level above'] }));
  const { plan } = await compareReports(raw);
  const mis = plan.levels.filter((l) => l.kind === 'instance');
  assert.equal(mis.length, 3);
  for (const l of mis) assert.equal(l.header_hash, 'match', l.detail);
  for (const l of mis) assert.equal(l.body_hash, 'match', l.detail);
});

test('instances with the same body share one body hash computation', async () => {
  // m=3 changes only a header, so m=3 and m=2 hold the same body.
  const raw = mkMsg({ headers: H, maxM: 3, body: 'a\r\nb\r\n',
    recipes: { 3: { h: { subject: [{ d: ['x'] }] } }, 2: { b: [{ c: [1, 1] }] } } });
  const { parseMessage, collectLevels } = await import('../parse.js');
  const { planChain } = await import('../plan.js');
  const { textToBinary, binaryToBytes } = await import('../b64.js');
  const { headers, body } = parseMessage(binaryToBytes(textToBinary(raw)));
  const { instances } = collectLevels(headers);
  const chain = planChain(headers, body, instances, 3);
  assert.equal(chain.bodyHash(3, 'sha256'), chain.bodyHash(2, 'sha256'));
  assert.notEqual(chain.bodyHash(2, 'sha256'), chain.bodyHash(1, 'sha256'));
});
