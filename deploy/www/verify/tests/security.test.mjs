import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyMessage } from '../verify.js';
import { parseKeyRecord } from '../doh.js';
import { parseMessage, parseTagList, trimWsp } from '../parse.js';
import { canonBody } from '../canon.js';

// CVE-2026-129847 (reported against Mail::DKIM2 0.34): a line in the header
// section that is not a field -- no colon, WSP in or nothing before the
// name, a first line starting with WSP -- was dropped by the parser, so no
// Message-Instance header hash covered it: anyone could add such lines to a
// signed message, and it still passed here ("NoColonHere" did), while other
// parsers read them. Such a header section is malformed: PERMERROR, before
// every other check.
const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..', '..');
const SIGNED = readFileSync(join(repoRoot, 'dkim2tests', 'tests', 'mailfrom_case.signed'), 'utf8');
const dns = JSON.parse(readFileSync(join(repoRoot, 'dkim2tests', 'dns.json'), 'utf8'));
const fetchKey = async (selector, domain) => {
  const rec = dns[`${selector}._domainkey.${domain}`];
  if (rec === undefined) throw new Error('key-notfound');
  return parseKeyRecord(rec);
};
const OPTS = { fetchKey, now: 1782394336 + 3600 };
const MALFORMED = 'PERMERROR: malformed header field';

function afterSubject(msg, line) {
  const i = msg.indexOf('\r\nSubject:') + 2;
  const j = msg.indexOf('\r\n', i) + 2;
  return msg.slice(0, j) + line + msg.slice(j);
}

test('the unaltered sample passes (the control for the cases below)', async () => {
  assert.equal((await verifyMessage(SIGNED, OPTS)).overall, 'pass');
});

for (const [label, msg] of [
  ['no colon', afterSubject(SIGNED, 'NoColonHere\r\n')],
  ['WSP in the name', afterSubject(SIGNED, 'Sub ject: x\r\n')],
  ['an empty name', afterSubject(SIGNED, ':Empty: x\r\n')],
  ['a first line starting with WSP', ' Subject: evil\r\n' + SIGNED],
  ['a first line starting with HTAB', '\tSubject: evil\r\n' + SIGNED],
  ['no colon, folded', afterSubject(SIGNED, 'NoColon\r\n Here\r\n')],
  ['a colon only on the continuation line', afterSubject(SIGNED, 'Foo\r\n : x\r\n')],
  ['no colon, as octets', afterSubject(SIGNED, 'NoColonHere\r\n')],
]) {
  test(`a header line that is not a field (${label}) is "${MALFORMED}"`, async () => {
    const input = label.endsWith('as octets') ? Uint8Array.from(msg, (c) => c.charCodeAt(0)) : msg;
    const rep = await verifyMessage(input, OPTS);
    assert.equal(rep.overall, 'permerror');
    assert.equal(rep.errors[0], MALFORMED);
  });
}

test('a malformed header line is reported before the chain structure (C9 step a and on)', async () => {
  // m=2 missing (step f) as well: the malformed header section is primary.
  const gap = SIGNED.replace(/^DKIM2-Signature: /m, 'DKIM2-Signature: m=2; ');
  const rep = await verifyMessage(afterSubject(gap, 'NoColonHere\r\n'), OPTS);
  assert.equal(rep.errors[0], MALFORMED);
  // ...and before too many fields (step a).
  const many = 'Message-Instance: m=1\r\n'.repeat(40) + 'NoColonHere\r\n' + SIGNED;
  assert.equal((await verifyMessage(many, OPTS)).errors[0], MALFORMED);
});

test('a malformed header line in a message with no DKIM2 field is still none', async () => {
  const rep = await verifyMessage('From: a@example.com\r\nNoColonHere\r\nSubject: x\r\n\r\nhi\r\n');
  assert.equal(rep.overall, 'none');
});

test('the fields themselves: WSP before the colon is still a field, and folding is kept', () => {
  const { headers, malformedHeader } = parseMessage('Subject  : hi\r\nX-A: 1\r\n\t2\r\n\r\nbody\r\n');
  assert.equal(malformedHeader, false);
  assert.deepEqual(headers.map((h) => [h.name, h.value, h.raw]),
    [['Subject', ' hi', 'Subject  : hi\r\n'], ['X-A', ' 1\t2', 'X-A: 1\r\n\t2\r\n']]);
  assert.equal(parseMessage('A: 1\r\nB\r\n\r\n').malformedHeader, true);
  assert.equal(parseMessage(Uint8Array.from('A: 1\r\nB\r\n\r\n', (c) => c.charCodeAt(0))).malformedHeader, true);
});

// CVE-2026-129848 (reported against Mail::DKIM2 0.34): a tag=value parse
// with a backtracking regex was quadratic in a long run of white space in a
// value. parseTagList has no such regex: TAG_SPEC's white-space runs are
// each followed by a character that cannot be white space, and the value is
// cut by indexOf (measured linear: 160000 repeats in ~5 ms). Pinned by
// result, not by time (no wall-clock tests here): the folds are dropped.
test('a tag value with a long run of white space inside it parses (CVE-2026-129848)', () => {
  const v = 'a=b' + ' \r\n'.repeat(40000) + 'c';
  const { map } = parseTagList(v);
  assert.equal(map.a, 'bc');
});

// The same fault where it was real here: a trim written
// /^[ \t\r\n]+|[ \t\r\n]+$/ (h=, s=, a raw tag value, the From
// length check) or a body canon /(\r\n)*$/ rescans a white-space run from
// each position in it, so a pasted message with 80000 spaces inside one
// value held the tab ~4.5 s (measured once; 3 ms after). The linear
// replacements give the same answers.
test('trimWsp trims SP, HTAB, CR and LF at both ends only', () => {
  assert.equal(trimWsp(' \t\r\n a \t b \r\n\t '), 'a \t b');
  assert.equal(trimWsp(''), '');
  assert.equal(trimWsp(' \t\r\n'), '');
  assert.equal(trimWsp('x' + ' '.repeat(80000) + 'y'), 'x' + ' '.repeat(80000) + 'y');
  assert.equal(trimWsp('\fx\v'), '\fx\v');
});

test('canonBody drops every trailing CRLF, and only those', () => {
  assert.equal(canonBody(''), '\r\n');
  assert.equal(canonBody('a\r\n\r\n\r\n'), 'a\r\n');
  assert.equal(canonBody('a\r\n\r'), 'a\r\n\r\r\n');
  assert.equal(canonBody('\r\n'.repeat(80000) + 'x'), '\r\n'.repeat(80000) + 'x\r\n');
});
