// renderReport() on a minimal stand-in for the DOM: just enough of
// document.createElement and Element for report.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';

class El {
  constructor(tag) { this.tag = tag; this.className = ''; this.textContent = ''; this.children = []; }
  appendChild(c) { this.children.push(c); return c; }
  replaceChildren(...c) { this.children = c; }
  get text() { return [this.textContent, ...this.children.map((c) => c.text)].join(' '); }
}
globalThis.document = { createElement: (tag) => new El(tag) };
const { renderReport } = await import('../report.js');

const render = (rep) => { const out = new El('div'); renderReport(rep, out); return out; };

// -09 (contract E2): a null body Recipe is a PERMERROR, so a pass is always
// fully verified, and the page no longer has a "not fully verified" note.
test('E2: no "not fully verified" note, whatever fullyVerified says', () => {
  for (const rep of [{ overall: 'pass', fullyVerified: false, summary: 's' }, { overall: 'pass', fullyVerified: true },
    { overall: 'permerror', fullyVerified: false, summary: 'PERMERROR: Message-Instance m=2 has a null recipe' }]) {
    const out = render({ levels: [], ...rep });
    assert.equal(out.children[0].textContent, 'Overall: ' + rep.overall);
    assert.doesNotMatch(out.text, /fully verified/i);
  }
});

test('E1: a message with no DKIM2 header fields shows as none', () => {
  const out = render({ overall: 'none', fullyVerified: false, summary: 'No DKIM2 header fields found', errors: [], levels: [] });
  assert.equal(out.children[0].textContent, 'Overall: none');
  assert.match(out.children[0].className, /\bnone\b/);
  assert.equal(out.children[1].textContent, 'No DKIM2 header fields found');
});

test('E3: a From that fails shows its reason; one Authentic by policy shows why', () => {
  const sig = (from) => ({ kind: 'signature', i: 1, m: 1, result: 'pass', tags: [], items: [], from });
  assert.match(render({ overall: 'fail', levels: [sig({ ok: false, detail: 'FAIL: DKIM2-Signature i=1 From x.example forbids subdomain signing' })] }).text,
    /From: FAIL — FAIL: DKIM2-Signature i=1 From x\.example forbids subdomain signing/);
  assert.match(render({ overall: 'pass', levels: [sig({ ok: true, detail: 'Authentic: d= is below x.example' })] }).text,
    /From: Authentic: d= is below x\.example/);
});
