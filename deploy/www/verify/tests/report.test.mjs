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

test('D9: a pass that is not fully verified says so, under the verdict', () => {
  const out = render({ overall: 'pass', fullyVerified: false, summary: 's', levels: [] });
  assert.equal(out.children[0].textContent, 'Overall: pass');
  const note = out.children[1];
  assert.match(note.className, /warn/);
  assert.match(note.textContent, /^Not fully verified/);
});

test('D9: a fully verified pass, and any other result, carry no such note', () => {
  for (const rep of [{ overall: 'pass', fullyVerified: true }, { overall: 'fail', fullyVerified: false, summary: 'FAIL: x' }]) {
    assert.doesNotMatch(render({ levels: [], ...rep }).text, /fully verified/i);
  }
});
