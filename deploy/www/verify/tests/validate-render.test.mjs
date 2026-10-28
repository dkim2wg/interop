// The server validator's page script (deploy/www/validate/validate.js), run
// on a minimal stand-in for the DOM with fetch() answering a canned report.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
const SCRIPT = readFileSync(join(here, '..', '..', 'validate', 'validate.js'), 'utf8');

class El {
  constructor(tag) { this.tag = tag; this.className = ''; this.textContent = ''; this.children = []; this.value = ''; this.handlers = {}; }
  appendChild(c) { this.children.push(c); return c; }
  replaceChildren(...c) { this.children = c; }
  addEventListener(ev, fn) { this.handlers[ev] = fn; }
  get text() { return [this.textContent, ...this.children.map((c) => c.text)].join(' '); }
}

// Run the page with fetch() answering `report`; resolves to the #out element
// once the report is rendered.
async function renderWith(report) {
  const els = { out: new El('div'), msg: new El('textarea'), go: new El('button'), example: new El('a') };
  const ctx = {
    document: { getElementById: (id) => els[id], createElement: (tag) => new El(tag) },
    fetch: async () => ({ json: async () => report }),
  };
  vm.runInNewContext(SCRIPT, ctx);
  els.go.handlers.click();
  for (let n = 0; n < 10; n++) await new Promise((r) => setImmediate(r));
  return els.out;
}

test('D9: a pass the back end reports not fully verified carries a warning under the verdict', async () => {
  const out = await renderWith({ overall: 'pass', fully_verified: 0,
    summary: 'ok; not fully verified: a null body Recipe hides the body below it', levels: [] });
  assert.equal(out.children[0].textContent, 'Overall: pass');
  assert.match(out.children[1].className, /warn/);
  assert.match(out.children[1].textContent, /^Not fully verified/);
});

test('D9: no warning when fully verified, when not a pass, or from a back end without the field', async () => {
  for (const rep of [{ overall: 'pass', fully_verified: 1 }, { overall: 'pass' },
    { overall: 'fail', fully_verified: 0, summary: 'FAIL: x' }]) {
    assert.doesNotMatch((await renderWith({ levels: [], ...rep })).text, /Not fully verified/);
  }
});
