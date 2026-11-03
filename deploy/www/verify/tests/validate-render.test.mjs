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

test('-09 E2: a null recipe shows as the failure summary, with no "not fully verified" note', async () => {
  const out = await renderWith({ overall: 'fail', fully_verified: 0,
    summary: 'permerror (PERMERROR: Message-Instance m=2 has a null recipe)', levels: [] });
  assert.equal(out.children[0].textContent, 'Overall: fail');
  assert.match(out.text, /has a null recipe/);
  assert.doesNotMatch(out.text, /Not fully verified/);
});

test('-09 E2: no "not fully verified" note for any report, an old back end\'s included', async () => {
  for (const rep of [{ overall: 'pass', fully_verified: 1 }, { overall: 'pass' },
    { overall: 'pass', fully_verified: 0 }, { overall: 'fail', fully_verified: 0, summary: 'FAIL: x' }]) {
    assert.doesNotMatch((await renderWith({ levels: [], ...rep })).text, /Not fully verified/);
  }
});
