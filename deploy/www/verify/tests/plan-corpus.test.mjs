// Parity of the planned chain walk with the undo walk on real mail: every
// captured list message in the corpus (if present) and the Perl expected
// .eml files, each also with one body byte changed and with the Subject
// changed. Compares every per-instance hash, Recipe error and header value,
// and the whole report.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseKeyRecord } from '../doh.js';
import { bytesToBinary } from '../b64.js';
import { compareChains, compareReports } from './plan-helpers.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..', '..');

// The corpus is untracked: look beside the repo, in it, and in the main
// checkout when this is a git worktree. DKIM2_CORPUS overrides.
function corpusDir() {
  const roots = [repoRoot];
  try {
    const common = execFileSync('git', ['-C', repoRoot, 'rev-parse', '--git-common-dir'], { encoding: 'utf8' }).trim();
    roots.push(dirname(join(repoRoot, common)), dirname(common));
  } catch (e) { /* not a git checkout */ }
  const cands = process.env.DKIM2_CORPUS ? [process.env.DKIM2_CORPUS] : [];
  for (const r of roots) cands.push(join(r, '..', 'corpus', 'results'), join(r, 'corpus', 'results'));
  return cands.find((d) => existsSync(join(d, 'capture'))) || null;
}

const corpus = corpusDir();
const dns = {};
for (const p of [join(repoRoot, 'dns.json'), corpus && join(corpus, 'dns-live.json')]) {
  if (!p || !existsSync(p)) continue;
  for (const [domain, names] of Object.entries(JSON.parse(readFileSync(p, 'utf8')))) {
    for (const [name, recs] of Object.entries(names)) dns[`${name}.${domain}`] = recs?.[0]?.[1];
  }
}
async function fetchKey(selector, domain) {
  const rec = dns[`${selector}._domainkey.${domain}`];
  if (rec === undefined) throw new Error('key-notfound');
  return parseKeyRecord(rec);
}
function pickNow(bin) {
  const ts = [...bin.matchAll(/[;\s]t=(\d+)/gi)].map((m) => parseInt(m[1], 10));
  return (ts.filter(Number.isFinite).reduce((a, b) => Math.max(a, b), 0) || 1782394336) + 3600;
}

// One body octet changed (a letter, so line structure stays), and the
// Subject changed.
function variants(bytes) {
  const out = [['as captured', bytes]];
  const bin = bytesToBinary(bytes);
  const sep = bin.search(/\r?\n\r?\n/);
  if (sep >= 0) {
    const mid = sep + Math.floor((bin.length - sep) / 2);
    const rel = bin.slice(mid).search(/[A-Za-z]/);
    if (rel >= 0) {
      const b = Uint8Array.from(bytes);
      b[mid + rel] = b[mid + rel] === 0x5a ? 0x59 : 0x5a;
      out.push(['body byte changed', b]);
    }
    const subj = /^Subject:/im.exec(bin);
    if (subj && subj.index < sep) {
      const b = Uint8Array.from(bytes);
      b[subj.index + 8] = 0x58; // the octet after "Subject:"
      out.push(['Subject changed', b]);
    }
  }
  return out;
}

function files() {
  const out = [];
  if (corpus) {
    const dir = join(corpus, 'capture');
    for (const f of readdirSync(dir).filter((f) => f.endsWith('.eml')).sort()) out.push(join(dir, f));
  }
  const perl = join(repoRoot, 'perl', 'tests', 'expected');
  if (existsSync(perl)) for (const f of readdirSync(perl).filter((f) => f.endsWith('.eml')).sort()) out.push(join(perl, f));
  return out;
}

test('planned walk matches the undo walk on every real message', { timeout: 600000 }, async (t) => {
  if (!corpus) t.diagnostic('corpus/results/capture not found: Perl expected files only');
  const list = files();
  let compared = 0, fallbacks = 0, multiLevel = 0;
  for (const path of list) {
    for (const [what, bytes] of variants(new Uint8Array(readFileSync(path)))) {
      const where = `${path} (${what})`;
      const { undo, plan, fallback } = await compareChains(bytes);
      if (fallback) fallbacks++;
      else assert.deepEqual(plan, undo, where);
      if (Object.values(undo.levels).filter(Boolean).length > 1) multiLevel++;
      const reps = await compareReports(bytes, { fetchKey, now: pickNow(bytesToBinary(bytes)) });
      assert.deepEqual(reps.plan, reps.undo, where);
      compared++;
    }
  }
  t.diagnostic(`${list.length} files, ${compared} messages compared, ${multiLevel} with more than one instance, ${fallbacks} left to the undo walk`);
  assert.ok(list.length > 0);
});
