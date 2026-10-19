// Shared helpers for the planned-walk parity tests: build messages with
// Recipes, and compare planChain() (plan.js) with undoChain() (verify.js).
import { parseMessage, collectLevels } from '../parse.js';
import { decodeRecipe } from '../recipes.js';
import { verifyMessage, undoChain } from '../verify.js';
import { planChain } from '../plan.js';
import { textToBinary, bytesToBinary } from '../b64.js';

const b64json = (obj) => Buffer.from(typeof obj === 'string' ? obj : JSON.stringify(obj), 'utf8').toString('base64');

// spec: { headers: [[name, value]...], body: string, recipes: {m: recipe},
//         maxM, mTag: {m: 'm= text'}, rawR: {m: 'r= text'} }
// A recipe of undefined leaves r= off; a string is JSON text as-is.
export function mkMsg(spec) {
  const maxM = spec.maxM || 1;
  let out = '';
  for (let m = 1; m <= maxM; m++) {
    const mt = (spec.mTag && spec.mTag[m]) || String(m);
    let r = '';
    if (spec.rawR && m in spec.rawR) r = `; r=${spec.rawR[m]}`;
    else if (spec.recipes && spec.recipes[m] !== undefined) r = `; r=${b64json(spec.recipes[m])}`;
    out += `Message-Instance: m=${mt}; h=sha256:HDR${m}:BODY${m}${r}\r\n`;
  }
  out += `DKIM2-Signature: i=1; m=${maxM}; t=1000000; d=example.com; s=sel:rsa-sha256:AAAA; nd=example.net\r\n`;
  for (const [n, v] of spec.headers || [['From', 'a@example.com'], ['Subject', 'hi']]) out += `${n}:${v}\r\n`;
  if (spec.noSeparator) return out;
  return out + '\r\n' + (spec.body === undefined ? 'hello\r\n' : spec.body);
}

function parts(raw) {
  const bin = typeof raw === 'string' ? textToBinary(raw) : bytesToBinary(raw);
  const { headers, body } = parseMessage(bin);
  const { instances } = collectLevels(headers);
  const maxM = Math.max(...Object.keys(instances).map(Number));
  return { bin, headers, body, instances, maxM };
}

// Rewrite the placeholder h= values with the hashes the undo walk computes,
// so the MI levels match and the whole hash path runs.
export async function selfConsistent(raw) {
  const { headers, body, instances, maxM } = parts(raw);
  const chain = undoChain(headers, body, instances, maxM);
  let out = raw;
  for (let m = maxM; m >= 1; m--) {
    if (!chain.has(m)) continue;
    out = out.replace(`HDR${m}:`, (await chain.headerHash(m, 'sha256')) + ':');
    if (!chain.noBody(m)) out = out.replace(`BODY${m}`, await chain.bodyHash(m, 'sha256'));
  }
  return out;
}

function recipeNames(instances) {
  const names = new Set();
  for (const mi of Object.values(instances)) {
    try {
      const r = decodeRecipe(mi.map.r);
      if (r && r.h && typeof r.h === 'object') for (const k of Object.keys(r.h)) { names.add(k); names.add(k.toLowerCase()); }
    } catch (e) { /* no names */ }
  }
  return names;
}

// Everything verifyOnce() can read from a chain.
export async function snapshot(chain, instances, maxM, names) {
  const snap = {
    undoBroken: chain.undoBroken, undoBrokenReason: chain.undoBrokenReason,
    nullBodyAt: chain.nullBodyAt, nullBodyInstances: [...chain.nullBodyInstances].sort(),
    levels: {},
  };
  for (let m = maxM + 1; m >= 0; m--) {
    if (!chain.has(m)) { snap.levels[m] = null; continue; }
    const lvl = { noBody: chain.noBody(m), header: {}, body: {}, values: {} };
    for (const alg of ['sha256', 'sha512']) {
      lvl.header[alg] = await chain.headerHash(m, alg);
      if (!lvl.noBody) lvl.body[alg] = await chain.bodyHash(m, alg);
    }
    for (const n of names) lvl.values[n] = chain.headerValues(m, n);
    snap.levels[m] = lvl;
  }
  if (instances[1] && 'r' in instances[1].map && chain.has(1)) {
    let rec;
    try { rec = decodeRecipe(instances[1].map.r); } catch (e) { rec = undefined; }
    if (rec !== undefined) {
      try { chain.checkBottom(rec); snap.bottom = 'ok'; } catch (e) { snap.bottom = e.name; }
    }
  }
  return snap;
}

// { plan, undo, fallback } snapshots for one message.
export async function compareChains(raw) {
  const { headers, body, instances, maxM } = parts(raw);
  const names = new Set([...recipeNames(instances), ...headers.map((f) => f.name.toLowerCase())]);
  const undo = await snapshot(undoChain(headers, body, instances, maxM), instances, maxM, names);
  const p = planChain(headers, body, instances, maxM);
  const plan = p ? await snapshot(p, instances, maxM, names) : null;
  return { undo, plan, fallback: !p };
}

const notFound = async () => { throw new Error('key-notfound'); };

export async function compareReports(raw, opts = {}) {
  const o = { fetchKey: notFound, now: 1000000, ...opts };
  const undo = await verifyMessage(raw, { ...o, undoWalk: true });
  const plan = await verifyMessage(raw, o);
  return { undo, plan };
}
