// DKIM2 verification orchestrator per spec-04 §10/§11. Built from spec.
import { parseMessage, collectLevels, parseTagList } from './parse.js';
import { canonBody, canonHeaderHash, isUnsignedHeader, signingInput } from './canon.js';
import { sha256Bytes, sha256B64, verifyRsa, verifyEd25519 } from './crypto.js';
import { fetchKey as dohFetchKey } from './doh.js';
import { decodeRecipe, bodyToLines, linesToBody, applyBodyRecipe, applyHeaderRecipe } from './recipes.js';
import { stringToBytes, b64ToBytes, b64ToString } from './b64.js';

const SIG_MI_NAMES = new Set(['message-instance', 'dkim2-signature']);

export function domainOf(path) {
  const m = /<?[^@<>]*@([^>]*)>?/.exec(path || '');
  return m ? m[1].toLowerCase() : '';
}

export function relaxedDomainMatch(fromDomain, targetDomain) {
  let a = (fromDomain || '').toLowerCase();
  const b = (targetDomain || '').toLowerCase();
  while (a) {
    if (a === b) return true;
    const dot = a.indexOf('.');
    if (dot < 0) return false;
    a = a.slice(dot + 1);
  }
  return false;
}

// Signed header fields (for the §6.2 header hash) at a given message state.
function signedFields(fields) {
  return fields.filter((f) => !isUnsignedHeader(f.name) && !SIG_MI_NAMES.has(f.name.toLowerCase()));
}

// Parse the h= hash-set list into [{alg, headerHash, bodyHash}].
function parseHashSets(hValue) {
  return (hValue || '').split(',').map((set) => {
    const [alg, headerHash, bodyHash] = set.split(':');
    return { alg: (alg || '').trim(), headerHash, bodyHash };
  });
}

// Parse the s= sig-set list into [{selector, alg, sig}].
function parseSigSets(sValue) {
  return (sValue || '').split(',').map((set) => {
    const [selector, alg, sig] = set.split(':');
    return { selector: (selector || '').trim(), alg: (alg || '').trim().toLowerCase(), sig: (sig || '').trim() };
  });
}

const SUPPORTED_ALGS = new Set(['rsa-sha256', 'ed25519-sha256']);

export async function verifyMessage(raw, opts = {}) {
  const fetchKey = opts.fetchKey || dohFetchKey;
  const now = opts.now || Math.floor(Date.now() / 1000);
  const { headers, body } = parseMessage(raw);
  const { instances, signatures } = collectLevels(headers);

  const miNums = Object.keys(instances).map(Number).sort((a, b) => a - b);
  const sigNums = Object.keys(signatures).map(Number).sort((a, b) => a - b);

  if (sigNums.length === 0) {
    return { overall: 'none', summary: 'No DKIM2-Signature header field present.', levels: [] };
  }

  const levels = [];
  let overall = 'pass';
  const bump = (state) => {
    // Precedence for the overall verdict: fail > permerror > temperror > pass.
    const rank = { pass: 0, temperror: 1, permerror: 2, fail: 3 };
    if (rank[state] > rank[overall]) overall = state;
  };

  // --- §11.2 structural validation -------------------------------------
  const maxM = miNums[miNums.length - 1];
  const maxI = sigNums[sigNums.length - 1];
  const structErr = [];
  for (let i = 1; i <= maxI; i++) if (!signatures[i]) structErr.push(`DKIM2-Signature i=${i} missing`);
  for (let m = 1; m <= maxM; m++) if (!instances[m]) structErr.push(`Message-Instance m=${m} missing`);
  if (maxM > maxI) structErr.push(`Message-Instance m=${maxM} is not signed`);
  for (const i of sigNums) {
    const s = signatures[i];
    for (const t of ['i', 'm', 't', 'd', 's']) if (!(t in s.map)) structErr.push(`DKIM2-Signature i=${i} tag=${t} missing`);
    const hasNd = 'nd' in s.map, hasMf = 'mf' in s.map, hasRt = 'rt' in s.map;
    if (hasNd && (hasMf || hasRt)) structErr.push(`DKIM2-Signature i=${i} tag=nd was unexpected`);
    if (!hasNd && !(hasMf && hasRt)) structErr.push(`DKIM2-Signature i=${i} tag=mf missing`);
  }
  for (const m of miNums) {
    const mi = instances[m];
    for (const t of ['m', 'h']) if (!(t in mi.map)) structErr.push(`Message-Instance m=${m} tag=${t} missing`);
  }
  if (structErr.length) {
    return { overall: 'permerror', summary: structErr.join('; '), levels: [] };
  }

  // --- reconstruct message state per instance (top-down) ----------------
  // state[m] = { fields, bodyLines } representing the message at instance m.
  const states = {};
  states[maxM] = { fields: headers.slice(), bodyLines: bodyToLines(body) };
  let undoBroken = null; // m at which undo became impossible
  for (let m = maxM; m >= 2; m--) {
    const mi = instances[m];
    if (!('r' in mi.map)) { undoBroken = m; break; }
    let recipe;
    try { recipe = decodeRecipe(mi.map.r); } catch (e) { undoBroken = m; break; }
    if (recipe.b === null) { undoBroken = m; break; } // §5.2 unrecoverable
    const cur = states[m];
    let fields = cur.fields;
    let bodyLines = cur.bodyLines;
    if (recipe.h) fields = applyHeaderRecipe(cur.fields, recipe.h);
    if (recipe.b) bodyLines = applyBodyRecipe(cur.bodyLines, recipe.b);
    states[m - 1] = { fields, bodyLines };
  }

  // --- §11.7 MI hash checks (top-down) ----------------------------------
  for (let m = maxM; m >= 1; m--) {
    const mi = instances[m];
    const state = states[m];
    const level = {
      kind: 'instance', m,
      tags: mi.tags.map((t) => ({ tag: t.tag, value: t.value })),
      header_hash: 'not-checked', body_hash: 'not-checked',
      header_recipes: [], undo: m === 1 ? 'n/a' : 'clean',
      result: 'pass', detail: '',
    };
    if (!state) {
      level.result = 'not-checked';
      level.undo = undoBroken === m + 1 ? 'unrecoverable' : 'not-checked';
      level.detail = `state unavailable (undo broke at m=${undoBroken})`;
      levels.push(level);
      continue;
    }
    const sets = parseHashSets(mi.map.h);
    const hdrBytes = stringToBytes(canonHeaderHash(signedFields(state.fields)));
    const bodyBytes = stringToBytes(canonBody(linesToBody(state.bodyLines)));
    const hdrHash = await sha256B64(hdrBytes);
    const bodyHash = await sha256B64(bodyBytes);
    // Compare against the sha256 hash-set (ignore unknown algs, §3.4).
    const sha = sets.find((s) => s.alg === 'sha256');
    if (sha) {
      level.header_hash = hdrHash === sha.headerHash ? 'match' : 'mismatch';
      level.body_hash = bodyHash === sha.bodyHash ? 'match' : 'mismatch';
      if (level.header_hash === 'mismatch') { level.result = 'fail'; level.detail = `Message Instance m=${m} header hash mismatch`; bump('fail'); }
      else if (level.body_hash === 'mismatch') { level.result = 'fail'; level.detail = `Message Instance m=${m} body hash mismatch`; bump('fail'); }
    }
    if (m >= 2 && undoBroken === m) level.undo = recipeUndoLabel(instances[m]);
    levels.push(level);
  }

  // --- §11.3–§11.6 signature checks (top-down) --------------------------
  for (let i = maxI; i >= 1; i--) {
    const sig = signatures[i];
    const level = {
      kind: 'signature', i, m: parseInt(sig.map.m, 10),
      tags: sig.tags.map((t) => ({ tag: t.tag, value: t.value })),
      items: [], timestamp: { ok: true, detail: '' },
      custody: { ok: true, detail: '' }, result: 'pass', detail: '',
    };

    // §11.3 timestamp: >14 days old (or, if configured, future).
    if (!opts.skipTimestamp && sig.map.t) {
      const t = parseInt(sig.map.t, 10);
      const ageDays = (now - t) / 86400;
      if (ageDays > 14) { level.timestamp = { ok: false, status: 'expired', detail: `signature expired (${Math.floor(ageDays)}d)` }; level.result = 'fail'; bump('fail'); }
    }

    // §11.4 chain-of-custody (inter-signature + d=/mf=).
    custodyCheck(level, signatures, i, maxI, opts);
    if (!level.custody.ok) { level.result = 'fail'; bump(level.custodyState || 'permerror'); }

    // §11.5/§11.6 fetch key + verify each s= sig-set.
    const mAtSig = parseInt(sig.map.m, 10);
    const state = states[mAtSig];
    if (!state) {
      level.result = 'not-checked';
      level.detail = 'message state for this signature could not be reconstructed';
      levels.push(level);
      continue;
    }
    // Signing input = MI 1..mAtSig then DKIM2-Signature 1..i (target blanked).
    const ordered = [];
    for (let m = 1; m <= mAtSig; m++) ordered.push(fieldFor(instances[m]));
    for (let k = 1; k <= i; k++) ordered.push(fieldFor(signatures[k]));
    const inputBytes = stringToBytes(signingInput(ordered, sig.field));
    const inputHash = await sha256Bytes(inputBytes);

    const sigSets = parseSigSets(sig.map.s);
    let anyChecked = false, allPass = true;
    for (const ss of sigSets) {
      if (!SUPPORTED_ALGS.has(ss.alg)) continue; // §3.4 ignore unknown
      anyChecked = true;
      let ok = false, detail = '';
      try {
        const key = await fetchKey(ss.selector, sig.map.d);
        const sigBytes = b64ToBytes(ss.sig);
        if (ss.alg === 'ed25519-sha256') {
          if (key.k !== 'ed25519') { detail = 'algorithm mismatch'; }
          else ok = await verifyEd25519(key.p, sigBytes, inputHash);
        } else { // rsa-sha256
          if (key.k !== 'rsa') { detail = 'algorithm mismatch'; }
          else ok = await verifyRsa(key.p, sigBytes, inputBytes);
        }
      } catch (e) {
        detail = keyErrorDetail(e);
        if (e.message === 'key-temperror') { level.itemTemp = true; }
        else if (e.message === 'ed25519-unsupported') { detail = 'ed25519 unsupported in this browser'; }
      }
      if (!ok) allPass = false;
      level.items.push({ selector: ss.selector, algorithm: ss.alg, result: ok ? 'pass' : (detail || 'fail') });
    }
    if (!anyChecked) {
      level.result = level.result === 'fail' ? 'fail' : 'not-checked';
      if (level.result === 'not-checked') level.detail = 'no supported signature algorithm';
    } else if (!allPass) {
      if (level.itemTemp) { level.result = 'temperror'; bump('temperror'); }
      else { level.result = 'fail'; level.detail = `DKIM2-Signature i=${i} incorrect signature`; bump('fail'); }
    }
    levels.push(level);
  }

  const summary = overall === 'pass'
    ? `i=1..${maxI} verified; Message-Instance m=1..${maxM} intact`
    : levels.filter((l) => l.detail).map((l) => l.detail).join('; ') || `verification ${overall}`;
  return { overall, summary, levels };
}

function fieldFor(level) { return { name: level.field.name, value: level.field.value }; }

function recipeUndoLabel(mi) {
  try {
    const r = decodeRecipe(mi.map.r);
    return r.b === null ? 'unrecoverable' : 'failed';
  } catch (e) { return 'failed'; }
}

function keyErrorDetail(e) {
  const map = {
    'key-notfound': 'public key does not exist',
    'key-multiple': 'public key has multiple records',
    'key-syntax': 'public key has a syntax error',
    'key-revoked': 'public key has been revoked',
    'key-temperror': 'public key could not be fetched',
  };
  return map[e.message] || String(e.message || e);
}

// §11.4: inter-signature mf/rt match + d=/mf= relaxed match + nd= handling.
function custodyCheck(level, signatures, i, maxI, opts) {
  const sig = signatures[i];
  const hasNd = 'nd' in sig.map;

  if (hasNd) {
    const next = signatures[i + 1];
    if (!next) {
      // nd= on the highest signature: needs out-of-band trust (§9.3). SHOULD.
      level.custody = { ok: true, detail: `nd=${sig.map.nd} (top hop; out-of-band trust assumed)` };
      return;
    }
    if ((next.map.d || '').toLowerCase() !== sig.map.nd.toLowerCase()) {
      level.custody = { ok: false, detail: `nd= does not match i=${i + 1} d=` };
      level.custodyState = 'permerror';
    } else {
      level.custody = { ok: true, detail: `nd=${sig.map.nd} matches i=${i + 1} d=` };
    }
    return;
  }

  // d= vs mf= relaxed match (skip when mf empty, e.g. DSN).
  const mfDomain = domainOf(b64ToString(sig.map.mf || ''));
  if (mfDomain && !relaxedDomainMatch(mfDomain, (sig.map.d || '').toLowerCase())) {
    level.custody = { ok: false, detail: `i=${i} MAIL FROM and d= do not match` };
    level.custodyState = 'permerror';
    return;
  }

  // Inter-signature: mf= of this hop matches an rt= of the next-lower hop.
  if (i > 1) {
    const lower = signatures[i - 1];
    const rtDomains = (lower.map.rt || '').split(',').map((r) => domainOf(b64ToString(r)));
    const matched = rtDomains.some((rt) => relaxedDomainMatch(mfDomain, rt));
    if (!matched) {
      level.custody = { ok: false, detail: `i=${i} MAIL FROM ${mfDomain} did not match i=${i - 1} rt=` };
      level.custodyState = 'permerror';
      return;
    }
  }
  level.custody = { ok: true, detail: i === 1 ? 'origin' : 'chain intact' };
}
