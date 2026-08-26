// DKIM2 verification orchestrator per spec-04 §10/§11. Built from spec.
import { parseMessage, collectLevels, parseTagList, parseHashSets } from './parse.js';
import { canonBody, canonHeaderHash, isUnsignedHeader, signingInput } from './canon.js';
import { sha256Bytes, sha256B64, verifyRsa, verifyEd25519, HASH_ALGS, hashB64 } from './crypto.js';
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

// Parse the s= sig-set list into [{selector, alg, sig}].
function parseSigSets(sValue) {
  return (sValue || '').split(',').map((set) => {
    const [selector, alg, sig] = set.split(':');
    return { selector: (selector || '').trim(), alg: (alg || '').trim().toLowerCase(), sig: (sig || '').trim() };
  });
}

const SUPPORTED_ALGS = new Set(['rsa-sha256', 'ed25519-sha256']);

// spec-05 §8.9 duplicate/limit rules for one DKIM2-Signature s= tag: a
// Selector MUST NOT appear more than once, and the same signing algorithm may
// appear at most twice, and only with distinct Selectors. Both comparisons
// are case-insensitive (a Selector is a Domain, §3.5; algorithm names are
// ABNF quoted strings, RFC 5234). items is the parsed LIST of {selector, alg}
// sig-sets (never a deduplicated map — a second occurrence must stay visible).
export function checkSignatureDuplicates(items, i) {
  const errors = [];
  const selectors = items.map((it) => (it.selector || '').toLowerCase());
  if (new Set(selectors).size !== selectors.length) {
    errors.push(`PERMERROR DKIM2-Signature i=${i} has a duplicate selector`);
  }
  const counts = new Map();
  for (const it of items) {
    const alg = (it.alg || '').toLowerCase();
    counts.set(alg, (counts.get(alg) || 0) + 1);
  }
  if ([...counts.values()].some((n) => n > 2)) {
    errors.push(`PERMERROR DKIM2-Signature i=${i} has too many signatures`);
  }
  return errors;
}

// All (unfolded, WSP-trimmed) values of a header field name, in document order.
function headerValues(fields, name) {
  const n = name.toLowerCase();
  return fields.filter((f) => f.name.toLowerCase() === n).map((f) => f.value.trim());
}

// A short human-readable summary of a decoded recipe (§5), e.g.
// "headers: subject; body: 1 step" — mirrors the /validate/ r= tag display.
function recipeSummary(rec) {
  if (rec == null) return 'null (previous state not recoverable)';
  const parts = [];
  if (rec.h && Object.keys(rec.h).length) parts.push('headers: ' + Object.keys(rec.h).sort().join(', '));
  if (rec.b === null) parts.push('body: null (not recoverable)');
  else if (Array.isArray(rec.b)) parts.push('body: ' + rec.b.length + ' step' + (rec.b.length === 1 ? '' : 's'));
  return parts.length ? parts.join('; ') : 'none';
}

// Return the (lowercased) name of the first tag that appears more than once in
// a parsed tag list, or null. Tag names are case-insensitive (§7/§8), and
// parseTagList already lowercases them.
function duplicateTag(tags) {
  const seen = new Set();
  for (const t of tags) {
    if (seen.has(t.tag)) return t.tag;
    seen.add(t.tag);
  }
  return null;
}

// verifyMessage(raw, opts) — verify a DKIM2 message and return a structured
// report.
//
// Prior to spec-05, a receiving MTA's Received-SPF header (Fastmail adds one)
// was covered by the Message-Instance header hash and could break
// verification; this used to retry once with it stripped. spec-05 §4
// excludes Received-SPF from the hash via the "Received-*" prefix rule, so
// stripping it can no longer change any hash or verdict -- the retry was
// provably a no-op. Removed rather than kept as a "safety net": it was
// hardcoded to the literal name Received-SPF, not a general mechanism, so it
// covered nothing else anyway. Mirrored removal in
// Mail::DKIM2::Validate::report().
export async function verifyMessage(raw, opts = {}) {
  return verifyOnce(raw, opts);
}

async function verifyOnce(raw, opts = {}) {
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
    const rank = { pass: 0, warn: 1, temperror: 2, permerror: 3, fail: 4 };
    if (rank[state] > rank[overall]) overall = state;
  };

  // --- §11.2 structural validation -------------------------------------
  const maxM = miNums[miNums.length - 1];
  const maxI = sigNums[sigNums.length - 1];
  const structErr = [];
  // A signed message MUST carry at least Message-Instance m=1 (§11.2).
  if (miNums.length === 0) structErr.push('Message-Instance m=1 missing');
  for (let i = 1; i <= maxI; i++) if (!signatures[i]) structErr.push(`DKIM2-Signature i=${i} missing`);
  for (let m = 1; m <= maxM; m++) if (!instances[m]) structErr.push(`Message-Instance m=${m} missing`);
  // §11.2: the highest MI m= must be covered by some signature's m= VALUE
  // (i= hop count and m= do not necessarily track together).
  const maxSigM = Math.max(...sigNums.map((i) => parseInt(signatures[i].map.m, 10)));
  if (maxM > maxSigM) structErr.push(`Message-Instance m=${maxM} is not signed`);
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
    // §7: tags may appear in any order but MUST be only one of each kind.
    const dupM = duplicateTag(mi.tags);
    if (dupM) structErr.push(`Message-Instance m=${m} tag=${dupM} appears more than once`);
  }
  for (const i of sigNums) {
    const s = signatures[i];
    // §8: tags may appear in any order but MUST be only one of each kind.
    const dupS = duplicateTag(s.tags);
    if (dupS) structErr.push(`DKIM2-Signature i=${i} tag=${dupS} appears more than once`);
    // §8.3: the n= nonce value MUST NOT exceed 64 characters.
    if ('n' in s.map && s.map.n.length > 64) structErr.push(`DKIM2-Signature i=${i} n= nonce exceeds 64 characters`);
  }
  if (structErr.length) {
    return { overall: 'permerror', summary: structErr.join('; '), levels: [] };
  }

  // --- reconstruct message state per instance (top-down) ----------------
  // state[m] = { fields, bodyLines } representing the message at instance m.
  const states = {};
  states[maxM] = { fields: headers.slice(), bodyLines: bodyToLines(body) };
  let undoBroken = null; // m at which undo became impossible
  let undoBrokenReason = null; // 'redacted' (§5.2, legitimate) | 'invalid-json' | 'broken'
  for (let m = maxM; m >= 2; m--) {
    const mi = instances[m];
    if (!('r' in mi.map)) { undoBroken = m; undoBrokenReason = 'broken'; break; }
    let recipe;
    try {
      recipe = decodeRecipe(mi.map.r);
    } catch (e) {
      // spec-05 §11.2: "errors in a JSON object specifying Recipes should be
      // called out specifically" -- a malformed r= payload (JSON.parse
      // throws SyntaxError) is reported distinctly from other undo failures
      // (a bad base64 r= value, or a structurally-invalid-but-parseable
      // recipe caught below), which stay lumped as a generic 'broken' undo.
      undoBroken = m;
      undoBrokenReason = e instanceof SyntaxError ? 'invalid-json' : 'broken';
      break;
    }
    if (recipe.b === null) { undoBroken = m; undoBrokenReason = 'redacted'; break; } // §5.2 intentional redaction
    const cur = states[m];
    let fields = cur.fields;
    let bodyLines = cur.bodyLines;
    try {
      if (recipe.h) fields = applyHeaderRecipe(cur.fields, recipe.h);
      if (recipe.b) bodyLines = applyBodyRecipe(cur.bodyLines, recipe.b);
    } catch (e) { undoBroken = m; undoBrokenReason = 'broken'; break; }
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
      // No reconstructed state: distinguish intentional redaction (§5.2 —
      // legitimate, do NOT downgrade overall) from a broken chain (fail).
      level.result = 'not-checked';
      if (undoBrokenReason === 'redacted') {
        level.undo = 'unrecoverable';
        level.detail = `state unavailable (redaction at m=${undoBroken})`;
      } else if (undoBrokenReason === 'invalid-json') {
        // spec-05 §11.2: report the specific invalid-JSON PERMERROR, not the
        // generic "undo broke" fail below -- and every level whose state is
        // unreachable because of it must bump 'permerror' too (not 'fail',
        // which outranks 'permerror' in the overall verdict), so the final
        // verdict is permerror rather than being clobbered by a downstream fail.
        level.undo = undoBroken === m + 1 ? 'failed' : 'not-checked';
        level.detail = `PERMERROR Message-Instance m=${undoBroken} contains invalid JSON`;
        bump('permerror');
      } else {
        level.undo = undoBroken === m + 1 ? 'failed' : 'not-checked';
        level.detail = `state unavailable (undo broke at m=${undoBroken})`;
        bump('fail');
      }
      levels.push(level);
      continue;
    }
    try {
      const sets = parseHashSets(mi.map.h);
      // spec-05 §7.3: an algorithm MUST NOT be present more than once. This
      // must run before any hash is computed or compared, over the parsed
      // LIST (never a deduplicated map, or a second occurrence would be
      // silently overwritten and go undetected).
      const algSeen = new Set();
      const dupAlg = sets.some((s) => (algSeen.has(s.alg) ? true : (algSeen.add(s.alg), false)));
      if (dupAlg) {
        level.result = 'fail';
        level.detail = `PERMERROR Message-Instance m=${m} has a duplicate hash algorithm`;
        bump('fail');
        levels.push(level);
        continue;
      }
      const hdrBytes = stringToBytes(canonHeaderHash(signedFields(state.fields)));
      const bodyBytes = stringToBytes(canonBody(linesToBody(state.bodyLines)));
      // §3.4: ignore hash-sets naming algorithms we do not implement; all the
      // ones we do implement must match (mirrors §11.6 for signatures).
      const usable = sets.filter((s) => s.alg in HASH_ALGS);
      if (usable.length === 0) {
        level.result = 'fail';
        level.detail = `Message Instance m=${m} no supported hash algorithm`;
        bump('fail');
      } else {
        level.header_hash = 'match';
        level.body_hash = 'match';
        for (const s of usable) {
          if (await hashB64(hdrBytes, s.alg) !== s.headerHash) {
            level.header_hash = 'mismatch';
            level.result = 'fail';
            level.detail = `Message Instance m=${m} ${s.alg} header hash mismatch`;
            bump('fail');
            break;
          }
          if (await hashB64(bodyBytes, s.alg) !== s.bodyHash) {
            level.body_hash = 'mismatch';
            level.result = 'fail';
            level.detail = `Message Instance m=${m} ${s.alg} body hash mismatch`;
            bump('fail');
            break;
          }
        }
      }
    } catch (e) {
      level.result = 'fail';
      level.detail = `Message Instance m=${m} hash computation error`;
      bump('fail');
    }
    if (m >= 2 && undoBroken === m) level.undo = recipeUndoLabel(instances[m]);

    // Recipe breakdown (§5/§7.2): decode r= and show what it changed — a
    // readable summary in the r= tag, the decoded recipe JSON, and per-header
    // current<-previous values (matching the /validate/ display).
    if ('r' in mi.map) {
      let rec;
      try { rec = decodeRecipe(mi.map.r); } catch (e) { rec = undefined; }
      if (rec !== undefined) {
        const hasH = rec.h && Object.keys(rec.h).length > 0;
        level.recipe = rec.b === null ? 'null' : (hasH || Array.isArray(rec.b)) ? 'diff' : 'none';
        level.body_recipe = rec.b === null ? 'null' : (Array.isArray(rec.b) ? 'diff' : 'none');
        level.recipe_json = rec;
        // Replace the raw base64 r= value in the tag grid with a readable summary.
        const rtag = level.tags.find((t) => t.tag === 'r');
        if (rtag) rtag.value = recipeSummary(rec);
        // Per-header current<-previous, only when the previous state exists.
        const prev = states[m - 1];
        if (rec.h && prev) {
          for (const name of Object.keys(rec.h).sort()) {
            const cur = headerValues(state.fields, name).join(' / ');
            const pre = headerValues(prev.fields, name).join(' / ');
            level.header_recipes.push({
              name,
              current: cur.length ? cur : '(absent)',
              previous: pre.length ? pre : '(absent)',
            });
          }
        }
      }
    }
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

    // §11.3 timestamp: a signature more than 14 days old is graded as a soft
    // WARNING, not a hard failure. The spec says a verifier SHOULD fail on age
    // (§11.3) but MAY ignore it (§8.4); for a paste-a-saved-message tool, old
    // messages are the norm, so we surface age as a warning and still verify
    // the crypto (matching the reference /validate/ behaviour). The upgrade to
    // 'warn' happens only if the signature otherwise passes (see below).
    let expired = false;
    if (!opts.skipTimestamp && sig.map.t) {
      const t = parseInt(sig.map.t, 10);
      if (Number.isFinite(t)) {
        const ageDays = (now - t) / 86400;
        if (ageDays > 14) {
          expired = true;
          level.timestamp = { ok: false, status: 'expired', detail: `signature more than 14 days old (${Math.floor(ageDays)}d)` };
        }
      }
    }

    // §11.4 chain-of-custody (inter-signature + d=/mf=), plus the top-hop
    // envelope exact-match against the actual delivery MAIL FROM / RCPT TO.
    try {
      custodyCheck(level, signatures, i, maxI, opts);
      if (i === maxI && level.custody.ok) envelopeCheck(level, sig, i, opts);
    } catch (e) {
      // e.g. invalid base64 in a present mf=/rt= (b64ToString throws).
      level.custody = { ok: false, detail: `i=${i} mf/rt malformed` };
      level.custodyState = 'permerror';
    }
    if (!level.custody.ok) {
      // A chain-of-custody / envelope failure (§11.4) is a permanent error for
      // this signature; short-circuit before the crypto check so a subsequent
      // key-not-found does not mask the permerror as a plain 'fail'.
      level.result = level.custodyState || 'permerror';
      level.detail = level.custody.detail;
      bump(level.custodyState || 'permerror');
      levels.push(level);
      continue;
    }

    // §11.5/§11.6 fetch key + verify each s= sig-set.
    const mAtSig = parseInt(sig.map.m, 10);
    const state = states[mAtSig];
    if (!state) {
      // Reconstruction did not reach this signature's instance: broken chain
      // downgrades overall; intentional redaction (§5.2) does not.
      level.result = 'not-checked';
      level.detail = 'message state for this signature could not be reconstructed';
      if (undoBrokenReason === 'broken') bump('fail');
      levels.push(level);
      continue;
    }
    // Signing input = MI 1..mAtSig then DKIM2-Signature 1..i (target blanked).
    // Build `ordered` from the actual parsed Field objects so the target
    // signature matches by REFERENCE inside signingInput() (which blanks s=
    // only for the element that is `=== sig.field`).
    let inputBytes, inputHash;
    try {
      const ordered = [];
      for (let m = 1; m <= mAtSig; m++) ordered.push(instances[m].field);
      for (let k = 1; k <= i; k++) ordered.push(signatures[k].field);
      inputBytes = stringToBytes(signingInput(ordered, sig.field));
      inputHash = await sha256Bytes(inputBytes);
    } catch (e) {
      level.result = 'fail';
      level.detail = `DKIM2-Signature i=${i} signing input error`;
      bump('fail');
      levels.push(level);
      continue;
    }

    const sigSets = parseSigSets(sig.map.s);
    // §8.9 syntax: the s= value must contain sig-sets, each with a selector and
    // an algorithm name. An empty/malformed s= is a syntax error (permerror),
    // distinct from a well-formed sig-set naming an unsupported algorithm
    // (algorithm_only_future), which is a plain 'fail' below.
    const sSyntaxOk = (sig.map.s || '').trim() !== '' && sigSets.every((ss) => ss.selector && ss.alg);
    if (!sSyntaxOk) {
      level.result = 'permerror';
      level.detail = `DKIM2-Signature i=${i} syntax error`;
      bump('permerror');
      levels.push(level);
      continue;
    }

    // spec-05 §8.9: duplicate-selector and too-many-signatures checks must
    // run before any DNS lookup or crypto work.
    const dupErrors = checkSignatureDuplicates(sigSets, i);
    if (dupErrors.length) {
      level.result = 'permerror';
      level.detail = dupErrors.join('; ');
      bump('permerror');
      levels.push(level);
      continue;
    }
    let anyChecked = false, allPass = true;
    for (const ss of sigSets) {
      if (!SUPPORTED_ALGS.has(ss.alg)) continue; // §3.4 ignore unknown
      anyChecked = true;
      let ok = false, detail = '';
      try {
        const key = await fetchKey(ss.selector, sig.map.d);
        const sigBytes = b64ToBytes(ss.sig);
        if (ss.alg === 'ed25519-sha256') {
          if (key.k !== 'ed25519') { detail = 'algorithm mismatch'; level.itemPerm = true; }
          else ok = await verifyEd25519(key.p, sigBytes, inputHash);
        } else { // rsa-sha256
          if (key.k !== 'rsa') { detail = 'algorithm mismatch'; level.itemPerm = true; }
          else ok = await verifyRsa(key.p, sigBytes, inputBytes);
        }
      } catch (e) {
        detail = keyErrorDetail(e);
        // §11.5/§11.6: a permanent key problem (not found, syntax, revoked,
        // too small) is a permerror; a fetch failure is a temperror.
        if (e.message === 'key-temperror') { level.itemTemp = true; }
        else if (e.message === 'key-tooshort') { detail = `RSA public key size too small, ${e.bits} bits`; level.itemPerm = true; }
        else if (e.message === 'ed25519-unsupported') { detail = 'ed25519 unsupported in this browser'; }
        else if (['key-notfound', 'key-multiple', 'key-syntax', 'key-revoked'].includes(e.message)) { level.itemPerm = true; }
      }
      if (!ok) allPass = false;
      level.items.push({ selector: ss.selector, algorithm: ss.alg, result: ok ? 'pass' : (detail || 'fail') });
    }
    if (!anyChecked) {
      // No verifiable signature set (no supported algorithm, or none parsed):
      // this signature cannot be trusted — fail it (matches algorithm_only
      // _future=fail). §3.4 only lets us IGNORE unknown algs alongside a known
      // one, not accept a signature we cannot check at all.
      level.result = 'fail';
      if (!level.detail) level.detail = `DKIM2-Signature i=${i} has no supported signature algorithm`;
      bump('fail');
    } else if (!allPass) {
      if (level.itemPerm) { level.result = 'permerror'; level.detail = `DKIM2-Signature i=${i} public key ${level.items.map((it) => it.result).find((r) => r !== 'pass') || 'error'}`; bump('permerror'); }
      else if (level.itemTemp) { level.result = 'temperror'; level.detail = `DKIM2-Signature i=${i} ${(level.items.find((it) => it.result !== 'pass') || {}).result || 'public key could not be fetched'}`; bump('temperror'); }
      else { level.result = 'fail'; level.detail = `DKIM2-Signature i=${i} incorrect signature`; bump('fail'); }
    }
    // A valid but old signature is a soft warning, not a failure (§11.3/§8.4).
    // Only downgrade a level that otherwise passed — a real failure outranks it.
    if (expired && level.result === 'pass') {
      level.result = 'warn';
      level.detail = `DKIM2-Signature i=${i} more than 14 days old`;
      bump('warn');
    }
    levels.push(level);
  }

  const summary = overall === 'pass'
    ? `i=1..${maxI} verified; Message-Instance m=1..${maxM} intact`
    : overall === 'warn'
    ? `i=1..${maxI} verified; Message-Instance m=1..${maxM} intact — with warnings: ${levels.filter((l) => l.result === 'warn' && l.detail).map((l) => l.detail).join('; ')}`
    : levels.filter((l) => l.detail).map((l) => l.detail).join('; ') || `verification ${overall}`;
  return { overall, summary, levels };
}

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

  // §8.5: the decoded mf= reverse-path MUST include the angle brackets
  // (unless empty). A non-empty value that is not <...> is a permerror.
  const mfDecoded = b64ToString(sig.map.mf || '');
  if (mfDecoded !== '' && !(mfDecoded.startsWith('<') && mfDecoded.endsWith('>'))) {
    level.custody = { ok: false, detail: `i=${i} MAIL FROM ${mfDecoded} did not match (missing angle brackets)` };
    level.custodyState = 'permerror';
    return;
  }

  // d= vs mf= relaxed match (skip when mf empty, e.g. DSN).
  const mfDomain = domainOf(mfDecoded);
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

// Normalize an envelope address for the §11.4 EXACT comparison: strip one
// leading '<' and trailing '>', split on the LAST '@' into localpart+domain,
// lower-case ONLY the domain (the local part case is significant), and keep
// the local part verbatim. An address with no '@' is returned as-is.
function normalizeAddr(a) {
  let s = String(a == null ? '' : a).trim();
  if (s.startsWith('<')) s = s.slice(1);
  if (s.endsWith('>')) s = s.slice(0, -1);
  const at = s.lastIndexOf('@');
  if (at < 0) return s;
  return s.slice(0, at) + '@' + s.slice(at + 1).toLowerCase();
}

// §11.4: the actual delivery MAIL FROM / RCPT TO MUST EXACTLY match (NOT the
// relaxed algorithm) the mf=/rt= of the highest-numbered DKIM2-Signature; only
// the domain is lower-cased. Applies only when the caller supplies the real
// envelope (opts.mailFrom + opts.rcptTo); the browser paste case has no
// envelope and skips this check. nd= (out-of-band, §11.4) and an empty '<>'
// reverse-path (DSN, §8.5/§12) skip the MAIL FROM comparison.
function envelopeCheck(level, sig, i, opts) {
  const mailFrom = opts.mailFrom;
  const rcptTo = opts.rcptTo;
  if (typeof mailFrom !== 'string' || !Array.isArray(rcptTo) || rcptTo.length === 0) return;
  if ('nd' in sig.map) return; // §11.4 out-of-band case: no mf=/rt= to match

  const mfDecoded = b64ToString(sig.map.mf || '');
  if (mfDecoded !== '<>') {
    if (normalizeAddr(mfDecoded) !== normalizeAddr(mailFrom)) {
      level.custody = { ok: false, detail: `DKIM2-Signature i=${i} MAIL FROM ${mailFrom} did not match` };
      level.custodyState = 'permerror';
      return;
    }
  }

  const rtNorm = (sig.map.rt || '').split(',')
    .filter((r) => r.trim() !== '')
    .map((r) => normalizeAddr(b64ToString(r.trim())));
  for (const rcpt of rcptTo) {
    if (!rtNorm.includes(normalizeAddr(rcpt))) {
      level.custody = { ok: false, detail: `DKIM2-Signature i=${i} RCPT TO ${rcpt} did not match` };
      level.custodyState = 'permerror';
      return;
    }
  }
}
