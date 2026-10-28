// DKIM2 verification orchestrator per draft-ietf-dkim-dkim2-spec-07 §13/§14. Built from spec.
import { parseMessage, collectLevels, parseTagList, parseHashSets, MAX_CHAIN_LENGTH } from './parse.js';
import { canonBody, canonHeaderHash, isUnsignedHeader, signingInput } from './canon.js';
import { sha256Bytes, sha256B64, verifyRsa, verifyEd25519, HASH_ALGS, hashB64 } from './crypto.js';
import { fetchKey as dohFetchKey, keyName, DEFINITIVE_KEY_ERRORS } from './doh.js';
import { decodeRecipe, recipeErrorText, bodyToLines, linesToBody, applyRecipe, applyHeaderRecipe, validateBodyRecipe, validateRecipeSteps } from './recipes.js';
import { b64ToBytes, b64ToString, bytesToBinary, binaryToBytes, textToBinary } from './b64.js';
import { planChain } from './plan.js';
import { domainOf, toALabel, relaxedMatch } from './domain.js';

const SIG_MI_NAMES = new Set(['message-instance', 'dkim2-signature']);

// The domain of an address (a decoded mf=/rt= path) as A-labels (§18), or
// a domain literal as it is; '' when there is none or it cannot be mapped.
// Either way relaxedMatch() treats the literal and '' as matching nothing.
function addrDomain(addr) {
  const { domain, literal } = domainOf(addr);
  return literal ? domain : (toALabel(domain) || '');
}

// A d= value, compared as A-labels.
function sigDomain(sig) {
  return toALabel((sig.map.d || '').toLowerCase()) || '';
}

// A decoded mf=/rt= value (§10.5/§10.6): a base64string (§2.14) whose
// decoded path carries its angle brackets; null when it is not.
function decodePath(v) {
  if (!BASE64.test(v)) return null;
  let path;
  try { path = b64ToString(v); } catch (e) { return null; }
  return /^<[^]*>$/.test(path) ? path : null;
}

// Signed header fields (for the §6.2 header hash) at a given message state.
function signedFields(fields) {
  return fields.filter((f) => !isUnsignedHeader(f.name) && !SIG_MI_NAMES.has(f.name.toLowerCase()));
}

// Parse the RAW s= value (FWS intact) into [{selector, alg, sig}], once per
// signature, or null on a §10.9 syntax error. Each item is exactly three
// parts on ":"; FWS around the comma and colons is trimmed and FWS inside
// the signature value removed, but none may sit inside the selector
// ([A-Za-z0-9_-]+ labels joined by ".") or the algorithm ([A-Za-z0-9_-]+):
// "rsa- sha256" is an error, never normalised to rsa-sha256. The algorithm
// name is kept byte-for-byte: tag values are case significant (§8), so
// "RSA-SHA256" is an unknown algorithm, not rsa-sha256.
const SELECTOR = /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/;
const SIG_NAME = /^[A-Za-z0-9_-]+$/;
function parseSigSets(sValue) {
  const trim = (x) => x.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');
  const out = [];
  for (const set of sValue.split(',')) {
    const parts = set.split(':');
    if (parts.length !== 3) return null;
    const selector = trim(parts[0]);
    const alg = trim(parts[1]);
    if (!SELECTOR.test(selector) || !SIG_NAME.test(alg)) return null;
    out.push({ selector, alg, sig: parts[2].replace(/[ \t\r\n]+/g, '') });
  }
  return out;
}

// §3.2/§3.3: the implemented signature algorithms, exactly as written (§10.9).
const SUPPORTED_ALGS = new Set(['rsa-sha256', 'ed25519-sha256']);
// A message-sig is a base64string (§10.9).
// A base64string: non-empty, padded with "=" to a multiple of four (§2.14).
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/;

// The raw value of a parsed tag (parseTagList strips ALL whitespace from
// .value; some rules need to see internal WSP), trimmed of surrounding WSP.
function rawTagValue(tag) {
  return tag.raw.slice(tag.raw.indexOf('=') + 1).replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');
}

// §10.9 duplicate/limit rules for one DKIM2-Signature s= tag: a
// Selector MUST NOT appear more than once, and the same signing algorithm may
// appear at most twice, and only with distinct Selectors. Both comparisons
// are case-insensitive (a Selector is a Domain, §3.6; algorithm names are
// ABNF quoted strings, RFC 5234). items is the parsed LIST of {selector, alg}
// sig-sets (never a deduplicated map — a second occurrence must stay visible).
export function checkSignatureDuplicates(items, i) {
  const errors = [];
  const selectors = items.map((it) => (it.selector || '').toLowerCase());
  if (new Set(selectors).size !== selectors.length) {
    errors.push(`PERMERROR: DKIM2-Signature i=${i} has a duplicate selector`);
  }
  const counts = new Map();
  for (const it of items) {
    const alg = (it.alg || '').toLowerCase();
    counts.set(alg, (counts.get(alg) || 0) + 1);
  }
  if ([...counts.values()].some((n) => n > 2)) {
    errors.push(`PERMERROR: DKIM2-Signature i=${i} has more selectors than allowed`);
  }
  return errors;
}

// Precedence for one signature's own state in the report: fail > permerror >
// temperror > pass. The overall result is the primary error's state (C9).
const RANK = { pass: 0, temperror: 1, permerror: 2, fail: 3 };
// §14.3: a signature more than 14 days old, or more than one day ahead.
const MAX_AGE = 14 * 86400;
const MAX_AHEAD = 86400;

// Message content is a binary string (one code unit per byte); for the
// report, show it as text: UTF-8 where it is, U+FFFD where it is not.
const displayDecoder = new TextDecoder();
function displayText(bin) {
  return displayDecoder.decode(binaryToBytes(bin));
}

// The one addr-spec of a From field value (text), or null when the field is
// not exactly one mailbox: a group, a list, or no address at all. Lenient
// otherwise: "Name <a@b>" or "a@b", with comments and quoted strings (which
// may hold any of , < : ; @) set aside first.
function singleMailbox(text) {
  let s = text.replace(/"(?:[^"\\]|\\[^])*"/g, '""');
  for (let prev = ''; prev !== s;) { prev = s; s = s.replace(/\((?:[^()\\]|\\[^])*\)/g, ' '); }
  if (/[:;,]/.test(s)) return null;
  const angle = /^[^<>]*<([^<>]*)>\s*$/.exec(s);
  const spec = (angle ? angle[1] : s).trim();
  return /^[^\s@<>]+@[^\s@<>]+$/.test(spec) ? spec : null;
}

// §11: the From of one message state is Authentic for d= when the state has
// exactly one From field, holding exactly one mailbox, whose domain is not a
// literal and relaxed-matches d= (From domain Parameter1), as A-labels (§18).
function fromIsAuthentic(values, d) {
  if (values.length !== 1) return false;
  const spec = singleMailbox(displayText(values[0]));
  if (!spec) return false;
  const { domain, literal } = domainOf(spec);
  return !literal && relaxedMatch(toALabel(domain) || '', d);
}

// §11 / §14.8 (contract C5 as corrected by Ruling 19): the signatures whose
// matching From is not Authentic. The From in effect when each signature was
// made is checked: i=1 against the From of state m(i=1), and each i >= 2
// against the From of state m(i) when some instance k with m(i-1) < k <= m(i)
// has a header Recipe that replaces From. A From replaced before any
// signature covered it is never checked. A state the Recipes could not reach
// is not checked here: that is already an error of its own.
function unauthenticFrom(chain, instances, signatures, sigNums, maxM) {
  const bad = new Set();
  const changesFrom = new Set();
  for (let k = 2; k <= maxM; k++) {
    let rec;
    try { rec = decodeRecipe(instances[k].map.r); } catch (e) { continue; }
    if (rec.h && Object.keys(rec.h).some((n) => n.toLowerCase() === 'from')) changesFrom.add(k);
  }
  let prevM = null;
  for (const i of sigNums) {
    const m = parseInt(signatures[i].map.m, 10);
    let due = i === 1;
    if (!due && prevM !== null) {
      for (const k of changesFrom) if (k > prevM && k <= m) due = true;
    }
    prevM = m;
    if (due && chain.has(m) && !fromIsAuthentic(chain.headerValues(m, 'from'), sigDomain(signatures[i]))) bad.add(i);
  }
  return bad;
}

// All (unfolded, WSP-trimmed) values of a header field name, in document order.
function headerValues(fields, name) {
  const n = name.toLowerCase();
  return fields.filter((f) => f.name.toLowerCase() === n).map((f) => f.value.trim());
}

// A short human-readable summary of a decoded Recipe (§5), e.g.
// "headers: subject; body: 1 step" — mirrors the /validate/ r= tag display.
function recipeSummary(rec) {
  const parts = [];
  if (rec.h) parts.push('headers: ' + Object.keys(rec.h).sort().join(', '));
  if (rec.b === null) parts.push('body: null (not recoverable)');
  else if (Array.isArray(rec.b)) parts.push('body: ' + rec.b.length + ' step' + (rec.b.length === 1 ? '' : 's'));
  return parts.length ? parts.join('; ') : 'none';
}

// Return the name of the first tag that appears more than once in a parsed
// tag list, or null. Tag names are compared as written (-08 §8, D10).
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
// Prior to spec-06, a receiving MTA's Received-SPF header (Fastmail adds one)
// was covered by the Message-Instance header hash and could break
// verification; this used to retry once with it stripped. spec-06 §4
// excludes Received-SPF from the hash via the "Received-*" prefix rule, so
// stripping it can no longer change any hash or verdict -- the retry was
// provably a no-op. Removed rather than kept as a "safety net": it was
// hardcoded to the literal name Received-SPF, not a general mechanism, so it
// covered nothing else anyway. Mirrored removal in
// Mail::DKIM2::Validate::report().
// raw: the message as a Uint8Array (exact octets -- what a file or an SMTP
// stream gives) or a string (pasted text, taken as UTF-8). Either way the
// verifier works on octets: the header fields as binary strings, one code
// unit per byte (see b64.js), and the body as the octets themselves.
export async function verifyMessage(raw, opts = {}) {
  let octets;
  if (raw instanceof Uint8Array) octets = raw;
  else if (ArrayBuffer.isView(raw)) octets = new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
  else if (raw instanceof ArrayBuffer) octets = new Uint8Array(raw);
  else octets = binaryToBytes(textToBinary(String(raw)));
  return verifyOnce(octets, opts);
}

async function verifyOnce(raw, opts = {}) {
  const now = opts.now || Math.floor(Date.now() / 1000);
  const { headers, body, lines } = parseMessage(raw);
  const fields = collectLevels(headers);
  const { instances, signatures } = fields;

  // No DKIM2 header fields at all: nothing to verify, and no error.
  if (!fields.miFields.length && !fields.sigFields.length) {
    return { overall: 'none', summary: 'No DKIM2 header fields present.', levels: [] };
  }

  const miNums = Object.keys(instances).map(Number).sort((a, b) => a - b);
  const sigNums = Object.keys(signatures).map(Number).sort((a, b) => a - b);

  // Contract C9: the checks run in -07 §14 order, the Message-Instances
  // (walk included) before the signatures, and the first error found is the
  // PRIMARY one: its state is the result. Later errors may be listed after
  // it, but no key is used unless the Message-Instances, walk included,
  // have all passed.

  // --- §14.2 structure: the field names and their m=/i= numbers --------
  const structural = structureError(fields, miNums, sigNums);
  if (structural) return failed([displayText(structural)], []);
  const maxM = miNums[miNums.length - 1];
  const maxI = sigNums[sigNums.length - 1];

  // Each DKIM2-Signature's own content (§14.2), worked out now but
  // reported where C9 ranks it, after the walk: only a signature that
  // passes has its keys looked up (an s= of thousands of Selectors is
  // rejected before any lookup).
  const sigContent = {};
  for (const i of sigNums) sigContent[i] = signatureContentError(signatures[i], i);

  // Start every public-key lookup now, so they overlap each other and the
  // hashing below. No key is used until the Message-Instances have passed.
  const fetchKey = opts.fetchKey || prefetchKeys(signatures, sigNums.filter((i) => !sigContent[i]),
    { fetch: opts.dohFetch, dohUrl: opts.dohUrl });

  // --- §14.2 Message-Instance content, by ascending m= -------------------
  const miLevels = {};
  const hashSets = {};
  const miErrors = [];
  for (const m of miNums) {
    const mi = instances[m];
    const level = miLevels[m] = {
      kind: 'instance', m,
      tags: mi.tags.map((t) => ({ tag: t.tag, value: t.value })),
      header_hash: 'not-checked', body_hash: 'not-checked',
      header_recipes: [], undo: m === 1 ? 'n/a' : 'not-checked',
      result: 'not-checked', detail: '',
    };
    const { sets, error, recipe } = instanceContent(mi, m);
    hashSets[m] = sets;
    if (error) {
      level.result = 'permerror';
      level.detail = error;
      miErrors.push(error);
      // A Recipe that cannot be undone: the state below it cannot be
      // recreated either.
      if (recipe && m >= 2) {
        level.undo = 'failed';
        const below = miLevels[m - 1];
        if (below.result === 'not-checked') Object.assign(below, { undo: 'failed', detail: error });
      }
    }
  }
  const sigLevels = {};
  for (const i of sigNums) sigLevels[i] = signatureLevel(signatures[i], i);
  const levelList = () => [
    ...miNums.slice().reverse().map((m) => miLevels[m]),
    ...sigNums.slice().reverse().map((i) => sigLevels[i]),
  ];
  if (miErrors.length) return failed(miErrors, explain(levelList(), 'not checked: a Message-Instance is malformed'));

  // --- the chain of message states, one per instance (top-down) ----------
  // The planned walk (plan.js) works out every instance's hash input from
  // the current message without rebuilding any of them; the undo walk
  // (undoChain below) literally rebuilds each previous message and is kept
  // as the reference (opts.undoWalk). Both give the same answers.
  const chain = (!opts.undoWalk && planChain(headers, body, instances, maxM, lines))
    || undoChain(headers, body, instances, maxM);
  const { undoBroken, undoBrokenReason, nullBodyAt, nullBodyInstances } = chain;

  // --- §14.7 the chain walk, top down ------------------------------------
  // A lower instance is rebuilt from the one above it, so the highest one
  // that fails is primary. Within one instance: every header hash, in h=
  // order, before any body hash; then its Recipe applied to the message (a
  // "c" range past the end), which only the walk can find.
  const walkErrors = [];
  for (let m = maxM; m >= 1; m--) {
    const mi = instances[m];
    const level = miLevels[m];
    if (!chain.has(m)) {
      // No reconstructed state: the Recipe at m=undoBroken could not be
      // applied (the error is that instance's).
      level.undo = undoBroken === m + 1 ? 'failed' : 'not-checked';
      level.detail = `PERMERROR: Message-Instance m=${undoBroken} ${undoBrokenReason}`;
      continue;
    }
    level.result = 'pass';
    const noBody = chain.noBody(m);
    // §3.5: ignore hash-sets naming algorithms we do not implement; all the
    // ones we do implement must match (§14.7), and there must be one.
    const usable = hashSets[m].filter((s) => Object.hasOwn(HASH_ALGS, s.alg));
    let err = usable.length ? null : `PERMERROR: Message-Instance m=${m} no supported hash algorithm`;
    try {
      for (const s of err ? [] : usable) {
        if (await chain.headerHash(m, s.alg) !== s.headerHash) {
          level.header_hash = 'mismatch';
          err = `FAIL: Message-Instance m=${m} header hash ${s.alg} mismatch`;
          break;
        }
      }
      if (!err) level.header_hash = 'match';
      if (!err && !noBody) {
        level.body_hash = 'match';
        for (const s of usable) {
          if (await chain.bodyHash(m, s.alg) !== s.bodyHash) {
            level.body_hash = 'mismatch';
            err = `FAIL: Message-Instance m=${m} body hash ${s.alg} mismatch`;
            break;
          }
        }
      }
    } catch (e) {
      err = `PERMERROR: Message-Instance m=${m} hash computation error`;
    }
    if (noBody) level.detail = `body not checked (null body Recipe at m=${nullBodyAt})`;
    // This instance's Recipe against the message, after its own hashes.
    let applyErr = null;
    if (m >= 2) {
      if (undoBroken === m) {
        level.undo = 'failed';
        applyErr = `PERMERROR: Message-Instance m=${m} ${undoBrokenReason}`;
      } else {
        level.undo = nullBodyInstances.has(m) ? 'unrecoverable' : 'clean';
      }
    } else if ('r' in mi.map) {
      // §12.1: the bottom instance MAY carry Recipes too ("if it is wished
      // to record any changes made to a message as it enters the DKIM2
      // ecosystem"); there is no earlier state to undo to, so dry-run it
      // against the m=1 state (a null "b" is left alone).
      try {
        chain.checkBottom(decodeRecipe(mi.map.r));
      } catch (e) {
        applyErr = `PERMERROR: Message-Instance m=1 ${recipeErrorText(e)}`;
      }
    }
    for (const text of [err, applyErr]) {
      if (!text) continue;
      walkErrors.push(text);
      if (level.result === 'pass') { level.result = stateOf(text); level.detail = text; }
    }
    recipeBreakdown(mi, m, chain, level);
  }
  // A walk that fails is the primary error whatever is wrong with the
  // signatures: none of them is verified, and no key is used.
  const walkOk = !walkErrors.length;

  // --- §14.2 DKIM2-Signature content, by ascending i= --------------------
  const sigErrors = [];
  for (const i of sigNums) {
    const text = sigContent[i];
    if (text) {
      Object.assign(sigLevels[i], { result: 'permerror', detail: text, errors: [text] });
      sigErrors.push(text);
    }
  }
  if (sigErrors.length) {
    return failed([...walkErrors, ...sigErrors], explain(levelList(), 'not checked: a DKIM2-Signature is malformed'));
  }

  // --- §14.3–§14.6, §14.8 signature checks -------------------------------
  const badFrom = unauthenticFrom(chain, instances, signatures, sigNums, maxM);
  for (let i = maxI; i >= 1; i--) {
    const sig = signatures[i];
    const level = sigLevels[i];
    // Every error found for this signature, each a "STATE: text" string,
    // and the worst state among them.
    const errors = [];
    let state = 'pass';
    const fail = (st, text) => {
      errors.push(text);
      if (RANK[st] > RANK[state]) state = st;
    };

    // §14.4 Chain of Custody (d=/mf=, and this signature against the one
    // below it), plus the top-hop envelope exact-match against the actual
    // delivery MAIL FROM / RCPT TO. A failure here stops this signature
    // short of the key lookup and the crypto (it outranks them, C9).
    const custody = custodyErrors(signatures, i, maxI);
    if (!custody.length && i === maxI) custody.push(...envelopeErrors(sig, i, opts));
    let notChecked = false;
    if (custody.length) {
      level.custody = { ok: false, detail: custody.join('; ') };
      for (const text of custody) fail('fail', text);
    } else {
      level.custody = { ok: true, detail: i === 1 ? 'origin' : 'chain intact' };
    }
    // §14.8: recorded here, ranked last (C9): it never stops the crypto.
    if (badFrom.has(i)) {
      level.from = { ok: false };
      fail('fail', `FAIL: DKIM2-Signature i=${i} matching From is not authentic`);
    }
    if (!custody.length) {
      if (!sig.sets.some((ss) => SUPPORTED_ALGS.has(ss.alg))) {
        // §3.5 only lets us IGNORE unknown algorithms alongside a known one,
        // not accept a signature we cannot check at all (ranks with §14.5).
        fail('permerror', `PERMERROR: DKIM2-Signature i=${i} has no signature with a supported algorithm`);
      } else if (!walkOk || !chain.has(level.m)) {
        // The Message-Instances did not verify: nothing here is checked
        // against a key.
        notChecked = true;
      } else {
        await checkCrypto(sig, i, sig.sets, instances, signatures, fetchKey, level, fail);
      }
    }

    // §14.3 timestamps, against the current time (a pasted message has no
    // delivery time): more than 14 days old, or more than a day ahead, and
    // the message is not Validly Signed. Checked after the crypto so the
    // report still shows whether the signature itself verified.
    // t= is 1*DIGIT (checked above); 10^12 and beyond fit a double.
    if (!opts.skipTimestamp) {
      const t = parseInt(sig.map.t, 10);
      level.timestamp = { ok: true, detail: '' };
      if (now - t > MAX_AGE) {
        level.timestamp = { ok: false, status: 'expired', detail: `t= is ${Math.floor((now - t) / 86400)} days before now` };
        fail('fail', `FAIL: DKIM2-Signature i=${i} signature expired`);
      } else if (t - now > MAX_AHEAD) {
        level.timestamp = { ok: false, status: 'future', detail: `t= is ${Math.floor((t - now) / 3600)} hours after now` };
        fail('fail', `FAIL: DKIM2-Signature i=${i} signature is from the future`);
      }
    }

    level.result = notChecked && state === 'pass' ? 'not-checked' : state;
    level.detail = errors.join('; ')
      || (notChecked ? 'not checked: the Message-Instances do not match the message' : '');
    level.errors = errors;
  }

  // Every distinct error, in contract C9 order: the first is the PRIMARY
  // error, and its state is the result (never the "worst" state).
  const found = [];
  for (const i of sigNums) found.push(...sigLevels[i].errors);
  const errors = [...walkErrors, ...primaryFirst([...new Set(found)])];
  if (errors.length) return failed(errors, levelList());
  const nullNote = nullBodyAt !== null && nullBodyAt > 1
    ? `; body not checked below m=${nullBodyAt} (null body Recipe), header history verified` : '';
  return {
    overall: 'pass',
    summary: `i=1..${maxI} verified; Message-Instance m=1..${maxM} intact${nullNote}`,
    errors: [], levels: levelList(),
  };
}

// The report for a message that did not verify: errors in C9 order (the
// first is the primary error, and its state is the result).
function failed(errors, levels) {
  return { overall: stateOf(errors[0]), summary: errors.join('; '), errors, levels };
}

// levels, each one never checked given why in its detail.
function explain(levels, why) {
  for (const l of levels) if (l.result === 'not-checked' && !l.detail) l.detail = why;
  return levels;
}

// The result state an error string carries (§14.1: "STATE: text").
function stateOf(text) {
  return text.startsWith('FAIL: ') ? 'fail' : text.startsWith('TEMPERROR: ') ? 'temperror' : 'permerror';
}

// §14.2 structure (contract C9 steps a..h): what the field names and their
// m=/i= numbers alone decide, in exactly this order; the first that applies
// is the error, or null. b..e decide which fields are in the chain at all,
// so they come before the gaps and the coverage worked out from them.
function structureError(fields, miNums, sigNums) {
  const { instances, signatures, instanceErrors, signatureErrors, dupInstances, dupSignatures } = fields;
  // a. too many fields, unusable ones included: Message-Instance first;
  if (fields.miFields.length > MAX_CHAIN_LENGTH) return `PERMERROR: more than ${MAX_CHAIN_LENGTH} Message-Instance fields`;
  if (fields.sigFields.length > MAX_CHAIN_LENGTH) return `PERMERROR: more than ${MAX_CHAIN_LENGTH} DKIM2-Signature fields`;
  // b. a Message-Instance with no usable m=, the first top down;
  if (instanceErrors.length) return instanceErrors[0];
  // c. an m= given twice, the lowest;
  if (dupInstances.length) return `PERMERROR: Message-Instance m=${Math.min(...dupInstances)} appears more than once`;
  // d. a DKIM2-Signature with no usable i= (or an i=/m= out of range);
  if (signatureErrors.length) return signatureErrors[0];
  // e. an i= given twice, the lowest;
  if (dupSignatures.length) return `PERMERROR: DKIM2-Signature i=${Math.min(...dupSignatures)} appears more than once`;
  // f. a missing Message-Instance, from 1 up to the higher of the highest
  //    m= and the top signature's m= (a signed message has at least m=1);
  const sigM = (i) => (signatures[i].map.m === undefined ? 0 : parseInt(signatures[i].map.m, 10));
  const maxM = miNums.length ? miNums[miNums.length - 1] : 0;
  const maxI = sigNums.length ? sigNums[sigNums.length - 1] : 0;
  const upTo = Math.max(1, maxM, maxI ? sigM(maxI) : 0);
  for (let m = 1; m <= upTo; m++) if (!instances[m]) return `PERMERROR: Message-Instance m=${m} missing`;
  // g. the highest Message-Instance is covered by the m= of ANY signature,
  //    not only the top one (i= hop count and m= need not track together);
  if (!sigNums.some((i) => sigM(i) >= maxM)) return `PERMERROR: Message-Instance m=${maxM} is not signed`;
  // h. a missing DKIM2-Signature, the lowest.
  for (let i = 1; i <= maxI; i++) if (!signatures[i]) return `PERMERROR: DKIM2-Signature i=${i} missing`;
  return null;
}

// §14.2 for one Message-Instance on its own: its tag-list syntax (§8: a
// fragment that is not a well-formed tag, a tag given twice -- h= and H=
// included -- or an h= hash-set that is not name:digest:digest, §9.3),
// then its missing tags, then a duplicate hash algorithm, then its Recipe
// (base64, JSON, the §5 schema, "c" ranges ascending without overlap),
// whether or not the chain walk reaches it. Returns { sets } (the parsed
// h= hash-sets) or { error } (the PERMERROR text; recipe: it is the
// Recipe's).
function instanceContent(mi, m) {
  const who = `PERMERROR: Message-Instance m=${m}`;
  const hTag = mi.tags.find((t) => t.tag === 'h');
  let sets = null;
  if (hTag) { try { sets = parseHashSets(rawTagValue(hTag)); } catch (e) { /* syntax error */ } }
  if (mi.syntaxError || duplicateTag(mi.tags) || (hTag && !sets)) return { error: `${who} syntax error` };
  if (!hTag) return { error: `${who} tag=h missing` };
  // §9.3: an algorithm MUST NOT be present more than once, over the parsed
  // LIST (a map would silently drop the second occurrence).
  const algs = sets.map((s) => s.alg);
  if (new Set(algs).size !== algs.length) return { error: `${who} has a duplicate hash algorithm` };
  if ('r' in mi.map) {
    try {
      validateRecipeSteps(decodeRecipe(mi.map.r));
    } catch (e) {
      return { error: `${who} ${recipeErrorText(e)}`, recipe: true };
    }
  }
  return { sets };
}

// §14.2 for one DKIM2-Signature on its own: its tag-list syntax, then its
// missing or unexpected tags, then its tag values, then its s= (§10.9: the
// items parse, no Selector twice and no algorithm three times, every
// implemented item's value a base64string). Returns the PERMERROR text, or
// null with the decoded mf=/rt= (s.mf, s.rts) and s= items (s.sets) kept
// on the signature for the checks that follow.
function signatureContentError(s, i) {
  const who = `PERMERROR: DKIM2-Signature i=${i}`;
  if (s.syntaxError || duplicateTag(s.tags)) return `${who} syntax error`;
  for (const t of ['i', 'm', 't', 'd', 's']) if (!(t in s.map)) return `${who} tag=${t} missing`;
  // §10.7: an nd= signature has no mf= or rt=; any other has both.
  const hasNd = 'nd' in s.map;
  for (const t of ['mf', 'rt']) {
    if (hasNd && t in s.map) return `${who} tag=${t} was unexpected`;
    if (!hasNd && !(t in s.map)) return `${who} tag=${t} missing`;
  }
  // §10.4: t= is 1*DIGIT. Read the raw value: parseTagList strips internal
  // WSP, which would turn "12 34" into "1234".
  if (!/^[0-9]+$/.test(rawTagValue(s.tags.find((t) => t.tag === 't')))) return `${who} syntax error`;
  // §10.3: the n= nonce value MUST NOT exceed 64 characters.
  if ('n' in s.map && s.map.n.length > 64) return `${who} n= nonce exceeds 64 characters`;
  // §10.5/§10.6: mf= and each rt= are base64 of a path in angle brackets.
  if (!hasNd) {
    s.mf = decodePath(s.map.mf);
    s.rts = s.map.rt.split(',').map(decodePath);
    if (s.mf === null || s.rts.includes(null)) return `${who} syntax error`;
  }
  s.sets = parseSigSets(rawTagValue(s.tags.find((t) => t.tag === 's')));
  if (!s.sets) return `${who} syntax error`;
  const dupErrors = checkSignatureDuplicates(s.sets, i);
  if (dupErrors.length) return dupErrors[0];
  // §3.5: an item naming an algorithm we do not implement is ignored
  // entirely -- no key lookup, never verified. §10.9: every item we do
  // implement must carry a non-empty base64 signature.
  if (s.sets.some((ss) => SUPPORTED_ALGS.has(ss.alg) && !BASE64.test(ss.sig))) return `${who} syntax error`;
  return null;
}

// The report entry for one DKIM2-Signature, before any check of it.
function signatureLevel(sig, i) {
  return {
    kind: 'signature', i, m: sig.map.m === undefined ? null : parseInt(sig.map.m, 10),
    tags: sig.tags.map((t) => ({ tag: t.tag, value: t.value })),
    items: [], result: 'not-checked', detail: '', errors: [], // timestamp, custody: once checked
  };
}

// Recipe breakdown (§5/§9.2) for the report: decode r= and show what it
// changed -- a readable summary in the r= tag, the decoded Recipe JSON, and
// per-header current<-previous values (matching the /validate/ display).
function recipeBreakdown(mi, m, chain, level) {
  if (!('r' in mi.map)) return;
  let rec;
  try { rec = decodeRecipe(mi.map.r); } catch (e) { return; }
  const hasH = 'h' in rec;
  level.recipe = rec.b === null ? 'null' : (hasH || Array.isArray(rec.b)) ? 'diff' : 'none';
  level.body_recipe = rec.b === null ? 'null' : (Array.isArray(rec.b) ? 'diff' : 'none');
  level.recipe_json = rec;
  // Replace the raw base64 r= value in the tag grid with a readable summary.
  const rtag = level.tags.find((t) => t.tag === 'r');
  if (rtag) rtag.value = recipeSummary(rec);
  // Per-header current<-previous, only when the previous state exists.
  if (hasH && chain.has(m - 1)) {
    for (const name of Object.keys(rec.h).sort()) {
      const cur = displayText(chain.headerValues(m, name).join(' / '));
      const pre = displayText(chain.headerValues(m - 1, name).join(' / '));
      level.header_recipes.push({
        name,
        current: cur.length ? cur : '(absent)',
        previous: pre.length ? pre : '(absent)',
      });
    }
  }
}

// Contract C9, from §14.3 on: an error's place in -07 §14 order, as a key
// compared element by element. §14.3, §14.5, §14.6 and §14.8 (checks made
// per signature) go lowest i= first. §14.4 goes as C4 walks it: an
// unexpected top nd=, the envelope, then each signature S from i=1 up (S
// against the one below it, then S's own mf= against its d=). (§14.2 and
// §14.7 have each ended the verification before any of these is made.)
export function c9Key(text) {
  const num = (re) => { const m = re.exec(text); return m ? parseInt(m[1], 10) : 0; };
  const i = num(/\bi=(\d+)/);
  if (/ signature (?:expired|is from the future)$/.test(text)) return [3, i];
  if (/ unexpected nd= tag$/.test(text)) return [4, 0];
  if (/ (?:MAIL FROM|RCPT TO) .* did not match$/.test(text)) return [4, 1];
  if (/ nd= does not match$/.test(text)) return [4, 2, i + 1, 0];
  if (/ does not match the rt= of i=/.test(text)) return [4, 2, i, 0];
  if (/ MAIL FROM and d= do not match$/.test(text)) return [4, 2, i, 1];
  if (/ matching From is not authentic$/.test(text)) return [8, i];
  if (/^TEMPERROR: | public key | has no signature with a supported algorithm/.test(text)) return [5, i];
  if (/^FAIL: DKIM2-Signature /.test(text)) return [6, i];
  return [9];
}

// errors sorted into C9 order (stable: ties keep the order found).
function primaryFirst(errors) {
  const cmp = (a, b) => {
    for (let k = 0; k < Math.max(a.length, b.length); k++) {
      const d = (a[k] ?? 0) - (b[k] ?? 0);
      if (d) return d;
    }
    return 0;
  };
  return errors.map((text, n) => ({ text, n, key: c9Key(text) }))
    .sort((a, b) => cmp(a.key, b.key) || a.n - b.n)
    .map((e) => e.text);
}

// §14.5/§14.6: fetch the key for each sig-set of signature i and verify it,
// recording each in level.items and any error through fail(state, text).
async function checkCrypto(sig, i, sigSets, instances, signatures, fetchKey, level, fail) {
  // Signing input = MI 1..m then DKIM2-Signature 1..i (target blanked).
  // Build `ordered` from the actual parsed Field objects so the target
  // signature matches by REFERENCE inside signingInput() (which blanks s=
  // only for the element that is `=== sig.field`).
  const ordered = [];
  for (let m = 1; m <= level.m; m++) ordered.push(instances[m].field);
  for (let k = 1; k <= i; k++) ordered.push(signatures[k].field);
  const inputBytes = binaryToBytes(signingInput(ordered, sig.field));
  const inputHash = await sha256Bytes(inputBytes);

  // §3.5: only the items naming an algorithm we implement are checked
  // (signatureContentError has checked their values; the caller, that
  // there is at least one.)
  const known = sigSets.filter((ss) => SUPPORTED_ALGS.has(ss.alg));

  // An absent key (NXDOMAIN / no TXT) skips that item; a present but
  // unusable record (multiple, syntax, revoked, mismatch, too small) is a
  // PERMERROR for the whole signature even if another item verifies, and a
  // fetch failure a TEMPERROR. If every implemented item is absent, PERMERROR
  // naming the first absent one.
  const absent = [];
  let perm = null, temp = null, allPass = true;
  for (const ss of known) {
    let ok = false, detail = '';
    try {
      const key = await fetchKey(ss.selector, sig.map.d);
      const sigBytes = b64ToBytes(ss.sig);
      // §10.9/§14.5: the key must be of the algorithm's type (k= is case
      // significant; an unknown k= is never read as RSA).
      const want = ss.alg === 'ed25519-sha256' ? 'ed25519' : 'rsa';
      if (key.k !== want) throw new Error('key-mismatch');
      ok = ss.alg === 'ed25519-sha256'
        ? await verifyEd25519(key.p, sigBytes, inputHash)
        : await verifyRsa(key.p, sigBytes, inputBytes);
    } catch (e) {
      detail = keyErrorDetail(e, ss.selector);
      if (e.message === 'key-notfound') {
        absent.push(ss.selector);
        level.items.push({ selector: ss.selector, algorithm: ss.alg, result: detail, absent: true });
        continue;
      }
      if (e.message === 'key-temperror') temp = temp || detail;
      else if (e.message === 'ed25519-unsupported') detail = 'ed25519 unsupported in this browser';
      else if (['key-multiple', 'key-syntax', 'key-revoked', 'key-mismatch', 'key-malformed'].includes(e.message)) perm = perm || detail;
    }
    if (!ok) allPass = false;
    level.items.push({ selector: ss.selector, algorithm: ss.alg, result: ok ? 'pass' : (detail || 'fail') });
  }
  if (absent.length === known.length) return fail('permerror', `PERMERROR: DKIM2-Signature i=${i} public key ${absent[0]} does not exist`);
  if (allPass) return;
  if (perm) return fail('permerror', `PERMERROR: DKIM2-Signature i=${i} ${perm}`);
  if (temp) return fail('temperror', `TEMPERROR: DKIM2-Signature i=${i} ${temp}`);
  // §14.6: report the Selector(s) involved rather than the algorithm. When
  // some signatures pass and others fail, name both sides -- a Verifier that
  // can see the split is well placed to spot an attack on the weaker one.
  const passed = level.items.filter((it) => it.result === 'pass').map((it) => it.selector);
  const failed = level.items.filter((it) => it.result !== 'pass' && !it.absent).map((it) => it.selector);
  fail('fail', passed.length
    ? `FAIL: DKIM2-Signature i=${i} signature ${passed.join(', ')} signature ${failed.join(', ')} failed`
    : `FAIL: DKIM2-Signature i=${i} selector ${failed.join(', ')} incorrect signature`);
}


// The undo walk: rebuild the message state at each instance, top-down, by
// applying each Message-Instance's Recipe to the state above it (§5). The
// reference for planChain() (plan.js), which must give the same answers;
// opts.undoWalk selects it. body is the current body's octets (Uint8Array).
// Returns the chain interface verifyOnce() reads:
//  - undoBroken / undoBrokenReason: the m whose Recipe could not be undone
//    and its error text (recipeErrorText), or null; undoBrokenStage:
//    'decode' (the Recipe on its own is malformed) or 'apply' (it does not
//    fit the message: a copy past the end);
//  - nullBodyAt: the highest m with a null body Recipe; nullBodyInstances:
//    every such m;
//  - has(m): the state at m was reached; noBody(m): its body is gone;
//  - headerHash(m, alg) / bodyHash(m, alg): base64 §6 hashes of that state;
//  - headerValues(m, name): the trimmed values of a field, document order;
//  - checkBottom(recipe): dry-run the m=1 Recipe; throws as applyRecipe.
export function undoChain(headers, body, instances, maxM) {
  // state[m] = { fields, bodyLines } representing the message at instance m.
  const states = {};
  states[maxM] = { fields: headers.slice(), bodyLines: bodyToLines(bytesToBinary(body)) };
  const nullBodyInstances = new Set(); // every m whose body Recipe is null
  let nullBodyAt = null; // highest m whose body Recipe is null (§5.2)
  let undoBroken = null; // m at which undo became impossible
  let undoBrokenReason = null; // its error text (recipeErrorText)
  let undoBrokenStage = null; // 'decode': the Recipe on its own; 'apply': against the message
  for (let m = maxM; m >= 2; m--) {
    const mi = instances[m];
    // §9/§12.1: r= is optional; with no Recipes the previous instance is
    // this same message (a difference shows as a hash mismatch below).
    if (!('r' in mi.map)) { states[m - 1] = { ...states[m] }; continue; }
    let recipe;
    try {
      recipe = decodeRecipe(mi.map.r);
      validateRecipeSteps(recipe);
    } catch (e) {
      undoBroken = m;
      undoBrokenReason = recipeErrorText(e);
      undoBrokenStage = 'decode';
      break;
    }
    try {
      // decodeRecipe() has checked the §5 schema.
      if (states[m].noBody) {
        // Below a null body Recipe the body is gone: apply the header Recipe
        // only and carry on.
        validateBodyRecipe(recipe.b); // "c" order still checked; body not applied
        states[m - 1] = { fields: 'h' in recipe ? applyHeaderRecipe(states[m].fields, recipe.h) : states[m].fields, bodyLines: states[m].bodyLines, noBody: true };
        if (recipe.b === null) nullBodyInstances.add(m);
      } else if (recipe.b === null) {
        // §5.2 null "b": the previous body cannot be recreated, but the
        // header Recipe is mandatory and the header history is still
        // checkable. Sticky: every lower instance is header-hash-only.
        states[m - 1] = { fields: 'h' in recipe ? applyHeaderRecipe(states[m].fields, recipe.h) : states[m].fields, bodyLines: states[m].bodyLines, noBody: true };
        nullBodyInstances.add(m);
        if (nullBodyAt === null) nullBodyAt = m;
      } else {
        states[m - 1] = applyRecipe(recipe, states[m]);
      }
    } catch (e) {
      undoBroken = m;
      undoBrokenReason = recipeErrorText(e);
      undoBrokenStage = 'apply';
      break;
    }
  }
  const hdrBytes = {};
  return {
    undoBroken, undoBrokenReason, undoBrokenStage, nullBodyAt, nullBodyInstances,
    has: (m) => !!states[m],
    noBody: (m) => !!states[m].noBody,
    headerHash(m, alg) {
      if (!hdrBytes[m]) hdrBytes[m] = binaryToBytes(canonHeaderHash(signedFields(states[m].fields)));
      return hashB64(hdrBytes[m], alg);
    },
    bodyHash: (m, alg) => hashB64(binaryToBytes(canonBody(linesToBody(states[m].bodyLines))), alg),
    headerValues: (m, name) => headerValues(states[m].fields, name),
    checkBottom: (recipe) => { applyRecipe(recipe, states[1]); },
  };
}

// Start the DoH lookup of every distinct selector._domainkey.domain the
// DKIM2-Signatures name for an algorithm we implement, all at once, and
// return a fetchKey(selector, domain) that answers from them. A prefetched
// answer that is definitive (a key, NXDOMAIN, no TXT record, an unusable
// record) is used as it is; anything else (a timeout, SERVFAIL, a network
// error) is looked up again the ordinary way, so every verdict is what it
// would have been without the prefetch.
// At most PREFETCH_MAX lookups are started, top signature first; a key
// not prefetched is looked up the ordinary way if it is ever needed.
const PREFETCH_MAX = 8;
function prefetchKeys(signatures, sigNums, dohOpts) {
  const pending = new Map();
  for (const i of sigNums.slice().reverse()) {
    const sig = signatures[i];
    const sTag = sig.tags.find((t) => t.tag === 's');
    const sets = sTag && parseSigSets(rawTagValue(sTag));
    if (!sets || sig.map.d === undefined) continue;
    for (const ss of sets) {
      if (!SUPPORTED_ALGS.has(ss.alg)) continue;
      const name = keyName(ss.selector, sig.map.d);
      if (pending.has(name)) continue;
      if (pending.size >= PREFETCH_MAX) break;
      // Settled into an outcome, so an unawaited failure is never unhandled.
      pending.set(name, dohFetchKey(ss.selector, sig.map.d, dohOpts)
        .then((key) => ({ key }), (err) => ({ err })));
    }
  }
  return async (selector, domain) => {
    const p = pending.get(keyName(selector, domain));
    if (p) {
      const { key, err } = await p;
      if (!err) return key;
      if (err instanceof Error && DEFINITIVE_KEY_ERRORS.has(err.message)) throw err;
    }
    return dohFetchKey(selector, domain, dohOpts);
  };
}

// §14.5 wording, naming the Selector.
function keyErrorDetail(e, selector) {
  const map = {
    'key-notfound': 'does not exist',
    'key-multiple': 'has multiple records',
    'key-syntax': 'has a syntax error',
    'key-revoked': 'has been revoked',
    'key-mismatch': 'algorithm mismatch',
    'key-malformed': 'is malformed',
    'key-temperror': 'could not be fetched',
  };
  return e.message in map ? `public key ${selector} ${map[e.message]}` : String(e.message || e);
}

// §14.4 / §7.1 item 1: the Chain of Custody errors for signature i (empty
// when it holds). Against the signature P below it:
//  - after an nd= signature, d= must be exactly P's nd= (§12.3), and nothing
//    else is compared;
//  - an nd= signature, or one with mf=<>, must have its d= relaxed-matched
//    by a domain in P's rt= (rt= is Parameter1, d= Parameter2);
//  - otherwise mf= must relaxed-match a domain in P's rt= (mf= Parameter1).
// Then every signature with a non-null mf= relaxed-matches its d= (§7.1
// item 2). An nd= on the top signature is unexpected: inbound, there is no next
// signature to carry it (§12.3's out-of-band case is a signer's concern).
function custodyErrors(signatures, i, maxI) {
  const S = signatures[i];
  const d = sigDomain(S);
  const errs = [];
  const hasNd = 'nd' in S.map;
  if (hasNd && i === maxI) errs.push(`FAIL: DKIM2-Signature i=${i} unexpected nd= tag`);
  const nullMf = !hasNd && S.mf === '<>';
  if (i > 1) {
    const P = signatures[i - 1];
    if ('nd' in P.map) {
      if (d !== P.map.nd.toLowerCase()) errs.push(`FAIL: DKIM2-Signature i=${i - 1} nd= does not match`);
    } else if (hasNd || nullMf) {
      if (!P.rts.some((r) => relaxedMatch(addrDomain(r), d))) {
        errs.push(`FAIL: DKIM2-Signature i=${i} d= does not match the rt= of i=${i - 1}`);
      }
    } else if (!P.rts.some((r) => relaxedMatch(addrDomain(S.mf), addrDomain(r)))) {
      errs.push(`FAIL: DKIM2-Signature i=${i} mf= does not match the rt= of i=${i - 1}`);
    }
  }
  // S's own mf= against its d=, after S against P (the order C4 walks).
  if (!hasNd && !nullMf && !relaxedMatch(addrDomain(S.mf), d)) {
    errs.push(`FAIL: DKIM2-Signature i=${i} MAIL FROM and d= do not match`);
  }
  return errs;
}

// Normalize an envelope address for the §14.4 EXACT comparison: strip one
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

// §14.4: the actual delivery MAIL FROM / RCPT TO MUST EXACTLY match (NOT the
// relaxed algorithm) the mf=/rt= of the highest-numbered DKIM2-Signature;
// only the domain is lower-cased. Applies only when the caller supplies the
// real envelope (opts.mailFrom + opts.rcptTo); the browser paste case has no
// envelope and skips this check. An nd= signature (no mf=/rt=, and already
// an error on top) and an empty '<>' reverse-path skip the MAIL FROM
// comparison.
function envelopeErrors(sig, i, opts) {
  const mailFrom = opts.mailFrom;
  const rcptTo = opts.rcptTo;
  if (typeof mailFrom !== 'string' || !Array.isArray(rcptTo) || rcptTo.length === 0) return [];
  if ('nd' in sig.map) return [];
  if (sig.mf !== '<>' && normalizeAddr(sig.mf) !== normalizeAddr(mailFrom)) {
    return [`FAIL: DKIM2-Signature i=${i} MAIL FROM ${mailFrom} did not match`];
  }
  const rtNorm = sig.rts.map(normalizeAddr);
  for (const rcpt of rcptTo) {
    if (!rtNorm.includes(normalizeAddr(rcpt))) {
      return [`FAIL: DKIM2-Signature i=${i} RCPT TO ${rcpt} did not match`];
    }
  }
  return [];
}
