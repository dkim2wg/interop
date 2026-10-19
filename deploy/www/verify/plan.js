// The planned chain walk: every Message-Instance's §6 hash inputs worked out
// from the current message and the Recipes (§5), without rebuilding any
// previous message. Gives exactly what the undo walk (undoChain() in
// verify.js, the reference) gives: the same hashes, the same Recipe errors at
// the same instance, the same header values for the report.
//
// Body: each instance's body is a list of segments, [BODY, from, to] (a run
// of lines of the current body, 1-based) or [LIT, from, to] (a run of entries
// in one shared table of Recipe literal lines). The top instance is the whole
// current body. Walking down, a body Recipe's copy ranges are resolved
// against the list above (they ascend, so one forward pointer) and its
// literals become LIT segments. An instance with no body Recipe shares the
// list above it, and so its digests. The body stays octets from input to
// digest (never a string, never split into lines). A list that comes down to
// one run of the body is digested as a view into it, with no copy; only a
// list of several pieces is assembled, once (WebCrypto's digest is
// one-shot), from views into the body octets and the literals.
//
// Headers: field values are grouped by lowercased name once; each instance
// holds, per name, the values bottom-up (as Recipes number them). Unchanged
// names share their list and its canonical text, and a value is
// canonicalized only if its name is in the header hash.
import { walkRanges, walkSteps, decodeRecipe, classifyRecipeDecodeError,
         validateBodyRecipe, validateRecipeSteps, isPlainObject } from './recipes.js';
import { hashLine, isUnsignedHeader } from './canon.js';
import { hashB64 } from './crypto.js';
import { binaryToBytes } from './b64.js';
import { crlfCount } from './parse.js';

const BODY = 0;
const LIT = 1;
const CRLF = new Uint8Array([13, 10]);
const NO_FIELDS = [];

// Field names that are in the §6.2 header hash (as signedFields() in
// verify.js: the §4 names out, and Message-Instance / DKIM2-Signature).
function hashedName(name) {
  return !isUnsignedHeader(name) && name !== 'message-instance' && name !== 'dkim2-signature';
}

// Number of lines bodyToLines() would give for the body octets (CRLF line
// ends only: parseMessage() has already made every line end a CRLF; an
// unterminated last line still counts). parseMessage() gives this as
// `lines`, counted in the pass that checks the line ends.
function countLines(body) {
  const len = body.length;
  if (len === 0) return 0;
  const n = crlfCount(body);
  return body[len - 1] === 10 ? n : n + 1;
}

// Length of `u8` without its trailing CRLF pairs.
function trimCRLF(u8) {
  let e = u8.length;
  while (e >= 2 && u8[e - 2] === 13 && u8[e - 1] === 10) e -= 2;
  return e;
}

// A Recipe whose header part names Message-Instance: undoing it changes the
// Message-Instance fields the lower levels see, which the undo walk handles
// by rebuilding them. The planned walk leaves such a message to it.
function namesMessageInstance(instances, maxM) {
  for (let m = maxM; m >= 1; m--) {
    const mi = instances[m];
    if (!mi || !('r' in mi.map)) continue;
    let rec;
    try { rec = decodeRecipe(mi.map.r); } catch (e) { continue; }
    if (isPlainObject(rec) && isPlainObject(rec.h)
        && Object.keys(rec.h).some((k) => k.toLowerCase() === 'message-instance')) return true;
  }
  return false;
}

// planChain(headers, body, instances, maxM, nLines): body is the current
// body's octets and nLines its line count (parseMessage()'s `body` and
// `lines` for octets; counted here if not given). Returns the chain
// interface documented at undoChain() in verify.js, or null when this
// message is left to the undo walk (a header Recipe naming
// Message-Instance).
export function planChain(headers, body, instances, maxM, nLines = countLines(body)) {
  if (namesMessageInstance(instances, maxM)) return null;

  const literals = []; // shared literal-line table (binary strings)

  // --- headers: name -> values bottom-up; each value an entry {name, value}
  // whose canonical line is computed at most once.
  const topFields = new Map();
  for (let k = headers.length - 1; k >= 0; k--) {
    const f = headers[k];
    const n = f.name.toLowerCase();
    if (!topFields.has(n)) topFields.set(n, []);
    topFields.get(n).push({ name: n, value: f.value });
  }

  // §5.1 header Recipe, exactly as applyHeaderRecipe(): keys matched as
  // lowercase names (decodeRecipe has refused two differing only in case),
  // applied in key order. Returns the new name map and whether any name in
  // the header hash changed.
  function applyHeaders(fields, hObj) {
    const out = new Map(fields);
    let hashedChanged = false;
    for (const key of Object.keys(hObj)) {
      const name = key.toLowerCase();
      const cur = fields.get(name) || NO_FIELDS;
      const emitted = [];
      for (const item of walkSteps(hObj[key], cur.length, `header "${name}"`)) {
        emitted.push('copy' in item ? cur[item.copy - 1] : { name, value: item.literal });
      }
      out.set(name, emitted);
      if (hashedName(name)) hashedChanged = true;
    }
    return { fields: out, hashedChanged };
  }

  // --- body lists: { segs: [[kind, from, to]...], count }
  function pushSeg(segs, kind, from, to) {
    const last = segs[segs.length - 1];
    if (last && last[0] === kind && last[2] + 1 === from) last[2] = to;
    else segs.push([kind, from, to]);
  }

  // §5.2 body Recipe over `parent`, exactly as applyBodyRecipe() over the
  // parent's lines: the same steps validated in the same order, bounds
  // against the parent's line count.
  function composeBody(parent, steps) {
    const segs = [];
    let count = 0;
    let pi = 0; // parent segment holding the next line
    let pBase = 0; // parent lines before segment pi
    for (const item of walkRanges(steps, parent.count, 'body')) {
      if ('literal' in item) {
        literals.push(item.literal);
        pushSeg(segs, LIT, literals.length - 1, literals.length - 1);
        count++;
        continue;
      }
      let [s, e] = item.range;
      count += e - s + 1;
      for (;;) {
        const seg = parent.segs[pi];
        const len = seg[2] - seg[1] + 1;
        if (s > pBase + len) { pBase += len; pi++; continue; }
        const from = seg[1] + (s - pBase - 1);
        const take = Math.min(e, pBase + len) - s + 1;
        pushSeg(segs, seg[0], from, from + take - 1);
        s += take;
        if (s > e) break;
      }
    }
    return { segs, count };
  }

  // --- walk the instances top-down
  const top = { fields: topFields, hdr: {}, body: { segs: nLines ? [[BODY, 1, nLines]] : [], count: nLines }, noBody: false };
  const states = { [maxM]: top };
  const nullBodyInstances = new Set();
  let nullBodyAt = null;
  let undoBroken = null;
  let undoBrokenReason = null;
  let undoBrokenStage = null; // 'decode': the Recipe on its own; 'apply': against the message
  for (let m = maxM; m >= 2; m--) {
    const mi = instances[m];
    const cur = states[m];
    // §9/§12.1: r= is optional; with no Recipes the previous instance is
    // this same message, sharing its header and body digests.
    if (!('r' in mi.map)) { states[m - 1] = cur; continue; }
    let recipe;
    try {
      recipe = decodeRecipe(mi.map.r);
      validateRecipeSteps(recipe);
    } catch (e) {
      undoBroken = m;
      undoBrokenReason = classifyRecipeDecodeError(e);
      undoBrokenStage = 'decode';
      break;
    }
    try {
      let next;
      const withHeaders = (st) => {
        if (!('h' in recipe)) return { ...st, fields: cur.fields, hdr: cur.hdr };
        const { fields, hashedChanged } = applyHeaders(cur.fields, recipe.h);
        return { ...st, fields, hdr: hashedChanged ? {} : cur.hdr };
      };
      // decodeRecipe() has checked the §5 schema: an object with "h" and/or
      // "b", body Recipe steps or null.
      if (cur.noBody) {
        // Below a null body Recipe: "c" order checked, header Recipe applied.
        validateBodyRecipe(recipe.b);
        next = withHeaders({ body: cur.body, noBody: true });
        if (recipe.b === null) nullBodyInstances.add(m);
      } else if (recipe.b === null) {
        // §5.2 null "b": the body above is the last one there is (kept for
        // the bounds of an m=1 Recipe, as the undo walk keeps its lines).
        next = withHeaders({ body: cur.body, noBody: true });
        nullBodyInstances.add(m);
        if (nullBodyAt === null) nullBodyAt = m;
      } else {
        // As applyRecipe(): header Recipe, then body Recipe.
        next = withHeaders({ body: cur.body, noBody: false });
        if (Array.isArray(recipe.b)) next.body = composeBody(cur.body, recipe.b);
      }
      states[m - 1] = next;
    } catch (e) {
      undoBroken = m;
      undoBrokenReason = classifyRecipeDecodeError(e);
      undoBrokenStage = 'apply';
      break;
    }
  }

  // --- header hash input: names in hash order, values bottom-up.
  const nameText = new WeakMap(); // value list -> canonical text
  function headerBytes(st) {
    if (!st.hdr.bytes) {
      let text = '';
      for (const name of [...st.fields.keys()].filter(hashedName).sort()) {
        const list = st.fields.get(name);
        let t = nameText.get(list);
        if (t === undefined) {
          t = '';
          for (const entry of list) {
            if (entry.line === undefined) entry.line = hashLine(entry);
            t += entry.line;
          }
          nameText.set(list, t);
        }
        text += t;
      }
      st.hdr.bytes = binaryToBytes(text);
      st.hdr.digests = {};
    }
    return st.hdr;
  }

  // --- body hash input. On the first request, one pass over the body finds
  // the octet offset of every line a segment starts or ends at, for every
  // list still to be hashed: lines in the first half forwards from the top,
  // the rest backwards from the end (a wrapped original ends a few lines
  // short of it). A list's input is its pieces: views into the body octets,
  // literal lines and CRLFs.
  let lineAt = null; // line number -> octet offset of its start
  const terminated = body.length === 0 || body[body.length - 1] === 10;
  function locateLines() {
    const want = new Set();
    for (const st of Object.values(states)) {
      if (st.noBody) continue;
      for (const [kind, from, to] of st.body.segs) if (kind === BODY) { want.add(from); want.add(to + 1); }
    }
    const ks = [...want].sort((a, b) => a - b);
    lineAt = new Map();
    let line = 1, pos = 0; // forwards: pos is the start of `line`
    let j = 0;
    for (; j < ks.length && ks[j] <= nLines / 2; j++) {
      while (line < ks[j]) { while (body[pos++] !== 10); line++; }
      lineAt.set(ks[j], pos);
    }
    // backwards: likewise, from just after the last line (the CRLF an
    // unterminated one is hashed with counted in)
    line = nLines + 1; pos = terminated ? body.length : body.length + 2;
    for (let i = ks.length - 1; i >= j; i--) {
      const k = Math.min(ks[i], nLines + 1);
      // back over the CRLF ending line - 1, then to just after the LF before
      while (line > k) { pos -= 2; while (pos > 0 && body[pos - 1] !== 10) pos--; line--; }
      lineAt.set(ks[i], Math.min(pos, body.length));
    }
  }
  const literalBytes = new Map();
  function bodyInput(list) {
    if (list.input) return list.input;
    if (!lineAt) locateLines();
    const parts = [];
    for (const [kind, from, to] of list.segs) {
      if (kind === BODY) {
        parts.push(body.subarray(lineAt.get(from), lineAt.get(to + 1)));
        if (to === nLines && !terminated) parts.push(CRLF);
      } else {
        for (let k = from; k <= to; k++) {
          if (!literalBytes.has(k)) literalBytes.set(k, binaryToBytes(literals[k]));
          parts.push(literalBytes.get(k), CRLF);
        }
      }
    }
    // §6.1: trailing empty lines go; the body ends with exactly one CRLF.
    // Only a literal line or an unterminated last line can end without a
    // CRLF, and a CRLF piece always follows either, so no CRLF pair spans
    // two pieces: trim piece by piece from the end, then cut the last piece
    // left just after its first trimmed CRLF (still a view), or add a CRLF.
    while (parts.length) {
      const last = parts[parts.length - 1];
      const e = trimCRLF(last);
      if (e === 0) { parts.pop(); continue; }
      if (e < last.length) parts[parts.length - 1] = last.subarray(0, e + 2);
      else parts.push(CRLF);
      break;
    }
    if (parts.length <= 1) list.input = parts.length ? parts[0] : CRLF;
    else {
      let total = 0;
      for (const p of parts) total += p.length;
      const buf = new Uint8Array(total);
      let off = 0;
      for (const p of parts) { buf.set(p, off); off += p.length; }
      list.input = buf;
    }
    list.digests = {};
    return list.input;
  }

  return {
    undoBroken, undoBrokenReason, undoBrokenStage, nullBodyAt, nullBodyInstances,
    has: (m) => !!states[m],
    noBody: (m) => states[m].noBody,
    headerHash(m, alg) {
      const hdr = headerBytes(states[m]);
      if (!hdr.digests[alg]) hdr.digests[alg] = hashB64(hdr.bytes, alg);
      return hdr.digests[alg];
    },
    bodyHash(m, alg) {
      const list = states[m].body;
      const input = bodyInput(list);
      if (!list.digests[alg]) list.digests[alg] = hashB64(input, alg);
      return list.digests[alg];
    },
    headerValues: (m, name) => (states[m].fields.get(name.toLowerCase()) || NO_FIELDS)
      .map((entry) => entry.value.trim()).reverse(),
    // The (decoded) m=1 Recipe, dry-run as applyRecipe() does against the
    // m=1 state.
    checkBottom(recipe) {
      const st = states[1];
      if ('h' in recipe) applyHeaders(st.fields, recipe.h);
      if (Array.isArray(recipe.b)) { for (const _ of walkRanges(recipe.b, st.body.count, 'body')) { /* validate only */ } }
    },
  };
}
