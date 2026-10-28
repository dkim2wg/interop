// Recipe application (undo) per draft-ietf-dkim-dkim2-spec-08 §5 and §9.2.
import { b64ToBytes, bytesToBinary, textToBinary } from './b64.js';

// A Recipe that is valid JSON but not one this message's previous state can
// be recreated from, as a whole document (-08 contract D6): not an object,
// neither "h" nor "b", "h" not a non-empty object, "b" neither an array nor
// null; and a "c" range that runs past the fields/lines there are, which
// only applying the Recipe finds. verify.js reports it as "PERMERROR:
// Message-Instance m=<N> contains invalid JSON", the same as a JSON syntax
// error, a duplicate or uppercase key, a number with a fraction or an
// exponent, or a lone surrogate (SyntaxErrors).
export class InvalidRecipe extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidRecipe';
  }
}

// One step that the §5 schema or §5.1/§5.2 refuses (contract D6), reported
// as "Recipe <path> is invalid": path is b[<n>] or h.<name>[<n>] (the
// step's 0-based index), or h.<name> for a header entry that is not an
// array.
export class InvalidStep extends InvalidRecipe {
  constructor(path, message) {
    super(`${path}: ${message}`);
    this.name = 'InvalidStep';
    this.path = path;
  }
}

// A lone surrogate: a JSON string can spell one ("\udce9"), but it is not a
// character, so a string holding one is not UTF-8 text.
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

// The first whole-document fault in `text` (already known to be valid JSON)
// that JSON.parse lets through, or null (contract D6, D10):
//  - a key named twice in one object, compared exactly after unescaping;
//  - a key, at any level, holding an ASCII capital A-Z (non-ASCII letters
//    are not judged);
//  - a number with a fraction or an exponent, wherever it is ("1e0": JSON
//    libraries disagree on whether that is an integer, so the text decides);
//  - a string, key or value, holding a lone surrogate ("\udc80").
export function jsonDocumentError(text) {
  const stack = []; // per open container: a Set of keys (object) or null (array)
  let wantKey = false;
  const re = /\s+|[{}[\],:]|"(?:[^"\\]|\\.)*"|[^\s,:[\]{}"]+/gy;
  let m;
  while ((m = re.exec(text)) !== null) {
    const t = m[0];
    const top = stack[stack.length - 1];
    if (t === '{') { stack.push(new Set()); wantKey = true; }
    else if (t === '[') { stack.push(null); wantKey = false; }
    else if (t === '}' || t === ']') { stack.pop(); wantKey = false; }
    else if (t === ',') { wantKey = top instanceof Set; }
    else if (t[0] === '"') {
      const str = JSON.parse(t);
      if (LONE_SURROGATE.test(str)) return 'a string holds a lone surrogate';
      if (wantKey && top instanceof Set) {
        if (/[A-Z]/.test(str)) return `key ${JSON.stringify(str)} is not lowercase`;
        if (top.has(str)) return `duplicate JSON object key ${JSON.stringify(str)}`;
        top.add(str);
        wantKey = false;
      }
    } else if (/^[-0-9]/.test(t) && /[.eE]/.test(t)) {
      return `number ${t} is not an integer`;
    }
    if (re.lastIndex >= text.length) break;
  }
  return null;
}

export function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// Recipe text is UTF-8: octets that are not are invalid JSON (D10). A BOM
// is kept, for JSON.parse to refuse.
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

// Decode an r= value: base64 (a failure is a DOMException from atob), UTF-8
// and JSON (a SyntaxError), then every whole-document check
// (jsonDocumentError, a SyntaxError; validateRecipe, an InvalidRecipe).
// Duplicate keys matter because parsers disagree on which value wins, so
// {"b":[...],"b":null} would be a null body Recipe to some verifiers and a
// real one to others. The steps are validateRecipeSteps()'s: every
// whole-document check comes before any step check (D6).
export function decodeRecipe(rB64) {
  const bytes = b64ToBytes(rB64);
  let text;
  try { text = utf8.decode(bytes); } catch (e) { throw new SyntaxError('Recipe is not UTF-8'); }
  const rec = JSON.parse(text);
  const fault = jsonDocumentError(text);
  if (fault !== null) throw new SyntaxError(fault);
  validateRecipe(rec);
  return rec;
}

// The §5 schema for a decoded Recipe as a whole document. Throws
// InvalidRecipe.
export function validateRecipe(rec) {
  if (!isPlainObject(rec)) throw new InvalidRecipe('Recipe is not a JSON object');
  if (!('h' in rec) && !('b' in rec)) throw new InvalidRecipe('Recipe has neither "h" nor "b"');
  if ('h' in rec) {
    if (!isPlainObject(rec.h)) throw new InvalidRecipe('"h" is not an object');
    if (Object.keys(rec.h).length === 0) throw new InvalidRecipe('"h" names no header field');
  }
  if ('b' in rec && rec.b !== null && !Array.isArray(rec.b)) throw new InvalidRecipe('"b" is neither steps nor null');
}

// The path of a header Recipe (D6): "h." and the JSON key exactly as given,
// with every octet of its UTF-8 outside 0x21-0x7E written as \xHH.
export function headerPath(name) {
  let out = 'h.';
  for (const b of new TextEncoder().encode(name)) {
    out += b >= 0x21 && b <= 0x7e ? String.fromCharCode(b) : `\\x${b.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return out;
}

// The header names of a Recipe's "h", in the byte order of their UTF-8
// (D6: the first invalid step is reported, "b" first, then "h" by name).
function headerNamesInOrder(h) {
  const enc = new TextEncoder();
  const cmp = (a, b) => {
    const x = enc.encode(a), y = enc.encode(b);
    for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
    return x.length - y.length;
  };
  return Object.keys(h).sort(cmp);
}

export function bodyToLines(body) {
  if (body === '') return [];
  const parts = body.split('\r\n');
  if (parts[parts.length - 1] === '' && body.endsWith('\r\n')) parts.pop();
  return parts;
}

export function linesToBody(lines) {
  return lines.map((l) => l + '\r\n').join('');
}

// The three patterns the §5 schema gives a "base64-line": the alphabet with
// "=" padding only at the end, a multiple of four characters, and zero pad
// bits (the character before "==" or "=" may carry no stray bits, so "QR=="
// is not canonical; "QQ==" is).
const U_PATTERNS = [
  /^[A-Za-z0-9+/]*={0,2}$/,
  /^(?:.{4})*$/,
  /^(?:[^=]*|.*[AQgw]==|.*[AEIMQUYcgkosw048]=)$/,
];

// A "u" item: the raw octets of a line/value, base64 in the JSON string (for
// values that are not valid UTF-8: Latin-1, EUC-KR, any stray byte).
// Decoded to a binary string, exactly what textToBinary gives for a "d" item.
function decodeUItem(item, path) {
  if (typeof item !== 'string' || !U_PATTERNS.every((re) => re.test(item))) {
    throw new InvalidStep(path, '"u" item is not canonical base64');
  }
  const bin = bytesToBinary(b64ToBytes(item));
  if (/[\r\n]/.test(bin)) throw new InvalidStep(path, '"u" item contains CR or LF');
  return bin;
}

function decodeDItem(item, path) {
  if (typeof item !== 'string') throw new InvalidStep(path, '"d" item is not a string');
  // §5: the strings MUST NOT contain CR or LF characters.
  if (/[\r\n]/.test(item)) throw new InvalidStep(path, '"d" item contains CR or LF');
  // (A lone surrogate is a whole-document fault, refused by decodeRecipe.)
  if (LONE_SURROGATE.test(item)) throw new InvalidStep(path, '"d" item is not UTF-8 text');
  return textToBinary(item);
}

// One step (path: its b[<n>] / h.<name>[<n>]), checked against the schema:
// { c: [start, end] } or { literals: [binaryString...] }. Throws InvalidStep.
function decodeStep(step, path) {
  if (!isPlainObject(step)) throw new InvalidStep(path, 'step is not an object');
  const keys = Object.keys(step);
  if (keys.length !== 1) throw new InvalidStep(path, 'step must have exactly one key');
  const kind = keys[0];
  if (kind === 'c') {
    const c = step.c;
    if (!Array.isArray(c) || c.length !== 2 || !c.every((n) => Number.isInteger(n) && n >= 1)) {
      throw new InvalidStep(path, '"c" is not [start, end] integers of at least 1');
    }
    if (c[1] < c[0]) throw new InvalidStep(path, `"c" range [${c[0]}, ${c[1]}] ends before it starts`);
    return { c };
  }
  if (kind === 'd' || kind === 'u') {
    const items = step[kind];
    if (!Array.isArray(items) || items.length === 0) throw new InvalidStep(path, `"${kind}" is not a non-empty array`);
    const decode = kind === 'd' ? decodeDItem : decodeUItem;
    return { literals: items.map((item) => decode(item, path)) };
  }
  throw new InvalidStep(path, `unknown step "${kind}"`);
}

// Walk one step list (at `where`: "b", or headerPath(name)) against `count`
// current items (header field instances of one name, or body lines) and
// yield what it emits, in Recipe order, a range at a time: {range: [start,
// end]} for items start..end (1-based) or {literal: binaryString}. Each step
// is checked against the schema (decodeStep), and each "c" range must start
// after the end of every preceding "c" step (InvalidStep); then it must end
// by `count` (InvalidRecipe: the Recipe does not fit the message). The undo
// walk below expands ranges item by item (walkSteps); the planned walk
// (plan.js) takes them whole. Both see the same checks in the same order,
// so a Recipe is invalid to one exactly when it is to the other.
export function* walkRanges(steps, count, where, structuralOnly = false) {
  if (!Array.isArray(steps)) throw new InvalidStep(where, 'steps are not an array');
  let prevEnd = 0;
  for (let n = 0; n < steps.length; n++) {
    const path = `${where}[${n}]`;
    const s = decodeStep(steps[n], path);
    if (s.literals) {
      for (const literal of s.literals) yield { literal };
      continue;
    }
    const [start, end] = s.c;
    if (start <= prevEnd) {
      throw new InvalidStep(path, `"c" range [${start}, ${end}] does not follow the previous copy (ended at ${prevEnd})`);
    }
    if (!structuralOnly && end > count) {
      throw new InvalidRecipe(`${path}: "c" range [${start}, ${end}] is outside 1..${count}`);
    }
    if (!structuralOnly) yield { range: [start, end] };
    prevEnd = end;
  }
}

// walkRanges, one item at a time: {copy: n} for item number n (1-based) or
// {literal: binaryString}.
export function* walkSteps(steps, count, where, structuralOnly = false) {
  for (const item of walkRanges(steps, count, where, structuralOnly)) {
    if ('range' in item) for (let n = item.range[0]; n <= item.range[1]; n++) yield { copy: n };
    else yield item;
  }
}

// Structural check of a body Recipe ("b": null, or valid steps) without a
// body to apply it to: used below a null body Recipe, where the body is gone
// but an invalid Recipe is still an invalid Recipe. Bounds against the
// (absent) body are not checked; everything else is.
export function validateBodyRecipe(b) {
  if (b === undefined || b === null) return;
  if (!Array.isArray(b)) throw new InvalidRecipe('"b" is neither steps nor null');
  for (const _ of walkSteps(b, Infinity, 'b', true)) { /* validate only */ }
}

// The message-independent step rules (§5: every step well formed, "c"
// ranges ascending and not overlapping) for every step list of a decoded
// Recipe, "b" first, then "h" by name in byte order, each in step order
// (D6). Only a range past the end of the items a message actually has is
// left for applying it to find.
export function validateRecipeSteps(rec) {
  validateBodyRecipe(rec.b);
  if ('h' in rec) {
    for (const name of headerNamesInOrder(rec.h)) {
      for (const _ of walkSteps(rec.h[name], Infinity, headerPath(name), true)) { /* validate only */ }
    }
  }
}

// §5.2: body lines numbered top-down from 1.
export function applyBodyRecipe(curLines, steps) {
  const out = [];
  for (const item of walkSteps(steps, curLines.length, 'b')) {
    out.push('copy' in item ? curLines[item.copy - 1] : item.literal);
  }
  return out;
}

// §5.1: header fields numbered bottom-up (last instance of a name = #1).
// Recipe keys are lowercase header names (decodeRecipe has refused any
// other), matched against the field names lowercased.
export function applyHeaderRecipe(fields, hObj) {
  if (!isPlainObject(hObj)) throw new InvalidRecipe('"h" is not an object');

  // Group current fields by lowercased name, preserving document order.
  const byName = new Map();
  for (const f of fields) {
    const n = f.name.toLowerCase();
    if (!byName.has(n)) byName.set(n, []);
    byName.get(n).push(f);
  }

  const names = Object.keys(hObj).map((k) => [k, hObj[k]]);
  for (const [name, steps] of names) {
    const cur = byName.get(name) || [];
    const bottomUp = cur.slice().reverse(); // index0 = last in doc = #1
    const emitted = []; // processing order == bottom-up order of reconstruction
    for (const item of walkSteps(steps, bottomUp.length, headerPath(name))) {
      if ('copy' in item) {
        emitted.push(bottomUp[item.copy - 1]);
      } else {
        // `name` here is the Recipe key; `raw` is a synthesized, space-less
        // approximation. Both are harmless: canon/parse always lowercase
        // name and never read raw. The literal is already a binary string
        // (see b64.js), like the rest of the message.
        const val = item.literal;
        emitted.push({ name, value: val, raw: name + ':' + val + '\r\n' });
      }
    }
    // Reconstructed doc order (top->bottom) is the reverse of bottom-up.
    byName.set(name, emitted.slice().reverse());
  }

  // Flatten back to a doc-order list. Inter-name position is irrelevant to the
  // header hash (which sorts), so preserve first-seen name order; append names
  // introduced by the Recipe.
  const seen = [];
  for (const f of fields) {
    const n = f.name.toLowerCase();
    if (!seen.includes(n)) seen.push(n);
  }
  for (const [n] of names) if (!seen.includes(n)) seen.push(n);

  const out = [];
  for (const n of seen) for (const f of (byName.get(n) || [])) out.push(f);
  return out;
}

// Apply a whole decoded Recipe to a message state {fields, bodyLines} and
// return the previous state. The caller decides what a null "b" (§5.2
// redaction) means; here it leaves the body alone. Throws InvalidRecipe
// when the Recipe is not a §5 object or a "c" range does not fit, and
// InvalidStep when a step is invalid.
export function applyRecipe(recipe, state) {
  if (!isPlainObject(recipe)) throw new InvalidRecipe('Recipe is not a JSON object');
  if (!('h' in recipe) && !('b' in recipe)) throw new InvalidRecipe('Recipe has neither "h" nor "b"');
  let { fields, bodyLines } = state;
  if ('h' in recipe) fields = applyHeaderRecipe(state.fields, recipe.h);
  if (Array.isArray(recipe.b)) bodyLines = applyBodyRecipe(state.bodyLines, recipe.b);
  else if (recipe.b !== undefined && recipe.b !== null) throw new InvalidRecipe('"b" is neither steps nor null');
  return { fields, bodyLines };
}

// §14.2: the error text (after "Message-Instance m=<x> ") for a Recipe
// failure, so that Recipe errors are called out specifically:
//  - a bad base64 r= value (atob throws, typically DOMException) is a
//    "syntax error" in the Message-Instance -- the payload never even
//    reached JSON parsing;
//  - one invalid step (InvalidStep): "Recipe <path> is invalid" (-08 D6);
//  - a JSON.parse failure or any other whole-document fault (SyntaxError),
//    a Recipe the §5 schema does not allow as a document, or whose "c"
//    ranges do not fit the message (InvalidRecipe): "contains invalid JSON".
// Anything else is a generic, non-specific failure to undo.
export function recipeErrorText(e) {
  if (e instanceof InvalidStep) return `Recipe ${e.path} is invalid`;
  if (e instanceof InvalidRecipe || e instanceof SyntaxError) return 'contains invalid JSON';
  if (e instanceof DOMException) return 'syntax error';
  return 'previous instance cannot be recreated';
}
