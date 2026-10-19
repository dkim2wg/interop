// Recipe application (undo) per draft-ietf-dkim-dkim2-spec-07 §5 and §9.2.
import { b64ToBytes, b64ToString, bytesToBinary, textToBinary } from './b64.js';

// A Recipe that is valid JSON but not one this message's previous state can
// be recreated from: what the §5 schema does not allow (not an object,
// neither "h" nor "b", an empty "h", a step that is not exactly one of "c",
// "d" or "u", a "c" that is not two integers of at least 1, an empty "d"/"u"
// array, a "d" string with CR/LF or a lone surrogate, a "u" string that is
// not canonical base64 or decodes to CR/LF), and a "c" range that ends
// before it starts, does not follow the previous copy, or runs past the
// fields/lines there are. verify.js reports it as "PERMERROR:
// Message-Instance m=<N> contains invalid JSON", the same as a JSON syntax
// error or a duplicate key.
export class InvalidRecipe extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidRecipe';
  }
}

// The first key named twice in one object of `text` (already known to be
// valid JSON), compared after unescaping and without regard to case (keys
// are matched case-insensitively, so "Subject" and "subject" are the same
// key), or null.
export function jsonDuplicateKey(text) {
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
    else if (t[0] === '"' && wantKey && top instanceof Set) {
      const k = JSON.parse(t).toLowerCase();
      if (top.has(k)) return k;
      top.add(k);
      wantKey = false;
    }
    if (re.lastIndex >= text.length) break;
  }
  return null;
}

export function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// A copy of a plain object with its keys lowercased (no two can collide:
// jsonDuplicateKey has already refused that). Defined, never assigned, so a
// "__proto__" key stays an ordinary key.
function lowerKeys(o) {
  const out = {};
  for (const k of Object.keys(o)) {
    Object.defineProperty(out, k.toLowerCase(), { value: o[k], enumerable: true, writable: true, configurable: true });
  }
  return out;
}

// Keys are matched without regard to case at every level a Recipe defines
// (the top-level "h"/"b", header names inside "h", and the "c"/"d"/"u" step
// keys): lowercase them all once, here, so nothing downstream sees "H" or
// "Subject".
function normalizeRecipe(rec) {
  if (!isPlainObject(rec)) return rec;
  const steps = (s) => (Array.isArray(s) ? s.map((st) => (isPlainObject(st) ? lowerKeys(st) : st)) : s);
  const r = lowerKeys(rec);
  if (isPlainObject(r.h)) {
    const h = lowerKeys(r.h);
    for (const k of Object.keys(h)) h[k] = steps(h[k]);
    r.h = h;
  }
  if ('b' in r) r.b = steps(r.b);
  return r;
}

// Decode an r= value: base64 (a failure is a DOMException from atob), JSON
// (a SyntaxError), no duplicate keys (a SyntaxError: parsers disagree on
// which value wins, so {"b":[...],"b":null} would be a null body Recipe to
// some verifiers and a real one to others), keys lowercased, and the whole
// §5 schema checked (InvalidRecipe).
export function decodeRecipe(rB64) {
  const text = b64ToString(rB64);
  const obj = JSON.parse(text);
  const dup = jsonDuplicateKey(text);
  if (dup !== null) throw new SyntaxError(`duplicate JSON object key ${JSON.stringify(dup)}`);
  const rec = normalizeRecipe(obj);
  validateRecipe(rec);
  return rec;
}

// The §5 schema, for a decoded (key-normalized) Recipe. Throws InvalidRecipe.
export function validateRecipe(rec) {
  if (!isPlainObject(rec)) throw new InvalidRecipe('Recipe is not a JSON object');
  if (!('h' in rec) && !('b' in rec)) throw new InvalidRecipe('Recipe has neither "h" nor "b"');
  if ('h' in rec) {
    if (!isPlainObject(rec.h)) throw new InvalidRecipe('"h" is not an object');
    const names = Object.keys(rec.h);
    if (names.length === 0) throw new InvalidRecipe('"h" names no header field');
    for (const name of names) checkSteps(rec.h[name], `header "${name}"`);
  }
  if ('b' in rec && rec.b !== null) checkSteps(rec.b, 'body');
}

function checkSteps(steps, where) {
  if (!Array.isArray(steps)) throw new InvalidRecipe(`${where}: steps are not an array`);
  for (const step of steps) decodeStep(step, where);
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
function decodeUItem(item, where) {
  if (typeof item !== 'string' || !U_PATTERNS.every((re) => re.test(item))) {
    throw new InvalidRecipe(`${where}: "u" item is not canonical base64`);
  }
  const bin = bytesToBinary(b64ToBytes(item));
  if (/[\r\n]/.test(bin)) throw new InvalidRecipe(`${where}: "u" item contains CR or LF`);
  return bin;
}

// A lone surrogate: a JSON string can spell one ("\udce9"), but it is not a
// character, so a string holding one is not UTF-8 text.
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

function decodeDItem(item, where) {
  if (typeof item !== 'string') throw new InvalidRecipe(`${where}: "d" item is not a string`);
  // §5: the strings MUST NOT contain CR or LF characters.
  if (/[\r\n]/.test(item)) throw new InvalidRecipe(`${where}: "d" item contains CR or LF`);
  if (LONE_SURROGATE.test(item)) throw new InvalidRecipe(`${where}: "d" item is not UTF-8 text`);
  return textToBinary(item);
}

// One step, checked against the schema: { c: [start, end] } or
// { literals: [binaryString...] }. Throws InvalidRecipe.
function decodeStep(step, where) {
  if (!isPlainObject(step)) throw new InvalidRecipe(`${where}: step is not an object`);
  const keys = Object.keys(step);
  if (keys.length !== 1) throw new InvalidRecipe(`${where}: step must have exactly one key`);
  const kind = keys[0];
  if (kind === 'c') {
    const c = step.c;
    if (!Array.isArray(c) || c.length !== 2 || !c.every((n) => Number.isInteger(n) && n >= 1)) {
      throw new InvalidRecipe(`${where}: "c" is not [start, end] integers of at least 1`);
    }
    return { c };
  }
  if (kind === 'd' || kind === 'u') {
    const items = step[kind];
    if (!Array.isArray(items) || items.length === 0) throw new InvalidRecipe(`${where}: "${kind}" is not a non-empty array`);
    const decode = kind === 'd' ? decodeDItem : decodeUItem;
    return { literals: items.map((item) => decode(item, where)) };
  }
  throw new InvalidRecipe(`${where}: unknown step "${kind}"`);
}

// Walk one step list against `count` current items (header field instances
// of one name, or body lines) and yield what it emits, in Recipe order, a
// range at a time: {range: [start, end]} for items start..end (1-based) or
// {literal: binaryString}. Each step is checked against the schema
// (decodeStep), then each "c" range must have start <= end <= count, and
// start after the end of every preceding "c" step. Throws InvalidRecipe.
// The undo walk below expands ranges item by item (walkSteps); the planned
// walk (plan.js) takes them whole. Both see the same checks in the same
// order, so a Recipe is invalid to one exactly when it is to the other.
export function* walkRanges(steps, count, where, structuralOnly = false) {
  if (!Array.isArray(steps)) throw new InvalidRecipe(`${where}: steps are not an array`);
  let prevEnd = 0;
  for (const step of steps) {
    const s = decodeStep(step, where);
    if (s.literals) {
      for (const literal of s.literals) yield { literal };
      continue;
    }
    const [start, end] = s.c;
    if (end < start || (!structuralOnly && end > count)) {
      throw new InvalidRecipe(`${where}: "c" range [${start}, ${end}] is outside 1..${count}`);
    }
    if (start <= prevEnd) {
      throw new InvalidRecipe(`${where}: "c" range [${start}, ${end}] does not follow the previous copy (ended at ${prevEnd})`);
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
  for (const _ of walkSteps(b, Infinity, 'body', true)) { /* validate only */ }
}

// §5.2: body lines numbered top-down from 1.
export function applyBodyRecipe(curLines, steps) {
  const out = [];
  for (const item of walkSteps(steps, curLines.length, 'body')) {
    out.push('copy' in item ? curLines[item.copy - 1] : item.literal);
  }
  return out;
}

// §5.1: header fields numbered bottom-up (last instance of a name = #1).
// Recipe keys are header names, matched without regard to case
// (decodeRecipe has already refused two that differ only in case).
export function applyHeaderRecipe(fields, hObj) {
  if (!isPlainObject(hObj)) throw new InvalidRecipe('"h" is not an object');

  // Group current fields by lowercased name, preserving document order.
  const byName = new Map();
  for (const f of fields) {
    const n = f.name.toLowerCase();
    if (!byName.has(n)) byName.set(n, []);
    byName.get(n).push(f);
  }

  const names = Object.keys(hObj).map((k) => [k.toLowerCase(), hObj[k]]);
  for (const [name, steps] of names) {
    const cur = byName.get(name) || [];
    const bottomUp = cur.slice().reverse(); // index0 = last in doc = #1
    const emitted = []; // processing order == bottom-up order of reconstruction
    for (const item of walkSteps(steps, bottomUp.length, `header "${name}"`)) {
      if ('copy' in item) {
        emitted.push(bottomUp[item.copy - 1]);
      } else {
        // `name` here is the lowercased Recipe key; `raw` is a synthesized,
        // space-less approximation. Both are harmless: canon/parse always
        // lowercase name and never read raw. The literal is already a binary
        // string (see b64.js), like the rest of the message.
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
// when the Recipe is not a §5 object, a step is invalid, or a "c" range
// does not fit.
export function applyRecipe(recipe, state) {
  if (!isPlainObject(recipe)) throw new InvalidRecipe('Recipe is not a JSON object');
  if (!('h' in recipe) && !('b' in recipe)) throw new InvalidRecipe('Recipe has neither "h" nor "b"');
  let { fields, bodyLines } = state;
  if ('h' in recipe) fields = applyHeaderRecipe(state.fields, recipe.h);
  if (Array.isArray(recipe.b)) bodyLines = applyBodyRecipe(state.bodyLines, recipe.b);
  else if (recipe.b !== undefined && recipe.b !== null) throw new InvalidRecipe('"b" is neither steps nor null');
  return { fields, bodyLines };
}

// §14.2: classify a Recipe failure, so that Recipe errors are called out
// specifically:
//  - a bad base64 r= value (atob throws, typically DOMException) is a
//    "syntax error" in the Message-Instance -- the payload never even
//    reached JSON parsing;
//  - a JSON.parse failure or a duplicate key (SyntaxError), or a Recipe the
//    §5 schema does not allow or whose "c" ranges do not fit the message
//    (InvalidRecipe), "contains invalid JSON".
// Anything else is a generic, non-specific failure to undo.
export function classifyRecipeDecodeError(e) {
  if (e instanceof InvalidRecipe || e instanceof SyntaxError) return 'invalid-json';
  if (e instanceof DOMException) return 'syntax-error';
  return 'broken';
}
