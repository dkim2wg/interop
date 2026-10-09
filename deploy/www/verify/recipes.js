// Recipe application (undo) per spec-06 §5 and §7.2, plus the "b" step
// (base64 literal) proposed as an extension to §5.
import { b64ToBytes, b64ToString, bytesToBinary, textToBinary } from './b64.js';

// A Recipe that decodes to JSON but violates §5: a "c" range that is out of
// bounds, not ascending or overlapping, a literal carrying CR/LF, a "b" item
// that is not base64, an unknown step... §11.2 wants Recipe errors called
// out specifically, so this is its own class: verify.js reports it as
// "PERMERROR Message-Instance m=<N> has a malformed Recipe".
export class MalformedRecipe extends Error {
  constructor(message) {
    super(message);
    this.name = 'MalformedRecipe';
  }
}

// The first key named twice in one object of `text` (already known to be
// valid JSON), compared after unescaping, or null.
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
      const k = JSON.parse(t);
      if (top.has(k)) return k;
      top.add(k);
      wantKey = false;
    }
    if (re.lastIndex >= text.length) break;
  }
  return null;
}

// A key named twice in one object is invalid JSON here (a SyntaxError, as
// from JSON.parse): parsers disagree on which value wins, so
// {"b":[...],"b":null} would be a null body Recipe to some verifiers and a
// real one to others.
export function decodeRecipe(rB64) {
  const text = b64ToString(rB64);
  const obj = JSON.parse(text);
  const dup = jsonDuplicateKey(text);
  if (dup !== null) throw new SyntaxError(`duplicate JSON object key ${JSON.stringify(dup)}`);
  return obj;
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

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// Canonical RFC 4648 §4 base64: the standard alphabet, "=" padding present,
// length a multiple of 4. b64ToBytes() strips whitespace and atob() accepts
// unpadded input, so both are checked here first.
const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
function isCanonicalB64(s) {
  return typeof s === 'string' && B64_RE.test(s) && s.length % 4 === 0;
}

// A "b" item: the raw octets of a line/value, base64 in the JSON string (for
// values that are not representable as JSON text: Latin-1, EUC-KR, bytes
// that are not UTF-8). Decoded to a binary string, exactly what textToBinary
// gives for a "d" item.
function decodeBItem(item, where) {
  if (!isCanonicalB64(item)) throw new MalformedRecipe(`${where}: "b" item is not canonical base64`);
  let bytes;
  try {
    bytes = b64ToBytes(item);
  } catch (e) {
    throw new MalformedRecipe(`${where}: "b" item is not base64`);
  }
  const bin = bytesToBinary(bytes);
  if (/[\r\n]/.test(bin)) throw new MalformedRecipe(`${where}: "b" item contains CR or LF`);
  return bin;
}

function decodeDItem(item, where) {
  if (typeof item !== 'string') throw new MalformedRecipe(`${where}: "d" item is not a string`);
  // §5.1/§5.2: the text strings MUST NOT contain CR or LF characters.
  if (/[\r\n]/.test(item)) throw new MalformedRecipe(`${where}: "d" item contains CR or LF`);
  return textToBinary(item);
}

// Walk one step list against `count` current items (header field instances
// of one name, or body lines) and yield what it emits, in Recipe order:
// {copy: n} for item number n (1-based) or {literal: binaryString}.
// Validates as it goes (§5, extended):
//  - a step is an object with exactly one key, "c", "d" or "b";
//  - "c" is exactly two integers, 1 <= start <= end <= count, and each
//    start is greater than the end of every preceding "c" step;
//  - "d" and "b" arrays are non-empty (schema minItems 1); "d" items are
//    strings without CR/LF; "b" items canonical base64 of octets without
//    CR/LF.
function* walkSteps(steps, count, where, structuralOnly = false) {
  if (!Array.isArray(steps)) throw new MalformedRecipe(`${where}: steps are not an array`);
  let prevEnd = 0;
  for (const step of steps) {
    if (!isPlainObject(step)) throw new MalformedRecipe(`${where}: step is not an object`);
    const keys = Object.keys(step);
    if (keys.length !== 1) throw new MalformedRecipe(`${where}: step must have exactly one key`);
    const kind = keys[0];
    if (kind === 'c') {
      const c = step.c;
      if (!Array.isArray(c) || c.length !== 2 || !Number.isInteger(c[0]) || !Number.isInteger(c[1])) {
        throw new MalformedRecipe(`${where}: "c" is not [start, end] integers`);
      }
      const [start, end] = c;
      if (start < 1 || end < start || (!structuralOnly && end > count)) {
        throw new MalformedRecipe(`${where}: "c" range [${start}, ${end}] is outside 1..${count}`);
      }
      if (start <= prevEnd) {
        throw new MalformedRecipe(`${where}: "c" range [${start}, ${end}] does not follow the previous copy (ended at ${prevEnd})`);
      }
      if (!structuralOnly) for (let n = start; n <= end; n++) yield { copy: n };
      prevEnd = end;
    } else if (kind === 'd') {
      if (!Array.isArray(step.d) || step.d.length === 0) throw new MalformedRecipe(`${where}: "d" is not a non-empty array`);
      for (const item of step.d) yield { literal: decodeDItem(item, where) };
    } else if (kind === 'b') {
      if (!Array.isArray(step.b) || step.b.length === 0) throw new MalformedRecipe(`${where}: "b" is not a non-empty array`);
      for (const item of step.b) yield { literal: decodeBItem(item, where) };
    } else {
      throw new MalformedRecipe(`${where}: unknown step "${kind}"`);
    }
  }
}

// Structural check of a body Recipe ("b": null, or valid steps) without a
// body to apply it to: used below a null body Recipe, where the body is gone
// but a malformed Recipe is still a malformed Recipe. Bounds against the
// (absent) body are not checked; everything else is.
export function validateBodyRecipe(b) {
  if (b === undefined || b === null) return;
  if (!Array.isArray(b)) throw new MalformedRecipe('"b" is neither steps nor null');
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
export function applyHeaderRecipe(fields, hObj) {
  if (!isPlainObject(hObj)) throw new MalformedRecipe('"h" is not an object');

  // Group current fields by lowercased name, preserving document order.
  const byName = new Map();
  for (const f of fields) {
    const n = f.name.toLowerCase();
    if (!byName.has(n)) byName.set(n, []);
    byName.get(n).push(f);
  }

  // Normalize Recipe keys to lowercase.
  const recipe = {};
  for (const k of Object.keys(hObj)) recipe[k.toLowerCase()] = hObj[k];

  for (const name of Object.keys(recipe)) {
    const steps = recipe[name];
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
  for (const n of Object.keys(recipe)) if (!seen.includes(n)) seen.push(n);

  const out = [];
  for (const n of seen) for (const f of (byName.get(n) || [])) out.push(f);
  return out;
}

// Apply a whole decoded Recipe to a message state {fields, bodyLines} and
// return the previous state. The caller decides what a null "b" (§5.2
// redaction) means; here it leaves the body alone. Throws MalformedRecipe
// when the Recipe is not a §5 object or any step is invalid.
export function applyRecipe(recipe, state) {
  if (!isPlainObject(recipe)) throw new MalformedRecipe('Recipe is not a JSON object');
  if (!('h' in recipe) && !('b' in recipe)) throw new MalformedRecipe('Recipe has neither "h" nor "b"');
  let { fields, bodyLines } = state;
  if ('h' in recipe) fields = applyHeaderRecipe(state.fields, recipe.h);
  if (Array.isArray(recipe.b)) bodyLines = applyBodyRecipe(state.bodyLines, recipe.b);
  else if (recipe.b !== undefined && recipe.b !== null) throw new MalformedRecipe('"b" is neither steps nor null');
  return { fields, bodyLines };
}
