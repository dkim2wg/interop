// Recipe application (undo) per spec-05 §5 and §7.2.
import { b64ToString } from './b64.js';

export function decodeRecipe(rB64) {
  return JSON.parse(b64ToString(rB64));
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

// §5.2: body lines numbered top-down from 1.
export function applyBodyRecipe(curLines, steps) {
  const out = [];
  for (const step of steps) {
    if ('c' in step) {
      const [s, e] = step.c;
      for (let n = s; n <= e; n++) out.push(curLines[n - 1]);
    } else if ('d' in step) {
      for (const line of step.d) out.push(line);
    }
  }
  return out;
}

// §5.1: header fields numbered bottom-up (last instance of a name = #1).
export function applyHeaderRecipe(fields, hObj) {
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
    for (const step of steps) {
      if ('c' in step) {
        const [s, e] = step.c;
        for (let num = s; num <= e; num++) emitted.push(bottomUp[num - 1]);
      } else if ('d' in step) {
        for (const val of step.d) {
          // `name` here is the lowercased Recipe key; `raw` is a synthesized,
          // space-less approximation. Both are harmless: canon/parse always
          // lowercase name and never read raw.
          emitted.push({ name, value: val, raw: name + ':' + val + '\r\n' });
        }
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
