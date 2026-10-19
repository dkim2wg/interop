// RFC5322 message parsing and DKIM2 tag-value parsing. Built from spec-06.
import { bytesToBinary } from './b64.js';

function toCRLF(raw) {
  return raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\n/g, '\r\n');
}

// The number of LFs in `u8` when every line end in it is already a CRLF
// (every CR followed by LF, every LF preceded by CR), else -1. Four octets
// at a time: a word with no CR or LF in it (most of them) is passed over
// whole, by the "has a zero byte" test on the word XOR each.
export function crlfCount(u8) {
  const n = u8.length;
  let lfs = 0;
  // 1 for a CRLF's LF, 0 for an octet that is no line end, -1 for a bare one.
  const at = (i) => {
    const b = u8[i];
    if (b === 10) return i > 0 && u8[i - 1] === 13 ? 1 : -1;
    if (b === 13) return u8[i + 1] === 10 ? 0 : -1;
    return 0;
  };
  let i = 0;
  const head = Math.min(n, (4 - (u8.byteOffset & 3)) & 3);
  for (; i < head; i++) { const r = at(i); if (r < 0) return -1; lfs += r; }
  const words = (n - i) >> 2;
  const w32 = words ? new Uint32Array(u8.buffer, u8.byteOffset + i, words) : null;
  for (let k = 0; k < words; k++) {
    const w = w32[k];
    const lf = w ^ 0x0a0a0a0a, cr = w ^ 0x0d0d0d0d;
    if ((((lf - 0x01010101) & ~lf) | ((cr - 0x01010101) & ~cr)) & 0x80808080) {
      for (let p = i + (k << 2), e = p + 4; p < e; p++) { const r = at(p); if (r < 0) return -1; lfs += r; }
    }
  }
  for (i += words << 2; i < n; i++) { const r = at(i); if (r < 0) return -1; lfs += r; }
  return lfs;
}

// Every line end a CRLF, as toCRLF() makes them, in octets: the octets
// themselves (no copy) when they already are, as in nearly all mail;
// otherwise a normalized copy. With the number of LFs in them.
function crlfOctets(u8) {
  const count = crlfCount(u8);
  if (count >= 0) return { oct: u8, lfs: count };
  const n = u8.length;
  const out = new Uint8Array(n * 2);
  let o = 0, lfs = 0;
  for (let i = 0; i < n; i++) {
    const b = u8[i];
    if (b === 13) {
      out[o++] = 13; out[o++] = 10; lfs++;
      if (u8[i + 1] === 10) i++;
    } else if (b === 10) {
      out[o++] = 13; out[o++] = 10; lfs++;
    } else {
      out[o++] = b;
    }
  }
  return { oct: out.subarray(0, o), lfs };
}

// Field = { name: string, value: string, raw: string }
// `raw` is the full folded field text including its terminating CRLF.
// `value` is the unfolded value: each physical line's own trailing CRLF is
// stripped during continuation handling, so no literal `\r\n` ever survives
// in `value` — only the fold-boundary whitespace (the continuation line's
// leading WSP) remains. No leading colon, no trailing CRLF. Use `raw` if you
// need the literal folded bytes.
//
// raw is a binary string (body: a binary string) or a Uint8Array of the
// message octets (body: a Uint8Array, a view into them when their line ends
// are already CRLF, and lines: the number of lines bodyToLines() would give
// for it). Only the header block is ever made a string: the body goes from
// input to digest as octets.
export function parseMessage(raw) {
  if (typeof raw !== 'string') {
    const { oct, lfs } = crlfOctets(raw);
    let sep = -1;
    for (let i = oct.indexOf(13); i >= 0; i = oct.indexOf(13, i + 1)) {
      if (oct[i + 1] === 10 && oct[i + 2] === 13 && oct[i + 3] === 10) { sep = i; break; }
    }
    if (sep < 0) return { headers: parseHeaderBlock(bytesToBinary(oct)), body: oct.subarray(0, 0), lines: 0 };
    let bodyLfs = lfs;
    for (let i = 0; i < sep + 4; i++) if (oct[i] === 10) bodyLfs--;
    const body = oct.subarray(sep + 4);
    const lines = body.length === 0 || body[body.length - 1] === 10 ? bodyLfs : bodyLfs + 1;
    return { headers: parseHeaderBlock(bytesToBinary(oct.subarray(0, sep + 2))), body, lines };
  }
  const text = toCRLF(raw);
  const sep = text.indexOf('\r\n\r\n');
  const headerBlock = sep < 0 ? text : text.slice(0, sep + 2); // include final CRLF
  const body = sep < 0 ? '' : text.slice(sep + 4);
  return { headers: parseHeaderBlock(headerBlock), body };
}

function parseHeaderBlock(headerBlock) {
  // Split header block into physical lines (each ends with CRLF).
  const physical = headerBlock.match(/[^\r\n]*\r\n/g) || [];
  const headers = [];
  for (const line of physical) {
    if (/^[ \t]/.test(line) && headers.length) {
      // Continuation of the previous field.
      const prev = headers[headers.length - 1];
      prev.raw += line;
      prev.value += line.replace(/\r\n$/, '');
    } else {
      const m = line.match(/^([^:]*):([\s\S]*)\r\n$/);
      if (!m) continue; // not a valid header line; skip
      headers.push({ name: m[1].trim(), value: m[2], raw: line });
    }
  }
  return headers;
}

// spec-06 §7, §8 x-tag: `[FWS] name [FWS] "=" [FWS] [value] [FWS]`, name
// ALPHA *(ALPHA / DIGIT / "_"), value x-tag-char *([FWS] x-tag-char) with
// x-tag-char %x21-3A / %x3C-7E. The value is unfolded, so FWS is WSP here.
const TAG_SPEC = /^[ \t\r\n]*[A-Za-z][A-Za-z0-9_]*[ \t\r\n]*=[ \t\r\n]*(?:[\x21-\x3a\x3c-\x7e](?:[ \t\r\n]*[\x21-\x3a\x3c-\x7e])*)?[ \t\r\n]*$/;

// syntaxError is set when any non-empty fragment is not a well-formed tag
// (`junk`, `9bad=foo`, `=v`, a NUL/DEL/8-bit byte in any value): the whole
// field is then a syntax error (§11.2), never verified around the fragment.
export function parseTagList(value) {
  // value is a header value as produced by parseMessage: fold CRLFs are
  // already stripped, so this only needs to guard against a literal \r\n
  // reaching us directly (e.g. from `raw`). Semicolons only ever separate
  // tags (spec §7/§8).
  const flat = value.replace(/\r\n/g, ''); // drop folding
  const tags = [];
  const map = {};
  let syntaxError = false;
  for (const seg of flat.split(';')) {
    if (/^[ \t\r\n]*$/.test(seg)) continue;
    if (!TAG_SPEC.test(seg)) syntaxError = true;
    const eq = seg.indexOf('=');
    if (eq < 0) continue;
    const name = seg.slice(0, eq).trim().toLowerCase();
    // DKIM2 tag values are base64 / tokens / digits / domains and never carry
    // significant internal whitespace; any WSP present came from header folding
    // (FWS). Strip ALL whitespace so a value split across continuation lines —
    // e.g. a base64 h= hash or s= signature folded mid-token — is reassembled
    // intact. Leaving embedded fold WSP breaks hash-string comparison (the
    // folded-list-message verifier bug).
    const val = seg.slice(eq + 1).replace(/[ \t\r\n]/g, '');
    tags.push({ tag: name, value: val, raw: seg });
    if (!(name in map)) map[name] = val;
  }
  return { tags, map, syntaxError };
}

// spec-06 §7.3: h= is hash-set *("," hash-set). Hash names are lowercased —
// RFC 5234 makes ABNF quoted strings case-insensitive. h is the RAW value
// (FWS intact): FWS is allowed around the hash name and colons and inside
// the digests (removed), never inside the hash name. A set that is not
// exactly name:digest:digest, with both digests present, throws
// Error('h-syntax') -- never skipped.
export function parseHashSets(h) {
  const out = [];
  for (const item of (h || '').split(',')) {
    const parts = item.split(':');
    if (parts.length !== 3) throw new Error('h-syntax');
    const alg = parts[0].replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');
    const headerHash = parts[1].replace(/[ \t\r\n]+/g, '');
    const bodyHash = parts[2].replace(/[ \t\r\n]+/g, '');
    if (!/^[A-Za-z0-9_-]+$/.test(alg) || !headerHash || !bodyHash) throw new Error('h-syntax');
    out.push({ alg: alg.toLowerCase(), headerHash, bodyHash });
  }
  return out;
}

function isName(field, name) {
  return field.name.toLowerCase() === name;
}

// Every i= and m= names one hop, and a chain has at most this many.
export const MAX_CHAIN_LENGTH = 32;
// The largest number an i= or m= may be written as (at most three digits).
// Anything bigger is out of range before it is ever a chain number.
export const MAX_CHAIN_NUMBER = 100;

// The PERMERROR summary for an i= or m= value that is not a chain number, or
// null. A value must be 1*DIGIT (ASCII): parseInt would take the digit prefix
// of "4294967297x" and run the 1..max loops to it; anything else is a syntax
// error of the field (named by its own i=, or m= for a Message-Instance:
// `id`, the raw value). Then at most three digits and 1..MAX_CHAIN_NUMBER
// (so "01" and "001" are 1), and no more than MAX_CHAIN_LENGTH: local
// limits, with no -07 string of their own. A missing value (undefined) is
// left to the callers.
export function chainNumberError(field, tag, v, id = v) {
  if (v === undefined) return null;
  const malformed = `PERMERROR: ${field} ${field === 'Message-Instance' ? 'm' : 'i'}=${id} syntax error`;
  if (typeof v !== 'string' || !/^[0-9]+$/.test(v)) return malformed;
  if (/^0+$/.test(v)) return malformed;
  if (v.length > 3 || parseInt(v, 10) > MAX_CHAIN_NUMBER) {
    return `PERMERROR: ${field} ${tag}= exceeds the maximum chain number of ${MAX_CHAIN_NUMBER}`;
  }
  if (parseInt(v, 10) > MAX_CHAIN_LENGTH) {
    return `PERMERROR: ${field} ${tag}= exceeds the maximum chain length of ${MAX_CHAIN_LENGTH}`;
  }
  return null;
}

export function collectLevels(headers) {
  const instances = {};
  const signatures = {};
  const miFields = [];
  const sigFields = [];
  const dupInstances = [];
  const dupSignatures = [];
  // The i= values ('' when missing) of DKIM2-Signature fields whose i= is
  // missing or not a positive integer in ASCII digits: no verifier can place
  // or key one, so verifyOnce() reports a syntax error rather than verifying
  // around it.
  const unkeyableSignatures = [];
  // The first i= or m= that is not a chain number (chainNumberError), as a
  // PERMERROR summary; such a field is not placed in instances/signatures,
  // so nothing loops up to it.
  let rangeError = null;
  for (const f of headers) {
    if (isName(f, 'message-instance')) {
      miFields.push(f);
      const parsed = parseTagList(f.value);
      const err = chainNumberError('Message-Instance', 'm', parsed.map.m);
      if (err) { rangeError = rangeError || err; continue; }
      const m = parseInt(parsed.map.m, 10);
      if (!Number.isNaN(m) && instances[m]) dupInstances.push(m);
      if (!Number.isNaN(m)) instances[m] = { field: f, tags: parsed.tags, map: parsed.map, syntaxError: parsed.syntaxError };
    } else if (isName(f, 'dkim2-signature')) {
      sigFields.push(f);
      const parsed = parseTagList(f.value);
      const iv = parsed.map.i;
      const i = /^[0-9]+$/.test(iv || '') ? parseInt(iv, 10) : NaN;
      if (Number.isNaN(i) || i < 1) { unkeyableSignatures.push(iv || ''); continue; }
      const err = chainNumberError('DKIM2-Signature', 'i', iv)
               || chainNumberError('DKIM2-Signature', 'm', parsed.map.m, iv);
      if (err) { rangeError = rangeError || err; continue; }
      if (signatures[i]) dupSignatures.push(i);
      signatures[i] = { field: f, tags: parsed.tags, map: parsed.map, syntaxError: parsed.syntaxError };
    }
  }
  return { instances, signatures, miFields, sigFields, dupInstances, dupSignatures,
           unkeyableSignatures, rangeError };
}
