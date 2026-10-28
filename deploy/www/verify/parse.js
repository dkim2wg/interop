// RFC5322 message parsing and DKIM2 tag-value parsing. Built from draft-ietf-dkim-dkim2-spec-08.
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

// §8 tag-spec: `[FWS] name [FWS] "=" [FWS] [value] [FWS]`, name
// ALPHA *(ALPHA / DIGIT / "_"), value x-tag-char *([FWS] x-tag-char) with
// x-tag-char %x21-3A / %x3C-7E. The value is unfolded, so FWS is WSP here.
const TAG_SPEC = /^[ \t\r\n]*[A-Za-z][A-Za-z0-9_]*[ \t\r\n]*=[ \t\r\n]*(?:[\x21-\x3a\x3c-\x7e](?:[ \t\r\n]*[\x21-\x3a\x3c-\x7e])*)?[ \t\r\n]*$/;

// syntaxError is set when any non-empty fragment is not a well-formed tag
// (`junk`, `9bad=foo`, `=v`, a NUL/DEL/8-bit byte in any value): the whole
// field is then a syntax error (§14.2), never verified around the fragment.
export function parseTagList(value) {
  // value is a header value as produced by parseMessage: fold CRLFs are
  // already stripped, so this only needs to guard against a literal \r\n
  // reaching us directly (e.g. from `raw`). Semicolons only ever separate
  // tags (§8).
  const flat = value.replace(/\r\n/g, ''); // drop folding
  const tags = [];
  const map = {};
  let syntaxError = false;
  // §8: tag-list = tag-spec *(";" tag-spec) [";"]: only the segment after
  // a single trailing ";" may be empty; an empty one anywhere else (";;",
  // or a leading ";") is a syntax error.
  const segs = flat.split(';');
  segs.forEach((seg, n) => {
    if (/^[ \t\r\n]*$/.test(seg)) {
      if (n < segs.length - 1) syntaxError = true;
      return;
    }
    if (!TAG_SPEC.test(seg)) syntaxError = true;
    const eq = seg.indexOf('=');
    if (eq < 0) return;
    // -08 §8 (contract D10): tag names are lowercase, and compared as
    // written: "M" is an unknown tag, never m=, and "M=2" beside m=1 is
    // no duplicate.
    const name = seg.slice(0, eq).trim();
    // DKIM2 tag values are base64 / tokens / digits / domains and never carry
    // significant internal whitespace; any WSP present came from header folding
    // (FWS). Strip ALL whitespace so a value split across continuation lines —
    // e.g. a base64 h= hash or s= signature folded mid-token — is reassembled
    // intact. Leaving embedded fold WSP breaks hash-string comparison (the
    // folded-list-message verifier bug).
    const val = seg.slice(eq + 1).replace(/[ \t\r\n]/g, '');
    tags.push({ tag: name, value: val, raw: seg });
    if (!(name in map)) map[name] = val;
  });
  return { tags, map, syntaxError };
}

// A base64string: non-empty, padded with "=" to a multiple of four (§2.14).
export const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/;

// §9.3 (-08): h= is hash-any = hash-all *("|" hash-all), hash-all =
// hash-set *("," hash-set). Returns the hash-sets in h= order, each with
// the index of its "|" group. Hash names are kept as written: the ABNF
// gives them as %s"sha256" / %s"sha512", case sensitive (RFC 7405), so
// "SHA256" is an unknown algorithm. h is the RAW value (FWS intact):
// FWS is allowed around "|" and "," and the hash name and colons, and
// inside the digests (removed), never inside the hash name. A set that is
// not exactly name:digest:digest, with both digests base64strings (contract
// D3), or an empty member (a leading, trailing or doubled "|" or ","),
// throws Error('h-syntax') -- never skipped.
export function parseHashSets(h) {
  const out = [];
  (h || '').split('|').forEach((group, g) => {
    for (const item of group.split(',')) {
      const parts = item.split(':');
      if (parts.length !== 3) throw new Error('h-syntax');
      const alg = parts[0].replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');
      const headerHash = parts[1].replace(/[ \t\r\n]+/g, '');
      const bodyHash = parts[2].replace(/[ \t\r\n]+/g, '');
      if (!/^[A-Za-z0-9_-]+$/.test(alg) || !BASE64.test(headerHash) || !BASE64.test(bodyHash)) throw new Error('h-syntax');
      out.push({ alg, headerHash, bodyHash, group: g });
    }
  });
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
// limits, with no -08 string of their own, named in the C6 form (a
// signature's m= after its i=: "i=2 m=101 exceeds ..."). A missing value (undefined) is
// left to the callers.
export function chainNumberError(field, tag, v, id = v) {
  if (v === undefined) return null;
  const idTag = field === 'Message-Instance' ? 'm' : 'i';
  let who = `${field} ${idTag}=${id}`;
  if (typeof v !== 'string' || !/^[0-9]+$/.test(v)) return `PERMERROR: ${who} syntax error`;
  if (/^0+$/.test(v)) return `PERMERROR: ${who} syntax error`;
  if (tag !== idTag) who += ` ${tag}=${v}`;
  if (v.length > 3 || parseInt(v, 10) > MAX_CHAIN_NUMBER) {
    return `PERMERROR: ${who} exceeds the maximum chain number of ${MAX_CHAIN_NUMBER}`;
  }
  if (parseInt(v, 10) > MAX_CHAIN_LENGTH) {
    return `PERMERROR: ${who} exceeds the maximum chain length of ${MAX_CHAIN_LENGTH}`;
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
  // Contract C9 steps b and d: the PERMERROR for each Message-Instance with
  // no usable m=, and each DKIM2-Signature with no usable i= (or an i=/m=
  // that is not a chain number, chainNumberError), top down. Such a field is
  // not placed in instances/signatures, so nothing loops up to it
  // (4294967297, or 4294967297x, used to run this page out of memory).
  const instanceErrors = [];
  const signatureErrors = [];
  for (const f of headers) {
    if (isName(f, 'message-instance')) {
      miFields.push(f);
      const parsed = parseTagList(f.value);
      const err = parsed.map.m === undefined ? 'PERMERROR: Message-Instance m= tag=m missing'
        : chainNumberError('Message-Instance', 'm', parsed.map.m);
      if (err) { instanceErrors.push(err); continue; }
      const m = parseInt(parsed.map.m, 10);
      if (instances[m]) dupInstances.push(m);
      instances[m] = { field: f, tags: parsed.tags, map: parsed.map, syntaxError: parsed.syntaxError };
    } else if (isName(f, 'dkim2-signature')) {
      sigFields.push(f);
      const parsed = parseTagList(f.value);
      const iv = parsed.map.i;
      const err = iv === undefined ? 'PERMERROR: DKIM2-Signature i= tag=i missing'
        : chainNumberError('DKIM2-Signature', 'i', iv)
          || chainNumberError('DKIM2-Signature', 'm', parsed.map.m, iv);
      if (err) { signatureErrors.push(err); continue; }
      const i = parseInt(iv, 10);
      if (signatures[i]) dupSignatures.push(i);
      signatures[i] = { field: f, tags: parsed.tags, map: parsed.map, syntaxError: parsed.syntaxError };
    }
  }
  return { instances, signatures, miFields, sigFields, dupInstances, dupSignatures,
           instanceErrors, signatureErrors };
}
