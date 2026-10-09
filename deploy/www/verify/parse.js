// RFC5322 message parsing and DKIM2 tag-value parsing. Built from spec-06.

function toCRLF(raw) {
  return raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\n/g, '\r\n');
}

// Field = { name: string, value: string, raw: string }
// `raw` is the full folded field text including its terminating CRLF.
// `value` is the unfolded value: each physical line's own trailing CRLF is
// stripped during continuation handling, so no literal `\r\n` ever survives
// in `value` — only the fold-boundary whitespace (the continuation line's
// leading WSP) remains. No leading colon, no trailing CRLF. Use `raw` if you
// need the literal folded bytes.
export function parseMessage(raw) {
  const text = toCRLF(raw);
  const sep = text.indexOf('\r\n\r\n');
  const headerBlock = sep < 0 ? text : text.slice(0, sep + 2); // include final CRLF
  const body = sep < 0 ? '' : text.slice(sep + 4);

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
  return { headers, body };
}

export function parseTagList(value) {
  // value is a header value as produced by parseMessage: fold CRLFs are
  // already stripped, so this only needs to guard against a literal \r\n
  // reaching us directly (e.g. from `raw`). Semicolons only ever separate
  // tags (spec §7/§8).
  const flat = value.replace(/\r\n/g, ''); // drop folding
  const tags = [];
  const map = {};
  for (const seg of flat.split(';')) {
    if (seg.trim() === '') continue;
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
  return { tags, map };
}

// spec-06 §7.3: h= is hash-set *("," hash-set). Hash names are lowercased —
// RFC 5234 makes ABNF quoted strings case-insensitive. parseTagList has
// already stripped all FWS from the value.
export function parseHashSets(h) {
  const out = [];
  for (const item of (h || '').split(',')) {
    const parts = item.trim().split(':');
    if (parts.length !== 3) continue;
    out.push({ alg: parts[0].trim().toLowerCase(), headerHash: parts[1], bodyHash: parts[2] });
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
// of "4294967297x" and run the 1..max loops to it. Then at most three digits
// and 1..MAX_CHAIN_NUMBER (so "01" and "001" are 1), and no more than
// MAX_CHAIN_LENGTH. A missing value (undefined) is left to the callers.
export function chainNumberError(field, tag, v) {
  if (v === undefined) return null;
  const malformed = tag === 'i'
    ? `${field} has a missing or malformed i= tag`
    : `${field} has a malformed ${tag}= tag`;
  if (typeof v !== 'string' || !/^[0-9]+$/.test(v)) return malformed;
  if (/^0+$/.test(v)) return malformed;
  if (v.length > 3 || parseInt(v, 10) > MAX_CHAIN_NUMBER) {
    return `${field} ${tag}= exceeds the maximum chain number of ${MAX_CHAIN_NUMBER}`;
  }
  if (parseInt(v, 10) > MAX_CHAIN_LENGTH) {
    return `${field} ${tag}= exceeds the maximum chain length of ${MAX_CHAIN_LENGTH}`;
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
  // DKIM2-Signature fields whose i= is missing or not a positive integer in
  // ASCII digits: no verifier can place or key one, so verifyOnce() reports
  // a PERMERROR rather than verifying around it.
  let unkeyableSignatures = 0;
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
      if (!Number.isNaN(m)) instances[m] = { field: f, tags: parsed.tags, map: parsed.map };
    } else if (isName(f, 'dkim2-signature')) {
      sigFields.push(f);
      const parsed = parseTagList(f.value);
      const iv = parsed.map.i;
      const i = /^[0-9]+$/.test(iv || '') ? parseInt(iv, 10) : NaN;
      if (Number.isNaN(i) || i < 1) { unkeyableSignatures++; continue; }
      const err = chainNumberError('DKIM2-Signature', 'i', iv)
               || chainNumberError('DKIM2-Signature', 'm', parsed.map.m);
      if (err) { rangeError = rangeError || err; continue; }
      if (signatures[i]) dupSignatures.push(i);
      signatures[i] = { field: f, tags: parsed.tags, map: parsed.map };
    }
  }
  return { instances, signatures, miFields, sigFields, dupInstances, dupSignatures,
           unkeyableSignatures, rangeError };
}
