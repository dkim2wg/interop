// Public-key retrieval over DNS-over-HTTPS (Cloudflare) + key-record parsing.
// Built from spec-06 §3.6 / §11.5 and draft-ietf-dkim-dkim2-dns-00 §3.2,
// §3.4.1, §3.4.2.2.

const DEFAULT_DOH = 'https://cloudflare-dns.com/dns-query';

export function keyName(selector, domain) {
  return `${selector}._domainkey.${domain}`;
}

const WSP = /^[ \t\r\n]*$/;
const TAG_SPEC = /^[ \t\r\n]*([A-Za-z][A-Za-z0-9_]*)[ \t\r\n]*=([\s\S]*)$/;
// A base64string: non-empty, padded with "=" to a multiple of four (§2.13).
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/;

// spec-06 §11.5: the Verifier MUST validate the key record and MUST NOT use
// a malformed one. The whole record is a tag-list (dns-00 §3.2), never
// searched for p=: split on ";", skip empty specs (a trailing ";"), every
// other spec is `[WSP] name [WSP] "=" value` with name ALPHA *(ALPHA /
// DIGIT / "_"). Tag names are case sensitive (as DKIM1); a repeated name
// makes the record invalid. v=, if present, is first and exactly DKIM1.
// k= defaults to rsa and is returned verbatim -- an unknown k= is an
// algorithm mismatch for the caller, never read as RSA. p= is required,
// FWS removed; empty is revoked; otherwise it must be base64 (whether it
// imports as a key of type k= is checked where it is imported). Unknown and
// retired tags (h=, n=, s=, t=) are ignored.
export function parseKeyRecord(txt) {
  const tags = new Map();
  let first = null;
  for (const spec of String(txt).split(';')) {
    if (WSP.test(spec)) continue;
    const m = TAG_SPEC.exec(spec);
    if (!m || tags.has(m[1])) throw new Error('key-syntax');
    if (first === null) first = m[1];
    tags.set(m[1], m[2].replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, ''));
  }
  if (tags.has('v') && (first !== 'v' || tags.get('v') !== 'DKIM1')) throw new Error('key-syntax');
  if (!tags.has('p')) throw new Error('key-syntax');
  const p = tags.get('p').replace(/[ \t\r\n]+/g, '');
  if (p === '') throw new Error('key-revoked');
  if (!BASE64.test(p)) throw new Error('key-syntax');
  return { k: tags.has('k') ? tags.get('k') : 'rsa', p };
}

// The record held by ONE TXT RR as DoH JSON presents it. Cloudflare gives
// the RR in zone-file presentation form: each character-string quoted,
// separated by a space, with \" \\ and \DDD escapes. The strings of one RR
// are concatenated with nothing between them (dns-00 §3.4.2.2). Some
// resolvers give the data unquoted; that is taken as-is.
export function txtData(data) {
  const s = String(data);
  if (!s.startsWith('"')) return s;
  let out = '';
  let i = 0;
  while (i < s.length) {
    if (s[i] === ' ' || s[i] === '\t') { i++; continue; }
    if (s[i] !== '"') throw new Error('key-syntax');
    i++;
    for (;;) {
      if (i >= s.length) throw new Error('key-syntax'); // unterminated
      const c = s[i];
      if (c === '"') { i++; break; }
      if (c === '\\') {
        const ddd = /^[0-9]{3}/.exec(s.slice(i + 1, i + 4));
        if (ddd) { out += String.fromCharCode(parseInt(ddd[0], 10)); i += 4; }
        else if (i + 1 < s.length) { out += s[i + 1]; i += 2; }
        else throw new Error('key-syntax');
      } else { out += c; i++; }
    }
  }
  return out;
}

export async function fetchKey(selector, domain, opts = {}) {
  const url = new URL(opts.dohUrl || DEFAULT_DOH);
  url.searchParams.set('name', keyName(selector, domain));
  url.searchParams.set('type', 'TXT');
  let resp;
  try {
    // Bound a hung DoH request so it surfaces as a temperror rather than
    // hanging the verification. Any fetch rejection (incl. AbortError on
    // timeout) maps to key-temperror, preserving the cause for diagnosis.
    resp = await fetch(url, { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) });
  } catch (e) {
    throw new Error('key-temperror', { cause: e });
  }
  if (resp.status >= 500) throw new Error('key-temperror');
  if (!resp.ok) throw new Error('key-notfound');
  const data = await resp.json();
  if (data.Status === 2) throw new Error('key-temperror'); // SERVFAIL
  if (data.Status === 3) throw new Error('key-notfound');  // NXDOMAIN
  // Only the TXT RRs (a CNAME on the way is not one). More than one TXT RR
  // for the name is an error (spec-06 §11.5), even if they are identical.
  const answers = (data.Answer || []).filter((a) => a.type === 16);
  if (answers.length === 0) throw new Error('key-notfound');
  if (answers.length > 1) throw new Error('key-multiple');
  return parseKeyRecord(txtData(answers[0].data));
}
