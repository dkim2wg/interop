// Public-key and Domain Policy Record retrieval over DNS-over-HTTPS
// (Cloudflare), and the parsing of both. Built from
// draft-ietf-dkim-dkim2-spec-09 §3.7, §3.8, §14.5, §14.8 and
// draft-ietf-dkim-dkim2-dns-03 (key records, the Domain Policy Record).

const DEFAULT_DOH = 'https://cloudflare-dns.com/dns-query';

export function keyName(selector, domain) {
  return `${selector}._domainkey.${domain}`;
}

const WSP = /^[ \t\r\n]*$/;
const isWsp = (c) => c === ' ' || c === '\t' || c === '\r' || c === '\n';
// s with surrounding WSP removed, in linear time: a record is
// attacker-served (up to 64 KB), and a trailing-WSP regex is quadratic on
// a long run of WSP that is not at the end.
export function trimWsp(s) {
  let a = 0, b = s.length;
  while (a < b && isWsp(s[a])) a++;
  while (b > a && isWsp(s[b - 1])) b--;
  return s.slice(a, b);
}
// The value, unknown tags included, is RFC 6376 §3.2 tag-value: VALCHARs
// (%x21-3A / %x3C-7E) with WSP/FWS only between them, so a NUL, DEL or
// 8-bit byte anywhere is a syntax error.
const TAG_SPEC = /^[ \t\r\n]*([A-Za-z][A-Za-z0-9_]*)[ \t\r\n]*=([ \t\r\n]*(?:[\x21-\x3a\x3c-\x7e](?:[ \t\r\n]*[\x21-\x3a\x3c-\x7e])*)?[ \t\r\n]*)$/;
// A base64string: non-empty, padded with "=" to a multiple of four (§2.14).
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/;

// §14.5: the Verifier MUST validate the key record and MUST NOT use
// a malformed one. The whole record is a tag-list (dns-03), never
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
  const { tags, first } = parseRecordTags(txt, 'key-syntax');
  if (tags.has('v') && (first !== 'v' || tags.get('v') !== 'DKIM1')) throw new Error('key-syntax');
  if (!tags.has('p')) throw new Error('key-syntax');
  const p = tags.get('p').replace(/[ \t\r\n]+/g, '');
  if (p === '') throw new Error('key-revoked');
  if (!BASE64.test(p)) throw new Error('key-syntax');
  return { k: tags.has('k') ? tags.get('k') : 'rsa', p };
}

// The tag-list of a key record or Domain Policy Record (dns-03): a Map of
// tag name to its WSP-trimmed value, and the first tag's name. Throws
// Error(err) on a spec that is not a tag, or a tag given twice.
function parseRecordTags(txt, err) {
  const tags = new Map();
  let first = null;
  for (const spec of String(txt).split(';')) {
    if (WSP.test(spec)) continue;
    const m = TAG_SPEC.exec(spec);
    if (!m || tags.has(m[1])) throw new Error(err);
    if (first === null) first = m[1];
    tags.set(m[1], trimWsp(m[2]));
  }
  return { tags, first };
}

// The value of a record's first tag when that tag is v= ([WSP] "v" [WSP]
// "=" ...), WSP-trimmed; null when the first tag is not v= (or the record
// does not start with a tag at all). Case sensitive: "V=" is not v=.
function firstTagV(txt) {
  const s = String(txt);
  let k = 0;
  while (k < s.length && isWsp(s[k])) k++;
  if (s[k] !== 'v') return null;
  k++;
  while (k < s.length && isWsp(s[k])) k++;
  if (s[k] !== '=') return null;
  const end = s.indexOf(';', k + 1);
  return trimWsp(s.slice(k + 1, end < 0 ? s.length : end));
}

// §3.7 / dns-03: the key record among the TXT records at a selector name
// (each RR's strings already joined). A record whose first tag is v= with
// a value other than DKIM1 is ignored; one with no v= is kept (v= is
// optional for keys), as is one that starts with something unparseable
// (it is then "has a syntax error" if it is the only one). None left is
// key-notfound, more than one key-multiple.
export function selectKeyRecord(txts) {
  const kept = txts.filter((t) => { const v = firstTagV(t); return v === null || v === 'DKIM1'; });
  if (kept.length === 0) throw new Error('key-notfound');
  if (kept.length > 1) throw new Error('key-multiple');
  return parseKeyRecord(kept[0]);
}

// §3.8 / dns-03 the Domain Policy Record, from the TXT records at
// _domainkey.<domain> (each RR's strings already joined): 'open' (subdomains
// may make the domain's From Authentic), 'strict', or 'multiple'. Only the
// records whose first tag is v= with exactly the value DKIM1 count; none is
// 'open', more than one 'multiple'. The one record left is a tag-list
// parsed as key records are (a tag given twice is a syntax error, names are
// case sensitive, unknown tags ignored). f= is flags joined by ":" with
// [FWS] around each, every flag a hyphenated-word; it is strict when one
// flag is exactly "strict". A record that does not parse, or an f= that
// breaks the ABNF (an empty flag, or one that is not a hyphenated-word),
// is strict: fail closed (contract E3.2). An empty f= is no flags.
const HYPHENATED_WORD = /^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/;
export function evaluatePolicy(txts) {
  const kept = txts.filter((t) => firstTagV(t) === 'DKIM1');
  if (kept.length === 0) return 'open';
  if (kept.length > 1) return 'multiple';
  let tags;
  try { ({ tags } = parseRecordTags(kept[0], 'policy-syntax')); } catch (e) { return 'strict'; }
  if (!tags.has('f') || tags.get('f') === '') return 'open';
  const flags = tags.get('f').split(':').map(trimWsp);
  if (flags.some((f) => !HYPHENATED_WORD.test(f))) return 'strict';
  return flags.includes('strict') ? 'strict' : 'open';
}

// The record held by ONE TXT RR as DoH JSON presents it. Cloudflare gives
// the RR in zone-file presentation form: each character-string quoted,
// separated by a space, with \" \\ and \DDD escapes. The strings of one RR
// are concatenated with nothing between them (dns-03). Some
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

// The fetchKey() failures that are a definitive answer about the name (no
// such key, or a record that is unusable): looking again cannot change them.
// Anything else (key-temperror, a malformed DoH response) may.
export const DEFINITIVE_KEY_ERRORS = new Set(['key-notfound', 'key-multiple', 'key-syntax', 'key-revoked']);

export async function fetchKey(selector, domain, opts = {}) {
  const url = new URL(opts.dohUrl || DEFAULT_DOH);
  url.searchParams.set('name', keyName(selector, domain));
  url.searchParams.set('type', 'TXT');
  let resp;
  try {
    // Bound a hung DoH request so it surfaces as a temperror rather than
    // hanging the verification. Any fetch rejection (incl. AbortError on
    // timeout) maps to key-temperror, preserving the cause for diagnosis.
    // opts.fetch: a fetch() stand-in (tests).
    const init = { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) };
    resp = await (opts.fetch ? opts.fetch(url, init) : fetch(url, init));
  } catch (e) {
    throw new Error('key-temperror', { cause: e });
  }
  if (resp.status >= 500) throw new Error('key-temperror');
  if (!resp.ok) throw new Error('key-notfound');
  const data = await resp.json();
  if (data.Status === 2) throw new Error('key-temperror'); // SERVFAIL
  if (data.Status === 3) throw new Error('key-notfound');  // NXDOMAIN
  // Only the TXT RRs (a CNAME on the way is not one). More than one
  // record left once the non-DKIM1 ones are ignored is an error (§3.7,
  // §14.5), even if they are identical.
  const answers = (data.Answer || []).filter((a) => a.type === 16);
  return selectKeyRecord(answers.map((a) => txtData(a.data)));
}

// The TXT records at _domainkey.<domain> (the Domain Policy Record's name,
// §3.8), each RR's strings joined: [] for NXDOMAIN, no TXT record, or an
// HTTP 4xx (as for keys). Throws Error('policy-temperror') for a temporary
// failure: a network error or timeout, an HTTP 5xx, SERVFAIL or any other
// error RCODE, a truncated answer, or an answer that cannot be read.
// domain: the From domain as an A-label, lowercased, no trailing dot.
export async function fetchPolicy(domain, opts = {}) {
  const url = new URL(opts.dohUrl || DEFAULT_DOH);
  url.searchParams.set('name', `_domainkey.${domain}`);
  url.searchParams.set('type', 'TXT');
  try {
    const init = { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) };
    const resp = await (opts.fetch ? opts.fetch(url, init) : fetch(url, init));
    if (resp.status >= 500) throw new Error('5xx');
    if (!resp.ok) return [];
    const data = await resp.json();
    if (data.Status === 3) return [];
    if ((data.Status ?? 0) !== 0 || data.TC) throw new Error(`rcode ${data.Status}`);
    return (data.Answer || []).filter((a) => a.type === 16).map((a) => txtData(a.data));
  } catch (e) {
    throw new Error('policy-temperror', { cause: e });
  }
}
