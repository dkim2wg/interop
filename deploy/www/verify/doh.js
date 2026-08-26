// Public-key retrieval over DNS-over-HTTPS (Cloudflare) + key-record parsing.
// Built from spec-05 §3.6 / §11.5.

const DEFAULT_DOH = 'https://cloudflare-dns.com/dns-query';

export function keyName(selector, domain) {
  return `${selector}._domainkey.${domain}`;
}

export function parseKeyRecord(txt) {
  const map = {};
  for (const seg of txt.split(';')) {
    const eq = seg.indexOf('=');
    if (eq < 0) continue;
    map[seg.slice(0, eq).trim().toLowerCase()] = seg.slice(eq + 1).trim();
  }
  if (!('p' in map)) throw new Error('key-syntax');
  if (map.p === '') throw new Error('key-revoked');
  return { k: (map.k || 'rsa').toLowerCase(), p: map.p.replace(/\s+/g, '') };
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
  const answers = (data.Answer || []).filter((a) => a.type === 16); // TXT
  if (answers.length === 0) throw new Error('key-notfound');
  if (answers.length > 1) throw new Error('key-multiple');
  // DoH TXT data is a quoted string, possibly split into 255-char chunks.
  const txt = answers[0].data
    .replace(/^"(.*)"$/s, '$1')
    .replace(/"\s*"/g, '');
  return parseKeyRecord(txt);
}
