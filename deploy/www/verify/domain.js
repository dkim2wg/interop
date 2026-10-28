// Address domains and the relaxed domain match, per
// draft-ietf-dkim-dkim2-spec-08 §7 and §18. Built from spec.

// The domain of an address (a decoded mf=/rt= path, or an addr-spec): the
// text after the last "@", up to a closing ">", lowercased, with one
// trailing dot removed (§7.2 item 2). A domain literal ("[192.0.2.1]") is
// returned as it is, marked literal: it never matches anything. An address
// with no "@" (the null path "<>") has the empty domain.
export function domainOf(addr) {
  const s = String(addr == null ? '' : addr);
  const at = s.lastIndexOf('@');
  if (at < 0) return { domain: '', literal: false };
  let d = s.slice(at + 1);
  const close = d.indexOf('>');
  if (close >= 0) d = d.slice(0, close);
  d = d.trim().toLowerCase();
  if (d.startsWith('[')) return { domain: d, literal: true };
  if (d.endsWith('.')) d = d.slice(0, -1);
  return { domain: d, literal: false };
}

// §18: a domain as A-labels. Each label holding non-ASCII is lowercased and
// becomes "xn--" + Punycode, by the URL host parser (the browser's IDNA);
// ASCII labels are left alone. Returns null when a label cannot be mapped,
// which then matches nothing.
export function toALabel(domain) {
  const d = String(domain == null ? '' : domain);
  if (/^[\x00-\x7f]*$/.test(d)) return d;
  const out = [];
  for (const label of d.split('.')) {
    if (/^[\x00-\x7f]*$/.test(label)) { out.push(label); continue; }
    try {
      const host = new URL('http://' + label.toLowerCase()).hostname;
      if (!/^xn--[a-z0-9-]+$/.test(host)) return null;
      out.push(host);
    } catch (e) {
      return null;
    }
  }
  return out.join('.');
}

// §7.2 relaxed domain match of two domains (strings, as domainOf().domain
// or a d= value). Asymmetric: only Parameter1 is shortened, a label at a
// time from the left. A domain literal, or an empty domain, never matches.
export function relaxedMatch(p1, p2) {
  let a = String(p1 == null ? '' : p1).toLowerCase();
  const b = String(p2 == null ? '' : p2).toLowerCase();
  if (!a || !b || a.startsWith('[') || b.startsWith('[')) return false;
  for (;;) {
    if (a === b) return true;
    const dot = a.indexOf('.');
    if (dot < 0) return false;
    a = a.slice(dot + 1);
  }
}
