// Canonicalization per draft-ietf-dkim-dkim2-spec-05 §6.1, §6.2, §9.6.

// Unsigned header fields per §4, §4.1. message-instance and dkim2-signature
// are also filtered upstream in signedFields(); they are listed here so this
// set matches the other five implementations.
const UNSIGNED_EXACT = new Set([
  'apparently-to', 'arc-authentication-results', 'arc-message-signature',
  'arc-seal', 'authentication-results', 'auto-submitted', 'delivered-to',
  'dkim-signature', 'dkim2-signature', 'dl-expansion-history',
  'message-instance', 'original-recipient', 'received', 'return-path',
  'sio-label-history', 'vbr-info', 'x400-received', 'x400-trace',
]);

export function isUnsignedHeader(name) {
  const n = name.toLowerCase();
  if (UNSIGNED_EXACT.has(n)) return true;
  // §4 narrowed the ARC- prefix to the three exact names above and added the
  // Received-* rule for future trace fields of that form.
  if (n.startsWith('x-')) return true;
  if (n.startsWith('received-')) return true;
  return false;
}

export function canonBody(body) {
  // §6.1: ignore all trailing empty lines; "*CRLF" at end becomes "CRLF";
  // if no body or no trailing CRLF, a CRLF is added.
  return body.replace(/(\r\n)*$/, '') + '\r\n';
}

function unfold(value) {
  // Remove folding: a CRLF that is part of header folding joins the line.
  return value.replace(/\r\n/g, '');
}

// §6.2 canonical line for one header field.
function hashLine(field) {
  let v = unfold(field.value);
  v = v.replace(/[ \t]+/g, ' '); // collapse WSP runs to single SP
  v = v.replace(/ +$/, '');      // delete trailing WSP
  v = v.replace(/^ +/, '');      // delete WSP after the colon
  return field.name.toLowerCase() + ':' + v + '\r\n';
}

export function canonHeaderHash(fields) {
  // fields: flat doc-order list of {name,value}, already filtered to signed
  // headers (caller excludes §4 names AND message-instance/dkim2-signature).
  const withIdx = fields.map((f, i) => ({
    name: f.name.toLowerCase(),
    line: hashLine(f),
    i,
  }));
  // Alphabetical by name; within a name, bottom-up (later in doc first).
  withIdx.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : b.i - a.i));
  return withIdx.map((x) => x.line).join('');
}

export function blankSignatureValues(rawValue) {
  return rawValue
    .split(';')
    .map((seg) => {
      const eq = seg.indexOf('=');
      if (eq < 0) return seg;
      const name = seg.slice(0, eq).trim().toLowerCase();
      if (name !== 's') return seg;
      const rest = seg.slice(eq + 1);
      const sets = rest.split(',').map((s) => {
        const parts = s.split(':');
        // selector:sig-name:message-sig -> selector:sig-name:
        return (parts[0] || '') + ':' + (parts[1] || '') + ':';
      });
      return seg.slice(0, eq + 1) + sets.join(',');
    })
    .join(';');
}

// §9.6 canonical line for the signing input: delete ALL WSP, keep colon + CRLF.
function signLine(name, value) {
  const v = unfold(value).replace(/[ \t]/g, '');
  return name.toLowerCase() + ':' + v + '\r\n';
}

export function signingInput(orderedFields, targetSig) {
  let out = '';
  for (const f of orderedFields) {
    const value = f === targetSig ? blankSignatureValues(f.value) : f.value;
    out += signLine(f.name, value);
  }
  return out;
}
