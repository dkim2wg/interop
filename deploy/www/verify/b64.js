// Base64 and UTF-8 conversion helpers. Works in browsers and Node 20+
// (both provide global atob/btoa, TextEncoder, TextDecoder).
const enc = new TextEncoder();
const dec = new TextDecoder();

export function stringToBytes(s) { return enc.encode(s); }
export function bytesToString(u8) { return dec.decode(u8); }

export function b64ToBytes(s) {
  const bin = atob(s.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64(u8) {
  let bin = '';
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

export function b64ToString(s) { return bytesToString(b64ToBytes(s)); }

// A message is a sequence of octets (spec-06 §6). Inside the verifier it
// travels as a "binary string": one code unit per byte (0..255), so the RFC
// 5322 structure can be handled with ordinary string and regex tools while
// every byte -- a raw Big5 Subject, a Latin-1 body -- reaches the hash
// intact. Decoding the message as UTF-8 text instead turns each byte that is
// not valid UTF-8 into U+FFFD and the hashes never match (found 2026-10-04
// replaying the SpamAssassin corpus through every verifier).
export function bytesToBinary(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  }
  return s;
}

export function binaryToBytes(bin) {
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
  return out;
}

// Text -> binary string, by UTF-8 encoding. Used for a pasted message and
// for Recipe "d" literals, which are JSON strings. ASCII text is already its
// own binary string. (Octets that are not UTF-8 travel in a Recipe as a "u"
// step, spec-07 §5; a "d" string holding a lone surrogate is refused before
// it gets here.)
export function textToBinary(text) {
  if (/^[\x00-\x7f]*$/.test(text)) return text;
  return bytesToBinary(enc.encode(text));
}
