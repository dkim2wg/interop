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
