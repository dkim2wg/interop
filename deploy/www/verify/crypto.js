// WebCrypto wrappers for DKIM2. Built from spec-04 §3.
import { b64ToBytes, bytesToB64 } from './b64.js';

const subtle = globalThis.crypto.subtle;

export async function sha256Bytes(bytes) {
  return new Uint8Array(await subtle.digest('SHA-256', bytes));
}

export async function sha256B64(bytes) {
  return bytesToB64(await sha256Bytes(bytes));
}

export async function verifyRsa(keyB64, sigBytes, msgBytes) {
  const der = b64ToBytes(keyB64);
  // A DKIM p= record may carry the key either as a full SubjectPublicKeyInfo
  // (PKIX, RFC 5280) or as a bare PKCS#1 RSAPublicKey (RFC 8017). WebCrypto
  // only imports SPKI, so wrap a bare PKCS#1 key before importing (§3.2).
  const spki = isPkcs1RsaPublicKey(der) ? pkcs1ToSpki(der) : der;
  const key = await subtle.importKey(
    'spki', spki,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  // §3.2: Signers MUST use RSA keys of at least 1024 bits; reject smaller keys
  // (a key-record syntax error / permerror), even if the maths would verify.
  const bits = key.algorithm.modulusLength;
  if (bits < 1024) {
    const e = new Error('key-tooshort');
    e.bits = bits;
    throw e;
  }
  return subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, sigBytes, msgBytes);
}

// True if `der` is a bare PKCS#1 RSAPublicKey: SEQUENCE { INTEGER, INTEGER }.
// (An SPKI instead begins SEQUENCE { SEQUENCE {...algorithm...}, ... }.)
function isPkcs1RsaPublicKey(der) {
  if (der[0] !== 0x30) return false; // outer must be SEQUENCE
  let i = 1 + derLengthOctets(der, 1); // skip outer length to first element
  return der[i] === 0x02; // INTEGER => PKCS#1 (0x30 would mean SPKI algId)
}

// Number of octets used by the DER length field starting at `pos`.
function derLengthOctets(der, pos) {
  const first = der[pos];
  return first < 0x80 ? 1 : 1 + (first & 0x7f);
}

// DER length encoding for a content of `n` bytes.
function derLen(n) {
  if (n < 0x80) return [n];
  const out = [];
  for (let v = n; v > 0; v = v >> 8) out.unshift(v & 0xff);
  return [0x80 | out.length, ...out];
}

// Wrap a PKCS#1 RSAPublicKey DER into a SubjectPublicKeyInfo DER.
function pkcs1ToSpki(pkcs1) {
  // AlgorithmIdentifier { OID rsaEncryption 1.2.840.113549.1.1.1, NULL }.
  const algId = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
  // BIT STRING with 0 unused bits wrapping the PKCS#1 key.
  const bitStr = [0x03, ...derLen(pkcs1.length + 1), 0x00, ...pkcs1];
  const body = [...algId, ...bitStr];
  return new Uint8Array([0x30, ...derLen(body.length), ...body]);
}

export async function verifyEd25519(rawPubB64, sigBytes, hashBytes) {
  const rawPub = b64ToBytes(rawPubB64);
  let key;
  try {
    key = await subtle.importKey('raw', rawPub, { name: 'Ed25519' }, false, ['verify']);
  } catch (e) {
    if (e.name === 'NotSupportedError') throw new Error('ed25519-unsupported');
    throw e;
  }
  // §3.3: Ed25519 signs the SHA-256 hash value as its message.
  return subtle.verify({ name: 'Ed25519' }, key, sigBytes, hashBytes);
}
