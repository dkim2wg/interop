// WebCrypto wrappers for DKIM2. Built from draft-ietf-dkim-dkim2-spec-08 §3.
import { b64ToBytes, bytesToB64 } from './b64.js';

const subtle = globalThis.crypto.subtle;

// §3.1: two hashing algorithms are defined; Verifiers MUST implement
// both. Values are WebCrypto SubtleCrypto digest names.
export const HASH_ALGS = { sha256: 'SHA-256', sha512: 'SHA-512' };

export async function hashBytes(bytes, alg) {
  const name = HASH_ALGS[alg.toLowerCase()];
  if (!name) throw new Error(`unsupported hash algorithm: ${alg}`);
  return new Uint8Array(await subtle.digest(name, bytes));
}

export async function hashB64(bytes, alg) {
  return bytesToB64(await hashBytes(bytes, alg));
}

export async function sha256Bytes(bytes) {
  return hashBytes(bytes, 'sha256');
}

export async function sha256B64(bytes) {
  return hashB64(bytes, 'sha256');
}

export async function verifyRsa(keyB64, sigBytes, msgBytes) {
  const der = b64ToBytes(keyB64);
  // A DKIM p= record may carry the key either as a full SubjectPublicKeyInfo
  // (PKIX, RFC 5280) or as a bare PKCS#1 RSAPublicKey (RFC 8017). WebCrypto
  // only imports SPKI, so wrap a bare PKCS#1 key before importing (§3.2).
  const spki = isPkcs1RsaPublicKey(der) ? pkcs1ToSpki(der) : der;
  // -08 §14.5 (contract D7): a p= that does not import as an RSA key
  // (garbage, or a key of another type) is malformed, never a plain
  // signature failure.
  let key;
  try {
    key = await subtle.importKey(
      'spki', spki,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  } catch (e) {
    throw new Error('key-malformed', { cause: e });
  }
  // -08 §3.2: Verifiers MUST NOT validate signatures with keys shorter than
  // 1024 bits, even if the maths would verify: such a key is malformed.
  if (key.algorithm.modulusLength < 1024) throw new Error('key-malformed');
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
  // -08 §14.5: an Ed25519 key is exactly 32 octets (so a DER
  // SubjectPublicKeyInfo is malformed too).
  if (rawPub.length !== 32) throw new Error('key-malformed');
  let key;
  try {
    key = await subtle.importKey('raw', rawPub, { name: 'Ed25519' }, false, ['verify']);
  } catch (e) {
    if (e.name === 'NotSupportedError') throw new Error('ed25519-unsupported');
    // §14.5: a p= that is not a raw Ed25519 key is malformed.
    throw new Error('key-malformed', { cause: e });
  }
  // §3.3: Ed25519 signs the SHA-256 hash value as its message.
  return subtle.verify({ name: 'Ed25519' }, key, sigBytes, hashBytes);
}
