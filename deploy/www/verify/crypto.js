// WebCrypto wrappers for DKIM2. Built from spec-04 §3.
import { b64ToBytes, bytesToB64 } from './b64.js';

const subtle = globalThis.crypto.subtle;

export async function sha256Bytes(bytes) {
  return new Uint8Array(await subtle.digest('SHA-256', bytes));
}

export async function sha256B64(bytes) {
  return bytesToB64(await sha256Bytes(bytes));
}

export async function verifyRsa(spkiB64, sigBytes, msgBytes) {
  const key = await subtle.importKey(
    'spki', b64ToBytes(spkiB64),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  return subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, sigBytes, msgBytes);
}

export async function verifyEd25519(rawPubB64, sigBytes, hashBytes) {
  let key;
  try {
    key = await subtle.importKey('raw', b64ToBytes(rawPubB64), { name: 'Ed25519' }, false, ['verify']);
  } catch (e) {
    throw new Error('ed25519-unsupported');
  }
  // §3.3: Ed25519 signs the SHA-256 hash value as its message.
  return subtle.verify({ name: 'Ed25519' }, key, sigBytes, hashBytes);
}
