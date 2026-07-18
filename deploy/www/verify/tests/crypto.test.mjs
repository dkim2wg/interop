import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256B64, verifyEd25519, verifyRsa } from '../crypto.js';
import { stringToBytes, b64ToBytes } from '../b64.js';

test('sha256B64 matches known DKIM2 body hash', async () => {
  // §6.1 canonical body "Hello, this is a simple test message.\r\n"
  const body = 'Hello, this is a simple test message.\r\n';
  assert.equal(await sha256B64(stringToBytes(body)),
    'SgG5fNGEg1x24MwItCUYGDHQkWKng06W1/IvTGBdwzU=');
});

test('verifyEd25519 accepts a valid signature and rejects a corrupt one', async () => {
  // Signature over the SHA-256 hash of the ASCII message "test".
  const pub = 'nJjZf8LyVfo7pxT28dT3gWhRkcM12+6qhYiOwx8oPco=';
  const { subtle } = globalThis.crypto;
  const hash = new Uint8Array(await subtle.digest('SHA-256', stringToBytes('test')));
  // Sign with the matching private key to produce a known-good signature.
  const pkcs8 = b64ToBytes('MC4CAQAwBQYDK2VwBCIEIM6FWyVRYd3E5RZd/OzN7uiBCpcHwnrTUu7qymtM9kln');
  const priv = await subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
  const sig = new Uint8Array(await subtle.sign({ name: 'Ed25519' }, priv, hash));
  assert.equal(await verifyEd25519(pub, sig, hash), true);
  const bad = sig.slice(); bad[0] ^= 0xff;
  assert.equal(await verifyEd25519(pub, bad, hash), false);
});

test('verifyRsa verifies a self-produced RSASSA-PKCS1-v1_5/SHA-256 signature', async () => {
  const { subtle } = globalThis.crypto;
  const kp = await subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify']);
  const msg = stringToBytes('message-instance:m=1\r\n');
  const sig = new Uint8Array(await subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, kp.privateKey, msg));
  const { bytesToB64 } = await import('../b64.js');
  const spki = bytesToB64(new Uint8Array(await subtle.exportKey('spki', kp.publicKey)));
  assert.equal(await verifyRsa(spki, sig, msg), true);
});
