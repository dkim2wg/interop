// Test helper: build a genuinely Ed25519-signed DKIM2 chain with WebCrypto
// and this verifier's own canonicalization, so tests do not depend on any
// other implementation's fixtures.
import { canonHeaderHash, canonBody, signingInput } from '../canon.js';
import { hashB64, sha256Bytes } from '../crypto.js';
import { bytesToB64, binaryToBytes, textToBinary, stringToBytes } from '../b64.js';

const { subtle } = globalThis.crypto;

export const newKeyPair = () => subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
export const publicKeyB64 = async (kp) => bytesToB64(new Uint8Array(await subtle.exportKey('raw', (await kp).publicKey)));
export const b64text = (text) => bytesToB64(stringToBytes(text));

export const T = 1740000000;

// A field value or body is text (UTF-8), or { bin } for a binary string
// (one code unit per octet) carrying octets that are not UTF-8.
const bin = (v) => (typeof v === 'string' ? textToBinary(v) : v.bin);

// states[k - 1] is the message at Message-Instance m=k: { fields: [[name,
// value]...], body, recipe }, where recipe is the r= of that instance (an
// object, JSON.stringify'd, or a string of JSON text used as it is).
// hops[n - 1] is DKIM2-Signature i=n: { d, m, mf, rt: [...], nd, f, t, extra,
// sel, kp }; nd= replaces mf=/rt=, extra is raw tag text appended, sel
// defaults to "sel" and kp to the shared key pair given.
// Returns the signed message as octets.
export async function signChain(states, hops, kp) {
  const miField = async (k) => {
    const st = states[k - 1];
    const fields = st.fields.map(([n, v]) => ({ name: n, value: ' ' + bin(v) }));
    const hh = await hashB64(binaryToBytes(canonHeaderHash(fields.filter((f) => !/^x-/i.test(f.name)))), 'sha256');
    const bh = await hashB64(binaryToBytes(canonBody(bin(st.body))), 'sha256');
    let v = ` m=${k}; h=sha256:${hh}:${bh}`;
    if (st.recipe !== undefined) {
      const json = typeof st.recipe === 'string' ? st.recipe : JSON.stringify(st.recipe);
      v += `; r=${b64text(json)}`;
    }
    return { name: 'Message-Instance', value: v };
  };
  const mis = [];
  for (let k = 1; k <= states.length; k++) mis.push(await miField(k));
  const sigs = [];
  for (let n = 0; n < hops.length; n++) {
    const h = hops[n];
    let v = ` i=${n + 1}; m=${h.m || 1}; t=${h.t || T}; d=${h.d}`;
    if (h.nd) v += `; nd=${h.nd}`;
    else v += `; mf=${b64text(h.mf)}; rt=${h.rt.map(b64text).join(',')}`;
    if (h.f) v += `; f=${h.f}`;
    if (h.extra) v += h.extra;
    v += `; s=${h.sel || 'sel'}:ed25519-sha256:`;
    const draft = { name: 'DKIM2-Signature', value: v };
    const input = binaryToBytes(signingInput([...mis.slice(0, h.m || 1), ...sigs, draft], draft));
    const key = (await (h.kp || kp)).privateKey;
    const sig = bytesToB64(new Uint8Array(await subtle.sign({ name: 'Ed25519' }, key, await sha256Bytes(input))));
    sigs.push({ name: 'DKIM2-Signature', value: v + sig });
  }
  const top = states[states.length - 1];
  const line = (f) => `${f.name}:${f.value}\r\n`;
  const raw = sigs.slice().reverse().map(line).join('') + mis.slice().reverse().map(line).join('')
    + top.fields.map(([n, v]) => `${n}: ${bin(v)}\r\n`).join('') + '\r\n' + bin(top.body);
  return binaryToBytes(raw);
}
