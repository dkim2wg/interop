import { verifyMessage } from './verify.js';
import { renderReport } from './report.js';

const out = document.getElementById('out');
const ta = document.getElementById('msg');

async function run() {
  out.replaceChildren(Object.assign(document.createElement('p'), { className: 'muted', textContent: 'Verifying in your browser…' }));
  try {
    const rep = await verifyMessage(ta.value);
    renderReport(rep, out);
  } catch (e) {
    out.replaceChildren(Object.assign(document.createElement('p'), { className: 'verdict fail', textContent: 'Error: ' + (e && e.message || e) }));
  }
}

document.getElementById('go').addEventListener('click', run);
document.getElementById('example').addEventListener('click', (ev) => {
  ev.preventDefault();
  ta.value = 'Paste a real DKIM2-signed message here.\n(Tip: send mail through one of the reflector-*@dkim2.com addresses, then paste the reply.)\n';
});

// One-time capability note for browsers without WebCrypto Ed25519.
(async () => {
  try {
    await globalThis.crypto.subtle.importKey('raw', new Uint8Array(32), { name: 'Ed25519' }, false, ['verify']);
  } catch (e) {
    document.getElementById('caps').textContent =
      'Note: this browser lacks WebCrypto Ed25519; ed25519-sha256 signatures will show as unsupported. Use a current Chrome, Firefox, or Safari.';
  }
})();
