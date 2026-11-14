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

// One-time capability note for browsers without WebCrypto Ed25519.
(async () => {
  try {
    await globalThis.crypto.subtle.importKey('raw', new Uint8Array(32), { name: 'Ed25519' }, false, ['verify']);
  } catch (e) {
    document.getElementById('caps').textContent =
      'Note: this browser lacks WebCrypto Ed25519; ed25519-sha256 signatures will show as unsupported. Use a current Chrome, Firefox, or Safari.';
  }
})();
