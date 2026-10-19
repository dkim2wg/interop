import { readFileSync } from 'node:fs';
const V = new URL('../../deploy/www/verify/', import.meta.url).href;
const { verifyMessage } = await import(V + 'verify.js');
const { parseKeyRecord } = await import(V + 'doh.js');
const [lst, dnsf, repsS] = process.argv.slice(2); const reps = +repsS;
const dns = JSON.parse(readFileSync(dnsf, 'utf8'));
function fetchKey(sel, dom) { const r = dns[dom]?.[`${sel}._domainkey`]?.[0]?.[1]; if (r === undefined) throw new Error('key-notfound'); return parseKeyRecord(r); }
const msgs = readFileSync(lst, 'utf8').split('\n').filter(Boolean).map((p) => new Uint8Array(readFileSync(p)));
// The verifier's clock: an hour after the newest t= (as verify-file.mjs does), worked out before timing.
const nows = msgs.map((m) => Math.max(0, ...[...new TextDecoder('latin1').decode(m).matchAll(/[;\s]t=(\d+)/gi)].map((x) => +x[1])) + 3600);
for (const walk of ['plan', 'undo']) {
  let best = 9e9, v = {};
  for (let i = 0; i < reps; i++) {
    v = {}; const t = performance.now();
    for (let j = 0; j < msgs.length; j++) {
      const rep = await verifyMessage(msgs[j], { fetchKey, now: nows[j], undoWalk: walk === 'undo' });
      v[rep.overall] = (v[rep.overall] || 0) + 1;
    }
    best = Math.min(best, (performance.now() - t) / 1000);
  }
  console.log(`js ${walk} ${best.toFixed(3)} ${Object.keys(v).sort().map((k) => `${k}=${v[k]}`).join(',')}`);
}
