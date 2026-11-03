#!/usr/bin/env node
// Thin file-driven entry point over the same verifyMessage() code path that
// tests/vectors.test.mjs drives through node --test. Exists because the
// browser JS verifier otherwise has no CLI: this lets util/hash-matrix.sh
// (and any other shell-driven interop check) feed a real .eml file through
// the REAL verifier entry point, not a parsing helper called directly.
//
// Usage: node tests/verify-file.mjs <path-to-message> [<path-to-dns.json>] [--real-clock]
//   dns.json defaults to the repo root's dns.json (nested
//   {domain: {"selector._domainkey": [["txt", value]]}} shape -- the same
//   file util/hash-matrix.sh's other verifiers use).
//   --real-clock checks the §14.3 timestamps against the real time instead
//   of "newest t= + 1h" (util/negative-vectors.sh's expired vector).
// Exits 0 and prints "pass: <summary>" on overall === 'pass'; exits 1
// otherwise and prints "<overall>: <primary error>" on the first line
// (contract C9: the primary error is the first "STATE: text" line), then
// every other error, one per line.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { selectKeyRecord } from '../doh.js';
import { bytesToBinary } from '../b64.js';
import { verifyMessage } from '../verify.js';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..', '..');

const args = process.argv.slice(2);
const realClock = args.includes('--real-clock');
const [msgPath, dnsArg] = args.filter((a) => a !== '--real-clock');
if (!msgPath) {
  console.error('usage: node tests/verify-file.mjs <path-to-message> [<path-to-dns.json>] [--real-clock]');
  process.exit(2);
}
const dnsPath = dnsArg || join(repoRoot, 'dns.json');

// Mock resolver over the nested dns.json shape:
// { domain: { "selector._domainkey": [["txt", value], ...],
//             "_domainkey": [["txt", value], ...] } }
// Every TXT record at a name is given, as DNS would, so a key next to a
// foreign record (-09 §3.7) and the Domain Policy Record (§3.8, at
// "_domainkey" itself) are judged exactly as the DoH path judges them.
const dns = JSON.parse(readFileSync(dnsPath, 'utf8'));
const txts = (domain, name) => (dns[domain.toLowerCase()]?.[name] || [])
  .filter(([type]) => type.toLowerCase() === 'txt').map(([, value]) => value);
const fetchKey = (selector, domain) => selectKeyRecord(txts(domain, `${selector}._domainkey`));
const fetchPolicy = (domain) => txts(domain, '_domainkey');

// Same "newest t= + 1h" deterministic clock as vectors.test.mjs, so a
// well-formed sample never spuriously trips the §14.3 14-day-old rule.
function pickNow(msg) {
  const ts = [...bytesToBinary(msg).matchAll(/[;\s]t=(\d+)/gi)].map((m) => parseInt(m[1], 10));
  const max = ts.filter(Number.isFinite).reduce((a, b) => Math.max(a, b), 0);
  return (max || 1782394336) + 3600;
}

// Bytes, not text: the message may carry octets that are not valid UTF-8.
const msg = new Uint8Array(readFileSync(msgPath));
const rep = await verifyMessage(msg, { fetchKey, fetchPolicy, now: realClock ? undefined : pickNow(msg) });

if (rep.overall === 'pass' || !rep.errors || !rep.errors.length) {
  console.log(`${rep.overall}: ${rep.summary}`);
} else {
  console.log(`${rep.overall}: ${rep.errors[0]}`);
  for (const e of rep.errors.slice(1)) console.log(e);
}
process.exit(rep.overall === 'pass' ? 0 : 1);
