import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyMessage } from '../verify.js';
import { parseKeyRecord } from '../doh.js';
import { bytesToBinary, binaryToBytes, textToBinary } from '../b64.js';

// A message is octets (spec-06 §6); the verifier must hash the bytes it was
// given, not a UTF-8 re-encoding of them. The fixture (signed by the Python
// signer with the repo's test1.dkim2.com key) has Big5 and Latin-1 bytes in
// the Subject and body that are NOT valid UTF-8 -- what 2003 spam and some
// current senders still emit. Every native verifier accepts it.

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..', '..');
const dns = JSON.parse(readFileSync(join(repoRoot, 'dns.json'), 'utf8'));
function fetchKey(selector, domain) {
  const rec = dns[domain]?.[`${selector}._domainkey`]?.[0]?.[1];
  if (rec === undefined) throw new Error('key-notfound');
  return parseKeyRecord(rec);
}
const fixture = new Uint8Array(readFileSync(join(here, 'fixtures', 'invalid-utf8-bytes.eml')));
const now = 1759579200 + 3600;

test('binary string helpers round-trip every byte value', () => {
  const all = new Uint8Array(256).map((_, i) => i);
  assert.deepEqual(binaryToBytes(bytesToBinary(all)), all);
});

test('textToBinary UTF-8 encodes text and maps surrogateescape to raw bytes', () => {
  assert.equal(textToBinary('café'), 'caf\xc3\xa9');
  // Python: 'caf\xe9'.decode('utf-8', 'surrogateescape') -> 'caf\udce9'
  assert.equal(textToBinary('caf\udce9'), 'caf\xe9');
});

test('verifyMessage given bytes hashes non-UTF-8 octets intact', async () => {
  const rep = await verifyMessage(fixture, { fetchKey, now });
  assert.equal(rep.overall, 'pass', rep.summary);
});

test('the same message decoded as UTF-8 text cannot verify (why bytes are the input)', async () => {
  const asText = new TextDecoder().decode(fixture); // invalid bytes -> U+FFFD
  const rep = await verifyMessage(asText, { fetchKey, now });
  assert.notEqual(rep.overall, 'pass');
});

test('a valid-UTF-8 message verifies the same from text and from bytes', async () => {
  const bytes = new Uint8Array(readFileSync(join(repoRoot, 'python', 'tests', 'expected', 'simple-rsa2048.eml')));
  const [fromBytes, fromText] = await Promise.all([
    verifyMessage(bytes, { fetchKey, now: 1782394336 + 3600 }),
    verifyMessage(new TextDecoder().decode(bytes), { fetchKey, now: 1782394336 + 3600 }),
  ]);
  assert.equal(fromBytes.overall, fromText.overall);
});
