// Verifier strictness (docs/superpowers/specs/2026-10-09-verifier-strictness-
// review-fixes.md, sections A-D) through the REAL verifyMessage() entry
// point, on genuinely signed one-hop messages: A signature algorithms
// (spec-06 §3.4, §8.9), B key records (§11.5, dns-00 §3.2/§3.4.1),
// C Message-Instance tag case and repeats (§7), D t= syntax (§8.4).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyMessage } from '../verify.js';
import { parseKeyRecord, fetchKey as dohFetchKey } from '../doh.js';
import { parseMessage, collectLevels } from '../parse.js';
import { canonHeaderHash, canonBody, signingInput } from '../canon.js';
import { hashB64, sha256Bytes } from '../crypto.js';
import { stringToBytes, bytesToB64, binaryToBytes } from '../b64.js';

const { subtle } = globalThis.crypto;
const T = 1740000000;
const b64text = (text) => bytesToB64(stringToBytes(text));
const MF = b64text('<sender@example.com>');
const RT = b64text('<rcpt@example.com>');

const rsaKp = subtle.generateKey(
  { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  true, ['sign', 'verify']);
const edKp = subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
const RSA_P = (async () => bytesToB64(new Uint8Array(await subtle.exportKey('spki', (await rsaKp).publicKey))))();
const ED_P = (async () => bytesToB64(new Uint8Array(await subtle.exportKey('raw', (await edKp).publicKey))))();

// Key records by selector; tests override. Every fetch is counted.
async function defaultRecords() {
  return {
    rsa: `v=DKIM1; k=rsa; p=${await RSA_P}`,
    ed: `v=DKIM1; k=ed25519; p=${await ED_P}`,
  };
}
function fetcher(records, calls) {
  return async (selector) => {
    calls.push(selector);
    if (!(selector in records)) throw new Error('key-notfound');
    return parseKeyRecord(records[selector]);
  };
}

const FIELDS = [{ name: 'From', value: ' a@example.com' }, { name: 'Subject', value: ' strict' }];
const BODY = 'hello\r\n';

// One-hop signed message. mi(hh, bh) gives the Message-Instance value;
// items are {sel, alg, key: 'rsa'|'ed'|undefined, sig: literal}; sigTags
// gives the DKIM2-Signature tags before s=.
async function signed({ mi = (hh, bh) => ` m=1; h=sha256:${hh}:${bh}`, items = [{ sel: 'rsa', alg: 'rsa-sha256', key: 'rsa' }],
  sigTags = ` i=1; m=1; t=${T}; d=example.com; mf=${MF}; rt=${RT}` } = {}) {
  const hh = await hashB64(binaryToBytes(canonHeaderHash(FIELDS)), 'sha256');
  const bh = await hashB64(binaryToBytes(canonBody(BODY)), 'sha256');
  const content = FIELDS.map((f) => `${f.name}:${f.value}\r\n`).join('') + '\r\n' + BODY;
  const miLine = `Message-Instance:${mi(hh, bh)}\r\n`;
  const sigLine = (sigs) => `DKIM2-Signature:${sigTags}; s=${items.map((it, n) => `${it.sel}:${it.alg}:${sigs[n]}`).join(',')}\r\n`;
  const draft = sigLine(items.map(() => '')) + miLine + content;
  const { headers } = parseMessage(draft);
  const miField = headers.find((f) => f.name === 'Message-Instance');
  const sigField = headers.find((f) => f.name === 'DKIM2-Signature');
  const input = binaryToBytes(signingInput([miField, sigField], sigField));
  const sigs = [];
  for (const it of items) {
    if (it.key === 'rsa') {
      sigs.push(bytesToB64(new Uint8Array(await subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, (await rsaKp).privateKey, input))));
    } else if (it.key === 'ed') {
      sigs.push(bytesToB64(new Uint8Array(await subtle.sign({ name: 'Ed25519' }, (await edKp).privateKey, await sha256Bytes(input)))));
    } else sigs.push(it.sig || '');
  }
  return sigLine(sigs) + miLine + content;
}

async function verify(raw, { records, calls = [], ...opts } = {}) {
  const recs = records || await defaultRecords();
  return verifyMessage(raw, { now: T + 10, fetchKey: fetcher(recs, calls), ...opts });
}

const sigLevel = (rep) => rep.levels.find((l) => l.kind === 'signature' && l.i === 1);

test('control: RSA and Ed25519 one-hop messages pass', async () => {
  let rep = await verify(await signed());
  assert.equal(rep.overall, 'pass', rep.summary);
  rep = await verify(await signed({ items: [{ sel: 'ed', alg: 'ed25519-sha256', key: 'ed' }] }));
  assert.equal(rep.overall, 'pass', rep.summary);
});

// --- A. signature algorithms ---------------------------------------------

test('A: RSA-signed but declared future-alg does not pass, and no key is fetched', async () => {
  const calls = [];
  const rep = await verify(await signed({ items: [{ sel: 'rsa', alg: 'future-alg', key: 'rsa' }] }), { calls });
  assert.notEqual(rep.overall, 'pass', rep.summary);
  assert.deepEqual(calls, []);
});

test('A: algorithm names are case significant: RSA-SHA256 is unknown, never verified as RSA', async () => {
  const calls = [];
  const rep = await verify(await signed({ items: [{ sel: 'rsa', alg: 'RSA-SHA256', key: 'rsa' }] }), { calls });
  assert.notEqual(rep.overall, 'pass', rep.summary);
  assert.deepEqual(calls, []);
});

test('A: ed25519-sha256x is unknown', async () => {
  const calls = [];
  const rep = await verify(await signed({ items: [{ sel: 'ed', alg: 'ed25519-sha256x', key: 'ed' }] }), { calls });
  assert.notEqual(rep.overall, 'pass', rep.summary);
  assert.deepEqual(calls, []);
});

test('A: sel2:future-alg:AAAA,sel1:rsa-sha256:<good> passes with exactly one key lookup', async () => {
  const calls = [];
  const rep = await verify(await signed({ items: [
    { sel: 'sel2', alg: 'future-alg', sig: 'AAAA' }, { sel: 'rsa', alg: 'rsa-sha256', key: 'rsa' }] }), { calls });
  assert.equal(rep.overall, 'pass', rep.summary);
  assert.deepEqual(calls, ['rsa']);
});

test('A: 4000 distinct unknown items plus one good item pass quickly with one key lookup', async () => {
  const items = [];
  for (let n = 0; n < 4000; n++) items.push({ sel: `s${n}`, alg: `future-${n}`, sig: 'AAAA' });
  items.push({ sel: 'rsa', alg: 'rsa-sha256', key: 'rsa' });
  const raw = await signed({ items });
  const calls = [];
  const t0 = Date.now();
  const rep = await verify(raw, { calls });
  assert.equal(rep.overall, 'pass', rep.summary);
  assert.deepEqual(calls, ['rsa']);
  assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0}ms`);
});

for (const [name, sig] of [['empty', ''], ['not base64', '!!!!'], ['base64 with junk', 'AAAA*AAA']]) {
  test(`A: a known algorithm with a ${name} signature value is a syntax error, before any lookup`, async () => {
    const calls = [];
    const rep = await verify(await signed({ items: [{ sel: 'rsa', alg: 'rsa-sha256', sig }] }), { calls });
    assert.equal(rep.overall, 'permerror', rep.summary);
    assert.equal(sigLevel(rep).detail, 'PERMERROR DKIM2-Signature i=1 syntax error');
    assert.deepEqual(calls, []);
  });
}

test('A: a signature value folded with FWS is still base64', async () => {
  const raw = (await signed()).replace(/(s=rsa:rsa-sha256:.{20})/, '$1\r\n  ');
  const rep = await verify(raw);
  assert.equal(rep.overall, 'pass', rep.summary);
});

test('A: rsa-sha256 against an Ed25519 key is an algorithm mismatch naming the selector', async () => {
  const records = { rsa: `v=DKIM1; k=ed25519; p=${await ED_P}` };
  const rep = await verify(await signed(), { records });
  assert.equal(rep.overall, 'permerror', rep.summary);
  assert.equal(sigLevel(rep).detail, 'PERMERROR DKIM2-Signature i=1 public key rsa algorithm mismatch');
});

test('A: ed25519-sha256 against an RSA key is an algorithm mismatch', async () => {
  const records = { ed: `v=DKIM1; k=rsa; p=${await RSA_P}` };
  const rep = await verify(await signed({ items: [{ sel: 'ed', alg: 'ed25519-sha256', key: 'ed' }] }), { records });
  assert.equal(rep.overall, 'permerror', rep.summary);
  assert.equal(sigLevel(rep).detail, 'PERMERROR DKIM2-Signature i=1 public key ed algorithm mismatch');
});

// --- B. key records --------------------------------------------------------

const keyCase = (name, record, expected) => test(`B: ${name}`, async () => {
  const rec = record.replace('<rsa>', await RSA_P);
  const rep = await verify(await signed(), { records: { rsa: rec } });
  if (expected === 'pass') { assert.equal(rep.overall, 'pass', rep.summary); return; }
  assert.equal(rep.overall, 'permerror', rep.summary);
  assert.equal(sigLevel(rep).detail, `PERMERROR DKIM2-Signature i=1 public key rsa ${expected}`);
});

keyCase('a repeated p= is a syntax error, not the good key', 'v=DKIM1; p=; p=<rsa>', 'has a syntax error');
keyCase('a repeated k= is a syntax error', 'v=DKIM1; k=rsa; k=rsa; p=<rsa>', 'has a syntax error');
keyCase('v=garbage is a syntax error', 'v=garbage; p=<rsa>', 'has a syntax error');
keyCase('v= not first is a syntax error', 'k=rsa; v=DKIM1; p=<rsa>', 'has a syntax error');
keyCase('a spec that is not a tag is a syntax error', 'v=DKIM1; junk; p=<rsa>', 'has a syntax error');
keyCase('a bad tag name is a syntax error', 'v=DKIM1; 9k=rsa; p=<rsa>', 'has a syntax error');
keyCase('no p= is a syntax error', 'v=DKIM1; k=rsa', 'has a syntax error');
keyCase('p= not base64 is a syntax error', 'v=DKIM1; k=rsa; p=!!notbase64!!', 'has a syntax error');
keyCase('p= base64 but not a key is a syntax error', 'v=DKIM1; k=rsa; p=AAAAAAAA', 'has a syntax error');
keyCase('unknown k= is an algorithm mismatch, never read as RSA', 'v=DKIM1; k=unknown; p=<rsa>', 'algorithm mismatch');
keyCase('k=RSA (case significant) is an algorithm mismatch', 'v=DKIM1; k=RSA; p=<rsa>', 'algorithm mismatch');
keyCase('empty p= is revoked', 'v=DKIM1; k=rsa; p=', 'has been revoked');
keyCase('no v=, trailing ; and unknown / retired tags are fine', 'k=rsa; h=sha1; n=note; s=email; t=y; x_1=z; p=<rsa>;', 'pass');
keyCase('FWS inside p= is removed', 'v=DKIM1;k=rsa;p= <rsa>', 'pass');
keyCase('tag names are case sensitive: P= is not p=', 'v=DKIM1; P=<rsa>', 'has a syntax error');

test('B: a key record with p= split by whitespace still imports', async () => {
  const p = await RSA_P;
  const rep = await verify(await signed(), { records: { rsa: `v=DKIM1; k=rsa; p=${p.slice(0, 100)} \t ${p.slice(100)}` } });
  assert.equal(rep.overall, 'pass', rep.summary);
});

// DoH: drive fetchKey() with a stubbed fetch returning DNS JSON.
async function withDoh(answers, fn) {
  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ Status: 0, Answer: answers }),
    { status: 200, headers: { 'content-type': 'application/dns-json' } });
  try { return await fn(); } finally { globalThis.fetch = real; }
}
const txt = (data) => ({ name: 'rsa._domainkey.example.com', type: 16, TTL: 300, data });

test('B: DoH: two TXT RRs (even identical) are multiple records', async () => {
  const p = await RSA_P;
  const rec = `"v=DKIM1; k=rsa; p=${p}"`;
  await withDoh([txt(rec), txt(rec)], async () => {
    const rep = await verifyMessage(await signed(), { now: T + 10, fetchKey: dohFetchKey });
    assert.equal(rep.overall, 'permerror', rep.summary);
    assert.equal(sigLevel(rep).detail, 'PERMERROR DKIM2-Signature i=1 public key rsa has multiple records');
  });
});

test('B: DoH: one TXT RR made of several strings is joined with nothing between', async () => {
  const p = await RSA_P;
  // Cloudflare presents each character-string quoted, separated by a space.
  const data = `"v=DKIM1; k=rsa; p=${p.slice(0, 200)}" "${p.slice(200)}"`;
  await withDoh([txt(data)], async () => {
    const rep = await verifyMessage(await signed(), { now: T + 10, fetchKey: dohFetchKey });
    assert.equal(rep.overall, 'pass', rep.summary);
  });
});

test('B: DoH: presentation-format escapes in a TXT string are decoded', async () => {
  const p = await RSA_P;
  // \059 is ";" and \" a quote: the decoded record has an x=\"; tag which is
  // ignored, so the key still verifies.
  const data = `"v=DKIM1; k=rsa; x=\\"q\\"\\059 p=${p}"`;
  await withDoh([txt(data)], async () => {
    const rep = await verifyMessage(await signed(), { now: T + 10, fetchKey: dohFetchKey });
    assert.equal(rep.overall, 'pass', rep.summary);
  });
});

test('B: DoH: an unquoted TXT data value (some resolvers) is taken as-is', async () => {
  const p = await RSA_P;
  await withDoh([txt(`v=DKIM1; k=rsa; p=${p}`)], async () => {
    const rep = await verifyMessage(await signed(), { now: T + 10, fetchKey: dohFetchKey });
    assert.equal(rep.overall, 'pass', rep.summary);
  });
});

// --- C. Message-Instance tags --------------------------------------------

test('C: a correctly signed instance written with H= passes', async () => {
  const rep = await verify(await signed({ mi: (hh, bh) => ` m=1; H=sha256:${hh}:${bh}` }));
  assert.equal(rep.overall, 'pass', rep.summary);
});

test('C: a correctly signed instance written with M= passes', async () => {
  const rep = await verify(await signed({ mi: (hh, bh) => ` M=1; h=sha256:${hh}:${bh}` }));
  assert.equal(rep.overall, 'pass', rep.summary);
});

for (const [name, mi] of [
  ['h= twice, bogus first', (hh, bh) => ` m=1; h=sha256:AAAA:AAAA; h=sha256:${hh}:${bh}`],
  ['h= twice, bogus last', (hh, bh) => ` m=1; h=sha256:${hh}:${bh}; h=sha256:AAAA:AAAA`],
  ['h= and H=', (hh, bh) => ` m=1; h=sha256:${hh}:${bh}; H=sha256:${hh}:${bh}`],
  ['m= and M=', (hh, bh) => ` m=1; M=1; h=sha256:${hh}:${bh}`],
]) {
  test(`C: a repeated Message-Instance tag (${name}) is a syntax error`, async () => {
    const rep = await verify(await signed({ mi }));
    assert.equal(rep.overall, 'permerror', rep.summary);
    assert.match(rep.summary, /PERMERROR Message-Instance m=1 syntax error/);
  });
}

// --- D. timestamps -----------------------------------------------------------

const withT = (t) => signed({ sigTags: ` i=1; m=1; t=${t}; d=example.com; mf=${MF}; rt=${RT}` });

for (const bad of ['garbage', '-5', '1e9', '0x10', '12 34', '', '+5', '1.5']) {
  for (const skipTimestamp of [false, true]) {
    test(`D: t=${JSON.stringify(bad)} is a syntax error${skipTimestamp ? ' even when skipping the age check' : ''}`, async () => {
      const rep = await verify(await withT(bad), { skipTimestamp });
      assert.equal(rep.overall, 'permerror', rep.summary);
      assert.match(rep.summary, /PERMERROR DKIM2-Signature i=1 syntax error/);
    });
  }
}

test('D: t= with surrounding WSP is fine', async () => {
  const rep = await verify(await withT(` ${T} `));
  assert.equal(rep.overall, 'pass', rep.summary);
});

test('D: t=0 is valid syntax and expired by the age check', async () => {
  const rep = await verify(await withT('0'));
  assert.equal(rep.overall, 'warn', rep.summary);
  assert.equal(sigLevel(rep).timestamp.status, 'expired');
});

test('D: t=10^12 does not overflow (a future timestamp, not expired)', async () => {
  const rep = await verify(await withT('1000000000000'));
  assert.equal(rep.overall, 'pass', rep.summary);
  assert.equal(sigLevel(rep).timestamp.ok, true);
});

// --- E. outcome of a signature's items --------------------------------------

test('E1: no item with an implemented algorithm is FAIL with the §E wording', async () => {
  const calls = [];
  const rep = await verify(await signed({ items: [{ sel: 'rsa', alg: 'future-alg', key: 'rsa' }] }), { calls });
  assert.equal(rep.overall, 'fail', rep.summary);
  assert.equal(sigLevel(rep).detail, 'DKIM2-Signature i=1 has no signature with a supported algorithm');
  assert.deepEqual(calls, []);
});

test('E2: an unpadded signature value (AAA) for a known algorithm is a syntax error', async () => {
  const calls = [];
  const rep = await verify(await signed({ items: [{ sel: 'rsa', alg: 'rsa-sha256', sig: 'AAA' }] }), { calls });
  assert.equal(rep.overall, 'permerror', rep.summary);
  assert.equal(sigLevel(rep).detail, 'PERMERROR DKIM2-Signature i=1 syntax error');
  assert.deepEqual(calls, []);
});

test('E2: an unpadded p= (AAA) is a key syntax error', () => {
  assert.throws(() => parseKeyRecord('v=DKIM1; k=rsa; p=AAA'), /key-syntax/);
});

test('E2: a real Ed25519 key with its "=" padding removed is a key syntax error', async () => {
  const p = (await ED_P).replace(/=+$/, ''); // 32 bytes: 43 chars + "="
  assert.notEqual(p, await ED_P);
  const rep = await verify(await signed({ items: [{ sel: 'ed', alg: 'ed25519-sha256', key: 'ed' }] }),
    { records: { ed: `v=DKIM1; k=ed25519; p=${p}` } });
  assert.equal(rep.overall, 'permerror', rep.summary);
  assert.equal(sigLevel(rep).detail, 'PERMERROR DKIM2-Signature i=1 public key ed has a syntax error');
});

const twoItems = () => signed({ items: [{ sel: 'rsa', alg: 'rsa-sha256', key: 'rsa' }, { sel: 'ed', alg: 'ed25519-sha256', key: 'ed' }] });

for (const [why, rec, wording] of [
  ['revoked', 'v=DKIM1; k=ed25519; p=', 'has been revoked'],
  ['syntax error', 'v=garbage; k=ed25519; p=AAAA', 'has a syntax error'],
  ['algorithm mismatch', 'v=DKIM1; k=rsa; p=AAAA', 'algorithm mismatch'],
]) {
  test(`E3: a ${why} key on one item is PERMERROR for the whole signature even though the other verifies`, async () => {
    const records = { rsa: `v=DKIM1; k=rsa; p=${await RSA_P}`, ed: rec };
    const rep = await verify(await twoItems(), { records });
    assert.equal(rep.overall, 'permerror', rep.summary);
    assert.equal(sigLevel(rep).detail, `PERMERROR DKIM2-Signature i=1 public key ed ${wording}`);
  });
}

test('E3: an absent key on one item is skipped when another item verifies', async () => {
  const records = { rsa: `v=DKIM1; k=rsa; p=${await RSA_P}` };
  const rep = await verify(await twoItems(), { records });
  assert.equal(rep.overall, 'pass', rep.summary);
});

test('E3: an absent key plus a failing item is FAIL', async () => {
  const records = { rsa: `v=DKIM1; k=rsa; p=${await RSA_P}` };
  const raw = (await twoItems()).replace(/(s=rsa:rsa-sha256:)(.)/, (_m, pre, c) => pre + (c === 'A' ? 'B' : 'A'));
  const rep = await verify(raw, { records });
  assert.equal(rep.overall, 'fail', rep.summary);
});

test('E4: every implemented item absent is PERMERROR naming the first absent selector', async () => {
  const rep = await verify(await twoItems(), { records: {} });
  assert.equal(rep.overall, 'permerror', rep.summary);
  assert.equal(sigLevel(rep).detail, 'PERMERROR DKIM2-Signature i=1 public key rsa does not exist');
});

test('E3: a DNS failure is TEMPERROR naming the selector', async () => {
  const rep = await verifyMessage(await signed(), { now: T + 10, fetchKey: async () => { throw new Error('key-temperror'); } });
  assert.equal(rep.overall, 'temperror', rep.summary);
  assert.equal(sigLevel(rep).detail, 'TEMPERROR DKIM2-Signature i=1 public key rsa could not be fetched');
});

// --- F. whole-field syntax (follow-up review) --------------------------------
// Each message below is genuinely signed over the field as written, so a
// verifier that skips or normalises the bad part would PASS it.

const SIG_TAGS = ` i=1; m=1; t=${T}; d=example.com; mf=${MF}; rt=${RT}`;
const MI_OK = (hh, bh) => ` m=1; h=sha256:${hh}:${bh}`;

for (const [name, extra] of [
  ['a fragment that is not a tag (junk)', ' junk'],
  ['a tag name starting with a digit (9bad=foo)', ' 9bad=foo'],
  ['a fragment with no tag name (=v)', ' =v'],
  ['a NUL in an unknown tag value', ' x=a\x00b'],
  ['a DEL in an unknown tag value', ' x=a\x7fb'],
  ['an 8-bit byte in an unknown tag value', ' x=a\xe9b'],
  ['a NUL in a known tag value (n=)', ' n=a\x00b'],
]) {
  test(`F1: DKIM2-Signature with ${name} is a syntax error`, async () => {
    const rep = await verify(await signed({ sigTags: `${SIG_TAGS};${extra}` }));
    assert.equal(rep.overall, 'permerror', rep.summary);
    assert.match(rep.summary, /PERMERROR DKIM2-Signature i=1 syntax error/);
  });
  test(`F1: Message-Instance with ${name} is a syntax error`, async () => {
    const rep = await verify(await signed({ mi: (hh, bh) => `${MI_OK(hh, bh)};${extra}` }));
    assert.equal(rep.overall, 'permerror', rep.summary);
    assert.match(rep.summary, /PERMERROR Message-Instance m=1 syntax error/);
  });
}

test('F1: empty fragments and well-formed unknown tags (FWS inside, empty value) pass', async () => {
  const rep = await verify(await signed({
    sigTags: ` i=1;; m=1; x_1 = a b\r\n\tc ; y=; t=${T}; d=example.com; mf=${MF}; rt=${RT}`,
    mi: (hh, bh) => ` m=1;; Zz9 =\tq ;h=sha256:${hh}:${bh};`,
  }));
  assert.equal(rep.overall, 'pass', rep.summary);
});

for (const [name, items, mutate] of [
  ['FWS inside the algorithm (rsa- sha256)', [{ sel: 'rsa', alg: 'rsa- sha256', key: 'rsa' }]],
  ['a fold inside the algorithm', [{ sel: 'rsa', alg: 'rsa-\r\n\tsha256', key: 'rsa' }]],
  ['FWS inside the selector (r sa)', [{ sel: 'r sa', alg: 'rsa-sha256', key: 'rsa' }]],
  ['a bad selector character', [{ sel: 'r$a', alg: 'rsa-sha256', key: 'rsa' }]],
  ['an empty selector label', [{ sel: 'rsa..x', alg: 'rsa-sha256', key: 'rsa' }]],
  ['a bad algorithm character', [{ sel: 'sel2', alg: 'future*alg', sig: 'AAAA' }, { sel: 'rsa', alg: 'rsa-sha256', key: 'rsa' }]],
  ['an item with only two parts', null, (raw) => raw.replace('s=rsa:', 's=sel2:future-alg,rsa:')],
  ['an item with four parts', null, (raw) => raw.replace('s=rsa:', 's=sel2:future-alg:AAAA:AAAA,rsa:')],
]) {
  test(`F2: s= with ${name} is a syntax error, before any lookup`, async () => {
    const calls = [];
    let raw = await signed(items ? { items } : {});
    if (mutate) raw = mutate(raw);
    const rep = await verify(raw, { calls });
    assert.equal(rep.overall, 'permerror', rep.summary);
    assert.equal(sigLevel(rep).detail, 'PERMERROR DKIM2-Signature i=1 syntax error');
    assert.deepEqual(calls, []);
  });
}

test('F2: FWS around the s= comma and colons and inside the signature passes', async () => {
  const raw = (await signed({ items: [
    { sel: 'sel2.sub ', alg: '\r\n\tfuture_alg ', sig: ' AA\r\n AA ' },
    { sel: '\r\n rsa\t', alg: ' rsa-sha256\r\n ', key: 'rsa' }] }))
    .replace(/(s=.*?rsa-sha256\r\n :.{30})/s, '$1\r\n\t');
  const rep = await verify(raw);
  assert.equal(rep.overall, 'pass', rep.summary);
});

for (const [name, mi] of [
  ['FWS inside the hash name (sha 256)', (hh, bh) => ` m=1; h=sha 256:${hh}:${bh}`],
  ['a fold inside the hash name', (hh, bh) => ` m=1; h=sha\r\n 256:${hh}:${bh}`],
  ['a set with no body hash', (hh, bh) => ` m=1; h=sha256:${hh}:${bh},sha512:AAAA`],
  ['a set with an empty body hash', (hh, bh) => ` m=1; h=sha256:${hh}:${bh},sha512:AAAA:`],
  ['a set with four parts', (hh, bh) => ` m=1; h=sha256:${hh}:${bh},sha512:AAAA:AAAA:AAAA`],
  ['an empty set', (hh, bh) => ` m=1; h=sha256:${hh}:${bh},`],
]) {
  test(`F3: h= with ${name} is a syntax error`, async () => {
    const rep = await verify(await signed({ mi }));
    assert.equal(rep.overall, 'permerror', rep.summary);
    assert.match(rep.summary, /PERMERROR Message-Instance m=1 syntax error/);
  });
}

test('F3: FWS around the hash name and colons and inside the digests passes', async () => {
  const rep = await verify(await signed({ mi: (hh, bh) =>
    ` m=1; h=\r\n sha256 :${hh.slice(0, 10)}\r\n\t${hh.slice(10)}\t:\r\n ${bh.slice(0, 5)} ${bh.slice(5)} , x-new\t: AAAA :AAAA` }));
  assert.equal(rep.overall, 'pass', rep.summary);
});

keyCase('F4: a NUL in an unknown tag value is a syntax error', 'v=DKIM1; n=a\x00b; k=rsa; p=<rsa>', 'has a syntax error');
keyCase('F4: a DEL in an unknown tag value is a syntax error', 'v=DKIM1; n=a\x7fb; k=rsa; p=<rsa>', 'has a syntax error');
keyCase('F4: an 8-bit byte in an unknown tag value is a syntax error', 'v=DKIM1; n=caf\xe9; k=rsa; p=<rsa>', 'has a syntax error');
keyCase('F4: a NUL in p= is a syntax error', 'v=DKIM1; k=rsa; p=\x00<rsa>', 'has a syntax error');
keyCase('F4: a NUL in k= is a syntax error', 'v=DKIM1; k=rsa\x00; p=<rsa>', 'has a syntax error');
keyCase('F4: WSP between VALCHARs in an unknown tag is fine', 'v=DKIM1; n=hello \t world ; k=rsa; p=<rsa>', 'pass');
