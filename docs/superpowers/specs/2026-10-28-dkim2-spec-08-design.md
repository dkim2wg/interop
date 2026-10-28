# DKIM2 draft -08: implementation contract

Spec: `spec/draft-ietf-dkim-dkim2-spec-08.txt` (published 2026-10-27). Our code targets -07.
Audit items A-M: `docs/superpowers/specs/2026-10-28-dkim2-spec-08-audit.md`.

This document fixes every choice that the spec leaves open, so that all of the
implementations behave identically. Where it says "MUST", that is our contract,
not necessarily the spec's. The -07 contract (C1-C9 in
`2026-10-18-dkim2-spec-07-design.md`) still holds except where this one
replaces it; in particular the C9 check order and "first error is the result".

## Decisions (Bron, 2026-10-28)

1. **Auto-Submitted / VBR-Info are hashed.** Every implementation flips in one
   deploy. No fallback to the -07 list. Bron refreshes the hm vendor straight after.
2. **ML-DSA-44: DEFERRED** (revised 2026-10-28, see D8). Most of our languages have no
   library that verifies pure ML-DSA-44 with a context string.
3. **Null body Recipe: the result stays PASS**, plus a "not fully verified"
   property (D9).
4. (2026-10-26, with Richard) **Tag names and JSON keys are strictly lowercase.**
   This reverses -07 Decision 2 ("liberal in receive").

## D1. Ignored header fields (§4)

Remove `auto-submitted` and `vbr-info` from the ignore list in every signer and
verifier. Nothing else changes in the list: `Received-*` and `X-*` stay as prefixes.

## D2. AND/OR syntax in h= and s= (§9.3, §10.9)

- Parse `h=` as hash-any = hash-all *("|" hash-all), where hash-all =
  hash-set *("," hash-set). `s=` has the same shape. FWS is allowed on either
  side of `|` and `,`.
- An empty member gives "syntax error": a leading, trailing or doubled `|` or `,`.
- The duplicate rules apply across the WHOLE tag, not per group. A hash name
  twice anywhere in `h=` gives "has a duplicate hash algorithm". A selector twice
  anywhere in `s=` gives "has a duplicate selector".
- Remove the "has more selectors than allowed" check and its string. -08 allows
  any number of same-algorithm signatures if each has its own selector.
- Signing input (§12.8): blank only the base64 signature values. Selectors,
  algorithm names and every `:` `,` `|` stay, byte for byte after the usual
  WSP removal.
- Signers keep emitting a single `,` group (all signatures required, as today).
  No signer emits `|`.

## D3. Combining signature results (§14.6)

Each sig-set in `s=` order gives one intermediate result:

| condition | result | string |
|---|---|---|
| verifies | PASS | — |
| sig-name not implemented (includes the old `mldsa44-ed25519-sha512`) | PERMERROR | `DKIM2-Signature i=<x> selector <s> algorithm unknown` |
| key fetch / key error | as §14.5 today | existing §14.5 strings |
| signature doesn't verify | FAIL | `DKIM2-Signature i=<x> selector <s> incorrect signature` |

- Don't fetch a key for an unimplemented algorithm. Prefetch skips those selectors.
- **Local limit (review of Perl 0.28):** -08 dropped "more selectors than
  allowed", and every item can cost a DNS lookup and a verify. So an `s=`
  with more than **8** items (any algorithms, any groups) gives
  `PERMERROR: DKIM2-Signature i=<x> has more than 8 signatures`. It is a
  §14.2 check, made after the duplicate-selector check and before any key
  is fetched.
- Every item's value must be a non-empty base64string, whatever its
  algorithm, or the result is "syntax error". The same goes for both
  hashes of every hash-set in `h=`.
- sig-all: all PASS gives PASS. Otherwise, if every non-PASS is TEMPERROR, the
  result is TEMPERROR. Otherwise any FAIL gives FAIL. Otherwise PERMERROR.
- sig-any: any PASS gives PASS. Otherwise any TEMPERROR gives TEMPERROR.
  Otherwise any FAIL gives FAIL. Otherwise PERMERROR.
- **Reported string** (so all verifiers agree):
  - One group: the string of the first sig-set, in `s=` order, whose own result
    equals the group's result.
  - More than one group, result FAIL: `FAIL: DKIM2-Signature i=<x> no group of
    signatures passed`.
  - More than one group, result TEMPERROR or PERMERROR: the string of the first
    sig-set, in `s=` order, with that result.
- Verify every sig-set. Don't short-circuit inside a tag: the result has to be
  deterministic whatever the evaluation order.
- **Amends C9:** an item's key error only counts if no `|` group passes, so
  §14.5 and §14.6 can't be separate passes over every signature any more.
  They are one step, signature by signature from i=1 up: each item's key,
  then its signature, then the groups combined. A key error at i=2 and a bad
  signature at i=1 now report the i=1 FAIL.
- Folding (Perl `fold_header`): FWS is allowed on either side of `,` and `|`
  in `s=` and `h=` (§9.3, §10.9 ABNF), so a fold may go there. A fold must
  never land inside a selector or algorithm name.

## D4. Combining hash results (§14.7)

Each hash-set in `h=` order: PASS if its header hash and its body hash both
match, FAIL if either doesn't, PERMERROR if the hash name isn't implemented.
There is no TEMPERROR. The `hash_algs` table decides "implemented":
sha256 and sha512.

- hash-all: all PASS gives PASS. Otherwise any FAIL gives FAIL. Otherwise PERMERROR.
- hash-any: any PASS gives PASS. Otherwise any FAIL gives FAIL. Otherwise PERMERROR.
- Strings for a set:
  - `FAIL: Message-Instance m=<x> header hash <alg> mismatch` when the header
    hash is wrong. Header comes before body, as in C9.
  - `... body hash <alg> mismatch` when only the body hash is wrong.
  - `PERMERROR: Message-Instance m=<x> algorithm <alg> unknown`, which replaces
    "no supported hash algorithm".
- Reported string: the same rules as D3. With one group, the first set (in `h=`
  order) whose result equals the group's. With more than one group, FAIL gives
  `FAIL: Message-Instance m=<x> no group of hashes passed`, and otherwise the
  first set with that result.
- This replaces C9's "every header hash before any body hash" for multi-set
  groups. Within a group the order is `h=` order, and each set reports its
  header before its body.
- §16.4 inbound DSN with no body: a set passes when its header hash matches.
  (Perl only; the other impls have no inbound DSN check.)

## D5. PERMERROR becomes FAIL (§14.3, §14.4, §14.8)

The text of these strings is unchanged; only the state changes:
- the timestamp checks: expired, from the future;
- all seven Chain of Custody strings;
- `matching From is not authentic`.

The A-R result is `dkim2=fail` for each of them. The check order is still C9.

## D6. Recipe errors (§14.2)

New string: `PERMERROR: Message-Instance m=<x> Recipe <path> is invalid`.
- `contains invalid JSON` stays for whole-document problems: not parseable;
  not an object; duplicate keys; a key that isn't lowercase (D10); any JSON
  number with a fraction or exponent, wherever it is (`1.5`, `1e0`: JSON
  libraries disagree on whether `1e0` is an integer, so it's judged from the
  text); `h` not a non-empty object; `b` not an array or null; neither `h`
  nor `b`.
- `Recipe <path> is invalid` covers one step that the schema or §5.1/§5.2
  rejects:
  - the step isn't an object;
  - the step doesn't have exactly one of `c`/`d`/`u`;
  - a `c` that isn't exactly two JSON integers >= 1, or has start > end;
  - a header entry in `h` that isn't an array: path `h.<name>`, no index;
  - an empty `d`/`u` array, or a non-string in one;
  - CR or LF in a line;
  - non-canonical base64;
  - copy ranges that overlap or are out of order. This replaces today's
    recipe_order_error wording.
- `<path>` is `b[<n>]` or `h.<name>[<n>]`. `<n>` is the step's 0-based index;
  `<name>` is the JSON key exactly as given, with every octet outside
  0x21-0x7E (space included) written as `\xHH` in uppercase hex.
- Every whole-document check comes before any step check. For example,
  `{"b":[{"x":1}],"h":[]}` is "contains invalid JSON". Report the first invalid step: `b` first, then `h`
  names in byte order, then steps in order.
- A copy range past the end of the message is still found when the Recipe is
  applied, and reports as today.

## D7. Key checks (§3.2, §14.5)

New string: `PERMERROR: DKIM2-Signature i=<x> public key <s> is malformed`, given for:
- an RSA key shorter than 1024 bits. This replaces Perl's "is shorter than 1024
  bits" and its equivalents. Keys up to 4096 bits MUST verify, and larger ones
  may.
- an Ed25519 `p=` that doesn't decode to exactly 32 octets;
- an ML-DSA-44 `p=` that doesn't decode to exactly 1312 octets.

- any other `p=` that is base64 but doesn't load as a key of its type.

`p=` that isn't base64 at all is still "has a syntax error". An Ed25519 key
published as a DER SubjectPublicKeyInfo is malformed: a real one exists
(proteamail.com), but -08 says Ed25519 keys are exactly 32 octets.

## D8. ML-DSA-44: deferred (§3.4)

Bron, 2026-10-28: not implemented for now, because no library is available
in most of our languages:
- C (OpenSSL 3.5+) and Node 25 have it natively;
- Perl's Crypt::PQClean::Sign 0.04 verifies with an empty ctx only;
- Python's cryptography 46 has none;
- Go 1.26 keeps ML-DSA internal;
- the browser has no WebCrypto ML-DSA.

So `mldsa44` (and the old `mldsa44-ed25519-sha512`) is an unimplemented
algorithm in every verifier: a PERMERROR item, "selector <s> algorithm
unknown" (D3), which a `|` alternative can override. No key is fetched for
it. Revisit once DKIMKEYS defines its key type.

## D9. Null body Recipe gives "not fully verified" (§13)

- If any MI m=k (k >= 2) has `"b": null`, the body hashes of MIs below k can't
  be checked. The result stays PASS, and the verifier exposes:
  - Perl: `$result->fully_verified` (0/1);
  - Python: `.fully_verified`;
  - Go: `FullyVerified bool`;
  - C: `fully_verified`;
  - JS: `fullyVerified`.
  It's also false for any non-pass result, and for a verification that
  skipped body hashes on purpose (Perl's HeadersOnly/InstancesOnly modes).
  Any other problem is already an error.
- Gaps or duplicates in m= or i= are errors already, as today.
- The browser verifier page and the validator display it.
- Not in A-R for now.

## D10. Strict lowercase (§8, §5)

- A tag name in MI or DKIM2-Signature that isn't lowercase is an unknown tag
  and is ignored. So `M=1` alone gives `tag=m missing`, and `m=1; M=2` is not a
  duplicate.
- A JSON key at any level (top, `h` header names, step keys) that isn't
  lowercase gives `contains invalid JSON`. Duplicate keys are compared exactly.

## D11. DSN generation (§7.1 item 4, §16.2)

The Perl DSN generator MUST choose a d= that relaxed-matches a domain in the
reported message's top `rt=`. If no configured key can do that, send no DKIM2
DSN. The check is the receiver's own `_check_alignment`, in
`DSN->may_generate(Domain => ...)`; `generate` and `Reflector::generate_dsn`
pass their signing domain, and the latter returns "no DSN" rather than dying.

## D12. Not done

- Provisionally Verified (§13.2): no new A-R state. Perl already has
  `provisionally_verified()` (since 0.23, used to gate DSNs). It now runs
  -08's steps 1, 2, 3 and 5:
  - step 5 is new: top d= relaxed-matches top mf= unless mf= is null;
  - it no longer checks timestamps, because §13.2 doesn't list them, so a
    DSN may report on a message too old to be Fully Verified;
  - step 4 (the envelope) belongs to the SMTP caller.
  Other implementations that have the notion follow the same rules.
- Replay (§15) stays decided against.

## D13. Names and versions

- DKIM2_DRAFT is `ietf-dkim-dkim2-spec-08` everywhere; DKIM2_DATE is the date
  each repo's change lands.
- "Validly Signed" becomes "Fully Verified" in comments, POD, docs and site text.
- Update `§` references for the renumbered §13.x and §16.x only. The version
  tests ban `spec-07`/`draft-07`, with the named history exceptions.
- Replace `c/dkim2-spec.txt` with the -08 text.

## Rollout

D1 makes this a lockstep change. Nothing deploys until every implementation is at -08.
1. Perl (Mail::DKIM2 0.28): whole contract, tests first; one release.
2. Port to Python, Go, C and JS, one at a time; shared vectors for D2-D10.
3. Mailman (`dkim2` first, then backport to 3.3.10 and cherry-pick to 3.3.8)
   and Sympa.
4. Deploy everything together, then run the prod acceptance tests
   (list smoke, validator good/bad, /verify/).
5. Bron uploads 0.28 to CPAN and refreshes hm.
