# Verifier strictness fixes from the spec-06 review — behaviour for every verifier

Date: 2026-10-09. Source: external review of the Perl library
(docs/reviews/2026-10-08-perl-spec-06.md), findings R1, R3–R8. Perl is fixed
(commits 3ae6dee, 7f99e1b, 969ff4a); this file states the required
behaviour so the C, Python, Go and browser-JS verifiers can be checked and
fixed from the spec, independently of the Perl code.

References: spec/draft-ietf-dkim-dkim2-spec-06.txt (§3.4, §7, §8, §8.4,
§8.9, §11.2, §11.5); draft-ietf-dkim-dkim2-dns-00 §3.2 (tag-lists), §3.4.1
(key record), §3.4.2.2 (TXT binding).

## A. Signature algorithms (R1, R3) — spec-06 §3.4, §8.9

- Implemented names are exactly `rsa-sha256` and `ed25519-sha256`
  (byte-for-byte; tag values are case significant, §8). `RSA-SHA256`,
  `ed25519-sha256x`, `future-alg` etc. are unknown.
- An s= item with an unknown algorithm is ignored entirely, BEFORE any key
  lookup (no DNS query, no callback) and is never verified with RSA or any
  other algorithm.
- A known algorithm whose value is not non-empty base64 (after removing
  FWS) is `PERMERROR DKIM2-Signature i=<x> syntax error`.
- The key must be of the algorithm's type (rsa-sha256 ↔ RSA key,
  ed25519-sha256 ↔ Ed25519 key), else
  `PERMERROR DKIM2-Signature i=<x> public key <selector> algorithm mismatch`.
- If no item is verifiable (all unknown, or no keys) the result is a
  permerror ("no verifiable signature items" or the implementation's
  equivalent) — never pass.
- Parse s= once per signature, not once per item access (thousands of items
  must stay linear).

Cases: a message correctly RSA-signed but declaring `future-alg` must NOT
pass; `sel2:future-alg:AAAA,sel1:rsa-sha256:<good>` passes with exactly one
key lookup; 4000 distinct unknown items plus one good item pass quickly
with one key lookup.

## B. Key records (R7, R8) — spec-06 §11.5, dns-00 §3.2, §3.4.1, §3.4.2.2

The whole record is a tag-list and must validate; never regex-search it.
- Split on `;`; empty specs (e.g. after a trailing `;`) are skipped; each
  spec is `[WSP] name [WSP] "=" value`, name `ALPHA *(ALPHA/DIGIT/"_")`.
  Tag names are case sensitive (as DKIM1). A repeated tag name makes the
  whole record invalid.
- `v=`: optional; if present it MUST be the first tag and exactly `DKIM1`,
  else the record is invalid.
- `k=`: default `rsa`; `rsa` and `ed25519` are known; anything else is an
  unsupported key type (never read as RSA).
- `p=`: required; FWS inside is removed; empty → revoked; otherwise must be
  base64 and import as a key of type k=.
- Unknown and retired tags (h=, n=, s=, t=) are ignored.
- DNS: the strings of ONE TXT RR are concatenated with nothing between;
  MORE THAN ONE TXT RR for the name is an error.

Errors (spec-06 §11.5 wording; the selector is named):
- `PERMERROR DKIM2-Signature i=<x> public key <sel> has multiple records`
- `PERMERROR DKIM2-Signature i=<x> public key <sel> has a syntax error`
  (not a tag-list, repeated tag, bad v=, no p=, p= not base64 / not a key)
- `PERMERROR DKIM2-Signature i=<x> public key <sel> has been revoked`
- `PERMERROR DKIM2-Signature i=<x> public key <sel> algorithm mismatch`
  (unknown k=, or k= not the signature algorithm's)
- An absent record keeps the implementation's existing behaviour; DNS
  failures stay TEMPERROR.

Cases: `v=DKIM1; p=; p=<good>` → syntax error (not the good key);
`v=garbage; p=<good>` → syntax error; `k=rsa; v=DKIM1; p=<good>` → syntax
error; `v=DKIM1; k=unknown; p=<good rsa>` → algorithm mismatch for
rsa-sha256; `v=DKIM1; k=rsa; p=` → revoked; two TXT RRs (even identical)
→ multiple records; one RR split into two strings → fine.

## C. Message-Instance tags (R4, R5) — spec-06 §7

- Tag identifiers are case insignificant: `M=1; H=sha256:...` is the same
  as `m=1; h=...` everywhere (parsing, finding m= to order instances for
  the signing input, reading h=, chain walks, validators). Signers keep
  emitting lowercase.
- A tag present twice, in any case combination (`h=...; h=...`,
  `h=...; H=...`, `m=1; M=1`), is `PERMERROR Message-Instance m=<x> syntax
  error` — never last-one-wins or first-one-wins.

Cases: a correctly signed instance written with `H=` passes; with `M=`
passes; `m=1; h=sha256:AAAA:AAAA; h=<correct>` (signed) does NOT pass.

## D. Timestamps (R6) — spec-06 §8.4, §11.2

- `t=` must be 1*DIGIT (after trimming the value's surrounding WSP). Any
  other value (`garbage`, `-5`, `1e9`, `0x10`, `12 34`) is `PERMERROR
  DKIM2-Signature i=<x> syntax error`, checked even when the implementation
  is told to skip the age check.
- `t=0` is valid syntax and subject to the age check (expired).
- Values up to at least 10^12 must not overflow.

## Also note

- Header field names in recipe JSON are lowercase-only (spec-06 §5); that is
  already enforced and is a different rule from C above.
