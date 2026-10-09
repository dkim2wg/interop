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

## E. Outcome of a signature's items (consolidation, 2026-10-09)

The first round left the implementations disagreeing on edge cases. Every
verifier applies these, in this order, to one DKIM2-Signature's s= items:

1. Items with an unimplemented algorithm are ignored (A). If NO item names
   an implemented algorithm: `FAIL DKIM2-Signature i=<x> has no signature
   with a supported algorithm`. (§11.6: "If all signatures that can be
   checked fail then FAIL MUST be reported" -- vacuously; this is also the
   Turscar vector algorithm_only_future's expected state.)
2. A known algorithm's value must be a base64string: non-empty, base64
   characters, padded with "=" to a multiple of four (§2.13 "MUST be
   padded"). Else `PERMERROR ... syntax error` (before any key lookup).
   The same strictness applies to a key record's p= (after FWS removal).
3. For each implemented item, fetch the key:
   - DNS failure: `TEMPERROR ... public key <sel> could not be fetched`.
   - Record present but unusable (multiple records, syntax error, revoked,
     algorithm mismatch): `PERMERROR ... public key <sel> <why>` for the
     whole signature -- even if another item verifies. §11.6: all
     signatures MUST be checked and an error SHOULD be reported if any
     fails; a revoked key is not a key we may skip.
   - Record absent (NXDOMAIN / no TXT): skip this item.
4. If every implemented item was skipped as absent: `PERMERROR
   DKIM2-Signature i=<x> public key <first absent sel> does not exist`
   (§11.5: "a DNS result that indicates the key is absent MUST be reported
   as a PERMERROR").
5. Verify each item that has a key. Any failure: `FAIL` (naming the
   selector). Otherwise pass.

## F. Whole-field syntax and folding (follow-up review, 2026-10-09)

From docs/reviews/2026-10-09-perl-spec-06-fix-review.md (F1-F5). Perl
(`fa4f7bc`) is done; every implementation applies the same rules.

1. **Tag lists** (spec-06 §7, §8 `x-tag`; §11.2). A DKIM2-Signature or
   Message-Instance value is split on `;`. Empty fragments (`;;`, a trailing
   `;`) are skipped. Every other fragment must be
   `[FWS] name [FWS] "=" [FWS] [value] [FWS]` with name
   `ALPHA *(ALPHA / DIGIT / "_")` and value
   `x-tag-char *([FWS] x-tag-char)`, x-tag-char = `%x21-3A / %x3C-7E`.
   Anything else (`junk`, `9bad=foo`, `=v`, a NUL/DEL/8-bit byte in any
   value, known or unknown tag) makes the field a syntax error:
   `PERMERROR DKIM2-Signature i=<x> syntax error` /
   `PERMERROR Message-Instance m=<x> syntax error`. Never skip the fragment
   and verify the rest. A well-formed unknown tag is ignored for meaning
   but stays in the signing input as before.
2. **s= items** (§8.9). Split on `,`, then each item into exactly three
   parts on `:`. FWS is allowed (trimmed) around the comma, around each
   colon, and inside the base64 value (removed). It is NOT allowed inside the
   selector or algorithm name: `rsa- sha256`, `rsa-\r\n\tsha256`, `se l1`
   are syntax errors (whole signature PERMERROR), never normalised to a
   known name. Selector: `[A-Za-z0-9_-]+` labels joined by `.`; algorithm:
   `[A-Za-z0-9_-]+`. An item with fewer than three parts is a syntax error.
3. **h= hash-sets** (§7.3). Same rule: hash name has no internal FWS
   (`sha 256` is a syntax error), FWS allowed around it and inside the base64
   digests; a set without both digests is a syntax error, not skipped.
4. **Key records** (RFC 6376 §3.2 tag-list, spec-06 §11.5). Every value,
   including unknown/ignored tags, must match the value grammar
   (`VALCHAR = %x21-3A / %x3C-7E`, WSP/FWS only between VALCHARs). A NUL,
   DEL or 8-bit byte anywhere makes the record `has a syntax error`.
5. **Signer folding** (§8.8 Domain, §8.9, §2.13). A signer folds its own
   DKIM2-Signature / Message-Instance only where the grammar allows FWS:
   after a tag's `;`, inside a base64 value (mf=, rt=, r=, h= digests, s=
   signature values), beside the `:`s of an s= or h= item, after a list
   comma (not in s=). Never inside a Domain (d=, nd=), selector, algorithm
   or hash name: such a token stays whole on a line longer than 78, up to
   RFC 5322's 998. Test: d= of two 40-char labels + `.example.com` must sign
   and verify (mf= in that domain).
6. **Header recipe generation** must be linear in repeated identical
   fields: 16,000 identical `Comments:` fields plus one added must not take
   quadratic time (Perl went from 2.9 s to 0.06 s).
