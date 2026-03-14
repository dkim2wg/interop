---
name: dkim2-spec-review
description: Issues and clarity suggestions for draft-clayton-dkim2-spec-08 found during interop testing
type: project
---

# draft-clayton-dkim2-spec-08 Review Notes

Issues found during interop testing between three independent implementations
(Perl, Python, Haskell).

## Confirmed Interop Failures

### 1. Signing input header ordering (Section 11.5) — INTEROP FAILURE

The spec says: "First come the Message-Instance header fields in ascending
version (v=) order. Second are the DKIM2-Signature header fields in ascending
sequence (i=) order. Last of all is an incomplete DKIM2-Signature header
field."

This was read two different ways:

- **All-then-all:** All MI headers first, then all DKIM2-Signature headers.
  For a 2-hop message signing i=2:
  `MI v=1, MI v=2, Sig i=1, Sig i=2 (incomplete)`

- **Interleaved:** Each DKIM2-Signature follows the MI headers that existed
  when it was created:
  `MI v=1, Sig i=1, MI v=2, Sig i=2 (incomplete)`

The interleaved ordering is the correct semantic interpretation: when sig i=1
was created, only MI v=1 existed. The signing input for sig i=2 should
reflect the full chain of headers as they were added in sequence.

**Suggested fix:** Replace "First come... Second are..." with explicit
interleaved ordering and a worked example for a multi-hop message.

### 2. "Null s=" ambiguity in signing input (Section 11.5) — INTEROP FAILURE

The spec says: "the signature value (s=) is null (that is the base64 value
is absent)."

This could mean:
- `s=` — literally nothing after the equals sign
- `s=<base64 of JSON with empty signature strings>` — preserving the
  selector/algorithm structure with empty values
- The s= tag is entirely absent

Because s= is included in the signing input, any disagreement here means
signatures cannot be cross-verified.

**Trade-offs:**
- `s=` (empty): Simpler, but loses selector and algorithm information. With
  multiple signatures (RSA + ed25519), the verifier can't confirm which
  algorithms were intended. The signing input becomes identical regardless
  of algorithm count.
- `s=<JSON with empty values>`: Preserves structure. The verifier can
  confirm the signing input included the correct algorithm/selector pairs.

**Suggested fix:** Provide an explicit byte-for-byte example of the
incomplete DKIM2-Signature header as it appears in the signing input.

### 3. Header ordering for duplicates in header hash (Section 5.2) — INTEROP FAILURE

The spec says duplicate headers with the same field name are "placed in the
order in which they occur in the message header, from the top downwards."

Two of three implementations use bottom-to-top (reverse message order).
On a message with 5 authentication-results headers, both orderings produce
24 canonicalized headers totalling 2753 bytes but completely different hashes.

**Suggested fix:** Clarify which direction. Either works as long as all
implementations agree.

### 4. s= tag JSON schema — "items" keyword collision (Section 7)

The signature JSON schema uses `"items"` as both a property name and a JSON
Schema keyword. Three implementations produced three interpretations:

1. `{"items": ["selector", "algorithm", "value"]}` — literal object reading
2. `["selector", "rsa", "sig", "selector2", "ed25519", "sig2"]` — flat array
3. `[["sel1", "rsa", "<sig>"], ["sel2", "ed25519", "<sig>"]]` — array-of-arrays

**Suggested fix:** Replace the JSON Schema with a concrete wire format
example showing the expected structure before and after base64 encoding.

## Spec Bugs

### 5. Typo: "DNS" instead of "DSN" (Section 13)

Line: "If this field is null ("mf=<>") then a DNS MUST NOT be sent."
Should be "DSN".

### 6. Numbered list uses "1)" three times (Section 13.1.2)

The three verification steps are all numbered "1)" instead of "1)", "2)",
"3)".

### 7. JSON Schemas are not valid JSON Schema (Sections 4, 6, 7)

Several JSON Schemas in the spec are syntactically invalid:

- Section 4 recipe schema: `"anyOf"` appears inside `"properties"` which is
  not valid placement. The `"recipes": { "type": "string" }` keyword is not
  a standard JSON Schema keyword.

- Section 6 SMTP params schema: `"description": "MAIL FROM"` appears at the
  same level as property names inside `"properties"`. The `"mf"` property is
  just `"mf": "string"` instead of `"mf": {"type": "string"}`.

- Section 7 signature schema: `"items"` is used as both a property name and
  a JSON Schema keyword (see issue #4 above).

Since these schemas are meant to be normative definitions of wire formats,
they should either be corrected to valid JSON Schema or replaced with
concrete examples (which may be clearer for implementers anyway).

### 8. Recipe copy ranges use strings inside JSON (Section 4.1/4.2)

The r= tag value is base64-encoded JSON, but copy ranges within the JSON are
encoded as parenthetical strings like `"(1-5)"` rather than JSON arrays like
`[1, 5]`. Since the data is already JSON, embedding a custom string format
for structured data adds unnecessary parsing complexity.

**Suggested fix:** Use `[start, end]` JSON arrays for copy ranges:
```json
{"b": [[1, 500], "PGEgaHJlZj0i..."]}
```

### 9. Recipe schema says `"recipes"` type is string (Section 4)

The recipe schema declares `"recipes": { "type": "string" }` but recipes are
either copy-range expressions or base64-encoded replacement text. The schema
doesn't describe the `"(start-end)"` format at all, and doesn't indicate how
to distinguish copy ranges from replacement text.

## Clarity Improvements Needed

### 10. Algorithm identifiers (Section 7 / Section 3)

The spec uses short names "rsa" and "ed25519" in the s= tag JSON. This is a
departure from DKIM1 (RFC 6376) which uses compound names like "rsa-sha256".

Using bare key-type names implicitly locks SHA-256 as the only hash, with no
way to express a different hash without defining entirely new identifiers.

**Options:**
- Keep short names but explicitly state SHA-256 is always implied
- Use compound names like DKIM1 for consistency
- Either way, define an IANA registry

### 11. Relay mf= update requirement (Section 11.2)

The spec requires d= to match mf= at every hop, and the chain of custody
requires mf of hop N to match an rt of hop N-1. The implication is that each
relay MUST update MAIL FROM to its own domain — but this is not stated
explicitly.

**Suggested fix:** Add explicit text stating that when a relay adds a new
DKIM2-Signature, it MUST set mf= to an address in its own domain (matching
d=), both for domain alignment and bounce routing.

### 12. Multiple signature items — signing semantics (Section 7/11.5)

When a DKIM2-Signature contains multiple signature items (e.g. RSA +
ed25519), the spec doesn't clearly state whether all items sign the same
signing input or each has its own signing process. This should be stated
explicitly.

### 13. Signing input and folding relationship (Section 11.5)

The spec describes canonicalization steps that handle folded headers but
doesn't explicitly state whether the signer MUST canonicalize its own
newly-created header before signing. A note clarifying that "the signer MUST
apply the same canonicalization to its own header before computing the hash"
would prevent subtle bugs.

### 14. Canonicalization worked example needed (Section 11.5)

A worked example showing a folded header before and after canonicalization
would help implementers verify their code. The interaction between unfolding
and WSP collapsing can be subtle.

### 15. Signing input worked example needed (Section 11.5)

A complete worked example showing a sample message, its MI/DK2 headers, the
canonicalized signing input (byte-for-byte), and the resulting hash/signature
would be invaluable. This was the most common source of interop failures.

### 16. m= tag with null MAIL FROM (Section 10/13)

The m= tag is required (Section 10) and `mf=<>` is valid for DSNs
(Section 13). But the verification behaviour for `mf=<>` is not explicit —
should the d= vs mf= domain match be skipped? Should the chain of custody
check be skipped for the DSN hop?

### 17. IANA Considerations incomplete (Section 16)

Section 16 just says "TBA". At minimum it should define registries for:
- Algorithm identifiers for the s= tag
- Flag values for the f= tag
- Tag names for DKIM2-Signature and Message-Instance headers

### 18. EAI and Security Considerations incomplete (Sections 15, 17)

Both sections just say "TBA".

### 19. Section 12.4 step 2 wording (Section 12.4)

"compute the signatures of the canonical copy" should say "compute the hash
of the canonical copy, then verify using the public key and signature value".
The current wording conflates hashing and signing.
