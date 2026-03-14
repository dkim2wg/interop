---
name: dkim2-spec-review
description: Issues and clarity suggestions for draft-clayton-dkim2-spec-08 found during interop testing
type: project
---

# draft-clayton-dkim2-spec-08 Review Notes

## Issues Found During Interop Testing

### 1. Header ordering for header hash (Section 5.2) — CONFIRMED INTEROP FAILURE

The spec says duplicate headers with the same field name are "placed in the
order in which they occur in the message header, from the top downwards."
The hs implementation and our Perl implementation both use bottom-to-top
(reverse message order) and agree on hashes.

**This has been confirmed as a real interop failure.** During testing between
the Perl and Python DKIM2 implementations on a message with 5
authentication-results headers and 1 received-spf header:

- **Perl implementation:** iterates bottom-to-top (`reverse`) within each
  header name — authentication-results headers hashed starting from the
  bottom-most in the message.
- **Python implementation:** iterates top-to-bottom (natural message order)
  within each header name — authentication-results headers hashed starting
  from the top-most in the message.

Both produce the same 24 canonicalized headers totalling 2753 bytes, but
the different ordering produces completely different SHA-256 hashes
(`PBdChCKT...` vs `VupJfc5...`). This means signatures cannot be
cross-verified between implementations that disagree on this ordering.

**Suggested fix:** Clarify whether duplicate headers with the same name are
hashed top-to-bottom or bottom-to-top. The current spec text says "from the
top downwards" but two of three implementations use bottom-to-top. Either
direction works as long as all implementations agree.

### 2. Algorithm identifiers in s= tag (Section 7 / Section 10)

The spec uses short names "rsa" and "ed25519" for algorithm identifiers in
the s= tag JSON. This is a departure from DKIM1 (RFC 6376) which uses
compound names like "rsa-sha256" that explicitly pair the key type with the
hash algorithm (ABNF: `sig-a-tag-k "-" sig-a-tag-h`).

Using bare key-type names implicitly locks SHA-256 as the only hash, with no
way to express a different hash without defining entirely new identifiers.
Hannah Stern's README also noted: "I think the algorithm specifiers would
need to be changed to include the hash name!"

**Options:**
- Keep short names but explicitly state SHA-256 is always implied, and
  document how new hashes would be added
- Use compound names like DKIM1 for consistency and future-proofing
- Either way, define an IANA registry (Section 16 currently says "TBA")

### 3. "Null s=" ambiguity in signing input (Section 11.5) — CONFIRMED INTEROP FAILURE

The spec says: "the signature value (s=) is null (that is the base64 value
is absent)."

This is ambiguous. It could mean:
- The s= tag is present with an empty value: `s=`
- The s= tag contains base64-encoded JSON with empty signature value strings:
  `s=WyJzZWwiLCJyc2EiLCIiXQ==` (i.e. `["sel","rsa",""]`)
- The s= tag is entirely absent from the header

**This has been confirmed as a real interop failure.** During testing between
the Perl and Python DKIM2 implementations:

- The **Python implementation** reads "the base64 value is absent" as meaning
  `s=` — literally nothing after the equals sign. The entire base64-encoded
  blob is absent from the signing input.
- The **Perl implementation** reads "the signature value is null" as meaning
  the signature value *within* the JSON structure is empty, but the JSON
  structure (including selector and algorithm) is preserved:
  `s=W1sic2VsMSIsInJzYSIsIiJdXQ==` (which decodes to `[["sel1","rsa",""]]]`)

Both are defensible readings. Because the s= tag is included in the signing
input, this difference means the two implementations compute different signing
inputs and **signatures cannot be cross-verified**. This is the
highest-priority spec clarification needed.

**Trade-offs between the two interpretations:**

- `s=` (empty): Simpler, but loses the selector and algorithm information.
  With multiple signature items (e.g. RSA + ed25519), the verifier can't
  confirm which algorithms were intended or which selector maps to which
  signature. The signing input becomes identical regardless of how many or
  which algorithms are used.

- `s=<base64 of JSON with empty values>`: Preserves the selector/algorithm
  structure. The verifier can confirm the signing input included the correct
  algorithm/selector pairs. However, this means the signer must decide all
  its algorithms and selectors before computing the hash for any of them.

**Suggested fix:** Provide an explicit example of the incomplete
DKIM2-Signature header as it appears in the signing input, showing exactly
what the s= tag looks like. This single example would resolve the ambiguity
immediately. We recommend preserving the JSON structure with empty signature
values, as it provides a more complete and verifiable signing input,
particularly for multi-algorithm signatures.

### 4. s= tag JSON schema is misleading — "items" keyword collision (Section 7)

The JSON schema for the s= tag uses `"items"` as both a **property name**
(the object key holding the signature data) and a **JSON Schema keyword**
(defining the array element type). This has caused three different
implementations to produce three different interpretations:

The schema as written in the spec:
```json
{
  "type": "object",
  "properties": {
    "items": {
      "type": "array",
      "items": {"type": "string"},
      "minItems": 3, "maxItems": 3
    }
  }
}
```

The three interpretations seen in interop testing:

1. **Python implementation (AI-written):** Read the schema literally as
   `"type": "object"` with an `"items"` property, producing:
   `{"items": ["selector", "algorithm", "value"]}`

2. **hs implementation (human-written):** Ignored the object wrapper and
   produced a flat array:
   `["selector", "rsa", "sig", "selector2", "ed25519", "sig2"]`

3. **Perl implementation (our reading):** Interpreted the inner `"items"`
   as defining array-of-arrays:
   `[["sel1", "rsa", "<sig>"], ["sel2", "ed25519", "<sig>"]]`

The Python AI was particularly insistent that its reading was correct,
arguing that `"type": "object"` at the top level unambiguously means the
result should be a JSON object, not an array. This is a reasonable reading
of the schema as written.

**This is a significant interop problem.** The collision between the JSON
Schema keyword `"items"` and the property name `"items"` makes the schema
genuinely ambiguous. At minimum, the property should be renamed to avoid
this collision (e.g. `"signatures"` or `"sigs"`).

**Suggested fix:** Either:
- Rename the property to avoid the keyword collision, OR
- Replace the JSON Schema with a concrete example showing the expected
  wire format before and after base64 encoding, e.g.:
```
[["sel1", "rsa", "<base64sig>"], ["sel2", "ed25519", "<base64sig>"]]
```
  This would eliminate any ambiguity about the intended structure.

### 12. Signing input header ordering ambiguity (Section 11.5) — CONFIRMED INTEROP FAILURE

The spec says: "First come the Message-Instance header fields in ascending
version (v=) order. Second are the DKIM2-Signature header fields in ascending
sequence (i=) order. Last of all is an incomplete DKIM2-Signature header field."

This was read two different ways:

- **Python implementation:** All MI headers first, then all DKIM2-Signature
  headers, then the incomplete sig. For a 2-hop message signing i=2:
  `MI v=1, MI v=2, Sig i=1, Sig i=2 (incomplete)`

- **Perl implementation:** Interleaved, so each DKIM2-Signature is preceded
  only by the headers that existed when it was created:
  `MI v=1, Sig i=1, MI v=2, Sig i=2 (incomplete)`

The interleaved ordering is the correct semantic interpretation: when sig i=1
was created, only MI v=1 existed. The signing input for sig i=2 should reflect
the full chain of headers as they were added in sequence. The "all MIs first"
reading groups headers by type rather than by chronological order, which loses
the relationship between each signature and the message state it signed.

**This has been confirmed as a real interop failure.** Signatures cannot be
cross-verified between the two implementations because the signing input
differs.

**Suggested fix:** Replace "First come the Message-Instance header fields...
Second are the DKIM2-Signature header fields..." with explicit interleaved
ordering, e.g.:

> "The headers are placed in the order they were added to the message:
> Message-Instance v=1, DKIM2-Signature i=1, Message-Instance v=2,
> DKIM2-Signature i=2, and so on. Last of all is the incomplete
> DKIM2-Signature header field (the one this system is creating)."

A worked example for a multi-hop message would eliminate any remaining
ambiguity.

### 13. Recipe copy ranges use strings instead of JSON arrays (Section 4.1/4.2)

The r= tag value is base64-encoded JSON, but copy ranges within the JSON are
encoded as parenthetical strings like `"(1-5)"` rather than as JSON arrays
like `[1, 5]`. Since the recipe data is already JSON, using strings to
represent structured data inside JSON is unnecessary and error-prone — it
requires custom parsing logic on top of the JSON parser that's already in use.

JSON arrays are the natural representation: `[1, 5]` is unambiguous, requires
no custom parser, and is directly usable by any JSON consumer. The string
format `"(1-5)"` adds complexity for no benefit.

**Suggested fix:** Use JSON arrays `[start, end]` for copy ranges instead of
parenthetical strings. For example, a body recipe that copies lines 1-500
and inserts new content would be:
```json
{"b": [[1, 500], "PGEgaHJlZj0i..."]}
```
instead of:
```json
{"b": ["(1-500)", "PGEgaHJlZj0i..."]}
```

### 5. IANA Considerations incomplete (Section 16)

Section 16 just says "TBA". At minimum it should define registries for:
- Algorithm identifiers for the s= tag
- Flag values for the f= tag
- Tag names for DKIM2-Signature and Message-Instance headers

### 6. Canonicalization steps could use a worked example (Section 11.5)

The canonicalization steps are clearly described but a worked example showing
a folded header before and after canonicalization would help implementers
verify their code. In particular, the interaction between unfolding (step 2)
and WSP collapsing (step 3) can introduce spaces in the middle of base64
values that were not present in the original unfolded header, and both signer
and verifier must handle this consistently.

### 7. Signing input construction needs a worked example (Section 11.5)

The most common source of interop failures will be disagreements about the
exact signing input. A complete worked example showing:
- A sample message with headers and body
- The Message-Instance header construction
- The incomplete DKIM2-Signature header
- The canonicalized signing input (byte-for-byte)
- The resulting hash and signature

would be invaluable for implementers.

### 11. Relay mf= update requirement not clear enough (Section 10/11.2)

The spec requires d= to match mf= at every hop, and the chain of custody
requires mf of hop N to match an rt of hop N-1. The implication is that
each relay MUST update the MAIL FROM (mf=) to its own domain when
re-signing — this is necessary both for domain alignment and so that
bounces route back through the chain correctly.

However, this requirement is not spelled out explicitly. During interop
testing, a Python implementation had relays that kept the original sender's
MAIL FROM (`sender@test1.dkim2.com`) while signing with `d=test2.dkim2.com`,
which violates the d= vs mf= match requirement. The implementer was not
aware that the relay needs to update the envelope sender.

**Suggested fix:** Add explicit text in Section 11.2 (or a new subsection)
stating that when a relay adds a new DKIM2-Signature, it MUST set mf= to
an address in its own domain (matching d=), both for domain alignment and
to ensure bounces route back through the custody chain.

## Code Issues Found (our implementation vs spec)

### A. Only first signature item verified (Verifier.pm)

The verifier only checks `signature_value(0)` — the first signature item in
the s= tag. The spec says "All available signatures MUST pass if verifier
supports the algorithm." When a DKIM2-Signature has multiple signature items
(e.g. both RSA and ed25519), we should verify all items whose algorithm we
support, not just the first.

### B. No d= vs mf= domain validation (Verifier.pm)

The spec says: "The domain in the d= tag MUST exactly match the rightmost
labels of the domain-name part of the mf= tag." The verifier does not
currently check this. The chain-of-custody check validates mf/rt between
consecutive signatures, but the d= vs mf= check on each individual
signature is missing.

### C. Chain of custody silently passes when mf/rt absent (Verifier.pm)

`_verify_chain()` skips the domain match check if either `$cur_mf` or
`$prev_rt` is missing (line 216: `if ($cur_mf && $prev_rt)`). The spec
should clarify whether missing SMTP parameters should cause a verification
failure or are acceptable.

## Additional Spec Clarity Suggestions

### 8. m= tag requirement unclear

The m= tag (SMTP parameters) is listed as required in Section 10, but the
spec doesn't clearly state what should happen when a verifier encounters a
DKIM2-Signature without an m= tag, or with an m= tag containing a null
MAIL FROM (`<>`). Section 13.2 mentions DSN handling with `mf=<>` but the
verification behaviour is not explicit.

### 9. Multiple signature items — signing semantics

When a DKIM2-Signature contains multiple signature items (e.g. RSA + ed25519),
the spec doesn't clearly state whether all items sign the same signing input
or whether each algorithm has its own signing process. The implication is that
all items sign the same canonicalized input, but this should be stated
explicitly.

### 10. Relationship between signing input and folding

The spec describes canonicalization steps that handle folded headers, but
doesn't explicitly state whether the signer MUST canonicalize its own
newly-created header before signing. In practice, the signer constructs the
DKIM2-Signature header, canonicalizes it (which may add or remove spaces
depending on folding), and signs the result. If the signer folds the header
after signing but the verifier canonicalizes the folded form, they must agree.
A note clarifying that "the signer MUST apply the same canonicalization to its
own header before computing the hash" would prevent subtle bugs.
