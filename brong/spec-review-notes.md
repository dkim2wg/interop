---
name: dkim2-spec-review
description: Issues and clarity suggestions for draft-clayton-dkim2-spec-08 found during interop testing
type: project
---

# draft-clayton-dkim2-spec-08 Review Notes

## Issues Found During Interop Testing

### 1. Header ordering for header hash (Section 5.2)

The spec says duplicate headers with the same field name are "placed in the
order in which they occur in the message header, from the top downwards."
This should be bottom-to-top (reverse message order). The hs implementation
and our implementation both use the same order and agree on hashes, but the
spec text says the opposite.

**Suggested fix:** Change "from the top downwards" to "from the bottom upwards".

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

### 3. "Null s=" ambiguity in signing input (Section 11.5)

The spec says: "the signature value (s=) is null (that is the base64 value
is absent)."

This is ambiguous. It could mean:
- The s= tag is present with an empty value: `s=`
- The s= tag contains base64-encoded JSON with empty signature value strings:
  `s=WyJzZWwiLCJyc2EiLCIiXQ==` (i.e. `["sel","rsa",""]`)
- The s= tag is entirely absent from the header

The parenthetical "(that is the base64 value is absent)" suggests `s=` with
nothing after it, but this loses the selector and algorithm information that
may be needed for the signing input to be deterministic.

**Suggested fix:** Provide an explicit example of the incomplete
DKIM2-Signature header as it appears in the signing input, showing exactly
what the s= tag looks like.

### 4. s= tag JSON format underspecified (Section 7)

The JSON schema shows the s= tag as an array of 3-element arrays:
`[["selector", "algorithm", "value"], ...]`

However, the hs implementation uses a flat array:
`["selector", "rsa", "sig", "selector2", "ed25519", "sig"]`

The schema text says:
```json
{
  "items": {
    "description": "selector, algorithm, value",
    "type": "array",
    "items": {"type": "string"},
    "minItems": 3, "maxItems": 3
  }
}
```

This is clear enough (array of 3-element arrays), but adding a concrete
example would prevent misinterpretation.

**Suggested fix:** Add a worked example showing the JSON before and after
base64 encoding, e.g.:
```
[["sel1", "rsa", "<base64sig>"], ["sel2", "ed25519", "<base64sig>"]]
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
