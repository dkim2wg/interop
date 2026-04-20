---
name: dkim2-spec-review
description: Issues and clarity suggestions for draft-ietf-dkim-dkim2-spec found during implementation and interop testing
type: project
---

# draft-ietf-dkim-dkim2-spec Review Notes

Issues found during implementation and interop testing.  Each issue is tagged
with the spec version where it was confirmed to still apply.

---

## Issues confirmed in draft-ietf-dkim-dkim2-spec-01

### 1. §8.1: Ambiguous antecedent in MI-skip condition

The sentence reads: "If hashing the message body or relevant header fields
does not give the same hash values as those recorded in the highest version
(m=) Message-Instance header field then a new Message-Instance header field
MUST be added and if they are the same a new Message-Instance header field
SHOULD NOT be added."

The phrase "if they are the same" has no clear antecedent — "they" could
refer to the body hash, the header hash, or both.  The full intent (skip
only when BOTH body hash AND header hash are unchanged) is only recoverable
by taking the logical inverse of the previous clause.

**Suggested fix:** Split into two sentences and name the subject explicitly:
"If BOTH hash values match those recorded in the existing Message-Instance
header field, a new Message-Instance header field SHOULD NOT be added."

### 2. §8.1: Spec does not require MI verification before diff computation

The spec describes how to compute a new Message-Instance header (the diff)
but does not say that an intermediary MUST verify the existing top MI before
using it as the diff baseline.  If an intermediary blindly computes a diff
against a tampered or invalid MI, the resulting chain is meaningless — the
new MI correctly records what changed, but "changed from what?" has no valid
answer.

**Suggested fix:** Add a normative requirement: "Before computing a new
Message-Instance header field at egress, the MTA SHOULD verify that the
highest-version existing Message-Instance header field's hash values match
the current message content.  If verification fails, the MTA SHOULD treat
the message as a fresh origination and add a new Message-Instance v=1."

### 3. §9/§10: Spec does not require the top DKIM2-Signature to cover the topmost MI

The verifier is expected to check each signature covers the headers that
existed when it was created.  But the spec does not explicitly require that
the highest-sequence DKIM2-Signature's m= tag equals the highest-version
Message-Instance header present.

If an intermediary adds a new MI header without adding a new DKIM2-Signature,
the message arrives with an uncovered MI at the top of the chain.  A verifier
that only checks "each signature covers the headers it declared" would pass
this message — but the topmost MI is not authenticated by anyone.

**Example:** MI v=1, MI v=2 present; DKIM2-Signature i=1 (m=1) only.
A verifier validating i=1's signing input (correctly including only MI v=1)
returns pass — but MI v=2 is entirely unauthenticated.

**Suggested fix:** Add a normative requirement in the verifier actions section:
"The highest-sequence DKIM2-Signature header field's m= value MUST equal the
number of Message-Instance header fields present.  If there are more
Message-Instance header fields than covered by the top DKIM2-Signature, the
verifier MUST return FAIL."
