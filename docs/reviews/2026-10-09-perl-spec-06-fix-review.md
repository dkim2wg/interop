# Follow-up review of the spec-06 fixes

Reviewed 2026-10-09, Mail::DKIM2 0.18 at `c69a1f7`, against the original review baseline `590bc6e`. Scope: the Perl implementation and its front-end/API documentation. Three independent follow-up reviewers covered protocol/key handling, performance/recipes, and APIs/documentation; the coordinator reproduced the findings below. Changes to other implementations were not audited.

The fixes address the original reproductions substantially. The complete updated suite passes: **81 files, 2,541 tests**, using `prove -lr t` in `perl` outside the sandbox so local integration listeners can start. Six behavioral findings remain or surfaced during this follow-up, plus one documentation nit. No implementation files were changed in this review.

## Findings

### F1 — P2: New header-recipe matching is quadratic for repeated fields

Location: [MessageInstance.pm:942](../../perl/lib/Mail/DKIM2/MessageInstance.pm#L942).

For each previous header value, `grep` scans and materializes every matching source index before taking the first eligible one. When N current and previous fields share a canonical value, this does N scans of an N-element list. A forwarder processing attacker-controlled repeated fields therefore incurs quadratic signing work despite the new bounded body diff.

Coordinator reproduction used N legitimate repeatable `Comments: same` fields and one added `Comments: changed`. `calculate($current, $previous)` timings:

| Fields | Seconds |
| ---: | ---: |
| 1,000 | 0.016 |
| 2,000 | 0.049 |
| 4,000 | 0.183 |
| 8,000 | 0.705 |
| 16,000 | 2.809 |

The largest header block is approximately 240 KB. The independent reviewer measured a similar curve using Subject fields. This is a newly introduced performance regression in the header recipe code, separate from original R2. Maintain a monotone cursor per canonical value, or binary-search for the first index above `$last_end`; do not materialize the whole remaining list each time.

### F2 — P2: The signer folds inside valid domain tokens and creates unverifiable output

Locations: [Signature.pm:317](../../perl/lib/Mail/DKIM2/Signature.pm#L317), [Common.pm:373](../../perl/lib/Mail/DKIM2/Common.pm#L373).

A valid domain made from a 40-character label, another 40-character label, and `example.com` is split inside `d=` by `fold_header`'s hard-break fallback. With that same domain in MAIL FROM, Signer reports `signed`, but Verifier reports `fail (DKIM2-Signature i=1 MAIL FROM and d= do not match)`. Both DNS labels are within the 63-character limit and the total domain is valid. The probe uses fixture key material through a callback to isolate folding from DNS.

Spec §8.8's Domain production does not allow internal FWS. §9.6's deletion of WSP makes valid refolding cryptographically invariant; it does not make every folding position syntactically valid or ensure that scalar accessors normalize it. Fold at tag separators and within base64 values where allowed. Leave a domain token intact even if it exceeds the preferred 72-character target, while enforcing the actual line-length limit. This is a previously missed signing defect, not a demonstrated regression from this change set.

### F3 — P2: Malformed header tag specifications are still silently ignored

Locations: [MessageInstance.pm:300](../../perl/lib/Mail/DKIM2/MessageInstance.pm#L300), [TagValueList.pm:32](../../perl/lib/Mail/DKIM2/TagValueList.pm#L32).

The MI parser skips nonmatching fragments and accepts `\w+` identifiers, which permits a digit as the first character. Correctly signed MIs with appended `; junk` or `; 9bad=foo` return `pass`. Spec §7's extension identifiers start with ALPHA and every nonempty specification requires `=`; valid unknown extensions may be ignored, malformed syntax may not (§11.2).

The signature parser has the same skip behavior. Appending ` junk;` after the final semicolon of an ordinary signed DKIM2-Signature also returns `pass` without recomputing its signature: the malformed fragment is discarded when the incomplete signing header is reconstructed. This is a syntax/reconstruction discrepancy, not a way to change authenticated valid tags or forge a cryptographic signature.

Validate the complete tag list before extracting tags. Reject malformed nonempty fragments and illegal names; preserve unknown valid extensions in the signing representation. The original duplicate and case-handling vectors now work, but that should not substitute for whole-field validation.

### F4 — P2: Internal whitespace turns malformed algorithm names into supported algorithms

Location: [Signature.pm:131](../../perl/lib/Mail/DKIM2/Signature.pm#L131), used by [Signature.pm:161](../../perl/lib/Mail/DKIM2/Signature.pm#L161).

`_strip_fws` removes whitespace from the entire item before the selector, algorithm, and signature value are separated. Consequently a correctly RSA-signed `s=sel1:rsa- sha256:...` returns `pass`: the verifier sees `rsa-sha256`. §8.9 allows FWS around the colons and inside base64, not inside the algorithm token. This also defeats the exact algorithm-name requirement in strictness section A.

Parse the components first and validate each component's own grammar. Strip only permitted surrounding FWS from selectors and algorithm names; strip internal FWS only from base64 values. The original `future-alg` attack is fixed, and this malformed-name case is not a cryptographic forgery.

### F5 — P2: DNS key extension values bypass whole-record syntax validation

Location: [Common.pm:593](../../perl/lib/Mail/DKIM2/Common.pm#L593).

The new key parser captures arbitrary `.*` values but only validates recognized `v`, `k`, and `p` semantics. A valid RSA record followed by `; x=` and an actual NUL or DEL byte still returns `Crypt::PK::RSA`. Unknown tags are ignored semantically only after their tag-list syntax validates. NUL and DEL are outside the permitted value-character range in the key tag-list grammar. See [RFC 6376 §3.2](https://www.rfc-editor.org/rfc/rfc6376.html#section-3.2) for the underlying DKIM tag-list grammar; spec-06 §11.5 requires rejecting malformed key records.

Validate every tag's value against the general tag-list grammar before applying known-tag semantics. This leaves original R8 partially addressed: duplicate keys, bad versions, unsupported types, revoked keys, and multiple records are now handled correctly, but the entire record still does not validate.

### F6 — P2: `load()` still swallows foreign reference exceptions

Location: [HeaderParser.pm:48](../../perl/lib/Mail/DKIM2/HeaderParser.pm#L48), also line 52.

Both capability probes call `$input->can(...)` inside `eval` without rethrowing reference exceptions. A supported message-input object's capability lookup can signal a host timeout; `load()` suppresses it, continues to the next probe, and eventually raises a replacement string error. The reproduced `Host::Input::can` throws a blessed `Host::Timeout`; the caller instead receives `load: cannot read a message from a Host::Input reference`.

This leaves R16 incomplete. The original Validate callback suppression is fixed and the callback is invoked once before the same reference escapes, but the distribution-wide promise still has an uncovered path. Rethrow reference exceptions immediately after each capability probe. The reproduction demonstrates exception-contract failure; no deployed MTA timeout bypass was tested.

### F7 — P3: Signature comments still describe the pre-spec empty-value and folding rules

Location: [Signature.pm:258](../../perl/lib/Mail/DKIM2/Signature.pm#L258), also lines 261 and 283.

The comments say signature data is replaced with a dot and show `sel:alg:.`; the implementation and spec require an empty value `sel:alg:`. The folded-input comment still says fold positions become part of what is signed, despite the corrected contributor guide explaining that §9.6 deletes WSP. Correct these comments so the source and new guide give the same instructions. The implementation's empty-value behavior is correct.

## Status of the original findings

| Original | Follow-up result |
| --- | --- |
| R1: unknown-item CPU/DNS work | Addressed. 1k/2k/4k/8k/16k items take about .002/.004/.008/.014/.030 seconds with zero callbacks. |
| R2: repeated-line body diff | Addressed. Capped Myers replaces the old diff; alternating 1k/2k/4k lines take about .0007/.0013/.0027 seconds. Independent reconstruction and dynamic-programming checks passed for 10,000 random pairs at four caps. F1 is a separate header regression. |
| R3: unknown algorithm verified as RSA | Original vector fixed. `future-alg` is ignored before lookup. F4 remains in syntax handling before exact dispatch. |
| R4/R5: MI case and duplicate tags | Original vectors fixed. Uppercase M/H pass; duplicate tags permerror. F3 remains in general syntax validation. |
| R6: malformed timestamp | Addressed. Garbage timestamps permerror even with age checks skipped; zero is subject to expiry. |
| R7: multiple key records | Addressed. Multiple TXT RRs permerror; strings within one RR concatenate. |
| R8: key record validation | Original cases fixed; whole-record validation still incomplete, F5. |
| R9: options | Addressed for reviewed public entry points; original misspellings croak. |
| R10/R11: README/module examples | Addressed; executable synopsis tests pass. |
| R12: contributor folding guidance | Canonicalization distinction corrected. F2 reveals a missing syntax qualification; F7 identifies stale source comments. |
| R13/R14: serialization/FWS explanations | Original comments corrected. F4 shows that acknowledged permissive stripping still needs grammar validation. |
| R15: DSN DNS/Resolver behavior | Addressed; authentication and propagation forward Resolver and support default DNS. |
| R16: foreign exceptions | Original Validate reproduction fixed; `load()` still incomplete, F6. |

The instance-parse design recommendation is addressed: parsing through an instance returns a fresh object. DSN unsigned compatibility is now explicitly documented, and propagation checks the returned top signature's domain against ForwarderDomain. Recognition of the caller's sending identity through `mf=` remains explicitly the caller's responsibility; this review does not recast that documented policy as a new spec violation.

## Reproduction and limits

Run the sibling probe script from the repository root:

```sh
perl docs/reviews/perl-spec-06-followup-probes.pl
```

It prints observed results for F1–F6, using local keys and callbacks; no external DNS requests are made. The original probe script stops at the multiple-record check because `fetch_public_key` now intentionally throws a PERMERROR there; that is expected fixed behavior, not a test failure.

This review did not modify production code, add regression tests, audit the other language implementations, run a broad fuzzing campaign, or test deployed MTA limits. Performance figures are local measurements. Prioritize F1/F2, complete syntax validation across the parsers (F3–F5), then close the remaining exception path and stale comments.
