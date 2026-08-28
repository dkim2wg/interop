# DKIM2 C Implementation — Interop Issue Log

Issues encountered during implementation and cross-implementation testing.
Useful for quality-of-implementation documents and advice to future implementors.

---

## 1. Trailing semicolon in tag-value header values

**Impact:** Signature verification failures across implementations.

**Detail:** The spec ABNF allows (and some implementations require) a trailing
semicolon after the last tag in a tag-list. Python's signer always appends `;`
after the final tag:

```
Message-Instance: m=1; h=sha256:...:...;
DKIM2-Signature: i=1; ...; s=sel:alg:sigval;
```

Our C implementation omitted the trailing semicolon. Since §8.5/§9.5
canonicalization deletes all whitespace but retains `;`, the canonicalized
signing input differed:

```
# Python signed:
message-instance:m=1;h=sha256:...:...;\r\n
# C signed:
message-instance:m=1;h=sha256:...:...\r\n
```

**Fix needed:** Implementations MUST either:
- Always emit a trailing semicolon (and verify by preserving raw form), OR
- Document clearly whether they include/exclude it, so verifiers can reconstruct

**Recommendation to spec:** Add a clear normative statement on whether the
trailing semicolon is required, optional, or forbidden.

---

## 2. Verifier must use raw header bytes, not reconstructed form

**Impact:** Cross-implementation signature failures.

**Detail:** Our C verifier initially reconstructed the signing input by calling
format functions (`dkim2_mi_format`, `dkim2_sig_format`) on the parsed structs.
This loses any formatting details from the original header (trailing semicolons,
specific whitespace, folding).

The correct approach is:

- For MI headers: use the raw header value as received (preserving original byte
  sequence), then canonicalize it.
- For the target DKIM2-Signature: take the raw header value and blank out the
  signature bytes within the s= tag, preserving everything else (including any
  trailing semicolon).

Python's verifier does this correctly:

```python
# Find s= tag, strip sig values, preserve trailing ";" if present
trailing = ";" if re.search(r";\s*(?:\r?\n)?$", sig_hdr) else ""
incomplete_sig = prefix + ",".join(stripped_items) + trailing
```

**Recommendation to spec:** §10 should explicitly state that the verifier MUST
reconstruct the signing input by zeroing sig values in the raw header byte
sequence, not by re-serializing from a parsed representation.

---

## 3. Timestamp check breaks stored/test emails

**Impact:** All test emails with fixed timestamps fail after 14 days.

**Detail:** The spec requires signatures to be verified within a 14-day window
(§10.3). Test suites use fixed timestamps for reproducibility (e.g., Python uses
`t=1740000000`). This means test emails expire.

Python's verifier performs no timestamp check at all. Our C verifier enforces
the 14-day window strictly.

**Fix:** Implementations should provide a `--no-timestamp-check` flag (or
equivalent API) for testing and forensic purposes.

**Recommendation to spec:** Consider recommending that implementations expose a
way to disable expiry checking for testing and archived mail analysis.

---

## 4. Dangling pointer after taglist_free (C-specific)

**Impact:** Incorrect algorithm detection during DNS key parsing; sporadic
verification failure.

**Detail:** In `parse_key_record`, `tag_get(tl, "k")` returns a pointer into
the taglist's internal memory. After `taglist_free(tl)`, that pointer points to
freed memory. Subsequent `strcmp(alg, "ed25519")` would read garbage — in
practice it read `'k'` (the tag name byte), causing the key type to be
unrecognised.

```c
/* WRONG: alg points into freed taglist memory */
const char *k_tag = tag_get(tl, "k");
taglist_free(tl);
if (strcmp(alg, "ed25519") == 0) ...   /* UB: k_tag is dangling */

/* CORRECT: strdup before freeing */
char *alg = strdup(k_tag ? k_tag : "rsa");
taglist_free(tl);
```

This was hard to debug because the bug only manifested when the garbage byte
happened to differ from the first character of the expected string.

---

## 5. addr_domain() off-by-one in angle-bracket stripping

**Impact:** Domain extraction from `<user@example.com>` returned `example.co`
instead of `example.com`.

**Detail:** Pointer arithmetic mistake: `end` was being used as an exclusive
pointer, but the `>` stripping loop was consuming `\0` as well as `>`, leaving
`end` pointing one character short.

```c
/* WRONG: consumes \0 and then > */
while (end > at && (*end == '>' || *end == '\0')) end--;

/* CORRECT: use end[-1] for exclusive-end pointer */
while (end > at && end[-1] == '>') end--;
```

---

## 6. DNS constants C_IN / T_TXT not available on macOS without BIND_8_COMPAT

**Impact:** Build failure on macOS.

**Detail:** `C_IN` and `T_TXT` are legacy BIND 8 constants. On macOS, they are
only available when `BIND_8_COMPAT` is defined. The POSIX resolver API provides
`ns_c_in` and `ns_t_txt` (from `<arpa/nameser.h>`) without this define.

```c
/* Portable: */
res_query(qname, ns_c_in, ns_t_txt, answer, sizeof answer);
```

Also requires `<netdb.h>` for `h_errno`/`TRY_AGAIN`, and `<openssl/x509.h>`
for `d2i_PUBKEY`.

---

## 7. libmilter build: sm_os.h must be at include/sm/sm_os.h

**Impact:** libmilter fails to compile from sendmail source.

**Detail:** `include/sm/config.h` includes `"sm_os.h"` (quoted, not angle),
meaning it searches relative to its own directory (`include/sm/`). The file
must exist at `include/sm/sm_os.h`. There is no Darwin-specific one in the
sendmail 8.18.2 distribution's `include/sm/os/` directory (which only has
files for specific OS variants like FreeBSD, Linux, etc.).

The fix is to create `include/sm/sm_os.h` manually for Darwin with the
correct defines (`SM_CONF_STRL=1`, `MI_SOMAXCONN=-1`, etc.), modelled on
the FreeBSD one.

The sendmail `Build` script (which uses the `devtools/` system) handles all
of this automatically — prefer using it over manual compilation.

---

## 8. MAIL FROM format: with vs without angle brackets

**Impact:** MAIL FROM matching failures between implementations.

**Detail:** Different contexts provide MAIL FROM in different formats:

- libmilter: `<sender@example.com>` (with angle brackets)
- Python CLI: `sender@example.com` (without angle brackets, per `--mailfrom`)
- DSN (null reverse-path): `<>` or `""`

The `mf=` tag stores the base64 encoding of whatever was passed. Both `addr_domain()`
and the local-part comparison must handle both formats.

**Resolution (2026-07):** Per spec §7.5/§7.6, `mf=`/`rt=` MUST carry the bracketed
RFC5321 path. The C signer now normalizes at encode time — `dkim2_sign.c`'s
`to_rfc5321_path()` wraps a bare address in `<...>` before base64-encoding
`mf=` and each `rt=` entry (NULL/empty mail_from becomes `<>`; an already-bracketed
value passes through unchanged). This makes bare CLI input (e.g. Python-style
`--mailfrom sender@example.com`) conformant too, so the historical bare-vs-bracketed
divergence between implementations is closed: all implementations (C, Perl, Python)
now emit and require bracketed `mf=`/`rt=`. The verifier hard-fails (PERMERROR)
any present `mf=` or `rt=` entry that isn't bracketed — see note 9 below.

---

## 9. MAIL FROM / RCPT TO matching in CLI verifier

**Impact:** The CLI verifier has no way to provide envelope data.

**Detail:** DKIM2 Chain of Custody verification requires matching the MAIL FROM
and RCPT TO from the SMTP envelope against the `mf=` and `rt=` tags in the
signature. A CLI tool verifying a stored `.eml` file has no access to the
original SMTP envelope.

Options:
- Skip the envelope check when not provided (our current approach)
- Read MAIL FROM from `Return-Path:` header
- Accept `--mailfrom` and `--rcptto` CLI flags

Python's verifier appears to skip envelope matching entirely when verifying
stored test emails, as the check is not in the verify path for the test suite.

**Resolution (2026-07):** Independent of the envelope-matching question above,
`dkim2_verify.c` now enforces the bracketing format of `mf=`/`rt=` themselves
(spec §7.5/§7.6) regardless of whether envelope data is available to cross-check
against: in the per-signature loop, a present `mf=` that isn't `<...>`-bracketed,
or any `rt=` entry that isn't `<...>`-bracketed, is a PERMERROR citing the
relevant spec section. `<>` (null reverse-path) passes. `nd=` hops carry no
mf=/rt= and are unaffected.

---

## 10. Header hash mismatch vs signature mismatch — two distinct failure modes

**Impact:** Diagnostics confusion.

**Detail:** During interop testing, some emails fail with "signature verification
failed" and others fail with "header hash mismatch". These are two different
stages of verification and indicate different root causes:

- **Signature verification failed**: The cryptographic signature over the
  signing input doesn't verify. Most likely cause: different signing input
  (canonicalization difference, trailing semicolon, different header ordering).

- **Header hash mismatch**: The signature verified, but the `h=` field in
  Message-Instance doesn't match the computed header hash. This means the
  implementations compute header hashes differently (canonicalization for
  §5.2 vs §9.5 differ in how WSP is handled).

**Status:** Still being investigated at time of writing.

---

## 11. Ed25519 vs RSA failures differ

**Impact:** Diagnostics confusion.

**Detail:** In our test run, ed25519 emails fail with "signature verification
failed", while RSA emails fail with "header hash mismatch". This suggests:

- For ed25519: the signing input itself differs (canonicalization issue)
- For RSA: the signing input matches (sig verifies) but the hash computation
  in the MI differs

This asymmetry may be because the RSA test emails happen to use the same
ordering/formatting for the signing input by coincidence, but the header hash
computation still differs.

---

## 13. Perl test keys were ephemeral (random at module load time)

**Impact:** All Perl-generated expected emails could not be cross-implementation
verified; the signed emails were useless for interop testing.

**Detail:** `DKIM2TestKeys.pm` generated fresh random RSA and Ed25519 keys each
time the test module was loaded. The expected email files were signed with these
ephemeral keys and committed to the repository. Since the keys were never
persisted:

- The Perl test suite verified its own output within a single run (sign and
  verify use the same ephemeral keys).
- `verify-sig.pl` (which reads `dns.json` with static public keys) always
  failed on these emails.
- The C verifier (also reading `dns.json`) always failed on these emails.

**Fix:** Rewrote `DKIM2TestKeys.pm` to load static private key PEM files from
the shared `keys/` directory (e.g. `sel1._domainkey.test1.dkim2.com.pem`).
Changed test domain names from `testN.example.com` to `testN.dkim2.com` to
match the shared key infrastructure. The `pubkey_callback` now reads from
`dns.json`. Regenerated all expected emails.

**Result:** All 10 Perl expected emails now pass C verification (and vice
versa). Together with 16 Python expected emails, all 26 expected files verify
cross-implementation.

---

## 14. Folded base64 hash values compared as strings (C-specific)

**Impact:** Body hash and header hash mismatches for any email whose
`Message-Instance` header was folded across multiple lines.

**Detail:** The `h=` tag in `Message-Instance` headers can span multiple
lines when folded for line-length compliance:

```
Message-Instance: m=1;
\th=sha256:tB8uwPQbcCHO6zvU0EnzEFWUKKBtwyzmrxeavy4Jn1g=:XI228V/720
\tXNelm76DFKQf934iOEQQCt6wZ3uKCIr9Q=;
```

Our C verifier parsed the raw folded string into the `body_hash` field
(containing `XI228V/720\r\n\tXNelm76...=`) then compared it with
`strcmp` against the computed hash (`XI228V/720XNelm76...=`). The folded
whitespace in the stored value caused the comparison to always fail.

Two fixes applied:
1. `parse_hsets()`: strip all FWS from the h= value before tokenising on `:`,
   so the colon-splitting works correctly even when a hash straddles a fold.
2. `dkim2_verify.c`: compare raw SHA-256 digest bytes rather than base64
   strings — `b64_decode` the stored hash value, then `memcmp` against the
   computed digest. This is robust to any encoding differences.

**Lesson:** Wherever a spec field contains base64 data that may be folded,
always compare decoded bytes, not the encoded string.

---

## 12. eml_parse stores entire file in memory

**Impact:** Memory usage for large messages.

**Detail:** Current `eml_parse()` reads the entire file, normalises line
endings into a new buffer (potentially doubling size), then copies headers and
body into separate allocations. For large attachments this is wasteful.

**TODO:** Rewrite to use a streaming parser that processes the file in chunks
without buffering the whole normalised form. The headers still need to be
fully buffered (for hash computation), but the body can be hashed on the fly.

---

## 15. 8bit DSNs + transport 8→7 conversion break DKIM2 signatures (spec §12)

**Impact:** A DKIM2-signed Delivery Status Notification verifies at the signer
but FAILS at a receiver reached across a non-8BITMIME hop.

**Detail:** Postfix's `bounce(8)` composes DSNs as **8bit** — the human-readable
`text/plain` part is `charset=utf-8; Content-Transfer-Encoding: 8bit` by default
(so the notice can carry non-ASCII addresses/subjects), and that `8bit`
propagates to the `multipart/report` container and the enclosed `message/rfc822`
part. This is independent of body content: a pure-ASCII bounce is still declared
8bit.

When a signer (here, our outbound milter) signs the 8bit DSN and it is then
relayed to a next hop that does **not** advertise `8BITMIME`, the MTA performs
an 8bit→7bit MIME conversion, rewriting `Content-Transfer-Encoding: 8bit` →
`7bit` (and re-encoding the body). That rewrite happens **after** signing, so the
DKIM2 Message-Instance header hash (which covers `Content-Transfer-Encoding`) no
longer matches → PERMFAIL header-hash mismatch. Confirmed empirically: delivered
to an 8BITMIME-advertising sink the DSN verifies `pass`; to a plain sink it
fails, differing only in that one header.

This is precisely spec **§12 "Preventing Transport Conversions"**: DKIM2 is
predicated on network-normal input and a transport conversion invalidates the
signature. It is a general interoperability hazard for *any* DKIM2 signer of
8bit content, not specific to bounces or to Postfix.

**Resolutions:**
- **Deployed mitigation (operational):** `disable_mime_output_conversion = yes`
  in Postfix `main.cf` — stops the 8→7 output conversion so the signed 8bit form
  survives to any hop. Trade-off: 8bit body sent as-is to non-8BITMIME servers
  (universally tolerated in practice). See `deploy/postfix-main.cf.patch` /
  `deploy/SERVER.md`.
- **Ideal (not readily achievable):** have the DSN generated as **7bit/us-ascii**
  in the first place, so there is nothing to downgrade. Postfix's `bounce(8)`
  does not expose a knob to force 7bit DSN notices, so this cannot be done by
  configuration alone — it would require patching the bounce templates / DSN
  generation. Recorded as an open interop issue: **a spec-conformant DKIM2
  signer should either ensure 7bit content or guarantee no downstream transport
  conversion**, and MTAs that auto-downgrade 8bit are hostile to DKIM2 integrity.

---

## 16. Leading WSP stripped before unfolding, not after (C-specific)

**Symptom:** a real Mailman list message verified in Perl, Python, Go and the
browser JS verifier but failed `Message-Instance m=2 header hash mismatch` in C.

`canon_header_for_hash()` applied §6.2 step 6 ("delete WSP at the start of the
value") to the *raw* header bytes, before the unfolding step had run:

```c
size_t vi = 0;
while (vi < vl && (v[vi] == ' ' || v[vi] == '\t')) vi++;   /* too early */
int in_wsp = 0;
for (size_t i = vi; i < vl; i++) { ... }                   /* unfolds here */
```

For a header folded *immediately after the colon* — which Gmail and Mailman both
emit — the value's raw bytes start with CRLF, so the pre-pass finds no leading
WSP to delete. The collapse loop then skips the CRLF, hits the space that opens
the continuation line, and emits it, leaving a stray leading SP:

```
Message-ID:\r\n <x@y>   ->  "message-id: <x@y>"   (wrong)
                            "message-id:<x@y>"     (Perl/Python/Go/JS)
```

The message that surfaced it had three such headers (`Message-ID:`,
`Archived-At:`, `List-Archive:`) of the 17 signed fields, so the hash was wrong
while every individual field *looked* right in a diff.

**Fix:** start the collapse loop already inside a WSP run (`int in_wsp = 1`), so
a leading WSP run is swallowed whichever side of the fold it sits on. The
separate pre-pass is then redundant and was removed. Covered by `test_hash.c`
(folded-after-colon, with and without a trailing space before the fold).

**Lesson:** ordering matters in the §6.2 step list, and the spec's step order is
not the only order that "looks" correct — see spec issue **S4**. Any step
phrased "at the start of the value" must run *after* unfolding, because
unfolding is what determines where the value starts.

---

## 17. NULL holes in the working header array crash the recipe undo (C-specific)

**Symptom:** SIGSEGV in `strchr` via `headers_for_name()` while undoing a
Mailman `Message-Instance` recipe. Latent until issue #16 was fixed — the header
hash mismatch had been short-circuiting before the recipe was ever applied.

`dkim2_apply_header_recipe()` processes each field named in the recipe's `h`
object in turn. Removing a field's existing instances blanks the slots rather
than compacting the array (compaction happens once, at the end):

```c
if (strcmp(tmp, fname) == 0) { free(working[i]); working[i] = NULL; }
```

The removal loop guards with `if (!working[i]) continue;`, but
`headers_for_name()` — called for the *next* field in the recipe — did not, and
dereferenced the hole. So any recipe naming **two or more** header fields, where
the first-processed one was present in the message, crashed. Single-field
recipes (all the existing tests) never hit it; Mailman recipes name a dozen
fields, so real list mail hit it every time.

**Fix:** skip NULL entries in both passes of `headers_for_name()`. Covered by a
multi-field-recipe case in `test_recipe.c`.

**Lesson:** a sentinel-holes-then-compact array is fine, but *every* reader of
the array has to know about the holes. Prefer compacting eagerly, or wrap the
array in an accessor that hides them.

---

## 18. §11.9 replay detection is deliberately not implemented

draft-06 added §11.9: a Verifier receiving multiple copies of a message that
carries no `exploded` flag SHOULD reject all of them. **No implementation here
does this, and that is a decision rather than an oversight.**

It is the only DKIM2 rule that requires a verifier to remember anything between
messages, so it needs a persistent cross-message store, a retention policy, and
somewhere to put the write. That machinery earns its keep at the volume where
DKIM replay is an actual abuse vector — Yahoo's scale, where the attack is
worth mounting. It does not pay for itself at ours, and none of these
implementations is the production path for mail at that volume anyway.

It is a SHOULD, not a MUST, so declining it is conformant. Two things worth
knowing if it is ever revisited:

**§11.9's suggested key is wrong.** It offers the m=1 Message-Instance hash
values as the message identity. Those identify the original *content*, so a
message reaching a recipient by two legitimate paths — a mailing list copy plus
a direct Cc, or two forwarding routes — has identical m=1 hashes but two
entirely different signature chains, and one of the two would be rejected as a
replay. The topmost DKIM2-Signature is the correct key: it matches only when
the same fully-signed bytes are re-injected, which is the attack itself. It
also makes the `exploded` skip exact — a list that signs once and sends
identical bytes to every subscriber is precisely the case the flag excuses,
while a list signing per-recipient (differing `rt=`) has distinct topmost
signatures and never needs it.

**Checking and recording must be separated.** An SMTP retry after a 4xx is
byte-identical to the original, so recording at verify time would make every
legitimate retry flag itself as a replay on the next attempt. Only the accept
path may write.

---

## Spec Quality Issues

These are ambiguities and gaps in draft-ietf-dkim-dkim2-spec-04 that caused
implementation mistakes. Recorded here as input for future spec revisions.
The ratio of genuine spec issues to implementation sloppiness is roughly 4:3 —
worse than expected for a new protocol seeking broad adoption.

---

### S1. Trailing semicolon MUST be normative, not optional

**ABNF as-is:** `tag-list = tag-spec *(";" tag-spec) [";"]` — trailing `;`
is shown as optional.

**Reality:** Every implementation (Python, Perl, C) appends a trailing `;`
unconditionally. Because §8.5/§9.5 canonicalization retains `;` but deletes
whitespace, a verifier that omits the trailing `;` when reconstructing the
blanked signature produces a different canonical string than was signed:

```
# Signed by all implementations:
dkim2-signature:i=1;m=1;...;s=sel:alg:;\r\n
# Verifier without trailing ";":
dkim2-signature:i=1;m=1;...;s=sel:alg:\r\n   ← will not verify
```

**Recommendation:** Add a normative statement: "Implementations MUST include a
trailing semicolon after the final tag in every tag-list. Verifiers MUST
preserve the trailing semicolon when reconstructing the signing input."

---

### S2. `ed25519-sha256` semantics are not specified

**Gap:** The spec names the algorithm `ed25519-sha256` but does not explain
what the `-sha256` component means. EdDSA/Ed25519 in its standard form
(RFC 8032) operates directly on raw data with its own internal hashing. It
is not obvious that the signing input must be pre-hashed.

**Reality:** Both Python and Perl pre-hash the signing input with SHA-256 and
then pass the 32-byte digest to the PureEdDSA primitive. Our C implementation
initially passed raw data, producing signatures that no other implementation
could verify.

**Recommendation:** Add to §3.x: "For `ed25519-sha256`, implementations MUST
compute SHA-256 of the signing input and pass the resulting 32-byte digest to
the Ed25519 signing or verification primitive."

---

### S3. §5.2 and §8.5 define two similar but different canonicalizations — not clearly flagged

**Gap:** §5.2 (header hash) collapses runs of whitespace to a single space.
§8.5 (signing input) deletes ALL whitespace characters. These two rules are
described in separate sections several pages apart with no cross-reference or
warning. The natural implementation mistake is to write one function and use
it for both purposes.

**Recommendation:** Add a caution note in each section: "Note: the whitespace
handling here differs from §X.Y. §5.2 collapses WSP to a single space;
§8.5 deletes all WSP entirely." A side-by-side example would also help:

```
Input:  "Subject:  Hello  World  \r\n"
§5.2:   "subject:Hello World\r\n"   (WSP collapsed)
§8.5:   "subject:HelloWorld\r\n"    (WSP deleted)
```

---

### S4. §5.2 leading whitespace stripping is easy to miss

**Gap:** §5.2 requires stripping leading and trailing whitespace from header
values, but this is listed alongside other steps without emphasis. The leading
space after the `:` (e.g. `"Subject: Hello"` → value is `" Hello"`) must be
stripped before collapsing internal whitespace.

**Reality:** Our C implementation stripped trailing CRLF but not the leading
space after the colon. Python correctly does `value.lstrip(" \t")`.

**Recommendation:** Add a concrete worked example to §5.2 showing the full
sequence of transformations on a multi-word, multi-line header value.

---

### S5. Same-name header bottom-up ordering is underspecified

**Gap:** §5.2 says that when multiple headers share the same name, they are
ordered bottom-up (reverse arrival order). However:

1. The interaction with the alphabetical sort is not stated. Must you sort by
   name first, then arrange same-name groups in bottom-up order within each
   group? (Yes, but this is not explicit.)
2. "Bottom-up" is relative to the email as stored, where headers appear in
   arrival order top-to-bottom. Implementers who read "descending" as
   "descending by field name" rather than "descending by position" will get
   this wrong.

**Recommendation:** Show a worked example with two `Authentication-Results`
headers and specify the exact canonical ordering.

---

### S6. Ascending m=/i= order in signing input conflicts with email storage order

**Gap:** §8.5 requires Message-Instance headers in ascending m= order and
DKIM2-Signature headers in ascending i= order. However, email stores these
headers newest-first (prepended at each hop), so the natural iteration order
is descending. The spec does not call out this inversion.

**Recommendation:** Add a note: "Note that DKIM2-Signature and
Message-Instance headers typically appear in a message in descending order
(each hop prepends its header). Implementations MUST explicitly sort into
ascending order before constructing the signing input."

---

### S7. Which MI headers are in scope for a given signature is not precisely stated

**Gap (currently under investigation):** The spec says the signing input
includes Message-Instance headers, but it is not unambiguous about the exact
set:

- Does it include the MI header whose m= value matches the signature's m= tag?
- Does the signer include the NEW MI header it is about to create, or only
  MI headers that existed before signing started?

The Perl signer includes only MI headers already present in the email at the
time of signing (none, for the originator). The Perl verifier includes the MI
header with m= ≤ the signature's m= value (which includes the new one). If
these two sets differ, the signer and verifier build different signing inputs.

**Recommendation:** Specify explicitly: "The signing input includes all
Message-Instance headers with m= ≤ the m= value in the DKIM2-Signature header
being constructed. For a signature that creates a new MI, the new MI header
itself MUST [or MUST NOT] be included."

---

### S8. No worked end-to-end examples

**Gap (meta-issue):** The spec describes each algorithm step individually but
provides no worked example showing a complete message going through signing and
verification with all intermediate values (header hash input, body hash input,
signing input bytes, encoded signature). Such an example would function as a
test vector and would have caught most of the above issues before
implementations were written.

**Recommendation:** Add an appendix with a minimal worked example: a 3-header
message, fixed timestamp, known key, showing every intermediate value.

---

## Summary table

| # | Issue | Status | Severity |
|---|-------|--------|----------|
| 1 | Trailing semicolon in tag-values | Fix needed in verifier (use raw bytes) | Critical for interop |
| 2 | Verifier reconstructs instead of using raw bytes | Fixed | Critical for interop |
| 3 | Timestamp check blocks test emails | Fixed (--no-timestamp-check) | Low (test infra) |
| 4 | Dangling pointer after taglist_free | Fixed | Critical (correctness) |
| 5 | addr_domain off-by-one | Fixed | High (correctness) |
| 6 | C_IN/T_TXT not on macOS | Fixed | Platform (macOS) |
| 7 | libmilter sm_os.h location | Fixed | Build (macOS) |
| 8 | MAIL FROM angle bracket handling | Partially fixed | Medium |
| 9 | CLI verifier missing envelope data | Workaround (skip check) | Medium |
| 10 | Signature vs hash mismatch diagnostics | Documenting | Low |
| 11 | Ed25519/RSA asymmetric failure modes | Resolved (was key issue #13) | High |
| 12 | eml_parse whole-file buffering | TODO | Low (performance) |
| 13 | Perl test keys were ephemeral random | Fixed (static keys from keys/) | Critical for interop |
| 14 | Folded base64 hash compared as string | Fixed (compare decoded bytes) | High (correctness) |
| 15 | 8bit DSN downgraded 8→7 breaks signatures | Mitigated (Postfix config) | High (correctness) |
| 16 | Leading WSP stripped before unfolding | Fixed (`in_wsp = 1`) | Critical for interop |
| 17 | NULL holes crash multi-field recipe undo | Fixed (skip holes) | Critical (crash) |
| 18 | §11.9 replay detection unimplemented | Won't do (scale) | Conformant (SHOULD) |
| S1 | Trailing `;` should be normative | Spec issue | Critical for interop |
| S2 | `ed25519-sha256` prehash semantics unstated | Spec issue | Critical for interop |
| S3 | §5.2 vs §8.5 WSP rules not cross-referenced | Spec issue | High |
| S4 | §5.2 leading WSP stripping easy to miss | Spec issue | Medium |
| S5 | Same-name header bottom-up order underspecified | Spec issue | Medium |
| S6 | Ascending m=/i= order conflicts with storage order | Spec issue | Medium |
| S7 | Which MI headers are in scope for a signature | Spec gap (open) | Critical for interop |
| S8 | No worked test-vector example in spec | Spec gap | High |
