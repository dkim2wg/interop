# DKIM2 spec -08 audit checklist

Spec text: /Users/brong/src/interop/spec/draft-ietf-dkim-dkim2-spec-08.txt
Previous:  /Users/brong/src/interop/spec/draft-ietf-dkim-dkim2-spec-07.txt
Published 27 October 2026. Read the -08 sections cited below for exact wording.
Our code currently targets -07.

## Section renumbering 07 -> 08 (for comment refs like "§13.1")
- 1.1 "DKIM2 architecture documents" -> "Other DKIM2 documents" (cites DKIM2BCP, DKIMKEYS)
- 3.4 "MLDSA44-Ed25519-SHA512" -> "ML-DSA-44" (same number, different algorithm)
- 13: NEW 13.1 "Messages that are not Fully Verified DKIM2 Messages";
  13.1 Provisionally Verified -> 13.2; 13.2 SMTP codes -> 13.3; 13.3 -> 13.4
- 16: NEW 16.2 "DSN header and SMTP parameters"; 16.2 propagation -> 16.3; 16.3 inbound -> 16.4
- 19 IANA (now real: registers DKIM2-Signature and Message-Instance as trace fields)
- Everything else keeps its -07 number.

## Wire-format changes (cross-implementation lockstep)

A. Ignored header list (§4): "Auto-Submitted" and "VBR-Info" are REMOVED from the
   list. They are now HASHED. Every signer and verifier must flip at the same
   time, or a message carrying either field fails between -07 and -08 code.
   Lists: perl Common.pm, python dkim2sign.py, go canon.go, c dkim2_hash.c,
   www canon.js, Mailman message_instance.py, Sympa (shares Perl lib), hm vendor.
   Sympa's own Template.pm emits Auto-Submitted; Fastmail outbound (hm) signs live.

B. MLDSA (§3.4): the composite "mldsa44-ed25519-sha512" is GONE. New sig-name
   "mldsa44": pure ML-DSA-44 (FIPS 204 Alg 2/3, not HashML-DSA), message = the
   canonical MI+Sig input of §12.8 fed directly, ctx = ASCII "DKIM2". Signers
   SHOULD use hedged signing. Sig is 3228 base64 chars (fold FWS inside it).
   Key MUST be 1312 octets (1752 base64 chars) or "public key <s1> is malformed".
   DKIMKEYS is now draft-ietf-dkim-dkim2-dns-02 (21 Oct 2026), which STILL only
   defines k=mldsa44-ed25519-sha512 -- no k= for pure mldsa44 (spec gap again).

C. h= and s= AND/OR algebra (§9.3, §10.9): "," binds tighter than "|".
   mi-h-tag = "h=" hash-any; hash-any = hash-all *("|" hash-all);
   hash-all = hash-set *("," hash-set). Same shape for s= (sig-any/sig-all).
   [FWS] allowed around "|" and ",". In -07 "," was already effectively AND
   (§14.7 "one passes, another fails -> failure"), so "|" is the new syntax.
   §12.8: when blanking signatures for the signed input, selectors, alg names
   and the ":" "," "|" punctuation all stay.

## Verifier changes

D. Result combination, signatures (§14.6 steps 3-8):
   - per signature: PASS / FAIL (mismatch) / TEMPERROR or PERMERROR (key issue);
     unimplemented algorithm = PERMERROR (was: silently disregarded).
   - sig-all: all PASS -> PASS; every non-PASS is TEMPERROR -> TEMPERROR;
     any FAIL -> FAIL; else PERMERROR.
   - sig-any: any PASS -> PASS; else any TEMPERROR -> TEMPERROR; else any FAIL -> FAIL; else PERMERROR.
   - New strings: "FAIL: DKIM2-Signature i=<x> no group of signatures passed",
     "PERMERROR: DKIM2-Signature i=<x> selector <s1> algorithm unknown".
     Removed: "signature <s1> signature <s2> failed".

E. Result combination, hashes (§14.7): per hash-set PASS if header AND body
   match, else FAIL; unimplemented hash = PERMERROR. hash-all: all PASS -> PASS,
   any FAIL -> FAIL, else PERMERROR. hash-any: any PASS -> PASS, any FAIL ->
   FAIL, else PERMERROR. (No TEMPERROR for hashes.) New strings:
   "FAIL: Message-Instance m=<x> no group of hashes passed",
   "PERMERROR: Message-Instance m=<x> algorithm <value> unknown".

F. Error-state reclassification PERMERROR -> FAIL:
   - §14.3 "signature expired", "signature is from the future"
   - §14.4 all seven Chain of Custody strings
   - §14.8 "matching From is not authentic"
   FAIL now means "verification completed, not Fully Verified" (§14.1).

G. §14.2 strings: NEW "PERMERROR: Message-Instance m=<x> Recipe <value> is invalid"
   (and §14.2 asks for invalid step text in messages); REMOVED
   "has more selectors than allowed" and the "same algorithm more than twice"
   limit (§10.9 now allows any number of same-alg sigs with distinct selectors).
   Remove the limit in perl Signature.pm, python, go, c, www verify.js + tests.

H. Keys (§3.2, §14.5): RSA verifiers MUST handle 1024-4096 bits and MUST NOT
   validate < 1024. Ed25519 key must be exactly 32 octets, ML-DSA-44 exactly 1312,
   else "PERMERROR: ... public key <s1> is malformed" (NEW string).
   Signers SHOULD use >= 2048-bit RSA (check our test/deploy keys).

I. Fully Verified (§13, renamed from "Validly Signed"): EVERY MI's hashes against
   the message recreated by undoing all higher Recipes, and EVERY signature over
   MIs <= its m= and Sigs < its i=. Gaps OR DUPLICATES in m=/i= -> not Fully Verified.
   NEW: a null body Recipe means lower body hashes can't be checked, so the
   message is NOT Fully Verified (we currently skip those hashes and pass).
   No error string given -- needs a decision.

J. Provisionally Verified (§13.2) is now a defined 5-step check on the top MI +
   top Sig only: (1) top Sig m= == top MI m=; (2) top s= PASS; (3) top h= PASS;
   (4) MAIL FROM / RCPT TO match top mf=/rt=; (5) top d= relaxed-matches top mf=
   unless mf=<>. Do our milters/A-R expose this as a separate state?

K. Tag names: -08 text is unchanged from -07 ("all tag-names MUST be in lower
   case", §8 default case-sensitive), but the 2026-10-26 ruling with Richard
   reverses -07 Decision 2: an uppercase tag is an unknown tag (so "M=1" ->
   "tag=m missing"), and JSON keys are strictly lowercase too.

L. From Authentic (§14.8): "previous From header fields that Recipes show have
   been present SINCE THE MESSAGE WAS FIRST SIGNED" -- matches the -07 ruling
   (From in effect at each signature; unsigned leading MIs fine). Verify only.

## DSN

M. §7.1 item 4 / §16.2: a DSN signer MUST choose d= so it relaxed-matches a
   recipient in the reported message's top rt= (check the Perl DSN generator).
   §16.4 item 3: inbound DSN h= evaluated per §14.7, except with no body
   present a hash-set passes if its header hash matches.
   Body-less returned message without DKIM2 headers: spec doesn't apply.

## Editorial (no code impact)
- "dexterity" -> "agility"; "sub-domain" -> "subdomain"; "email" -> "message".
- §6.2 order wording: "ascending order of the octet values of their (lower-cased)
  header field names" -- confirm every impl sorts by bytes, not locale.
- §4.1: MI and DKIM2-Signature are trace header fields (RFC 5322 §3.6.7).
- Replay (§15.1): "same" = m=1 header AND body hashes match (we don't implement replay).

## Version bumps
DKIM2_DRAFT -> ietf-dkim-dkim2-spec-08 per memory dkim2-spec-version
(perl Common.pm, Mailman message_instance.py, Sympa); version tests ban spec-07
with history exceptions; replace c/dkim2-spec.txt wholesale.

## Decisions (Bron, 2026-10-28)
1. Auto-Submitted / VBR-Info (A): flip everywhere together in one deploy; Bron
   refreshes the hm vendor from the CPAN release straight after. No dual-hash fallback.
2. ML-DSA-44 (B): VERIFY-ONLY in all verifiers, assuming k=mldsa44 with p= the raw
   1312-octet public key in base64 (DKIMKEYS -02 gap, to report). No signer emits it.
3. Null body Recipe (I): keep the PASS result, but expose a "not fully verified"
   property (body below m=<x> unrecoverable) that local policy can act on.
