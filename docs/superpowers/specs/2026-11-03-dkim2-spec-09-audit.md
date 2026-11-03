# DKIM2 spec -09 audit checklist

Spec text: spec/draft-ietf-dkim-dkim2-spec-09.txt (published 2026-11-01).
Previous:  spec/draft-ietf-dkim-dkim2-spec-08.txt.
Companions: draft-ietf-dkim-dkim2-dns-03 (DKIMKEYS, a substantial rework),
draft-gondwana-dkim2-authres-02, draft-gondwana-dkim2-debug-header-03 (all in ../spec).
Our code targets -08. "Current" below describes Perl Mail::DKIM2 0.28. The
other verifiers were not audited item by item; they were ported from the same
contract, so assume they behave the same until each port checks.

## Section numbering 08 -> 09

Two subsections are new and both are appended, so no existing number moves:
- §3.8 Domain Policy Record (after §3.7 Key management);
- §11.1 Using subdomains to make From header fields Authentic.
Every "§N.M" comment pointer stays valid apart from the draft number.

## Wire format

Nothing changes on the wire. No signer change is needed for interop: the hash
inputs, signing input, Recipes and tag sets are the same as -08. Every change
below is in what a verifier concludes, plus one new DNS record.

## Verifier changes

A. NONE is a fifth output state (§14.1, §14.2). A message with no
   Message-Instance and no DKIM2-Signature is NONE, string "NONE: No DKIM2
   header fields found". We already report `none` (the -07 ruling, and in
   A-R under authres-01). Current Perl details read "no DKIM2-Signature headers
   found" / "no Message-Instance headers found". Align the string. The authres-02
   mapping now comes straight from the spec, so no A-R change is needed.

B. Null Recipe = PERMERROR (§13, §14.2). NEW string "PERMERROR: Message-Instance
   m=<x> has a null recipe". "Whether such a message is nevertheless acceptable
   is a matter for local policy." This REVERSES -08 Decision 3: today Perl keeps
   PASS and sets `fully_verified` false (Validate.pm appends "not fully
   verified"). Where it goes in the §14.2 order (C9 a..h) and which m=<x> it
   names (the instance holding the null body Recipe, presumably) both need
   deciding. Consumer impact: hm and the milters see PERMERROR where they saw
   PASS. Our own list managers emit a null body Recipe when a body rewrite
   goes past the 1000-literal-line cap of the capped Myers diff (the epilogue
   fallback is disabled since 0.23), so those posts will no longer PASS
   downstream.

C. Domain Policy Record plus the upward match for an Authentic From (§3.8,
   §7.1 item 4, §11.1, §14.8; DKIMKEYS -03 §6). NEW behaviour:
   - When From-domain (P1) vs d= (P2) does not match, re-run the match with
     d= as P1 and the From domain as P2. A d= that is a SUBDOMAIN of the From
     domain then matches, unless the From domain's DPR says f=strict.
   - The DPR is a TXT record at `_domainkey.<from-domain>` (A-label). Ignore
     records that do not begin with v=DKIM1. More than one left over is a
     PERMERROR. A temporary DNS failure is a TEMPERROR. No record, no f=, or
     no "strict" flag means subdomains are authorized. f= is a colon-separated
     list; unknown flags are ignored. There is no inheritance: look up the
     exact From domain only.
   - NEW §14.8 strings:
       FAIL: DKIM2-Signature i=<x> From <value> forbids subdomain signing
       FAIL: DKIM2-Signature i=<x> From has more than one address
       FAIL: DKIM2-Signature i=<x> From uses a domain literal
       TEMPERROR: DKIM2-Signature i=<x> policy for <value> unavailable
       PERMERROR: DKIM2-Signature i=<x> multiple records for <value> policy
     Today the last three cases all report "matching From is not authentic".
     Perl relaxed_domain_match is one-way (Common.pm:862) and from_authentic
     returns only a boolean.
   - Performance: this is a new DNS query on the verify path, but only when
     the downward match fails and the upward one succeeds, which is rare. Do
     it lazily with query(), not in the key prefetch. It must go through the
     same resolver (override-only-`send` resolvers, see the 0.22 incident)
     and be cached per verify. PubkeyCallback users (hm?) need a way to
     supply it. This needs an API decision: a PolicyCallback, or route it
     through the resolver.
   - Signers: §12.4 "simple terms" now allows a subdomain d= for the From.
     Our signers' "can I make From authentic" gates (milter, Mailman and
     Sympa From rewrite) can stay downward-only, which is conservative and
     still valid.

D. Key records (§3.7, §14.5; DKIMKEYS -03 §4). Before counting, ignore TXT
   records at the selector that begin with "v=" and a value other than DKIM1.
   More than one left over is "has multiple records". Today Perl counts every
   TXT RR (Verifier.pm:1017), so a stray v=spf1-style record next to the key
   makes it a PERMERROR. Also: DKIMKEYS deprecates the h=, n=, s= and t= tags.
   We already ignore them once they parse, so no change.

E. RSA < 1024 (§3.2, §14.6 step 4). The MUST NOT is gone. A verifier MAY
   regard a key as too short, which gives the NEW string "PERMERROR:
   DKIM2-Signature i=<x> public key <s1> too short". Today Perl reports
   "is malformed" for < 1024 (Common.pm:1017, Verifier.pm:879).

F. "insecure" (§14.6, §14.7). NEW optional strings "selector <s1> algorithm
   insecure" and "Message-Instance m=<x> algorithm <value> insecure". We
   regard nothing we implement as insecure, so nothing emits them.

G. String renames and new §14.2 checks:
   - "Message-Instance m=<x> is duplicated" and "DKIM2-Signature i=<x> is
     duplicated" REPLACE our "<field> <tag>=<n> appears more than once"
     (Common.pm:242, C9 steps c/e);
   - "Message-Instance m=<x> recipe <value> is invalid": lower-case "recipe"
     (MessageInstance.pm:417);
   - "FAIL: DKIM2-Signature i=<x> mf= and d= do not match" replaces "MAIL FROM
     and d= do not match" (Verifier.pm:951);
   - NEW "PERMERROR: DKIM2-Signature i=1 has an exploded flag". Today the
     verifier does not check this; only signers drop it at i=1. It needs a slot
     in the C9 order (per-field validity, step d).

H. ML-DSA-44. DKIMKEYS -03 now defines k=mldsa44, with p= the raw 1312-octet
   pkEncode key and no wrapper. That is exactly what -08 Decision 2 assumed,
   so the spec gap we noted is closed. Python, Go and C verify it; Perl and JS
   don't (no library). Drop the "DKIMKEYS gap" notes; nothing else to do.

I. ABNF and editorial, no code: base64string now forbids leading FWS inside the
   token (tag-value [FWS] still covers it); "Tags may appear in any order,
   unless otherwise specified" (v= first in key/DPR records, as today); A-label
   before the DPR lookup; TEMPERROR now says "a DNS record", not "a public key".

## Companion drafts

- authres-02: NONE maps to "none". We already emit this, so no change.
- debug-header-03: `verify=` is one of the five states. Emitters bump
  draft=ietf-dkim-dkim2-spec-09 and their own DKIM2_DATE.

## Version bumps

DKIM2_DRAFT -> ietf-dkim-dkim2-spec-09 (perl Common.pm, Mailman
message_instance.py, Sympa DKIM2.pm). The version tests ban spec-08 pointers,
with history exceptions. Replace c/dkim2-spec.txt wholesale. Update
perl/CLAUDE.md, the README and the website (the verify page and operator
guide on null Recipes and NONE, and the DPR in the key-publishing text).

## Decisions needed (Bron)

1. Null Recipe (B): follow -09 (PERMERROR) and retire `fully_verified`?
2. DPR lookup API (C). hm's two callers differ. The authmilter DKIM2Verify
   sets `->resolver(...)`, so the DPR can go through the same resolver. The
   FastMTA EOD handler sets only a PubkeyCallback, which uses
   $transaction->resolver, and no Resolver. If we do nothing, the library
   would build a default Net::DNS resolver for the DPR and bypass FastMTA's
   resolver. The options are a new `PolicyCallback`, mirroring
   PubkeyCallback, or making FastMTA also set Resolver. (Separately,
   FastMTA's callback returns the first key that parses out of several TXT
   records. Under -09 that is an error once the non-DKIM1 ones are dropped.
   It is hm-side, worth a note.)
3. RSA < 1024 (E): keep refusing, with the new "too short" string?
4. Publish a DPR on dkim2.com / test zones (e.g. a f=strict test domain in
   dns.json for vectors)?

## Decisions (Bron, 2026-11-03)
1. Null Recipe (B): follow -09, PERMERROR "has a null recipe". `fully_verified()`
   stays as a deprecated accessor. ALSO raise the capped-Myers literal-line cap
   so our list managers rarely emit a null body Recipe (the new cap value is set
   in the design, the same in every generator, vectors/body-diff.json updated).
2. DPR API (C): a new `PolicyCallback` option, mirroring PubkeyCallback, falling
   back to Resolver. hm's FastMTA handler adds one that uses its own resolver.
3. RSA < 1024 (E): keep refusing, with the new "public key <s1> too short" string.
4. DPR fixtures (strict / non-strict / multiple / temp-fail) in the test zones
   (dns.json + vectors) only. Nothing on dkim2.com's live zone.
5. (follow-up, 2026-11-03) The null-recipe error names the m= of the instance that
   holds the null. The i=1 exploded check goes anywhere before the hashing and
   signing work (a well-formedness check). Leave the diff cap at 1000, and don't
   sign if we can't express the change (this supersedes "raise the cap" in 1).
6. (revised, 2026-11-03) SIGN over a null body Recipe ("it will PERMERROR regardless
   but at least we've signed our header changes"). The AllowNullBodyRecipe behaviour
   becomes the default and the option a no-op. A malformed v=DKIM1 DPR fails closed
   (treated as strict).
