# DKIM2 draft -09: implementation contract

Spec: `spec/draft-ietf-dkim-dkim2-spec-09.txt` (published 2026-11-01), with
draft-ietf-dkim-dkim2-dns-03. Our code targets -08.
Audit items A-I and Bron's decisions are in `2026-11-03-dkim2-spec-09-audit.md`.

This document fixes every choice the spec leaves open, so that all
implementations behave identically. "MUST" here is our contract. The -08
contract (`2026-10-28-dkim2-spec-08-design.md`, D1-D13) still holds except
where this one replaces it. In particular the C9 check order stays, and the
first error is the result.

Nothing changes on the wire. Signers and verifiers on -08 and -09 interoperate
on every message that -08 passed, except where noted below: a null Recipe
(E2), a subdomain From (E3) and a key next to a foreign TXT record (E4).
So, unlike -08, this need not deploy in lockstep, though we will still roll
it out in one go.

## E1. NONE (§14.1, §14.2)

- A message with no Message-Instance and no DKIM2-Signature field gives
  result `none` with details `No DKIM2 header fields found`. The details used
  to be "no DKIM2-Signature headers found".
- A-R stays `dkim2=none`, and the X-DKIM2-Info action stays `verify=none`.
- Nothing else is NONE. Instances with no signature, or signatures with no
  instance, give the existing §14.2 PERMERRORs. Perl's InstancesOnly mode
  keeps its own `none` for "no Message-Instance headers found" (an internal
  mode with no signatures to judge).

## E2. Null Recipe is a PERMERROR (§13, §14.2). Replaces -08 D9.

- An MI whose Recipe has `"b": null` gives `PERMERROR: Message-Instance m=<x>
  has a null recipe`, where `<x>` is the m= of the instance that holds the
  null.
- **Order:** this is a per-instance Recipe check, made in the same slot as
  `recipe <path> is invalid` for that instance and immediately after it. So it
  comes after the whole-document JSON checks and the step checks of that same
  instance, and every C9 structure error (a..h) still wins. The §14.2 content
  checks visit instances in ascending m=, so if several instances hold a null
  the LOWEST m= is named, and a lower instance's own Recipe fault beats a
  higher instance's null (vectors null-two, malformed-body-recipe-below-null).
  A signer's own view of the chain (Perl AllowUnsignedMI/MidProcess) skips the
  check for instances no signature covers yet.
- The check doesn't depend on whether the body below could have been
  checked. A null at the top instance with nothing below it is still a
  PERMERROR (spec text: "a PERMERROR will result").
- `fully_verified` (in every language) becomes a deprecated accessor: true
  exactly when the result is PASS, except that it stays false in Perl's
  HeadersOnly/InstancesOnly modes. A deprecated option that is still accepted
  warns only when it is set to a true value (hm passes
  `AllowNullBodyRecipe => 0` on every call). Validate.pm drops its "not fully verified" summary
  suffix. The verify page and validator drop their display of the flag.
- **Signers sign over a null** (Bron, 2026-11-03, revised: "just sign it, it
  will PERMERROR regardless but at least we've signed our header changes"):
  - The diff cap stays at 1000 literal lines (MAX_RECIPE_LITERALS). A
    generator over the cap writes a null body Recipe, as today.
  - The signer signs over an unsigned instance holding a null body Recipe, as
    `AllowNullBodyRecipe` does today. That behaviour becomes the only one:
    `AllowNullBodyRecipe` (Gate), `--allow-null-body-recipe` (dkim2-milter)
    and `allow_null_body_recipe` (DKIM2Sign) are still accepted, so configs
    don't break, but they do nothing and warn once that they are deprecated.
    `not-signed=null-body-recipe` goes away. Remove the options from
    deploy/examples and SERVER.md.
  - Only OUR OWN nulls (Bron, 2026-11-03): this covers an unsigned instance
    above every valid signature, which this host's list manager added. A null
    that arrived already signed fails upstream verification (`has a null
    recipe`), and the gate refuses it as `upstream-chain`, like any other
    broken upstream chain. In dkim2-milter that is the existing path for a
    message carrying a DKIM2-Signature: reject 550 5.7.1 "not signing: ...".
  - The DSN generator never carries a null-Recipe message, as already the case.

## E3. Authentic From: up/down match and the Domain Policy Record

### E3.1 The check, per (signature i, From values) pair (§14.8)

The pairs, and which From each signature is checked against, are unchanged
from -08 (Ruling 19). For each pair, in i order, the first failing step is
the result for the pair, and the first failing pair is the message's result:

1. More than one From field, or a value with a "," outside quotes and
   comments (a list of addresses, or a group holding more than one), gives
   `FAIL: DKIM2-Signature i=<x> From has more than one address`. No From
   field, a group without a ",", a value with no "@", or one that is not a
   mailbox at all give `FAIL: DKIM2-Signature i=<x> matching From is not
   authentic`. (Perl Common::from_mailbox is the reference.)
2. A domain literal gives `FAIL: DKIM2-Signature i=<x> From uses a domain
   literal`.
3. The downward match: relaxed_domain_match(From-domain, d=) PASS means the
   pair is Authentic. No DNS lookup.
4. The upward match: if relaxed_domain_match(d=, From-domain) fails, the
   result is `FAIL: DKIM2-Signature i=<x> matching From is not authentic`.
5. Otherwise look up the DPR for the From domain (E3.2):
   - a temporary failure gives `TEMPERROR: DKIM2-Signature i=<x> policy for
     <dom> unavailable`;
   - more than one record gives `PERMERROR: DKIM2-Signature i=<x> multiple
     records for <dom> policy`;
   - a strict flag gives `FAIL: DKIM2-Signature i=<x> From <dom> forbids
     subdomain signing`;
   - anything else means the pair is Authentic.

`<dom>` is the From domain as an A-label, lowercased, with no trailing dot.
This is also the name the lookup uses.

### E3.2 The Domain Policy Record (§3.8; DKIMKEYS -03 §6)

- Query: TXT at `_domainkey.<dom>`, the exact From domain only. There is no
  walk up or down the DNS tree.
- Concatenate each RR's strings with nothing in between. Keep only the
  records whose first tag is `v` with the value exactly `DKIM1`. The check is
  case-sensitive and allows WSP around `=` and before the first tag. Discard
  everything else. Trim WSP in linear time: the record is attacker-served
  (up to 64 KB), and a naive trailing-WSP regex is quadratic.
- No record left, NXDOMAIN or NODATA: subdomains are authorized.
- More than one record left: PERMERROR, as above.
- One record left: parse it as a tag=value list using the same parser and
  rules as key records (duplicate tags are a syntax error, tag names are
  case-sensitive, unknown tags are ignored). `f=` is a colon-separated list
  of flags with [FWS] around each `:`. Strict means the flag `strict` (exact,
  case-sensitive) is in that list. An `f=` that breaks the ABNF (an empty
  member such as `f=strict:` or `f=a::b`, or a member that is not a
  hyphenated-word: `[A-Za-z]([A-Za-z0-9-]*[A-Za-z0-9])?`) is a malformed
  record, and so strict. An empty `f=` is no flags.
- **A record that begins v=DKIM1 but fails to parse is treated as strict**
  (fail closed; the spec gives no string for it; Bron agreed 2026-11-03). It
  reports the same FAIL, `From <dom> forbids subdomain signing`.
- Temporary failure: SERVFAIL, timeout, a truncated answer that can't be
  retried, or the PolicyCallback dying with a TEMPERROR. This uses the same
  classification as the key fetch.
- One lookup per distinct `<dom>` per verification, cached. It is lazy: made
  only at step 5, never in the key prefetch, and never for a message that
  already has an error (first error wins).

### E3.3 API

- Perl: a new Verifier option `PolicyCallback => sub ($domain, $verifier)`.
  It returns an arrayref of TXT strings (each RR's strings already joined),
  `[]` or undef for none, and dies with `TEMPERROR: ...` for a temporary
  failure. The library then does E3.2's filtering, counting and parsing, so
  every caller gets the same semantics. With no PolicyCallback, the lookup
  goes through the Verifier's Resolver with `query()` (so override-only-`send`
  resolvers work), falling back to the default resolver, exactly like the
  key fetch. A `set_policy_callback()` setter mirrors `set_pubkey_callback`.
- hm: the FastMTA EOD DKIM2 handler adds a PolicyCallback using
  `$transaction->resolver`. The authmilter's DKIM2Verify already sets
  `resolver`, so it needs no change. Bron's hm CI is the gate.
- Other languages use their existing resolver abstraction (Python
  `dns_resolver`, Go `Resolver`, C txt-lookup hook, JS DoH fetch) plus a
  policy hook where they already have a key hook. The browser verifier does
  the DPR lookup over the same DoH path.
- Signers are unchanged: their "can I make From Authentic" gates stay
  downward-only (§12.4 permits more, but downward is always valid).

## E4. Key records (§3.7, §14.5)

- Before counting, discard TXT records at the selector name whose first tag is
  `v` with a value other than `DKIM1`. This uses the same first-tag test as
  E3.2, but here a record with no `v=` is kept (v= is optional for keys).
- More than one record left still gives `has multiple records`. A record that
  starts with something unparseable is kept, and then fails as `has a syntax
  error` if it is the only one.
- The PubkeyCallback contract is unchanged (it returns a key). Note for hm:
  FastMTA's callback returns the first parseable key among several records,
  which differs from E4. That is hm's to fix.

## E5. RSA too short (§3.2, §14.6)

`PERMERROR: DKIM2-Signature i=<x> public key <s> too short` for an RSA key
under 1024 bits. This replaces -08 D7's "is malformed" for that one case.
Everything else in D7 stands. Keys up to 4096 bits MUST verify, and larger
ones may.

## E6. Strings and the i=1 exploded check (§14.2, §14.4)

| -08 | -09 |
|---|---|
| `<field> m=<n> appears more than once` | `Message-Instance m=<x> is duplicated` |
| `<field> i=<n> appears more than once` | `DKIM2-Signature i=<x> is duplicated` |
| `Message-Instance m=<x> Recipe <path> is invalid` | `... recipe <path> is invalid` |
| `FAIL: ... MAIL FROM and d= do not match` | `FAIL: ... mf= and d= do not match` |
| (none) | `PERMERROR: DKIM2-Signature i=1 has an exploded flag` |

- **Exploded at i=1:** a per-field validity check on the i=1 signature, made
  in the §14.2 per-signature field checks (Perl `_check_sig_field`), after
  the tag missing/unexpected checks and
  before the duplicate-selector check (the spec's listing order). It is a
  header well-formedness check, made before any key fetch, hashing or signing
  work. `f=` holding `exploded` anywhere in its list counts.
- "insecure" (§14.6, §14.7): nothing we implement is regarded as insecure, so
  nothing emits it. Not implemented.

## E7. Names and versions

- DKIM2_DRAFT is `ietf-dkim-dkim2-spec-09` everywhere. DKIM2_DATE is the date
  each repo's change lands.
- X-DKIM2-Info conforms to debug-header-03. The format is unchanged; only the
  draft value moves.
- Section numbers don't move, so only the draft number in `§` pointers
  changes. The version tests ban `spec-08`/`draft-08` pointers, with history
  exceptions (the -08 change notes, D-numbered contract citations).
- Replace `c/dkim2-spec.txt` with the -09 text. Update perl/CLAUDE.md, the
  READMEs and the website: the verify page (NONE, null recipe, the From
  strings), the operator guide (DPR, `f=strict` for hosting-style parents,
  the retired null-Recipe option) and the key-publishing text.
- Remove the "DKIMKEYS has no k=mldsa44" notes. -03 defines it exactly as we
  assumed.

## E8. Vectors and fixtures

- dns.json (test zones only, Decision 4): a parent domain with `v=DKIM1;
  f=strict`, one with `v=DKIM1; f=foo:strict`, one with `v=DKIM1` (no f=),
  one with two v=DKIM1 records, one with a v=DKIM1 record that is
  unparseable, one with a non-DKIM1 TXT record only, and a key selector
  sitting next to a `v=spf1` TXT record. A temporary failure is simulated by
  each test harness, since dns.json cannot express one.
- Negative vectors for every new string in E1-E6, plus positive vectors: a
  subdomain d= with the From at its parent (non-strict) PASS, and the
  non-DKIM1 sibling record PASS. Every verifier must agree
  (`util/negative-vectors.sh`).

## Rollout

1. Perl (Mail::DKIM2 0.29): the whole contract, tests first, one release.
   Review for security, correctness, performance (the DPR lookup's latency
   and failure modes) and the consumer API (hm call sites).
   `PERL_JSON_BACKEND=JSON::PP make test`.
2. Port to Python, Go, C and JS, one at a time, against the shared vectors.
3. Mailman (`dkim2` first, then backport to 3.3.10 and cherry-pick to 3.3.8)
   and Sympa: the version bump and dropping the null-Recipe option use.
4. Deploy everything, then run the prod acceptance tests (list smoke,
   validator good/bad, /verify/).
5. Bron uploads 0.29 to CPAN and refreshes hm, adding the FastMTA
   PolicyCallback.
