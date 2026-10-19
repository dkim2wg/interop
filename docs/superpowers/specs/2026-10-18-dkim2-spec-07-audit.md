# DKIM2 spec -07 audit checklist

Spec text: /Users/brong/src/interop/spec/draft-ietf-dkim-dkim2-spec-07.txt
Previous:  /Users/brong/src/interop/spec/draft-ietf-dkim-dkim2-spec-06.txt
Read the -07 sections cited below for exact wording. Our code currently targets -06.

## Section renumbering 06 -> 07 (for comment refs like "§11.4")
- 3.4 other algs -> 3.5; 3.5 Selectors -> 3.6; 3.6 key mgmt -> 3.7; NEW 3.4 MLDSA44-Ed25519-SHA512
- 4, 5, 6 unchanged
- 9.4 relaxed domain match -> 7 (7.1 uses, 7.2 algorithm). NEW 8 Tag=Value lists
- 7 Message-Instance -> 9 (7.1->9.1, 7.2->9.2, 7.3->9.3)
- 8 DKIM2-Signature -> 10 (8.N -> 10.N)
- NEW 11 From header fields are required to be Authentic
- 9 Signer actions -> 12 (9.1->12.1, 9.2->12.2, 9.3->12.3, 9.5->12.7, 9.6->12.8; NEW 12.4 From Authentic, 12.5 exploded flag, 12.6 timestamp)
- 10 Verification requirements -> 13 (NEW 13.1 Provisionally Verified, 13.2 SMTP codes, 13.3)
- 11 Verifier actions -> 14 (11.1..11.7 -> 14.1..14.7; 11.8 donotmodify REMOVED; NEW 14.8 From Authentic)
- 11.9 replay -> 15 (rewritten, no verifier error string any more)
- 12 DSN -> 16 (12.1 -> 16.1, 12.1.1 -> 16.2, 12.1.2 -> 16.3)
- 13 transport -> 17; 14 EAI -> 18 (now real content); 15 IANA -> 19; 16 Security -> 20

## Items
A. f= flags (§10.10): "donotmodify" and "donotexplode" REMOVED. Remove verifier checks (old §11.8)
   and their error strings, signer options/APIs that emit them, accessors, tests.
   "exploded": MUST be set by an intermediary sending copies to >1 address (§12.5), even if copies
   differ; MUST NOT be set on i=1. Old "FAIL: Duplicate message with no exploded flag" error gone.
B. MLDSA44-Ed25519-SHA512 (§3.4): new sig-name "mldsa44-ed25519-sha512"; SHA-512 over the canonical
   MI+Sig headers (§12.8), signed by ML-DSA-44 (FIPS 204) AND Ed25519; sig value = MLDSA44 sig || Ed25519 sig.
   Verifiers MUST implement all algorithms. DKIMKEYS (draft-chuang-dkim2-dns-04) defines NO k= value
   or p= encoding for it (spec gap). Report: current algorithm dispatch points, and what crypto
   library is available in this language/runtime for ML-DSA-44 (versions installed here).
C. "u" Recipe step (§5, §5.1, §5.2): the spec adopted our proposed "b" step but named it "u".
   Each step MUST contain exactly one of "c","d","u". u strings: canonical base64 (no FWS, padded,
   zero pad bits — pattern in the §5 schema), decoded value MUST NOT contain CR/LF; "u" SHOULD NOT
   be used when "d" would suffice; "u" MUST be used when value is not valid UTF-8.
   Report every place "b" step is emitted, parsed, validated, displayed, tested.
D. JSON (§5): keys MUST be lowercase and MUST be unique within any object (duplicate keys outlawed).
   Do we reject duplicate keys (at every level, incl. inside "h" and inside step objects)?
   Do signers emit lowercase header-name keys in "h"? Do verifiers reject uppercase keys?
   (Note tension: §5.1 also says header names in keys match case-insensitively.)
   Unknown top-level keys ignored; inside h/b only defined structures.
E. Tag=Value (§8): duplicate tag-name -> whole tag-list invalid; unknown tags ignored; MI and Sig
   tag-names MUST be lowercase; tag-value grammar; optional trailing ";".
F. Chain of Custody (§7.1 item 1, §7.2, §14.4) — CHANGED:
   - i=1 not checked; any sig following an nd= sig is not relaxed-checked; instead its d= MUST equal nd= exactly.
   - sig with non-null mf=: relaxed match, Parameter1 = mf domain, Parameter2 = an rt= addr domain of previous sig.
   - sig with mf=<> (null): relaxed match, Parameter1 = previous sig's rt= domain, Parameter2 = this d=.  (NEW)
   - sig with nd=: relaxed match, Parameter1 = previous sig's rt= domain, Parameter2 = this d=.  (NEW)
   - EVERY sig: relaxed match Parameter1 = mf domain, Parameter2 = d= (skip when mf=<> or nd= present). (was SHOULD, top only)
   - Algorithm (§7.2) is asymmetric: strip leftmost labels from Parameter1 only. Domain literal never matches.
   - Error strings: "DKIM2-Signature i=<x> mf= does not match the rt= of i=<y>" (NEW),
     "DKIM2-Signature i=<x> d= does not match the rt= of i=<y>" (NEW), "DKIM2-Signature i=<x> nd= does not match"
     (was "MAIL nd= does not match"), "... MAIL FROM and d= do not match", "... unexpected nd= tag",
     "... MAIL FROM <value> did not match", "... RCPT TO <value> did not match".
G. From Authentic (§11, §12.4, §14.8) — NEW requirement:
   - Verifier: From domain relaxed-matches (Parameter1 = From addr-spec domain, Parameter2 = d=) the
     relevant sig: i=1 if From never changed; if a header Recipe in MI m=k changed From, the lowest i
     whose sig m= >= k, paired with the From as it was after that change. Check current From AND every
     previous From that Recipes show. From with >1 address or domain-literal is never Authentic.
     IDN: U-label -> A-label before compare (§18). Error: "PERMERROR: DKIM2-Signature i=<x> matching From is not authentic".
   - Signer: when originating, or when it modifies From, MUST choose d= so From is Authentic.
     Should a signer refuse when it can't? Does the signer gate (verify-before-sign) need this check?
   - Impact on test fixtures/vectors whose From domain doesn't match i=1 d=.
H. Error strings (§14.x) renamed/new:
   - "FAIL: Message-Instance m=<x> header hash <value> mismatch" / "... body hash ..." (06 had "Message Instance" no hyphen)
   - "FAIL: DKIM2-Signature i=<x> selector <s1> incorrect signature" (06: "i=<x> <selector> incorrect signature")
   - "FAIL: DKIM2-Signature i=<x> signature <s1> signature <s2> failed" (06: "<s1> signature passed, <s2> signature failed")
   - NEW "PERMERROR: Message-Instance m=<x> JSON is unacceptably complex"
   - NEW "PERMERROR: No DKIM2 header fields found"
   - key errors use Selector: "public key <s1> could not be fetched/does not exist/has multiple records/has a syntax error/algorithm mismatch/has been revoked"
   - "signature expired", "signature is from the future" (14 days / 1 day — now "not Validly Signed", not SHOULD)
   Compare every error string the implementation emits against §14.2-§14.8 lists.
I. §12 preamble: signer MUST NOT sign a non-initial message unless it is a Validly Signed DKIM2 Message
   (or out-of-band arrangement). §13: an invalid message MUST NOT be forwarded. Does the signer gate
   cover the new checks (From Authentic, new chain-of-custody rules)?
J. §13.1/13.2 SMTP: TEMPERROR -> 4xx SHOULD; failures 550/5.7.x SHOULD; DNS temp 451/4.7.5 SHOULD;
   human-readable string in the reply. DSN only for Provisionally Verified messages. (milters/handlers only)
K. §16 DSN: no DSN when top mf=<>; DSN itself has exactly one Sig and one MI and mf=<>;
   inbound DSN auth: Parameter1 = returned message's top rt= domain, Parameter2 = DSN i=1 d=.
L. §18 EAI: mf=/rt= domains recorded as A-labels; From domain A-label before compare.
M. Version constants / "spec-06" references / §-refs that need bumping (list files, not every line).

---

# Audit findings (2026-10-18, read-only audits against -06 code)

Line numbers are as of master de3d670. Where these findings conflict with the
contract (`2026-10-18-dkim2-spec-07-design.md`), the contract wins: liberal
receive of key/tag case, "u" emitted only for non-UTF-8, and so on.

## C (c/)
- A: the signer never emits f= (dkim2_sign.c:393/455); milter dkim2_milter.c:65 collects rcpts and signs once with no flag. test_header.c:250 uses donotmodify as sample data.
- C: dkim2_recipe.c:115-126 step_kind (c>d>b precedence, ignores step with none); :85-113 decode_b_item (pad bits unchecked); :132-160 walk_literals, :450; dkim2_plan.c:232; emit :505-528 add_literal (any byte >=0x80 becomes "b"). Tests test_recipe.c:195-272, :343-347; test_plan.c:315/398/400. "d" strings are not UTF-8-checked.
- D: duplicates rejected (has_duplicate_key :162-178), but case-sensitively. An uppercase "h" key matches nothing (:336/350/466); it must match case-insensitively.
- E: tagparse.c:62 lowercases names (OK under the contract); ";;" in the middle is accepted (:38), and it should not be.
- F: dkim2_verify.c:964-1023. The nd hop calls relaxed_domain_match(rt_d, cur->d); the helper strips its SECOND arg (:99-110), so the direction is REVERSED. mf=<> always fails, because addr_domain returns NULL. Chain errors are returned as DKIM2_FAIL (should be PERMERROR). mf-vs-d is at :838 (OK).
- H: no colon after the state, and many strings differ (dkim2_header.c:132-195, plan.c:822-837, verify.c:483-564, :730, :755, :800, :816, :845, :906-960, :1006, :1019). Future skew is 300 s (:813).
- I/J: dkim2_milter.c:196-205 ACCEPTs when the gate says not signing; :179/:182 REJECT/TEMPFAIL with no smfi_setreply.
- L: no IDN anywhere (to_rfc5321_path dkim2_sign.c:337).
- Fixed buffers: sigbuf[1024] dkim2_crypto.c:83, complete_sig[4096] dkim2_sign.c:452 (only matters for MLDSA, skipped).
- M: refs in most .c/.h files and tests; c/dkim2-spec.txt; c/TODO-dsn.md.

## Python (python/)
- A: _flag_enforcement_errors dkim2verify.py:393-436 (called :1168, :1252) to be deleted; signer flags dkim2sign.py:869, CLI --flag :1131; tests/test_flags.py:21-47.
- C: emit dkim2sign.py:306-313 (isascii); parse dkim2undo.py:135-155 (b64decode(validate=True) accepts non-zero pad bits; surrogateescape at :150-152 accepts lone surrogates in "d"); dkim2plan.py:115. Tests: test_recipe_b_steps.py, test_recipe_not_utf8.py, test_recipe_generation.py, test_recipe_malformed.py, generate_multihop.py, test_fold_fws.py, test_plan_walk.py.
- D: object_pairs_hook dkim2undo.py:60-74 (case-sensitive dups). Keys are lowercased at dkim2undo.py:265,281 and dkim2plan.py:127-143, where the first key wins. "h":{} is accepted.
- E: _tag_list_ok :349 accepts ";;" and a leading ";".
- F: _chain_custody_errors dkim2verify.py:250-311. nd hop REVERSED (_relaxed_domain_match(cur_d, rt)). mf=<> fails. The mf-vs-d check (:756-764) has no prefix, so it is classified as fail (:909). Literals are not excluded (_domain_from_addr :199).
- H: :617/:635 hash mismatch, :878, :749/:751 (300 s future), :274, :295, :301, :309, :281, :762, :1124, :1129, :1100, :1067 (none), :1072, :1060, :1089, :709, :1046, :582, :586, :610/:628, :244, :1324, :741, :778, dkim2sign.py:745-746.
- K: dkim2dsn.py:345, `if not upstream`, lets "<>" through.
- L: to_rfc5321_path dkim2sign.py:54.
- Gate: dkim2sign.py:926-1002.

## Perl (perl/)
- A: Verifier.pm:408-454 donot* check + POD :1424-1425, Signature.pm:462, Signer.pm:387. bin/dkim2-milter:930-937 _do_sign and Handler/DKIM2Sign.pm:270-274 never set exploded. Tests: t/verifier_flags.t, t/hash-agility.t (:96, :290-305), t/signature-flags.t, t/signature-accessors.t.
- C: MessageInstance.pm:257-292 emit (:286 non-ASCII becomes "b"); parse :401-447 (pad bits :437-444; first key wins; unknown keys ignored; bare arrays/strings :449-455 accepted, now invalid). POD :1288-1296, :1405. t/recipe-base64.t.
- D: Common.pm:238-277 _json_duplicate_key (case-sensitive); MessageInstance.pm:369-373, :389, :101/:121. {} is not rejected.
- E: TagValueList.pm:21-64; Verifier.pm:641 dup-tag string should be "syntax error".
- F: Verifier.pm:929-1003. nd hop REVERSED; mf=<> fails; results are 'fail'. Literal (Common.pm:570-580). mf-vs-d is at :776-786.
- G: Reflector.pm:369-395 dkim1-bridge signs i=1 as d=dkim2.com with the sender's From. bin/dkim2-milter:483 picks the key by envelope-from domain and only logs From alignment (~:590-597). Fixtures: t/lib/DKIM2SignedFixture.pm (From a@test1 ...), and From a@example.com/.org with d=test1 in body-plan, body-diff, gate-mime-warn, header-plan, mi-body-recipe-option, mi-chain, mi-null-header-history, undo-bounds, wrap tests.
- H: Verifier.pm:303 (none), :364, :375, :510, :617 (+MessageInstance.pm:1063-1066), :749 (300 s), :754, :911, :783, :947-997, :428/:502, :625, :731, :763/:771, :792, :821, :905, :861 "(why)" suffix; MessageInstance.pm:325, :383/:394, :398, :428-446; Signature.pm:380/383; Common.pm:130-177.
- I: Gate.pm:110-221 (allow_unsigned_mi).
- J: bin/dkim2-milter always SMFIS_CONTINUE (272-669); DKIM2Verify.pm:196-207.
- K: DSN.pm:128-135 falls back to the From: header when mf=<> (must not send); bin/dkim2-reflector.pl:81-91 sends a DSN regardless of verification. Inbound auth DSN.pm:251-270 OK.
- L: Common.pm:550 extract_domain; URI::_punycode is available.
- Crypto: CryptX 0.087 (no ML-DSA; MLDSA skipped anyway).

## Go (go/)
- A: verify.go:336-376 donot* block (keep hashSetsEqual, used by sign.go:133). The signer has no Flags: SignOptions signature.go:48-75, buildIncomplete :468-486. Tests flags_test.go:23-27, fold_fws_test.go:104-109.
- C: recipe.go:23-27 struct tag json:"b", :121-126, :134-157 (base64.StdEncoding accepts pad bits; use .Strict()), :162-227, emit appendLiteral :474-494. Tests recipe_bytes_test.go, bodydiff_test.go, plan_test.go, vectors/body-diff.json.
- D: jsonDuplicateKey recipe.go:239-281 is exact-case. encoding/json is case-insensitive for struct fields, so {"b":[1],"B":[2]} gets through; {"B":null} misses the null probe at :295. undo.go:228-230 and plan.go:213-219 collapse h keys by lowercasing. {} is not rejected.
- E: tagvalue.go:105-131; dup-tag string verify.go:394 should be "syntax error".
- F: checkChainOfCustody verify.go:648-699; relaxedDomainMatch :702 (d1 is P1). nd hop REVERSED (:668); mf=<> skipped (:682); literals can match (domainFromAddr). Tests verify_nd_test.go:120, verify_errstrings_test.go:69 pin old strings.
- H: no colon throughout (verify.go:545-606, mi.go:192-246, signature.go:119-166/254, recipe.go:81); verify.go:79/82, mi.go:114/145, verify.go:572, :406 (300 s), :411, :215/:320, :275/:299/:462, signature.go:365-380, mi.go:182/201, signature.go:272/284/350, verify.go:394/419/423. bufio.ErrTooLong at plan.go:659 is the candidate for "unacceptably complex".
- I: checkUpstream sign.go:276-320; it returns nil when there is no chain (:296).
- K: Propagate dsn.go:363-410 does not refuse an upstream mf=<>.
- L: no IDNA; the go.mod has no deps (keep it that way: hand-roll punycode).
- M: cmd/dkim2sign/main.go:20-22, cmd/dkim2dsn/main.go:1-2; version_test.go:16 should also ban spec-06/draft-06 and scan cmd/. Rebuild the prebuilt binaries in go/.

## Browser JS (deploy/www/verify/)
- A: no flag logic (OK).
- C: recipes.js:2,7, :77-92 decodeBItem, :108-110, :139-141; report.js:16-38, :64 label `recipe "b" (decoded)`; isCanonicalB64 :72-75 (pad bits); b64.js:45-62 textToBinary accepts lone surrogates (pinned by plan.test.mjs:52, bytes.test.mjs:32); "h":{} accepted.
- D: jsonDuplicateKey recipes.js:19-40 (exact-case); h keys are lowercased with last-wins at recipes.js:189-190 and plan.js:101-102 (pinned plan.test.mjs:70-71).
- E: parse.js:136, :165; verify.js:247 dup-tag string should be "syntax error".
- F: custodyCheck verify.js:731-799. mf=<> always fails; nd hop :756 REVERSED; consecutive nd fails; post-nd compare :742; top nd= passes as out-of-band (:737-740); literals match.
- H: no colon throughout; verify.js:188 (none), :204-230, :216, :226-227, :247, :254, :174, parse.js:188-196, :297/:322, :339-340 (dup hash is graded fail, should be permerror), :350/:375, :360/:367, :437/:595 (expired is a warn; no future check — the browser has no delivery time, so use the current time), :448, :486, :556-557, :573, :743, :757, :793, :770, :778, :586-587, :565, :718-728, :829, :840.
- L: domainOf verify.js:12-15.
- Site: deploy/www/index.html:336 "draft §9.3" becomes §12.3; verify/index.html:18 "§11.1" becomes §14.1.

## Mailman (../mailman, branch dkim2; dkim2-3.3.10 / dkim2-3.3.8 files identical)
- C: message_instance.py:498-524 _literal_steps (kind 'b' when not isascii, :516); docstrings 501-509, 692-693, 762; test parser mi_support.py:93, 130, 142-147 (pad bits; :102 accepts old bare forms); tests test_message_instance.py:460-483 (test_utf8_literal_is_a_b_step_too must expect "d"), 589-607, 745-756, 800-801, 870, ~1190; DKIM2-MESSAGE-INSTANCE.md:32-34.
- D: _parse_mi :1029 plain json.loads; mi_support.py:169-176.
- G: munge_from / always-wrap: confirm that From becomes the list address whenever DKIM2 is on and the list modifies or originates the message.
- M: message_instance.py:21, :47 DKIM2_DRAFT, :49 DKIM2_DATE; ~30 spec-06 § refs; schema.cfg:1065; DKIM2-MESSAGE-INSTANCE.md:4, 41, 46, 185; mi_support.py:50, 88, 102, 162, 254, 269.

## Sympa (../sympa, branch dkim2)
- Sympa adds only MIs plus X-DKIM2-Info; the MTA milter signs. Recipes go through Mail::DKIM2 (DKIM2.pm:83,119,147,192).
- A: copies go out per recipient (ProcessOutgoing.pm:416-424); there is no exploded hint.
- G: (1) unsigned input: ingress adds m=1 (DKIM2.pm:82-88) and the list MTA signs i=1 with the author's From; (2) resend-from-archive and anonymous lists strip the chain (DKIM2.pm:104-105, 289-293; ResendArchive.pm:107); (3) dmarc_protect (Message.pm:3318ff) has no DKIM2 awareness, and `dmarc_protection.other_email` (:68) can be any domain.
- M: DKIM2.pm:296 DKIM2_DRAFT, :298 DKIM2_DATE, POD :524; DKIM2-MESSAGE-INSTANCE.md:14, :247; t/DKIM2.t:718; cpanfile:210 and DKIM2.pm:54 require Mail::DKIM2 0.15 (bump to 0.23), :58, :536, :546.
