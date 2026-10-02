# Mail::DKIM2 API Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Perl Mail::DKIM2 library's public API consistent, documented and packageable for CPAN, without changing any wire-format behaviour.

**Architecture:** The streaming Signer/Verifier keep their Mail::DKIM-shaped
PRINT/CLOSE interface but gain validated CamelCase constructor options, a
`load()` one-shot, TIEHANDLE, and accessors so hosts never reach into the
object hash. Process-global configuration (ignore prefixes) becomes a
per-call/per-instance option. DNS key fetching moves from Signature to
Verifier. Every module gets a `$VERSION`, `=encoding utf8`, and POD that
describes spec-06 rather than draft-clayton-08. A top-level `Mail::DKIM2`
module documents the conventions. Dist split into separate CPAN
distributions is deferred to the packaging task that follows.

**Tech Stack:** Perl 5.20+, ExtUtils::MakeMaker, CryptX, Email::MIME,
Net::DNS, Test::More. Deploy via `deploy/deploy.sh` on host dkim2-dev.

**Spec:** The API review in this session (2026-10-02). Findings summarised
in the Review Focus below and in each task.

## Global Constraints

- No change to any byte emitted on the wire: `t/full-chain.t` fixtures in
  `tests/expected/` must not churn, `t/interop.t` must still pass.
- Constructor options are CamelCase (`SkipTimestampCheck`); methods are
  snake_case (`skip_timestamp_check`). Class-method options likewise
  CamelCase (`IgnorePrefixes => [...]`).
- Error contract: configuration mistakes `croak`; protocol outcomes are
  reported via `result()`/`details()`; the library only ever dies with
  strings, and any reference exception is rethrown untouched.
- Input is CRLF for `PRINT`; `load()` normalises bare LF.
- Minimum Perl 5.20. Only non-core deps: CryptX, Email::MIME, JSON, Net::DNS
  (runtime); Algorithm::Diff (recommended; recipe computation only).
- Finish tidy: MANIFEST regenerated, `make distcheck` clean, no dead files.
- Deploy on the box and run `deploy/dkim2-list-smoke.sh` afterwards.

## Review Focus

1. A typo in a Verifier constructor option must croak, not silently verify
   with defaults. (Task 1 test.)
2. A message fed through `load()` with bare LF must verify identically to the
   same message fed CRLF through PRINT. (Task 1 test.)
3. A resolver error string the library does not recognise must become
   `temperror`, never `permerror`/`fail`. (Task 4 test.)
4. IgnorePrefixes on one Verifier must not leak to another Verifier in the
   same process. (Task 3 test.)
5. A Signer handed an over-long or duplicated chain must report `fail` with
   a reason, and `PRINT`/`CLOSE` must not die. (Task 5 test.)

---

### Task 1: HeaderParser — validated options, `load()`, TIEHANDLE

**Files:**
- Modify: `perl/lib/Mail/DKIM2/HeaderParser.pm`
- Modify: `perl/lib/Mail/DKIM2/Signer.pm` (add `known_options`)
- Modify: `perl/lib/Mail/DKIM2/Verifier.pm` (add `known_options`, store
  options under CamelCase keys, honour ctor values)
- Test: `perl/t/headerparser.t` (create)

**Interfaces:**
- Produces: `Mail::DKIM2::HeaderParser->new(%opts)` croaks on a key not in
  `$class->known_options` (list). `load($input)` accepts a string, a scalar
  ref, a filehandle, or an `Email::MIME`; normalises line endings to CRLF;
  calls PRINT then CLOSE; returns `$self`. `TIEHANDLE($class, @args)`
  returns `$args[0]` if it is already an object of the class, else
  `$class->new(@args)`.
- Verifier options: `SkipTimestampCheck`, `AllowUnsignedMI`, `MidProcess`,
  `HeadersOnly`, `PubkeyCallback`, `Resolver`, `IgnorePrefixes`. The
  existing snake_case setters read/write the CamelCase slot.

- [ ] Write `t/headerparser.t`: unknown option croaks for Signer and Verifier;
  `Verifier->new(SkipTimestampCheck => 1)->skip_timestamp_check` is 1;
  `load` of an LF message gives the same `result` as PRINT of the CRLF
  message (sign a message with DKIM2TestKeys, verify both ways); `tie *FH`
  then `print FH $msg; close FH` verifies.
- [ ] Run: `prove -l t/headerparser.t` — expect failures.
- [ ] Implement in HeaderParser: `known_options` (returns empty list),
  validation in `new`, `load`, `TIEHANDLE`. In Signer add
  `sub known_options { qw(Domain Selector KeyFile Key Algorithm MailFrom
  RcptTo Nonce Flags Timestamp NextDomain) }`. In Verifier add
  `known_options` and change `init` to `$self->{SkipTimestampCheck} //= 0`
  etc.; setters use the CamelCase slots; every internal read of
  `$self->{skip_timestamp_check}` and friends updated.
- [ ] Run full suite: `prove -l -j8 t` — expect PASS.
- [ ] Commit: "HeaderParser: validate options, add load() and TIEHANDLE".

### Task 2: Verifier accessors — `signatures()`, `top_signature()`

**Files:**
- Modify: `perl/lib/Mail/DKIM2/Verifier.pm`
- Modify: `perl/lib/Mail/Milter/Authentication/Handler/DKIM2Verify.pm:175-190`
- Test: `perl/t/verifier-accessors.t` (create)

**Interfaces:**
- Produces: `signatures()` returns the parsed `Mail::DKIM2::Signature`
  objects in ascending `i=` order (list). `top_signature()` returns the
  highest-`i=` one or undef. Both valid after `CLOSE` (and after
  `finish_header` for a header-only stop).

- [ ] Write test: sign a 2-hop chain fixture (`tests/expected/chain-hop2-mailing-list.eml`),
  verify, assert `scalar(signatures) == 2`, `top_signature->sequence == 2`,
  `top_signature->domain` matches `header.d` the handler would emit.
- [ ] Implement accessors. Replace `$verifier->{details}` and
  `$verifier->{_dk2_headers}` in DKIM2Verify.pm with `details()` and
  `top_signature()`.
- [ ] Run: `prove -l t/verifier-accessors.t t/milter.t` — PASS.
- [ ] Commit: "Verifier: signatures()/top_signature(); handler stops poking internals".

### Task 3: Per-instance ignore prefixes

**Files:**
- Modify: `perl/lib/Mail/DKIM2/Common.pm` (remove `ignore_header_prefixes`
  and `@IGNORE_PREFIXES`; `should_skip($name, \@prefixes)`)
- Modify: `perl/lib/Mail/DKIM2/MessageInstance.pm` (`calculate` %opts
  `IgnorePrefixes`; `verify($msg, %opts)`; `chain_verifies($msg, %opts)`;
  `h_digest($msg, $alg, \@prefixes)`)
- Modify: `perl/lib/Mail/DKIM2/Verifier.pm` (thread `IgnorePrefixes` into
  `_verify_top_mi_headers` and `_verify_mi_chain`)
- Modify: both milter handlers (pass `IgnorePrefixes` from handler_config
  to `Verifier->new` and every MessageInstance call; delete
  `setup_callback`)
- Test: rewrite `perl/t/ignore-prefixes.t`

**Interfaces:**
- Produces: `should_skip($header_name, $prefixes_arrayref_or_undef)`.
  `Mail::DKIM2::MessageInstance->verify($msg, IgnorePrefixes => [...])`
  returns as before. `->chain_verifies($msg, IgnorePrefixes => [...])`.
  `->calculate($cur, $prev, IgnorePrefixes => [...])`.
  `Mail::DKIM2::Verifier->new(IgnorePrefixes => [...])`.

- [ ] Rewrite `t/ignore-prefixes.t` to use the option forms; add a subtest
  that two Verifiers in one process, one with the prefix and one without,
  return `pass` and not-`pass` respectively on the same annotated message.
- [ ] Run: `prove -l t/ignore-prefixes.t` — FAIL (option unknown).
- [ ] Implement. Prefixes lowercased at the point of use in `should_skip`.
- [ ] Run full suite — PASS. Also `grep -rn ignore_header_prefixes lib bin t ../deploy`
  must return nothing except the handler config key name.
- [ ] Commit: "Ignore prefixes are a per-instance option, not process state".

### Task 4: Key fetching moves to Verifier

**Files:**
- Modify: `perl/lib/Mail/DKIM2/Verifier.pm` (add `fetch_public_key($sig, $idx)`,
  `Resolver` option, call callback as `->($sig, $idx, $self)`)
- Modify: `perl/lib/Mail/DKIM2/Signature.pm` (remove `fetch_public_key`)
- Modify: `perl/lib/Mail/DKIM2/Validate.pm:97-117` (`_default_cb` falls
  back to `$verifier->fetch_public_key`, no swallowing eval)
- Modify: `perl/lib/Mail/DKIM2/Reflector.pm:440-450`
- Modify: `perl/bin/dkim2-milter.pl:525-535`
- Modify: `perl/lib/Mail/Milter/Authentication/Handler/DKIM2Verify.pm:280-310`
  (real-DNS path becomes `Resolver => $self->get_object('resolver')`)
- Test: rewrite `perl/t/dns-temperror.t`; fix `t/validate-report.t:385-398`

**Interfaces:**
- Produces: `$verifier->fetch_public_key($signature, $idx)` returns a
  Crypt::PK object, undef when DNS says the name has no TXT (errorstring
  NXDOMAIN, NOERROR or NODATA), and dies `"TEMPERROR: DNS lookup for
  $fqdn failed: $err"` for anything else. The pubkey callback receives
  `($signature, $idx, $verifier)`.

- [ ] Rewrite `t/dns-temperror.t`: MockResolver injected via
  `Verifier->new(Resolver => ...)`; transient cases plus an unrecognised
  string `'something new'` give temperror; NXDOMAIN/NOERROR/NODATA give
  undef. Keep the callback-dies and callback-undef subtests.
- [ ] Run — FAIL.
- [ ] Implement; delete `Signature::fetch_public_key` and its POD; update
  the three fallback callers to `$_[2]->fetch_public_key($_[0], $_[1])`.
- [ ] Fix `t/validate-report.t` FakeSig test to pass a fake verifier.
- [ ] Full suite — PASS.
- [ ] Commit: "Key fetching lives on the Verifier; unknown DNS errors are temperror".

### Task 5: Error contract — Signer reports instead of dying mid-stream

**Files:**
- Modify: `perl/lib/Mail/DKIM2/Signer.pm` (chain errors → `result 'fail'`,
  `details`, `stop`; `result()` undef before CLOSE; add `details()`)
- Modify: `perl/lib/Mail/Milter/Authentication/Handler/DKIM2Sign.pm:273-290`
- Modify: `perl/bin/dkim2sign.pl` (report `details` on failure)
- Modify: `perl/lib/Mail/DKIM2/DSN.pm` and `Reflector.pm` where they check
  `$signer->result eq 'signed'` (grep `result`)
- Test: `perl/t/chain-length.t:90-105,160-170`; `perl/t/signer-result.t` (create)

**Interfaces:**
- Produces: `Signer->result` is undef until CLOSE, then `'signed'` or
  `'fail'`; `Signer->details` is the reason on fail. `as_string` is `''`
  on fail.

- [ ] Write `t/signer-result.t`: result undef before CLOSE; after a good sign
  `'signed'`; over-long chain → `PRINT`/`CLOSE` return normally, result
  `'fail'`, details match `/PERMERROR more than 32 DKIM2-Signature fields/`,
  `as_string eq ''`.
- [ ] Update chain-length.t assertions from die to result/details.
- [ ] Implement. Handler logs `details` on failure.
- [ ] Full suite — PASS.
- [ ] Commit: "Signer reports chain errors through result/details".

### Task 6: Signature accessor consistency

**Files:**
- Modify: `perl/lib/Mail/DKIM2/Signature.pm` (`mail_from($v)`, `rcpt_to($v)`
  and `flags(\@f)` become get/set; remove `set_rcpt_to`)
- Modify: `perl/lib/Mail/DKIM2/Signer.pm:140-150` (`rcpt_to` setter)
- Test: `perl/t/signature-accessors.t` (create)

- [ ] Write test: construct with `new`, set `rcpt_to(['<a@b>'])`, read
  back `['<a@b>']`; `mail_from('<x@y>')` round-trips with brackets added by
  `to_rfc5321_path`; `flags(['donotmodify'])` reads back; `rcpt_to` on an
  nd= signature croaks.
- [ ] Implement; grep `set_rcpt_to` returns nothing.
- [ ] Full suite — PASS. Commit: "Signature: uniform get/set accessors".

### Task 7: One argument convention for DSN, Validate, Reflector

**Files:**
- Modify: `perl/lib/Mail/DKIM2/DSN.pm` (`generate(%args)`, `authenticate(%args)`,
  `propagate(%args)` with keys `Message`, `Signer`, `To`, `ReportingMTA`,
  `Status`, `Reason`, `PubkeyCallback`, `ForwarderDomain`,
  `SkipAuthentication`, `SkipTimestampCheck`)
- Modify: `perl/lib/Mail/DKIM2/Validate.pm` (`report($text, PubkeyCallback
  => ..., DnsPath => ..., SkipTimestampCheck => ...)`)
- Modify: `perl/lib/Mail/DKIM2/Reflector.pm` (`reflect`, `generate`,
  `generate_dsn`, `generate_brand` take CamelCase keys: `Mode`, `Domain`,
  `Selector`, `MailFrom`, `Message`, `PubkeyCallback`, `SkipTimestampCheck`,
  and whatever else the current lowercase keys are, renamed 1:1)
- Modify callers: `perl/bin/dkim2-reflector.pl`, `perl/bin/validate.cgi`,
  `deploy/deploy.sh:110-116`, `perl/t/dsn.t`, `perl/t/reflector.t`,
  `perl/t/reflector-dkim1.t`, `perl/t/validate-report.t`
- Test: existing tests updated

- [ ] Rename keys; run `prove -l t/dsn.t t/reflector.t t/reflector-dkim1.t t/validate-report.t t/validate-cgi.t t/reflector-cli.t`.
- [ ] Full suite — PASS. Commit: "CamelCase options everywhere".

### Task 8: CLI tidy

**Files:**
- Delete: `perl/bin/calculate-dkim2.pl`, `calculate-mailversion.pl`,
  `reverse-mailversion.pl`, `validate-mailversion.pl`
- Rename: `perl/bin/dkim2sign.pl` → `perl/bin/dkim2sign`
- Replace: `perl/bin/verify-sig.pl` → `perl/bin/dkim2verify` (Getopt:
  `--dns-json PATH`, `--ignore-timestamps`, `--ignore-prefix P` repeatable;
  file or stdin; prints `result_detail`; exit 0 on pass, 1 otherwise, 75 on
  temperror)
- Modify references: `util/interop-fold-mi.sh`, `util/lib-sign.sh`,
  `deploy/dkim2-list-smoke.sh`, `perl/t/sign-cli.t`, `perl/t/invalid-json.t`,
  `perl/t/validate-report.t`, `perl/t/fraud-detection.t`,
  `perl/t/hash-agility.t`, `deploy/SERVER.md`, `c/INTEROP-NOTES.md`
- Test: `perl/t/verify-cli.t` (create): good vector passes with
  `--dns-json ../dns.json --ignore-timestamps`; a damaged copy exits 1.

- [ ] Do the renames with `git mv`; write `dkim2verify`; update references
  (`grep -rn 'dkim2sign.pl\|verify-sig.pl\|mailversion\|calculate-dkim2' --exclude-dir=.git .`
  must only hit historical docs under `docs/superpowers/`).
- [ ] Full suite — PASS. Commit: "CLI: dkim2sign and dkim2verify; drop dead tools".

### Task 9: Packaging and POD

**Files:**
- Create: `perl/lib/Mail/DKIM2.pm` (`$VERSION = '0.10'`; POD: NAME,
  SYNOPSIS (sign + verify via `load`), DESCRIPTION, MODULES, CONVENTIONS
  (options, streaming vs load, CRLF, error contract, exceptions), STATUS
  (implements draft-ietf-dkim-dkim2-spec-06; deployed at Fastmail and
  dkim2.com; wire format tracks the draft; API 0.x), SEE ALSO, AUTHOR,
  LICENSE)
- Modify: every `lib/Mail/DKIM2/*.pm` and both handlers: `our $VERSION =
  '0.10';`, `=encoding utf8`, replace "Do not use in production" paragraph
  with a pointer to `Mail::DKIM2/STATUS`; copyright "2025-2026"
- Rewrite POD: Signature (spec-06 tags i m t d nd n f mf rt s), MessageInstance
  (m= h= r=; `IgnorePrefixes`; `chain_verifies`; `unrecoverable`;
  `hash_algs`; `parse_hash_sets`; `header_hash`; `set_null_body_recipe`),
  Verifier (options, `load`, `signatures`, `top_signature`, `fetch_public_key`,
  all setters), Signer (options incl. Timestamp/NextDomain, `sign_for_recipient`,
  `details`), Common (grouped FUNCTIONS, all exports), HeaderParser
  (`load`, `TIEHANDLE`, `stop`, `stopped`, `known_options`)
- Modify: `perl/Makefile.PL` (VERSION_FROM `lib/Mail/DKIM2.pm`; PREREQ_PM
  add `Net::DNS`, `File::Path`; META_MERGE prereqs runtime recommends
  `Algorithm::Diff`; TEST_REQUIRES add `Test::Pod`/`Test::Pod::Coverage` as
  recommends only; EXE_FILES `bin/dkim2sign bin/dkim2verify`)
- Modify: `perl/Changes` (0.10 entry 2026-10-02), `perl/README.md` (replace
  the IETF-email note with a dist README), `perl/CLAUDE.md` (API names)
- Create: `perl/t/pod.t`, `perl/t/pod-coverage.t` (skip_all unless the
  Test::Pod modules load; coverage `also_private => [qr/^(PRINT|CLOSE|
  TIEHANDLE|init|handle_header|finish_header|finish_body|known_options)$/]`,
  trustme for Reflector/Validate/Split/MessageStore/DSN only if needed)
- Regenerate: `perl/MANIFEST` (`make manifest`, remove `MANIFEST.bak`)

- [ ] `podchecker lib/Mail/DKIM2.pm lib/Mail/DKIM2/*.pm` — no errors.
- [ ] `prove -l t/pod.t t/pod-coverage.t` — PASS.
- [ ] `perl Makefile.PL && make && make test && make distcheck` — clean.
- [ ] Commit: "Package as Mail-DKIM2 0.10: top-level module, versions, POD, prereqs".

### Task 10: Deploy and acceptance

- [ ] `ssh dkim2 'cd /root/interop && git pull && deploy/deploy.sh'` (after
  merge to master and push).
- [ ] `deploy/dkim2-list-smoke.sh` — all green.
- [ ] Validator: good and bad vector via https://dkim2.com/validate/.
- [ ] Update memory: hm vendored copy needs refresh with the handler and
  DSN/Verifier API changes; CLI renames.
