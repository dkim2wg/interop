# DKIM2 `mf=`/`rt=` Angle-Bracket Conformance — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every implementation emit `mf=`/`rt=` as base64 of the **bracketed** RFC5321 path (`<user@domain>`, null `<>`) per spec §7.5/§7.6, and **hard-fail** verification of any present-but-unbracketed `mf=`/`rt=` — surfaced through the web validator.

**Architecture:** In each tree, add one **normalize-at-encode** helper (wrap bare address in `<…>`; leave `<>`/already-bracketed alone) at the signing choke point, and one **enforcement check** in the per-signature verify path (decoded `mf=`/each `rt=` MUST match `^<.*>$`). Domain extraction already strips brackets in all four trees, so relaxed matching is unchanged. Regenerate every interop/expected fixture (signed bytes change). Land Perl+Python together (shared `interop.t`), then C, then Go.

**Tech Stack:** Perl (`Mail::DKIM2::*`, CryptX, `prove`), Python 3 (`dkim2sign.py`/`dkim2verify.py`), C (`make`, OpenSSL/cJSON), Go 1.22 (`go test`).

## Global Constraints

- Spec: **draft-ietf-dkim-dkim2-spec-02 §7.5 (`mf=`) / §7.6 (`rt=`)** — value is base64 of the RFC5321 reverse-/forward-path and **"The angle brackets MUST be included"**; Mail-/Rcpt-parameters excluded. Null sender = `<>`.
- **Canonical path form:** real address → `<localpart@domain>`; null → `<>`. `rt=` is a comma list; **each** entry bracketed.
- **Normalize rule (encode):** given a value `a`: if `a` is empty/undef → `<>`; else if `a` matches `^<.*>$` → unchanged; else → `<a>`.
- **Enforcement rule (verify):** for every present `mf=` and every present `rt=` entry in every `DKIM2-Signature`, the decoded value MUST match `^<.*>$` (this accepts `<>`). Otherwise the signature level result is **fail** with reason text naming the tag and `spec 7.5`/`spec 7.6`. Enforcement is **strict** (dev): applies to the whole chain, not just the top signature.
- `nd=` (imaginary-hop) signatures carry no `mf=`/`rt=` — skip the check for them (mutual-exclusion already enforced).
- Accessors/decoders return the decoded value **as-is** (bracketed); domain extraction strips brackets for matching (already the case in all trees).
- Encoder change and enforcement check **land together within each tree** — never a state that emits brackets but rejects them, or vice-versa.
- Run/regenerate commands per tree:
  - **Perl** (from `brong/`): tests `prove -lv t/<file>.t`; full suite `prove -l t/`; regenerate fixtures `prove -l t/full-chain.t` (it `spew`s `tests/expected/*.eml`).
  - **Python** (from `python/`): `./run_tests.sh`; regenerate multihop fixtures `python3 tests/generate_multihop.py`.
  - **C** (from `c/`): `make check` (builds CLIs + runs unit tests).
  - **Go** (from `go/`): `go test ./...`.

---

### Task 1: Perl — normalize encode + enforce brackets

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Common.pm` (add `to_rfc5321_path` helper + export)
- Modify: `brong/lib/Mail/DKIM2/Signature.pm:39-43` (normalize `mf=`/`rt=` at encode)
- Modify: `brong/lib/Mail/DKIM2/Verifier.pm:~306` (enforcement check before the d=↔mf check)
- Test: `brong/t/mf-rt-brackets.t` (create)

**Interfaces:**
- Produces: `Mail::DKIM2::Common::to_rfc5321_path($addr)` → bracketed string; `<>` for empty. Wire form of `mf=`/`rt=` becomes bracketed; `Signature->mail_from`/`rcpt_to` now return bracketed strings.

- [ ] **Step 1: Write the failing test** — create `brong/t/mf-rt-brackets.t`:

```perl
#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More;
use lib 'lib'; use lib 't/lib';
use Email::MIME;
use Mail::DKIM2::Signer; use Mail::DKIM2::Signature; use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Verifier; use DKIM2TestKeys;
my $TS = 1740000000;

sub sign_msg {
    my (%o) = @_;
    my $raw = "From: s\@$o{dom}\r\nTo: r\@x.example\r\nSubject: t\r\n\r\nbody\r\n";
    my $mi = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($raw));
    my $with = "Message-Instance: ".$mi->as_string."\r\n".$raw;
    my $s = Mail::DKIM2::Signer->new(Domain=>$o{dom}, Selector=>'rsa1024',
        Key=>DKIM2TestKeys::private_key($o{dom},'rsa1024'),
        MailFrom=>$o{mf}, RcptTo=>$o{rt}, Timestamp=>$TS);
    $s->PRINT($with); $s->CLOSE;
    return ($s->as_string, $with);
}

# 1. bare address in -> bracketed on the wire
my ($sig_hdr) = sign_msg(dom=>'test1.dkim2.com', mf=>'sender@test1.dkim2.com',
                         rt=>['rcpt@test2.dkim2.com']);
(my $only = $sig_hdr) =~ s/^DKIM2-Signature:\s*//s;
my $sig = Mail::DKIM2::Signature->parse($only);
is($sig->mail_from, '<sender@test1.dkim2.com>', 'mf= wraps bare address in <>');
is_deeply($sig->rcpt_to, ['<rcpt@test2.dkim2.com>'], 'rt= wraps bare address in <>');

# 2. null sender stays <>
my ($sig2) = sign_msg(dom=>'test1.dkim2.com', mf=>'<>', rt=>['<rcpt@test2.dkim2.com>']);
(my $only2 = $sig2) =~ s/^DKIM2-Signature:\s*//s;
is(Mail::DKIM2::Signature->parse($only2)->mail_from, '<>', 'null sender stays <>');

# 3. enforcement: a hand-built signature with a BARE mf= fails verification
my ($ok_hdr, $with) = sign_msg(dom=>'test1.dkim2.com', mf=>'sender@test1.dkim2.com',
                               rt=>['rcpt@test2.dkim2.com']);
my $signed_ok = $ok_hdr."\r\n".$with;
# tamper: replace the bracketed mf= base64 with the BARE base64 (no <>)
use MIME::Base64 qw(encode_base64);
my $bare_b64 = encode_base64('sender@test1.dkim2.com','');
my $brkt_b64 = encode_base64('<sender@test1.dkim2.com>','');
(my $bad = $signed_ok) =~ s/\Q$brkt_b64\E/$bare_b64/;
my $v = Mail::DKIM2::Verifier->new; $v->set_pubkey_callback(DKIM2TestKeys::pubkey_callback()); $v->skip_timestamp_check(1);
$v->PRINT($bad); $v->CLOSE;
is($v->result, 'fail', 'bare mf= fails verification');
like($v->result_detail, qr/7\.5|bracket/i, 'failure reason cites mf= bracket rule');

# 4. the well-formed (bracketed) message verifies pass
my $v2 = Mail::DKIM2::Verifier->new; $v2->set_pubkey_callback(DKIM2TestKeys::pubkey_callback()); $v2->skip_timestamp_check(1);
$v2->PRINT($signed_ok); $v2->CLOSE;
is($v2->result, 'pass', 'bracketed message verifies pass');
done_testing;
```

- [ ] **Step 2: Run it — expect FAIL**

Run: `cd brong && prove -lv t/mf-rt-brackets.t`
Expected: FAILs at test 1 (`mf=` currently decodes to bare `sender@test1.dkim2.com`).

- [ ] **Step 3: Add the normalize helper to `Common.pm`**

In `brong/lib/Mail/DKIM2/Common.pm`, add to the sub list and `@EXPORT_OK` (near `extract_domain`), and define:

```perl
# Wrap an address as an RFC5321 reverse-/forward-path for mf=/rt= (spec
# §7.5/§7.6): angle brackets MUST be present. Empty/undef -> "<>"; an
# already-bracketed value (incl. "<>") is returned unchanged.
sub to_rfc5321_path {
    my ($addr) = @_;
    return '<>' unless defined $addr && length $addr;
    return $addr if $addr =~ /^<.*>$/s;
    return "<$addr>";
}
```

Add `to_rfc5321_path` to the `qw(...)` export list(s) alongside `extract_domain`.

- [ ] **Step 4: Normalize at encode in `Signature.pm`**

In `brong/lib/Mail/DKIM2/Signature.pm`, ensure `Common` is imported for `to_rfc5321_path` (it already `use`s Common; add the name to the import list), then change lines 39-43:

```perl
        if (defined $args{MailFrom}) {
            $self->set_tag('mf', encode_base64(to_rfc5321_path($args{MailFrom}), ''));
        }
        if (defined $args{RcptTo}) {
            my @encoded = map { encode_base64(to_rfc5321_path($_), '') } @{$args{RcptTo}};
            $self->set_tag('rt', join(',', @encoded));
        }
```

- [ ] **Step 5: Add the enforcement check in `Verifier.pm`**

In `brong/lib/Mail/DKIM2/Verifier.pm`, immediately before the existing `# Validate d= matches mf= domain` block (~line 306), insert:

```perl
    # Spec §7.5/§7.6: mf= and each rt= MUST be a bracketed RFC5321 path.
    my $mf_raw = $signature->mail_from;
    if (defined $mf_raw && length $mf_raw && $mf_raw !~ /^<.*>$/s) {
        $self->{result}  = 'fail';
        $self->{details} = "mf= is not a bracketed RFC5321 reverse-path at i=$i (spec 7.5)";
        return 0;
    }
    my $rt_raw = $signature->rcpt_to;
    if ($rt_raw) {
        for my $r (@$rt_raw) {
            next if defined $r && $r =~ /^<.*>$/s;
            $self->{result}  = 'fail';
            $self->{details} = "rt= entry is not a bracketed RFC5321 forward-path at i=$i (spec 7.6)";
            return 0;
        }
    }
```

(No change needed to the existing d=↔mf block: `extract_domain` at `Common.pm:263-264` already strips `<>`, and a bracketed real address `!= '<>'`.)

- [ ] **Step 6: Run the new test — expect PASS**

Run: `cd brong && prove -lv t/mf-rt-brackets.t`
Expected: PASS (all subtests).

- [ ] **Step 7: Regenerate Perl fixtures and update assertions**

Run: `cd brong && prove -l t/full-chain.t` (rewrites `tests/expected/*.eml` with bracketed `mf=`/`rt=`).
Then run the full suite: `cd brong && prove -l t/`
For any test that FAILS on an exact `mail_from`/`rcpt_to` value (e.g. asserting `'sender@origin.example'`), update the expectation to the bracketed form (`'<sender@origin.example>'`). Do NOT weaken assertions — only add the brackets the spec now requires. Re-run until green.

- [ ] **Step 8: Commit**

```bash
git add brong/lib/Mail/DKIM2/Common.pm brong/lib/Mail/DKIM2/Signature.pm brong/lib/Mail/DKIM2/Verifier.pm brong/t/ brong/tests/expected/
git commit -m "perl: mf=/rt= carry RFC5321 angle brackets; verifier enforces (spec 7.5/7.6)"
```

---

### Task 2: Perl — surface the violation through the web validator

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Validate.pm` (report a bracket violation as a failing level with `detail`)
- Test: `brong/t/validate-report.t` (extend) and `brong/t/validate-cgi.t` (extend)
- Verify (likely no change): `deploy/www/validate/validate.js`

**Interfaces:**
- Consumes: the `Verifier` enforcement from Task 1.
- Produces: `Mail::DKIM2::Validate::report($msg)` returns a level with `result => 'fail'` and `detail =>` a string containing `mf=`/`rt=` and `spec 7.5`/`7.6` when a bracket is missing.

- [ ] **Step 1: Write the failing test** — add to `brong/t/validate-report.t`:

```perl
{
    # a message whose mf= decodes to a BARE address must report a spec violation
    use MIME::Base64 qw(encode_base64);
    my $signed = build_signed_message_bare_mf();  # helper: sign then swap bracketed->bare mf= b64
    my $rep = Mail::DKIM2::Validate::report($signed, dns_path => 't/lib/dns.json');
    my ($lvl) = grep { ($_->{result}//'') eq 'fail' } @{$rep->{levels}};
    ok($lvl, 'validator reports a failing level for bare mf=');
    like($lvl->{detail}, qr/mf=.*7\.5|bracket/i, 'detail names the mf= bracket rule');
}
```

Add a small `build_signed_message_bare_mf()` helper in the test mirroring Task 1 Step 1's tamper (sign a bracketed message, then `s/<bracketed-b64>/<bare-b64>/`). Reuse the test's existing signing setup / `DKIM2TestKeys`.

- [ ] **Step 2: Run it — expect FAIL**

Run: `cd brong && prove -lv t/validate-report.t`
Expected: FAIL — the failing level or its `detail` is missing/does not cite the rule.

- [ ] **Step 3: Ensure `Validate.pm` carries the reason**

In `brong/lib/Mail/DKIM2/Validate.pm`, confirm the per-level report already copies the verifier's failure `detail` into the level's `detail` field (the verifier now sets `details` to the §7.5/§7.6 text in Task 1). If the report builds levels from the verifier result, no logic change is needed beyond ensuring the `detail`/`result` are propagated for this failure path; if `Validate.pm` computes levels independently, add the same bracket check there so the failing level carries `result => 'fail'` and the §7.5/§7.6 `detail`. Make the minimal change so the test passes.

- [ ] **Step 4: Run — expect PASS**

Run: `cd brong && prove -lv t/validate-report.t t/validate-cgi.t`
Expected: PASS.

- [ ] **Step 5: Verify the front-end renders it (no code change expected)**

`deploy/www/validate/validate.js:29-53` already renders each level's `result` (as the card class/heading) and `lvl.detail` (line 53 `kv('detail', ...)`). Confirm by reading those lines that a `result:'fail'` level with a `detail` string displays the violation. Only if the failure is carried in a NEW field not rendered by `validate.js`, add a one-line render for it. Record the outcome (change / no-change) in the commit message.

- [ ] **Step 6: Commit**

```bash
git add brong/lib/Mail/DKIM2/Validate.pm brong/t/validate-report.t brong/t/validate-cgi.t deploy/www/validate/validate.js
git commit -m "perl validator: report mf=/rt= bracket violation as a failing level (spec 7.5/7.6)"
```

---

### Task 3: Python — normalize encode + enforce brackets

**Files:**
- Modify: `python/dkim2sign.py:335-362` (normalize `mailfrom`/`rcptto` at build)
- Modify: `python/dkim2verify.py` (add enforcement in the chain-check path, ~before/with `_chain_custody_errors`, lines 538-541 / 564-566)
- Test: `python/tests/test_mf_rt_brackets.py` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks (independent tree).
- Produces: `dkim2sign.build_dkim2_signature(...)` emits bracketed `mf=`/`rt=`; `dkim2verify.verify_message(...)` fails on a bare `mf=`/`rt=`.

- [ ] **Step 1: Add the normalize helper + apply at encode**

In `python/dkim2sign.py`, add near `b64` (line ~41):

```python
def to_rfc5321_path(addr: str) -> str:
    """Wrap an address as an RFC5321 path for mf=/rt= (spec 7.5/7.6): angle
    brackets MUST be present. Empty -> '<>'; already-bracketed unchanged."""
    if not addr:
        return "<>"
    if addr.startswith("<") and addr.endswith(">"):
        return addr
    return f"<{addr}>"
```

Change the encode (lines 359-361) to normalize:

```python
        mf_b64 = b64(to_rfc5321_path(mailfrom).encode("utf-8"))
        rt_list = rcptto or ["unknown@example.com"]
        rt_b64 = ",".join(b64(to_rfc5321_path(r).encode("utf-8")) for r in rt_list)
```

- [ ] **Step 2: Add the enforcement check in `dkim2verify.py`**

Add a helper (near `_domain_from_addr`, line ~116):

```python
def _bracket_errors(sig_headers) -> list[str]:
    """Spec 7.5/7.6: every present mf= and rt= entry MUST be a bracketed
    RFC5321 path (matches <...>, incl. <>)."""
    import base64
    errs = []
    for i, raw in enumerate(sig_headers, start=1):
        tvl = _parse_tag_values(raw)   # use the module's existing tag parser
        for tag in ("mf", "rt"):
            v = tvl.get(tag)
            if not v:
                continue
            for part in v.split(","):
                part = part.strip()
                if not part:
                    continue
                dec = base64.b64decode(part).decode("utf-8", "surrogateescape")
                if not (dec.startswith("<") and dec.endswith(">")):
                    errs.append(f"i={i}: {tag}= is not a bracketed RFC5321 path (spec 7.{'5' if tag=='mf' else '6'})")
    return errs
```

Use the actual tag-parsing helper already in `dkim2verify.py` (the survey shows tag values are read via a `tvl`-style parser in `verify_dkim2_signature`; reuse that same parser rather than re-implementing). Then, where the verifier assembles chain-level errors (alongside the existing `_chain_custody_errors` call, lines 538-541 and the full-chain path 564-566), add:

```python
    errors.extend(_bracket_errors(sig_headers))
```

so a bracket violation makes the overall result an error/fail (matching how `_chain_custody_errors` results feed the verdict).

- [ ] **Step 3: Write the test** — create `python/tests/test_mf_rt_brackets.py`:

```python
import base64, subprocess, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import dkim2sign, dkim2verify

def _sig_header(msg): 
    for line in msg.split("\r\n"):
        if line.startswith("DKIM2-Signature:"): return line

def test_encode_wraps_bare_address():
    signed = dkim2sign.sign_message(SAMPLE_EML, "rsa1024", "test1.dkim2.com",
        KEYFILE, mailfrom="sender@test1.dkim2.com", rcptto=["rcpt@test2.dkim2.com"])
    # decode the mf= tag from the new signature and assert it is bracketed
    mf_b64 = _extract_tag(signed, "mf")
    assert base64.b64decode(mf_b64).decode() == "<sender@test1.dkim2.com>"

def test_null_sender_stays_bracketed():
    signed = dkim2sign.sign_message(SAMPLE_EML, "rsa1024", "test1.dkim2.com",
        KEYFILE, mailfrom="<>", rcptto=["<rcpt@test2.dkim2.com>"])
    assert base64.b64decode(_extract_tag(signed, "mf")).decode() == "<>"

def test_bare_mf_fails_verification():
    signed = dkim2sign.sign_message(SAMPLE_EML, "rsa1024", "test1.dkim2.com",
        KEYFILE, mailfrom="sender@test1.dkim2.com", rcptto=["rcpt@test2.dkim2.com"])
    bad = signed.replace(dkim2sign.b64(b"<sender@test1.dkim2.com>"),
                         dkim2sign.b64(b"sender@test1.dkim2.com"))
    res = dkim2verify.verify_message(bad, DNS_DATA, skip_timestamp_check=True)
    assert not res.ok
    assert any("7.5" in e or "bracket" in e for e in res.errors)
```

Fill `SAMPLE_EML`, `KEYFILE`, `DNS_DATA`, and `_extract_tag` from the patterns in the existing `python/tests/` (e.g. `test_dsn.py`, `test_flags.py`) — reuse their key path and dns.json loading. Keep assertions as written.

- [ ] **Step 4: Run — expect PASS**

Run: `cd python && python3 -m pytest tests/test_mf_rt_brackets.py -v` (or `./run_tests.sh` if that's the runner). Expected: PASS.

- [ ] **Step 5: Regenerate Python fixtures**

Run: `cd python && python3 tests/generate_multihop.py` (regenerates `tests/expected/multihop-*.eml` with bracketed mf/rt). Regenerate the other `tests/expected/*.eml` via their generators (the DSN/simple fixtures — use the same generator entry points the test suite uses). Then `cd python && ./run_tests.sh` and fix any assertion that checked an exact bare `mf`/`rt` value → bracketed form. Re-run until green.

- [ ] **Step 6: Commit**

```bash
git add python/dkim2sign.py python/dkim2verify.py python/tests/
git commit -m "python: mf=/rt= carry RFC5321 angle brackets; verifier enforces (spec 7.5/7.6)"
```

---

### Task 4: Perl↔Python interop — regenerate and cross-verify

**Files:**
- Modify: `brong/tests/expected/*` and `python/tests/expected/*` (already regenerated in Tasks 1 & 3)
- Test: `brong/t/interop.t` (Perl verifies Python fixtures)

- [ ] **Step 1: Run interop — expect it exercises the regenerated fixtures**

Run: `cd brong && prove -lv t/interop.t`
Expected: PASS — Perl verifies the (now bracketed) Python `tests/expected/*.eml`. If any fixture predates Task 3's regeneration, regenerate it (`cd python && python3 tests/generate_multihop.py` and siblings) and re-run.

- [ ] **Step 2: Cross-verify the other direction (Python verifies Perl fixtures)**

Run: `cd python && for f in ../brong/tests/expected/*.eml; do python3 dkim2verify.py --dns-json ../dns.json < "$f" || echo "FAIL: $f"; done`
Expected: no `FAIL:` lines (every Perl-generated fixture verifies under Python). Bracket enforcement must not reject them (they are now bracketed).

- [ ] **Step 3: Commit any remaining fixture churn**

```bash
git add brong/tests/expected/ python/tests/expected/
git commit -m "interop: regenerate Perl+Python fixtures with bracketed mf=/rt=; interop green"
```

---

### Task 5: C — normalize encode + enforce brackets

**Files:**
- Modify: `c/dkim2_sign.c:166-190` (normalize `mf`/`rt` at encode)
- Modify: `c/dkim2_verify.c` (enforcement in the per-signature loop ~line 440)
- Modify: `c/tests/test_verify.c` (add a bare-`mf=` rejection test) and any fixture using bare addresses
- Modify: `c/INTEROP-NOTES.md` (§8/§9 — record the resolution: all impls now bracket)

**Interfaces:**
- Note: C's API contract (`dkim2_internal.h:76-77`) already documents `mail_from`/`rcpt_to` as bracketed `<addr>`; the CLI passes argv through unmodified. Normalizing at encode makes bare CLI input conformant too.

- [ ] **Step 1: Add a normalize helper and apply at encode**

In `c/dkim2_sign.c`, add near the top (static):

```c
/* RFC5321 path for mf=/rt= (spec 7.5/7.6): brackets MUST be present.
 * Returns a malloc'd string the caller frees. NULL/empty -> "<>". */
static char *to_rfc5321_path(const char *addr) {
    if (!addr || !*addr) return strdup("<>");
    size_t n = strlen(addr);
    if (addr[0] == '<' && addr[n-1] == '>') return strdup(addr);
    char *out = malloc(n + 3);
    snprintf(out, n + 3, "<%s>", addr);
    return out;
}
```

At lines 166-190, wrap before base64: use `char *mfp = to_rfc5321_path(ctx->mail_from);` then `b64_encode((const unsigned char*)mfp, strlen(mfp), ...)` and `free(mfp)`; likewise wrap each `ctx->rcpt_to[i]` with `to_rfc5321_path` before `b64_encode`, freeing after. (Leave `dkim2_sig_format` in `dkim2_header.c` unchanged — it re-serializes an already-stored `sig->mf`/`sig->rt`, which are the decoded path values.)

- [ ] **Step 2: Add the enforcement check in `dkim2_verify.c`**

Inside the per-signature loop (~line 440), after the sig is parsed and before/with the d=↔mf domain check (457-466), add:

```c
    /* spec 7.5/7.6: mf= and each rt= MUST be a bracketed RFC5321 path */
    if (s->mf && s->mf[0] && !(s->mf[0]=='<' && s->mf[strlen(s->mf)-1]=='>')) {
        result->status = DKIM2_PERMFAIL;
        snprintf(result->message, sizeof result->message,
                 "i=%d: mf= is not a bracketed RFC5321 reverse-path (spec 7.5)", s->i);
        goto done; /* match the file's existing failure-exit idiom */
    }
    for (int r = 0; s->rt && s->rt[r]; r++) {
        size_t rn = strlen(s->rt[r]);
        if (!(rn >= 2 && s->rt[r][0]=='<' && s->rt[r][rn-1]=='>')) {
            result->status = DKIM2_PERMFAIL;
            snprintf(result->message, sizeof result->message,
                     "i=%d: rt= entry is not a bracketed RFC5321 forward-path (spec 7.6)", s->i);
            goto done;
        }
    }
```

Adapt `DKIM2_PERMFAIL`/`result->status`/`goto done` to the file's actual result-status enum and failure-exit pattern (see the timestamp/domain-check failures already in this loop). `<>` passes (starts `<`, ends `>`).

- [ ] **Step 3: Add a rejection test**

In `c/tests/test_verify.c`, add a case that signs with a bracketed address, rewrites the `mf=` base64 to the bare form, and asserts `dkim2_do_verify` yields a permfail whose message mentions `7.5`. Follow the existing test-case structure in that file. Confirm existing fixtures already use bracketed `<sender@example.com>` (test_verify.c:113-114, test_header.c:35) — they do, so no fixture rewrite is needed there; grep the C tests for any bare-address `mf` literal and bracket it.

- [ ] **Step 4: Build + test**

Run: `cd c && make check`
Expected: all unit tests pass, including the new rejection test.

- [ ] **Step 5: Update INTEROP-NOTES.md**

In `c/INTEROP-NOTES.md` §8/§9 ("MAIL FROM format: with vs without angle brackets"), record the resolution: per spec §7.5/§7.6 all implementations now emit and require bracketed `mf=`/`rt=`; the historical bare-vs-bracketed divergence is closed.

- [ ] **Step 6: Commit**

```bash
git add c/dkim2_sign.c c/dkim2_verify.c c/tests/ c/INTEROP-NOTES.md
git commit -m "c: mf=/rt= normalize to bracketed RFC5321 path; verifier enforces (spec 7.5/7.6)"
```

---

### Task 6: Go — normalize encode + enforce brackets

**Files:**
- Modify: `go/dkim2/signature.go` (normalize in `buildIncomplete` ~223-236 and `String()` ~159-165)
- Modify: `go/dkim2/verify.go` (enforcement in the per-signature loop ~line 234)
- Test: `go/dkim2/mf_rt_brackets_test.go` (create); update inline fixtures in `dkim2_test.go` that assert bare `mf`/`rt`

**Interfaces:**
- Produces: signer emits bracketed `mf=`/`rt=`; `Verify`/`VerifyFull` fail on a bare `mf=`/`rt=`.

- [ ] **Step 1: Add the normalize helper + apply at encode**

In `go/dkim2/signature.go`, add:

```go
// toRFC5321Path wraps an address as an RFC5321 path for mf=/rt= (spec 7.5/7.6):
// angle brackets MUST be present. "" -> "<>"; already-bracketed unchanged.
func toRFC5321Path(a string) string {
    if a == "" {
        return "<>"
    }
    if strings.HasPrefix(a, "<") && strings.HasSuffix(a, ">") {
        return a
    }
    return "<" + a + ">"
}
```

Apply in `buildIncomplete` (line ~230) and `String()` (line ~160): base64-encode `toRFC5321Path(sig.MailFrom)` / `toRFC5321Path(mailFrom)` and each `toRFC5321Path(r)` for `rt`.

- [ ] **Step 2: Add the enforcement check in `verify.go`**

In the per-signature loop (~line 234), after `parseSig` and before the d=↔mf check (259-269), add:

```go
        if sig.MailFrom != "" && !(strings.HasPrefix(sig.MailFrom, "<") && strings.HasSuffix(sig.MailFrom, ">")) {
            res.Error = fmt.Errorf("i=%d: mf= is not a bracketed RFC5321 reverse-path (spec 7.5)", sig.Sequence)
            results = append(results, res); continue
        }
        for _, r := range sig.RcptTo {
            if !(strings.HasPrefix(r, "<") && strings.HasSuffix(r, ">")) {
                res.Error = fmt.Errorf("i=%d: rt= entry is not a bracketed RFC5321 forward-path (spec 7.6)", sig.Sequence)
                break
            }
        }
        if res.Error != nil { results = append(results, res); continue }
```

Match the file's actual result-append / error-propagation idiom used by the existing d=↔mf failure at 259-269. (`<>` passes.)

- [ ] **Step 3: Write the test** — create `go/dkim2/mf_rt_brackets_test.go`:

```go
package dkim2

import ("encoding/base64"; "strings"; "testing")

func TestMFEncodesWithBrackets(t *testing.T) {
    signed := signTestMessage(t, SignOptions{MailFrom: "sender@test1.dkim2.com",
        RcptTo: []string{"rcpt@test2.dkim2.com"}, /* domain/selector/key per existing tests */})
    mf := extractTag(signed, "mf")
    dec, _ := base64.StdEncoding.DecodeString(mf)
    if string(dec) != "<sender@test1.dkim2.com>" {
        t.Fatalf("mf= = %q, want <sender@test1.dkim2.com>", dec)
    }
}

func TestBareMFFailsVerify(t *testing.T) {
    signed := signTestMessage(t, SignOptions{MailFrom: "sender@test1.dkim2.com",
        RcptTo: []string{"rcpt@test2.dkim2.com"}})
    bad := strings.Replace(signed,
        base64.StdEncoding.EncodeToString([]byte("<sender@test1.dkim2.com>")),
        base64.StdEncoding.EncodeToString([]byte("sender@test1.dkim2.com")), 1)
    res, _ := Verify(strings.NewReader(bad), testFetcher(t))
    if len(res) == 0 || res[len(res)-1].Error == nil ||
        !strings.Contains(res[len(res)-1].Error.Error(), "7.5") {
        t.Fatalf("expected 7.5 bracket failure, got %+v", res)
    }
}
```

Implement `signTestMessage`/`extractTag`/`testFetcher` from the patterns already in `go/dkim2/dkim2_test.go` (it already builds signed messages and a key fetcher). Keep assertions as written.

- [ ] **Step 4: Run — expect PASS + fix inline fixtures**

Run: `cd go && go test ./...`
Expected: new tests pass. Update any existing `*_test.go` assertion checking a bare `sig.MailFrom`/`RcptTo` value (e.g. `dkim2_test.go:423-424` `"sender@test1.dkim2.com"`) to the bracketed form `"<sender@test1.dkim2.com>"`. Re-run until green.

- [ ] **Step 5: Commit**

```bash
git add go/dkim2/
git commit -m "go: mf=/rt= carry RFC5321 angle brackets; verifier enforces (spec 7.5/7.6)"
```

---

## Self-Review

**Spec coverage:**
- Emit bracketed `mf=`/`rt=` (null `<>`) → Tasks 1 (Perl), 3 (Python), 5 (C), 6 (Go) encode steps + `to_rfc5321_path`/`toRFC5321Path` helper.
- Hard-fail unbracketed on verify → enforcement step in each of Tasks 1/3/5/6.
- Web validator surfacing → Task 2.
- Relaxed domain match unchanged → noted in each (extract/`_domain_from_addr`/`addr_domain`/`domainFromAddr` already strip brackets; no change).
- Regenerate all fixtures + interop → Tasks 1 Step 7, 3 Step 5, 4, 5 Step 3, 6 Step 4.
- Scope Perl/Python/C/Go, exclude rnc1/hs/arobins → tasks cover exactly those four trees.
- Strict/whole-chain enforcement (dev) → Global Constraints + per-signature checks apply to every signature.

**Placeholder scan:** No TBD/TODO. Where a tree's exact helper name/idiom must match existing code (result-status enum in C, result-append in Go, tag parser in Python), the step names the concrete site and says to match the existing idiom, with full code given — these are integration points, not placeholders.

**Type/name consistency:** helper is `to_rfc5321_path` (Perl/Python/C) and `toRFC5321Path` (Go); enforcement regex/logic is uniformly `^<.*>$` / `startswith('<') && endswith('>')`; failure text uniformly cites `spec 7.5`/`7.6`. Accessors return bracketed values in every tree; tests updated accordingly.

**Ordering:** Perl (1,2) and Python (3) can proceed in parallel but Task 4 (interop) requires both landed; C (5) and Go (6) are independent.
