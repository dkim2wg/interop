# DKIM2 Reflector — DKIM1-bridge signing & always-on Message-Instance — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the dkim2.com reflector also sign messages that have no DKIM2 chain but a valid `From:`-aligned DKIM1 signature (read from OpenDKIM's inbound `Authentication-Results`), and always emit the change-recording Message-Instance for transforming modes.

**Architecture:** All decision logic lives in `Mail::DKIM2::Reflector::reflect()`. The reflector keeps computing the DKIM2 verdict itself; the DKIM1 verdict is read from an `Authentication-Results` header (scoped to a configured authserv-id) that OpenDKIM stamps on inbound mail. A three-tier sign decision (DKIM2-pass / DKIM1-bridge / none) replaces the current "sign only if DKIM2 passed" gate. MI creation moves out of the sign block so it always runs for changing modes.

**Tech Stack:** Perl 5.20+, `Email::MIME`, `Mail::DKIM2::{Verifier,Signer,MessageInstance,Common}`, CryptX (existing). OpenDKIM (already installed on the server) for inbound DKIM1 verification. No new CPAN dependencies.

## Global Constraints

- Spec basis: `draft-ietf-dkim-dkim2-spec-02` (copy verbatim where referenced).
- No dependency on `Mail::DKIM`; the only crypto dependency is CryptX. Do **not** add a Public Suffix List dependency.
- Header folding rules in `brong/CLAUDE.md` apply: never refold headers read from disk/network; fold only headers we create, via `fold_header()`.
- Explanation headers (`X-*`, `Authentication-Results`) must stay excluded from the DKIM2 header hash by `should_skip()` — never put signing-relevant data in them.
- Reflector never bounces; on any error, log and reflect unsigned (existing behaviour).
- Run the module test suite with `perl -Ilib -It/lib t/reflector.t` (from `brong/`); the full suite with `prove -Ilib -It/lib t/`.
- Do **not** commit regenerated `brong/tests/expected/*.eml` files (full-chain.t rewrites them with a fresh timestamp — that churn is unrelated to this work).
- Configured authserv-id value: `mail.dkim2.com` (used by both the script and SERVER.md).

---

### Task 1: Relaxed domain-alignment helper

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Reflector.pm` (add `_domains_align`)
- Test: `brong/t/reflector.t`

**Interfaces:**
- Produces: `Mail::DKIM2::Reflector::_domains_align($from_domain, $d)` → `1` if the two domains align (relaxed, PSL-free), else `0`. Case-insensitive. Returns `0` if either is undef/empty.

- [ ] **Step 1: Write the failing test**

Add near the end of `brong/t/reflector.t`, before `done_testing;`:

```perl
# --- relaxed domain alignment (PSL-free) ---
{
    no warnings 'once';
    ok( Mail::DKIM2::Reflector::_domains_align('brong.net', 'brong.net'),
        'align: exact match');
    ok( Mail::DKIM2::Reflector::_domains_align('BRONG.NET', 'brong.net'),
        'align: case-insensitive');
    ok( Mail::DKIM2::Reflector::_domains_align('mail.brong.net', 'brong.net'),
        'align: from is a subdomain of d');
    ok( Mail::DKIM2::Reflector::_domains_align('brong.net', 'mail.brong.net'),
        'align: d is a subdomain of from');
    ok( !Mail::DKIM2::Reflector::_domains_align('brong.net', 'evil.example'),
        'align: unrelated domains do not align');
    ok( !Mail::DKIM2::Reflector::_domains_align('notbrong.net', 'brong.net'),
        'align: suffix-without-dot does not count as subdomain');
    ok( !Mail::DKIM2::Reflector::_domains_align('brong.net', ''),
        'align: empty d does not align');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd brong && perl -Ilib -It/lib t/reflector.t 2>&1 | grep -E 'align:'`
Expected: FAIL — `Undefined subroutine &Mail::DKIM2::Reflector::_domains_align`.

- [ ] **Step 3: Write minimal implementation**

Add to `brong/lib/Mail/DKIM2/Reflector.pm` (after `_split`, before `_transform_text`):

```perl
# Relaxed, PSL-free domain alignment: equal, or one a subdomain of the other.
sub _domains_align {
    my ($f, $d) = @_;
    return 0 unless defined $f && defined $d && length $f && length $d;
    $f = lc $f; $d = lc $d;
    return 1 if $f eq $d;
    return 1 if $f =~ /\.\Q$d\E\z/;   # f is a subdomain of d
    return 1 if $d =~ /\.\Q$f\E\z/;   # d is a subdomain of f
    return 0;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd brong && perl -Ilib -It/lib t/reflector.t 2>&1 | grep -E 'align:'`
Expected: all `ok ... align: ...` lines pass.

- [ ] **Step 5: Commit**

```bash
git add brong/lib/Mail/DKIM2/Reflector.pm brong/t/reflector.t
git commit -m "feat(reflector): relaxed domain-alignment helper"
```

---

### Task 2: Extract the From: header domain

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Reflector.pm` (add `_from_domain`)
- Test: `brong/t/reflector.t`

**Interfaces:**
- Consumes: nothing.
- Produces: `Mail::DKIM2::Reflector::_from_domain($message_text)` → lowercased domain string of the message's `From:` header, or `undef` if absent/unparseable. Prefers the address inside `<...>` when present.

- [ ] **Step 1: Write the failing test**

Add before `done_testing;`:

```perl
# --- From: domain extraction ---
{
    no warnings 'once';
    is( Mail::DKIM2::Reflector::_from_domain(
            "From: a\@brong.net\r\nSubject: x\r\n\r\nbody\r\n"),
        'brong.net', 'from_domain: bare addr-spec');
    is( Mail::DKIM2::Reflector::_from_domain(
            "From: \"Bron G\" <bron\@Brong.NET>\r\nSubject: x\r\n\r\nb\r\n"),
        'brong.net', 'from_domain: display name + angle addr, lowercased');
    is( Mail::DKIM2::Reflector::_from_domain(
            "Subject: x\r\n\r\nbody\r\n"),
        undef, 'from_domain: no From header -> undef');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd brong && perl -Ilib -It/lib t/reflector.t 2>&1 | grep -E 'from_domain:'`
Expected: FAIL — `Undefined subroutine &Mail::DKIM2::Reflector::_from_domain`.

- [ ] **Step 3: Write minimal implementation**

Add to `brong/lib/Mail/DKIM2/Reflector.pm` (after `_domains_align`):

```perl
# Lowercased domain of the message's From: header, or undef.
sub _from_domain {
    my ($text) = @_;
    my $from = eval { Email::MIME->new($text)->header('From') };
    return undef unless defined $from && length $from;
    my $addr = ($from =~ /<([^>]+)>/) ? $1 : $from;
    my ($dom) = $addr =~ /\@([A-Za-z0-9.\-]+)/;
    return defined $dom ? lc $dom : undef;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd brong && perl -Ilib -It/lib t/reflector.t 2>&1 | grep -E 'from_domain:'`
Expected: all `from_domain:` lines pass.

- [ ] **Step 5: Commit**

```bash
git add brong/lib/Mail/DKIM2/Reflector.pm brong/t/reflector.t
git commit -m "feat(reflector): extract From: header domain"
```

---

### Task 3: Read the aligned DKIM1 verdict from Authentication-Results

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Reflector.pm` (add `_dkim1_aligned`)
- Test: `brong/t/reflector.t`

**Interfaces:**
- Consumes: `_domains_align` (Task 1).
- Produces: `Mail::DKIM2::Reflector::_dkim1_aligned($message_text, $from_domain, $authserv_id)` → the lowercased `header.d` of the first `dkim=pass` result (in an `Authentication-Results` header whose authserv-id equals `$authserv_id`) that aligns with `$from_domain`; otherwise `undef`. Ignores A-R from other authserv-ids and any non-`pass` results.

- [ ] **Step 1: Write the failing test**

Add before `done_testing;`:

```perl
# --- DKIM1 verdict read from Authentication-Results (scoped to authserv-id) ---
{
    no warnings 'once';
    my $base = "From: a\@brong.net\r\nSubject: x\r\n\r\nbody\r\n";
    my $with_ar = sub {
        my ($ar) = @_;
        return "Authentication-Results: $ar\r\n" . $base;
    };
    is( Mail::DKIM2::Reflector::_dkim1_aligned(
            $with_ar->('mail.dkim2.com; dkim=pass header.d=brong.net'),
            'brong.net', 'mail.dkim2.com'),
        'brong.net', 'dkim1: aligned pass is found');
    is( Mail::DKIM2::Reflector::_dkim1_aligned(
            $with_ar->('mail.dkim2.com; dkim=pass header.d=evil.example'),
            'brong.net', 'mail.dkim2.com'),
        undef, 'dkim1: unaligned d is rejected');
    is( Mail::DKIM2::Reflector::_dkim1_aligned(
            $with_ar->('other.host; dkim=pass header.d=brong.net'),
            'brong.net', 'mail.dkim2.com'),
        undef, 'dkim1: foreign authserv-id is ignored');
    is( Mail::DKIM2::Reflector::_dkim1_aligned(
            $with_ar->('mail.dkim2.com; dkim=fail header.d=spoof.com; dkim=pass header.d=brong.net'),
            'brong.net', 'mail.dkim2.com'),
        'brong.net', 'dkim1: one matching pass among several wins');
    is( Mail::DKIM2::Reflector::_dkim1_aligned($base, 'brong.net', 'mail.dkim2.com'),
        undef, 'dkim1: no A-R header -> undef');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd brong && perl -Ilib -It/lib t/reflector.t 2>&1 | grep -E 'dkim1:'`
Expected: FAIL — `Undefined subroutine &Mail::DKIM2::Reflector::_dkim1_aligned`.

- [ ] **Step 3: Write minimal implementation**

Add to `brong/lib/Mail/DKIM2/Reflector.pm` (after `_from_domain`):

```perl
# The aligned header.d of a dkim=pass result in our authserv-id's
# Authentication-Results, or undef. Only A-R bearing $authserv_id are trusted.
sub _dkim1_aligned {
    my ($text, $from_domain, $authserv_id) = @_;
    return undef unless defined $from_domain && defined $authserv_id;
    my @ar = eval { Email::MIME->new($text)->header_raw('Authentication-Results') };
    for my $ar (@ar) {
        $ar =~ s/\r?\n[ \t]+/ /g;             # unfold
        my ($id, $rest) = split /;/, $ar, 2;
        next unless defined $rest;
        $id =~ s/^\s+|\s+$//g;
        $id =~ s/\s.*\z//;                     # drop optional version after authserv-id
        next unless lc($id) eq lc($authserv_id);
        for my $chunk (split /;/, $rest) {     # one resinfo per chunk
            next unless $chunk =~ /\bdkim\s*=\s*pass\b/i;
            next unless $chunk =~ /header\.d\s*=\s*([A-Za-z0-9.\-]+)/i;
            my $d = lc $1;
            return $d if _domains_align($from_domain, $d);
        }
    }
    return undef;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd brong && perl -Ilib -It/lib t/reflector.t 2>&1 | grep -E 'dkim1:'`
Expected: all `dkim1:` lines pass.

- [ ] **Step 5: Commit**

```bash
git add brong/lib/Mail/DKIM2/Reflector.pm brong/t/reflector.t
git commit -m "feat(reflector): read aligned DKIM1 verdict from Authentication-Results"
```

---

### Task 4: Three-tier sign decision + always-on MI in reflect()

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Reflector.pm:23-75` (rework `reflect()`)
- Test: `brong/t/reflector.t`

**Interfaces:**
- Consumes: `_from_domain` (Task 2), `_dkim1_aligned` (Task 3), existing `_verify`/`_transform_text`/`_build_mi`/`_sign`.
- Produces: `reflect(%args)` now also accepts `authserv_id => $str` and returns a hash with added keys `dkim1 => 'pass'|'none'` and `basis => 'dkim2'|'dkim1'|'none'` alongside the existing `message`, `auth`, `signed`, `mode`.

This task adds a test helper `mi_only_input($raw, $ar)` that builds a message with a `Message-Instance` (m=1, like the inbound milter adds) and an optional `Authentication-Results` header, but **no** DKIM2-Signature.

- [ ] **Step 1: Write the failing tests**

Add the helper next to `signed_input` near the top of `brong/t/reflector.t`:

```perl
# A message with an inbound MI (m=1) and optional A-R, but NO DKIM2 chain —
# mirrors what the inbound milter produces for non-DKIM2 mail.
sub mi_only_input {
    my ($raw, $ar) = @_;
    $raw =~ s/\r?\n/\r\n/g;
    my $msg = Email::MIME->new($raw);
    my $mi  = Mail::DKIM2::MessageInstance->calculate($msg);
    my $folded = fold_header("Message-Instance: " . $mi->as_string);
    $folded =~ s/^Message-Instance:\s*//;
    $msg->header_raw_prepend('Message-Instance', $folded);
    $msg->header_raw_prepend('Authentication-Results', $ar) if defined $ar;
    return $msg->as_string;
}
```

Add these test blocks before `done_testing;` (`%common` already sets
`domain => 'test2.dkim2.com'` and the test2 signing key; the new tests add
`authserv_id`):

```perl
my $AUTHSERV = 'mail.dkim2.com';

# --- T2: no DKIM2 chain but aligned DKIM1 -> bridge-signed ---
{
    my $in = mi_only_input(
        "From: a\@test1.dkim2.com\r\nTo: reflector-raw\@dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n",
        "$AUTHSERV; dkim=pass header.d=test1.dkim2.com");
    my $r = Mail::DKIM2::Reflector::reflect(
        %common, authserv_id => $AUTHSERV, mode => 'raw', message => $in);
    is($r->{auth},  'none', 'T2: no DKIM2 chain');
    is($r->{dkim1}, 'pass', 'T2: aligned DKIM1 found');
    is($r->{basis}, 'dkim1', 'T2: signing basis is dkim1');
    is($r->{signed}, 1, 'T2: bridge signed');
    like($r->{message}, qr/^DKIM2-Signature:/m, 'T2: has a DKIM2-Signature');
    like($r->{message}, qr/^X-DKIM2-Reflector:.*basis=dkim1.*signed=yes/m, 'T2: X- header');
    is(reflected_verifies($r->{message}), 'pass', 'T2: bridge-signed message verifies');
}

# --- T2 negative: DKIM1 present but not aligned -> not signed ---
{
    my $in = mi_only_input(
        "From: a\@test1.dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n",
        "$AUTHSERV; dkim=pass header.d=unrelated.example");
    my $r = Mail::DKIM2::Reflector::reflect(
        %common, authserv_id => $AUTHSERV, mode => 'raw', message => $in);
    is($r->{basis}, 'none', 'unaligned DKIM1: no signing basis');
    is($r->{signed}, 0, 'unaligned DKIM1: not signed');
    like($r->{message}, qr/^X-DKIM2-Reflector:.*signed=no/m, 'unaligned: signed=no');
}

# --- subdomain alignment bridges ---
{
    my $in = mi_only_input(
        "From: a\@mail.test1.dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n",
        "$AUTHSERV; dkim=pass header.d=test1.dkim2.com");
    my $r = Mail::DKIM2::Reflector::reflect(
        %common, authserv_id => $AUTHSERV, mode => 'raw', message => $in);
    is($r->{signed}, 1, 'subdomain From aligns with parent d -> signed');
}

# --- foreign authserv-id is ignored -> not signed ---
{
    my $in = mi_only_input(
        "From: a\@test1.dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n",
        "evil.relay; dkim=pass header.d=test1.dkim2.com");
    my $r = Mail::DKIM2::Reflector::reflect(
        %common, authserv_id => $AUTHSERV, mode => 'raw', message => $in);
    is($r->{signed}, 0, 'foreign authserv-id A-R is not trusted');
}

# --- broken DKIM2 chain does NOT fall back to DKIM1 ---
{
    my $good = signed_input(
        "From: a\@test1.dkim2.com\r\nTo: reflector-raw\@dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n");
    # Append a body line so the DKIM2 body hash no longer matches -> dkim2=fail.
    my $broken = $good . "tampered\r\n";
    $broken =~ s/^(From: a\@test1\.dkim2\.com\r\n)/Authentication-Results: $AUTHSERV; dkim=pass header.d=test1.dkim2.com\r\n$1/m;
    my $r = Mail::DKIM2::Reflector::reflect(
        %common, authserv_id => $AUTHSERV, mode => 'raw', message => $broken);
    is($r->{auth}, 'fail', 'broken chain reports dkim2=fail');
    is($r->{dkim1}, 'pass', 'aligned DKIM1 still reported');
    is($r->{basis}, 'none', 'no bridge on a broken chain');
    is($r->{signed}, 0, 'broken chain + DKIM1 -> not signed');
}

# --- MI is emitted for transforming modes even when unsigned (T3) ---
{
    my $in = mi_only_input("From: a\@nodkim.example\r\nSubject: hi\r\n\r\nbody\r\n");
    my $r = Mail::DKIM2::Reflector::reflect(
        %common, authserv_id => $AUTHSERV, mode => 'body', message => $in);
    is($r->{signed}, 0, 'T3: unsigned (no DKIM2, no DKIM1)');
    my @mi = (Email::MIME->new($r->{message}))->header_raw('Message-Instance');
    is(scalar @mi, 2, 'T3: change-recording MI added even though unsigned');
    like($r->{message}, qr/Reflected and signed by the DKIM2 reflector/, 'T3: footer applied');
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd brong && perl -Ilib -It/lib t/reflector.t 2>&1 | grep -E 'T2:|T3:|unaligned|subdomain|foreign|broken'`
Expected: FAIL — `reflect()` ignores `authserv_id`, never sets `dkim1`/`basis`, only signs on DKIM2 pass, and skips MI when unsigned. (e.g. `T2: signing basis is dkim1` gets undef; `T3: change-recording MI added` sees 1 not 2.)

- [ ] **Step 3: Rework `reflect()`**

Replace the body of `reflect()` from the `# 1. Verify` comment through the
`return { ... }` line (`brong/lib/Mail/DKIM2/Reflector.pm:41-74`) with:

```perl
    # 1. DKIM2 verdict (computed here) + DKIM1 verdict (read from A-R).
    my $auth = _verify($incoming, $a{pubkey_cb}, $a{skip_timestamp_check});
    my $from_domain = _from_domain($incoming);
    my $dkim1_d = _dkim1_aligned($incoming, $from_domain, $a{authserv_id});
    my $dkim1   = $dkim1_d ? 'pass' : 'none';

    # 2. Three-tier signing basis: DKIM2 chain, else DKIM1 bridge (only when no
    #    chain present — a broken chain, dkim2=fail, does NOT fall back).
    my $basis = ($auth eq 'pass')                  ? 'dkim2'
              : ($auth eq 'none' && $dkim1_d)      ? 'dkim1'
              :                                       'none';
    my $will_sign = ($basis ne 'none');

    # 3. Transform (always, except damage which mutates after signing).
    my $prev_text = $incoming;
    my $cur_text  = ($mode eq 'damage') ? $incoming : _transform_text($incoming, $mode);

    # 4. Message-Instance for our change — ALWAYS for changing modes (raw/damage
    #    reuse the top m=). Emitted whether or not we sign.
    my $mi = _build_mi($cur_text, $prev_text, $mode);
    if ($mi) {
        my $val = fold_header("Message-Instance: " . $mi->as_string);
        $val =~ s/^Message-Instance:\s*//;
        $cur_text = "Message-Instance: $val\r\n" . $cur_text;
    }

    # 5. Sign when we have a basis; for damage, break the body AFTER signing.
    my $signed = 0;
    if ($will_sign) {
        my $sig = _sign($cur_text, %a);
        $cur_text = "$sig\r\n" . $cur_text;
        $signed = 1;
        $cur_text .= $DAMAGE_LINE if $mode eq 'damage';
    }

    # 6. Explanation headers (excluded from the DKIM2 header hash by
    #    should_skip(): ^x- and authentication-results). Safe to prepend last.
    my $ar = "Authentication-Results: $a{domain}; dkim2=$auth";
    $ar .= "; dkim=pass header.d=$dkim1_d" if $dkim1_d;
    $ar .= "\r\n";
    my $xr = "X-DKIM2-Reflector: mode=$mode; auth=$auth; dkim1=$dkim1; "
           . "basis=$basis; signed=" . ($signed ? 'yes' : 'no')
           . "; note=reflected-to-sender\r\n";
    $cur_text = $ar . $xr . $cur_text;

    return {
        message => $cur_text, auth => $auth, dkim1 => $dkim1,
        basis => $basis, signed => $signed, mode => $mode,
    };
```

- [ ] **Step 4: Run the full reflector test file to verify it passes**

Run: `cd brong && perl -Ilib -It/lib t/reflector.t 2>&1 | tail -3`
Expected: all tests pass (existing T1/T3/mode/undo/damage cases plus the new
T2/alignment/foreign/broken/MI-always cases). No `not ok` lines.

- [ ] **Step 5: Run the whole suite for regressions**

Run: `cd brong && prove -Ilib -It/lib t/ 2>&1 | tail -5`
Expected: `Result: PASS`. Then discard any regenerated expected emails:
`git checkout -- brong/tests/expected/`

- [ ] **Step 6: Commit**

```bash
git add brong/lib/Mail/DKIM2/Reflector.pm brong/t/reflector.t
git commit -m "feat(reflector): DKIM1-bridge signing + always-on Message-Instance"
```

---

### Task 5: Pass the authserv-id through the CLI wrapper

**Files:**
- Modify: `brong/bin/dkim2-reflector.pl:26-36` (add `authserv_id`)
- Test: `brong/t/reflector-cli.t`

**Interfaces:**
- Consumes: `reflect()`'s new `authserv_id` arg (Task 4).
- Produces: the deployed wrapper calls `reflect(... authserv_id => 'mail.dkim2.com' ...)`.

- [ ] **Step 1: Write the failing test**

Add to `brong/t/reflector-cli.t` before `done_testing;`:

```perl
like($src, qr/authserv_id\s*=>\s*'mail\.dkim2\.com'/,
    'wrapper passes the configured authserv-id');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd brong && perl -Ilib -It/lib t/reflector-cli.t 2>&1 | grep authserv`
Expected: FAIL — `wrapper passes the configured authserv-id`.

- [ ] **Step 3: Add the argument**

In `brong/bin/dkim2-reflector.pl`, add the `authserv_id` line to the
`reflect(...)` call (after `mailfrom => 'reflector-bounces@dkim2.com',`):

```perl
        mailfrom => 'reflector-bounces@dkim2.com',
        authserv_id => 'mail.dkim2.com',
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd brong && perl -Ilib -It/lib t/reflector-cli.t 2>&1 | tail -3`
Expected: all pass, including the new authserv-id assertion and `wrapper compiles`.

- [ ] **Step 5: Commit**

```bash
git add brong/bin/dkim2-reflector.pl brong/t/reflector-cli.t
git commit -m "feat(reflector): wrapper passes configured authserv-id"
```

---

### Task 6: Document the rules and headers on the website

**Files:**
- Modify: `deploy/www/index.html` (the "Try it: reflector addresses" `<section>`)

**Interfaces:** none (static HTML; matches existing page style — plain
`<section>`/`<p>`/`<table>`/`<code>`, no new CSS).

- [ ] **Step 1: Add the "what to expect" rules and a headers reference**

In `deploy/www/index.html`, immediately **after** the existing per-address
`</table>` in the "Try it: reflector addresses" section and **before** the
closing `</section>`, insert:

```html
      <h3>When the reply is signed</h3>
      <p>The reflector adds its own <code>dkim2.com</code> chain link only when
        it can vouch for your message:</p>
      <ul>
        <li>your message already had a <strong>verified DKIM2 chain</strong> —
          the reply continues the chain;</li>
        <li>your message had <strong>no DKIM2 chain but a valid DKIM1
          signature</strong> aligned with your <code>From:</code> domain — the
          reply is signed as a <strong>DKIM1&nbsp;&rarr;&nbsp;DKIM2 bridge</strong>;</li>
        <li>neither — the reply comes back <strong>unsigned</strong> (the
          mode's transformation is still applied).</li>
      </ul>
      <p>A change-recording <code>Message-Instance</code> is added for every
        mode that alters the message (subject, body, both, redacted), whether
        or not the reply is signed.</p>

      <h3>Headers to look at in the reflected message</h3>
      <table>
        <thead>
          <tr><th>Header</th><th>What it tells you</th></tr>
        </thead>
        <tbody>
          <tr>
            <td><code>X-DKIM2-Reflector</code></td>
            <td>The reflector's summary: <code>mode</code>, the verdicts it saw
              (<code>auth</code> = DKIM2, <code>dkim1</code>), what it signed on
              (<code>basis</code> = <code>dkim2</code>/<code>dkim1</code>/<code>none</code>),
              and <code>signed</code>.</td>
          </tr>
          <tr>
            <td><code>Authentication-Results</code></td>
            <td>The <code>dkim2=</code> and (when a bridge applied)
              <code>dkim=pass header.d=</code> results the reflector relied on.</td>
          </tr>
          <tr>
            <td><code>DKIM2-Signature</code></td>
            <td>Present only when the reply is signed — the reflector's link in
              the chain.</td>
          </tr>
          <tr>
            <td><code>Message-Instance</code></td>
            <td>The <code>m=</code> snapshot recording the reflector's change
              (present for the changing modes).</td>
          </tr>
        </tbody>
      </table>
```

- [ ] **Step 2: Verify the markup balances**

Run:
```bash
python3 - <<'PY'
import re
d = open('deploy/www/index.html').read()
for t in ['section','table','thead','tbody','tr','td','th','ul','li','h3']:
    o=len(re.findall(r'<%s[ >]'%t,d)); c=len(re.findall(r'</%s>'%t,d))
    print(f'{t:7} {o} {c} {"OK" if o==c else "MISMATCH"}')
PY
```
Expected: every row prints `OK`.

- [ ] **Step 3: Commit**

```bash
git add deploy/www/index.html
git commit -m "docs(www): describe reflector signing rules + headers to inspect"
```

---

### Task 7: Server config (OpenDKIM inbound), deploy, end-to-end verify

**Files:**
- Modify: `deploy/SERVER.md` (§6 reflector — document OpenDKIM inbound verify + authserv-id)
- Server (documented, not in repo): `/etc/opendkim.conf`, `/etc/postfix/main.cf` `smtpd_milters`

**Interfaces:** consumes the deployed module/script/website from Tasks 4–6.

- [ ] **Step 1: Document the inbound-verify setup in SERVER.md §6**

Add to `deploy/SERVER.md` §6 (DKIM2 Reflector) a subsection stating:
- OpenDKIM must run on the **inbound** path so it stamps
  `Authentication-Results` on received mail. Add the OpenDKIM socket to
  `smtpd_milters` (it is already in `non_smtpd_milters` for outbound signing),
  ensure `Mode` includes `v` (verify), and set
  `AuthservID mail.dkim2.com` with `RemoveOldAuthenticationResults yes` so
  external A-R bearing our authserv-id are dropped before ours is added.
- The reflector trusts only `Authentication-Results` whose authserv-id is
  `mail.dkim2.com` (passed by `dkim2-reflect`); keep the two values in sync.
- Reload after changes: `systemctl reload postfix opendkim`.

```bash
git add deploy/SERVER.md
git commit -m "docs(server): OpenDKIM inbound verify for the reflector DKIM1 bridge"
```

- [ ] **Step 2: Push**

```bash
git push origin master
```

- [ ] **Step 3: Apply server config + deploy code and website**

```bash
# Server config (apply per SERVER.md §6): add OpenDKIM socket to smtpd_milters,
# set Mode sv / AuthservID mail.dkim2.com / RemoveOldAuthenticationResults yes,
# then: ssh dkim2 'systemctl reload postfix opendkim'

ssh dkim2 'cd /root/interop && git pull && \
    cd brong && perl Makefile.PL >/dev/null && make >/dev/null && make install >/dev/null && \
    install -m 755 bin/dkim2-reflector.pl /usr/local/bin/dkim2-reflect'
ssh dkim2 'cd /root/interop && install -m 644 deploy/www/index.html deploy/www/style.css /var/www/dkim2.com/'
```

- [ ] **Step 4: Verify inbound A-R is now stamped**

Send a normal DKIM1-signed (no DKIM2) message to any reflector address from an
aligned domain, then check the inbound copy logs an `Authentication-Results`
with our authserv-id and `dkim=pass`:

Run: `ssh dkim2 'grep -i "authserv\|dkim=pass\|reflector-" /var/log/mail.log | tail -10'`
Expected: a `dkim=pass` result attributed to `mail.dkim2.com`.

- [ ] **Step 5: Verify the bridge end-to-end**

Confirm the reply to a DKIM1-only message is bridge-signed: inspect the
received reply's headers for `X-DKIM2-Reflector: ... basis=dkim1; signed=yes`,
a `DKIM2-Signature:`, and (for changing modes) a `Message-Instance:`. Paste the
reply into <https://dkim2.com/validate/> and confirm it verifies.

Expected: `basis=dkim1`, `signed=yes`, validator reports a valid chain.

- [ ] **Step 6: Verify the website**

Run: `curl -s https://dkim2.com/ | grep -o "DKIM1.*bridge\|Headers to look at in the reflected message" | sort -u`
Expected: both the bridge rule text and the "Headers to look at…" heading appear.

---

## Self-Review

**Spec coverage:**
- Three-tier auth model → Task 4 (basis logic) + Tasks 1–3 (inputs). ✓
- `dkim2=none` only, no bridge on `fail` → Task 4 basis condition + broken-chain test. ✓
- OpenDKIM inbound verify + authserv-id scoping + RemoveOld → Task 7 (server) + Task 3 (scoping) + Task 5 (value). ✓
- Any-one-of-many DKIM1 signature matches → Task 3 (`for my $chunk`) + "one matching pass among several" test. ✓
- Relaxed PSL-free alignment → Task 1. ✓
- Always-on MI for changing modes; raw/damage reuse top m= → Task 4 (MI moved out of sign block; `_build_mi` unchanged) + MI-always test. ✓
- Explanation headers `dkim1=`/`basis=` and `dkim=pass header.d=` in A-R → Task 4. ✓
- `dkim1=` independent of `basis=` (fail case) → Task 4 broken-chain test asserts `dkim1=pass, basis=none`. ✓
- Website rules + "headers to look at" → Task 6. ✓
- Error handling (no A-R, no From) → Tasks 2/3 return undef → `none` tier; covered by `_from_domain`/`_dkim1_aligned` undef tests. ✓

**Placeholder scan:** none — every code/test step shows full content. ✓

**Type consistency:** `_domains_align($f,$d)`, `_from_domain($text)`,
`_dkim1_aligned($text,$from_domain,$authserv_id)`, and the `reflect()` return
keys (`message`,`auth`,`dkim1`,`basis`,`signed`,`mode`) are used identically
across Tasks 3–5 and the tests. Authserv-id value `mail.dkim2.com` is identical
in Tasks 5, 7 and the Global Constraints. ✓
