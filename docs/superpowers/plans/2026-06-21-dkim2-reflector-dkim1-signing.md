# DKIM1 Signatures on Reflector Output — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add classic DKIM1 signatures to every reflector reply — `d=dkim2.com` on all, plus a delegated `d=<brand>` on `reflector-brand` so it DMARC-aligns and lands in the inbox.

**Architecture:** A composable `Mail::DKIM2::Reflector::sign_dkim1($text, @specs)` helper (using `Mail::DKIM::Signer`) prepends DKIM1 signatures to a finished message. The `dkim2-reflector.pl` wrapper calls it on the built reply before injecting — always with the `dkim2.com/sel1` spec, plus the delegated `<brand>/dkim2test` spec for delegated brand replies.

**Tech Stack:** Perl 5.20+, `Mail::DKIM` (new dependency; `libmail-dkim-perl` on the server, `cpanm` locally), existing `Mail::DKIM2::Reflector`; `Test::More` + `DKIM2TestKeys`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-06-21-dkim2-reflector-dkim1-signing-design.md`.
- DKIM1 sigs are `rsa-sha256`, `relaxed/relaxed`. Confirmed: `Mail::DKIM::PrivateKey->load(File => …)` reads our PKCS#8 keys and signs with `From` in `h=` (no key conversion needed).
- Keys reused: `dkim2.com/sel1` (`/etc/dkim2/reflector/sel1.key`) for all; the delegated `dkim2test` (`/etc/dkim2/reflector/dkim2test.key`) for brand `d=<brand>`.
- `sign_dkim1` only prepends headers; it never alters the body or the DKIM2/MI headers.
- No change to the DKIM2 chain, Message-Instance, validator, or `Received-SPF` handling.

---

## File Structure

- `brong/lib/Mail/DKIM2/Reflector.pm` — add `sign_dkim1`.
- `brong/bin/dkim2-reflector.pl` — call `sign_dkim1` on the built reply before injecting.
- `brong/t/reflector-dkim1.t` (new) — helper tests (skips if `Mail::DKIM` absent).

---

### Task 1: `sign_dkim1` helper + tests

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Reflector.pm`
- Create: `brong/t/reflector-dkim1.t`

**Interfaces:**
- Produces: `Mail::DKIM2::Reflector::sign_dkim1($text, @specs) -> $text`. Each spec is a hashref `{domain, selector, keyfile}` or `{domain, selector, key => <PEM string>}`. Returns the message with a `DKIM-Signature:` header prepended per spec (CRLF endings preserved).

- [ ] **Step 1: Install `Mail::DKIM` locally (for the test run)**

```bash
cpanm --notest Mail::DKIM 2>&1 | tail -3 || cpan -T Mail::DKIM
perl -MMail::DKIM::Signer -e 'print "Mail::DKIM ok\n"'
```
Expected: `Mail::DKIM ok`.

- [ ] **Step 2: Write the failing test** — create `brong/t/reflector-dkim1.t`

```perl
#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More;
BEGIN { eval { require Mail::DKIM::Signer; 1 } or plan skip_all => 'Mail::DKIM not installed'; }
use lib 'lib', 't/lib';
use Mail::DKIM2::Reflector;
use DKIM2TestKeys;

my $msg = "From: a\@test2.dkim2.com\r\nTo: b\@example.test\r\nSubject: hi\r\n"
        . "Date: Tue, 01 Jan 2030 00:00:00 +0000\r\nMessage-ID: <x\@test2.dkim2.com>\r\n"
        . "MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nbody here\r\n";

# one spec -> one well-formed DKIM-Signature
my $pem = DKIM2TestKeys::private_key_pem('test2.dkim2.com', 'sel1');
my $out = Mail::DKIM2::Reflector::sign_dkim1($msg,
    { domain => 'test2.dkim2.com', selector => 'sel1', key => $pem });
my @sigs = $out =~ /^DKIM-Signature:/mg;
is(scalar @sigs, 1, 'one spec -> one DKIM-Signature');
like($out, qr/\bd=test2\.dkim2\.com\b/, 'd= set');
like($out, qr/\bs=sel1\b/, 's= set');
like($out, qr/a=rsa-sha256/, 'a=rsa-sha256');
like($out, qr{c=relaxed/relaxed}, 'c=relaxed/relaxed');
like($out, qr/\bbh=/, 'has a body hash');
like($out, qr/\r\n\r\nbody here\r\n\z/, 'body preserved at end');

# two specs -> two signatures, distinct domains
my $out2 = Mail::DKIM2::Reflector::sign_dkim1($msg,
    { domain => 'test1.dkim2.com', selector => 'dkim2test',
      key => DKIM2TestKeys::private_key_pem('test1.dkim2.com', 'dkim2test') },
    { domain => 'test2.dkim2.com', selector => 'sel1', key => $pem });
my @s2 = $out2 =~ /^DKIM-Signature:/mg;
is(scalar @s2, 2, 'two specs -> two DKIM-Signature headers');
like($out2, qr/\bd=test1\.dkim2\.com\b/, 'brand d= present');
like($out2, qr/\bs=dkim2test\b/, 'brand s=dkim2test present');

done_testing;
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd brong && perl -I lib -I t/lib t/reflector-dkim1.t 2>&1 | tail -6`
Expected: FAIL — `Undefined subroutine &Mail::DKIM2::Reflector::sign_dkim1`.

- [ ] **Step 4: Implement `sign_dkim1`** (add after `_dkim2test_cname_ok` in `Reflector.pm`)

```perl
# sign_dkim1($text, @specs) — prepend a classic DKIM1 DKIM-Signature per spec.
# Each spec: { domain, selector, keyfile } or { domain, selector, key => <PEM> }.
# rsa-sha256 / relaxed-relaxed. Composable post-step: only prepends headers,
# never touches the body or the DKIM2/MI headers. See
# docs/superpowers/specs/2026-06-21-dkim2-reflector-dkim1-signing-design.md.
sub sign_dkim1 {
    my ($text, @specs) = @_;
    require Mail::DKIM::Signer;
    require Mail::DKIM::PrivateKey;
    for my $s (@specs) {
        my $key = $s->{key}
            ? Mail::DKIM::PrivateKey->load(Data => $s->{key})
            : Mail::DKIM::PrivateKey->load(File => $s->{keyfile});
        my $signer = Mail::DKIM::Signer->new(
            Algorithm => 'rsa-sha256',
            Method    => 'relaxed/relaxed',
            Domain    => $s->{domain},
            Selector  => $s->{selector},
            Key       => $key,
        );
        $signer->PRINT($text);
        $signer->CLOSE;
        (my $sig = $signer->signature->as_string) =~ s/\r?\n/\r\n/g;
        $sig =~ s/\r\n\z//;
        $text = "$sig\r\n" . $text;
    }
    return $text;
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd brong && perl -I lib -I t/lib t/reflector-dkim1.t 2>&1 | tail -8`
Expected: PASS — all assertions `ok`.

- [ ] **Step 6: Full suite**

Run: `cd brong && prove -I lib -I t/lib t/ 2>&1 | tail -3`
Expected: `All tests successful.` (the new file runs since `Mail::DKIM` is now installed).

- [ ] **Step 7: Commit**

```bash
git add brong/lib/Mail/DKIM2/Reflector.pm brong/t/reflector-dkim1.t
git commit -m "feat(reflector): sign_dkim1 — prepend classic DKIM1 signatures

Composable helper using Mail::DKIM::Signer (rsa-sha256, relaxed/relaxed).
Each spec {domain,selector,keyfile|key} prepends one DKIM-Signature; body
and DKIM2/MI headers untouched.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Wrapper wiring — sign every reply

**Files:**
- Modify: `brong/bin/dkim2-reflector.pl`
- Test: `brong/t/reflector-cli.t`

**Interfaces:**
- Consumes: `Mail::DKIM2::Reflector::sign_dkim1` (Task 1).

- [ ] **Step 1: Write the failing test** (append to `brong/t/reflector-cli.t`, before `done_testing;`)

```perl
like($src, qr/sign_dkim1/, 'wrapper adds DKIM1 signatures to the reply');
like($src, qr{/etc/dkim2/reflector/sel1\.key}, 'wrapper DKIM1-signs as dkim2.com/sel1');
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd brong && perl -I lib -I t/lib t/reflector-cli.t 2>&1 | tail -6`
Expected: the `sign_dkim1` check `not ok`.

- [ ] **Step 3: Add the DKIM1 signing step** in `brong/bin/dkim2-reflector.pl`, right after the dispatch `eval` block that sets `$result` and the error check, and before the SMTP injection. Insert:

```perl
# Add classic DKIM1 signatures so the reply looks like real-world mail. Always
# sign as dkim2.com; for a delegated brand reply also sign as the brand domain
# with the delegated key (this is what DMARC-aligns From: dkim2demo@<brand>).
my @dkim1 = ({ domain => 'dkim2.com', selector => 'sel1',
               keyfile => '/etc/dkim2/reflector/sel1.key' });
if ($mode eq 'brand' && $result->{basis} eq 'brand') {
    my $bd = $sender; $bd =~ s/.*\@//;
    unshift @dkim1, { domain => $bd, selector => 'dkim2test',
                      keyfile => '/etc/dkim2/reflector/dkim2test.key' };
}
$result->{message} = eval { Mail::DKIM2::Reflector::sign_dkim1($result->{message}, @dkim1) }
    // $result->{message};
logmsg("dkim1 sign failed: $@") if $@;
```

(The brand branch sets `basis => 'brand'` only when `$delegated` was true — see Task 3 of the brand plan — so this adds the delegated `d=<brand>` sig exactly when the CNAME resolved. `sign_dkim1` failure is non-fatal: log and send the reply unsigned-by-DKIM1 rather than drop it.)

- [ ] **Step 4: Compile + cli test**

Run: `cd brong && perl -c -I lib bin/dkim2-reflector.pl 2>&1 | tail -1 && perl -I lib -I t/lib t/reflector-cli.t 2>&1 | tail -6`
Expected: `syntax OK`; all cli checks `ok`.

- [ ] **Step 5: Commit**

```bash
git add brong/bin/dkim2-reflector.pl brong/t/reflector-cli.t
git commit -m "feat(reflector): DKIM1-sign every reply (delegated d=<brand> for brand)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Deploy + verify

**Files:**
- Server: installed `Reflector.pm` + `/usr/local/bin/dkim2-reflect`.

- [ ] **Step 1: Push**

```bash
git push origin master
```

- [ ] **Step 2: Deploy** (confirm `libmail-dkim-perl`, reinstall lib + wrapper)

```bash
ssh dkim2 'set -e
perl -MMail::DKIM::Signer -e "print q{Mail::DKIM present\n}" || apt-get install -y libmail-dkim-perl
cd /root/interop && git pull --ff-only
cd brong && perl Makefile.PL >/dev/null 2>&1 && make >/dev/null 2>&1 && make install 2>&1 | grep -E "Installing.*Reflector" || true
install -m 755 /root/interop/brong/bin/dkim2-reflector.pl /usr/local/bin/dkim2-reflect
perl -c /usr/local/bin/dkim2-reflect 2>&1 | tail -1
grep -c "sign_dkim1" /usr/local/share/perl/5.40.1/Mail/DKIM2/Reflector.pm'
```
Expected: `Mail::DKIM present`; `Reflector.pm` reinstalled; wrapper `syntax OK`; grep ≥ 1.

- [ ] **Step 3: Smoke test — fresh reply carries d=dkim2.com DKIM1**

```bash
ssh dkim2 '
mbox=/var/spool/reflector-bounces/mbox; before=$(wc -c < "$mbox")
printf "From: nobody@example.com\nTo: reflector-fresh@dkim2.com\nSubject: x\n\nq\n" \
  | sendmail -f reflector-bounces@dkim2.com reflector-fresh@dkim2.com
sleep 40; postqueue -f 2>/dev/null; sleep 3
last=$(grep -n "^From " "$mbox" | tail -1 | cut -d: -f1)
sed -n "${last},\$p" "$mbox" | grep -iE "^DKIM-Signature:|d=dkim2.com" | head'
```
Expected: a `DKIM-Signature:` header with `d=dkim2.com` on the fresh reply.

- [ ] **Step 4: Final brand confirmation (delegated → two DKIM1 sigs → inbox)**

Send a real message from `brong@brong.net` to `reflector-brand@dkim2.com`. Confirm the reply:
- has **two** `DKIM-Signature` headers: `d=brong.net s=dkim2test` and `d=dkim2.com s=sel1`;
- now lands in the **inbox** (the `d=brong.net` DKIM1 aligns with `From: dkim2demo@brong.net` → DMARC pass);
- still shows the DKIM2 chain green in the validator.

---

## Self-Review

- **Spec coverage:** dependency (Task 1 §1), `sign_dkim1` helper (Task 1), wrapper wiring incl. delegated brand spec (Task 2), deploy + brand inbox verification (Task 3). All mapped.
- **Placeholders:** none — all code/commands concrete; the PKCS#8 key-load risk was spiked away (works as-is).
- **Type consistency:** `sign_dkim1($text, @specs)` with spec keys `domain`/`selector`/`keyfile`/`key` defined in Task 1, consumed identically in Task 2. `$result->{basis} eq 'brand'` matches the value set by the wrapper's brand branch.
