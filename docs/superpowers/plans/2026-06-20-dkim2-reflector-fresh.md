# reflector-fresh DKIM2 Message Generator — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `reflector-fresh@dkim2.com` address that originates a brand-new DKIM2 message (single `m=1` + single `i=1`, no chain) back to the sender, From a `dkim2.com` identity so it passes DMARC and lands in the inbox.

**Architecture:** A new `Mail::DKIM2::Reflector::generate(%args)` builds and signs a fresh message (separate from `reflect()`, which transforms an incoming one). The `dkim2-reflector.pl` wrapper gains a `fresh` mode that dispatches to `generate()`. Postfix routes `reflector-fresh@dkim2.com` through the existing `dkim2-reflect` pipe transport — only the transport/recipient map gains one line.

**Tech Stack:** Perl 5.20+, `Mail::DKIM2::{Reflector,Signer,MessageInstance,Common}`, `Email::MIME`, `POSIX::strftime`; `Test::More` + `DKIM2TestKeys`; Postfix `pipe(8)` transport.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-06-20-dkim2-reflector-fresh-design.md`.
- The generated message is `text/plain; charset=utf-8`, single part, CRLF line endings throughout.
- `From: "DKIM2 Generator" <fresh@<domain>>`; envelope/`mf=` is `reflector-bounces@<domain>`; `d=<domain>`, `s=<selector>`, `rsa-sha256`.
- `generate()` MUST accept injectable `now` (epoch) and `message_id` for deterministic tests; production omits them.
- Provenance header is `X-DKIM2-Info: ... action=generate` only — NO `X-DKIM2-Reflector` on the fresh path.
- Reuse the existing `_sign`, `_dkim2_info`, `_header_list_for_hash`, and the `fold_header` helper already in `Reflector.pm`. Do not duplicate them.

---

## File Structure

- `brong/lib/Mail/DKIM2/Reflector.pm` — add `generate(%args)` and a small `_rfc2822_date` helper.
- `brong/bin/dkim2-reflector.pl` — add `fresh` to the valid set and dispatch to `generate()`.
- `brong/t/reflector.t` — add a `generate()` test group.
- `deploy/postfix-dkim2-transport` — add the `reflector-fresh` route.
- Server (deploy task): `/etc/postfix/dkim2-transport` + `postmap` + `postfix reload`.

---

### Task 1: `generate()` in `Mail::DKIM2::Reflector`

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Reflector.pm`
- Test: `brong/t/reflector.t`

**Interfaces:**
- Consumes: `_sign($text, %a)`, `_dkim2_info($action, %extra)`, `_header_list_for_hash($mime)`, `fold_header(...)`, `Mail::DKIM2::MessageInstance->calculate($mime)` — all already present.
- Produces: `Mail::DKIM2::Reflector::generate(%args) -> $message_text` where `%args` keys are `sender` (required), `domain` (default `dkim2.com`), `selector` (default `sel1`), `key` or `keyfile`, `mailfrom` (default `reflector-bounces@dkim2.com`), `now` (epoch, default `time()`), `message_id` (default generated). Returns full signed message text (headers `X-DKIM2-Info`, `DKIM2-Signature`, `Message-Instance`, then `From/To/Subject/Date/Message-ID/MIME-Version/Content-Type`, blank line, body), CRLF throughout.

- [ ] **Step 1: Write the failing test** (append to `brong/t/reflector.t`, before `done_testing;`)

```perl
# --- fresh: originate a brand-new single-instance message ---
{
    my $msg = Mail::DKIM2::Reflector::generate(
        sender     => 'a@test1.dkim2.com',
        domain     => 'test2.dkim2.com',
        selector   => 'sel1',
        key        => DKIM2TestKeys::private_key('test2.dkim2.com', 'sel1'),
        mailfrom   => 'reflector-bounces@test2.dkim2.com',
        now        => 1740000000,
        message_id => '<fresh-test@test2.dkim2.com>',
    );
    my $em = Email::MIME->new($msg);
    is($em->header('To'), 'a@test1.dkim2.com', 'fresh: To is the sender');
    like($em->header('From'), qr/<fresh\@test2\.dkim2\.com>/, 'fresh: From is the generator identity');
    is(scalar($em->header_raw('DKIM2-Signature')), 1, 'fresh: exactly one signature (no chain)');
    is(scalar($em->header_raw('Message-Instance')), 1, 'fresh: exactly one Message-Instance');
    like($msg, qr/^X-DKIM2-Info:.*action=generate/ms, 'fresh: X-DKIM2-Info action=generate');
    unlike($msg, qr/^X-DKIM2-Reflector:/mi, 'fresh: no X-DKIM2-Reflector on the originated message');
    is(Mail::DKIM2::MessageInstance->verify(Email::MIME->new($msg)), 1, 'fresh: MI m=1 verifies');
    is(reflected_verifies($msg), 'pass', 'fresh: generated message verifies end to end');
    # determinism
    my $msg2 = Mail::DKIM2::Reflector::generate(
        sender => 'a@test1.dkim2.com', domain => 'test2.dkim2.com', selector => 'sel1',
        key => DKIM2TestKeys::private_key('test2.dkim2.com', 'sel1'),
        mailfrom => 'reflector-bounces@test2.dkim2.com',
        now => 1740000000, message_id => '<fresh-test@test2.dkim2.com>');
    is($msg2, $msg, 'fresh: deterministic for fixed now + message_id');
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd brong && perl -I lib -I t/lib t/reflector.t 2>&1 | tail -15`
Expected: FAIL — `Undefined subroutine &Mail::DKIM2::Reflector::generate`.

- [ ] **Step 3: Implement `generate()` and `_rfc2822_date`**

Add near the other helpers in `brong/lib/Mail/DKIM2/Reflector.pm` (after `_header_list_for_hash`). `POSIX` is needed for the date — add `use POSIX qw(strftime);` to the top `use` block.

```perl
# RFC 5322 date string (always UTC) for the given epoch.
sub _rfc2822_date {
    my ($epoch) = @_;
    return POSIX::strftime('%a, %d %b %Y %H:%M:%S +0000', gmtime($epoch));
}

# generate(%args) — ORIGINATE a brand-new DKIM2 message back to the sender:
# a single Message-Instance (m=1) and a single DKIM2-Signature (i=1), no chain.
# Unlike reflect(), the incoming message is not used (the caller passes only the
# reply target as `sender`). From is a <domain> identity so DMARC aligns and the
# message lands in the inbox. See the design spec.
sub generate {
    my (%a) = @_;
    croak "need a sender" unless $a{sender};
    $a{domain}   //= 'dkim2.com';
    $a{selector} //= 'sel1';
    $a{mailfrom} //= "reflector-bounces\@$a{domain}";
    my $now = $a{now} // time();
    $a{timestamp} //= $now;                       # _sign reads $a{timestamp}
    my $mid  = $a{message_id} // sprintf('<fresh-%d-%d@%s>', $now, $$, $a{domain});
    my $date = _rfc2822_date($now);

    my $body =
        "Hello,\r\n\r\n"
      . "This is a freshly-originated DKIM2 message from $a{domain}, generated\r\n"
      . "because you sent mail to reflector-fresh\@$a{domain}.\r\n\r\n"
      . "Unlike the other reflector addresses, this is NOT a forward of your\r\n"
      . "message: it is a brand-new message with a single Message-Instance (m=1)\r\n"
      . "and a single DKIM2-Signature (i=1), and no forwarding chain.\r\n\r\n"
      . "Paste it into https://$a{domain}/validate/ to see it verify.\r\n\r\n"
      . "Requested by: $a{sender}\r\n"
      . "Generated at: $date\r\n\r\n"
      . "-- \r\n"
      . "The DKIM2 reflector at $a{domain}\r\n";

    my $text =
        "From: \"DKIM2 Generator\" <fresh\@$a{domain}>\r\n"
      . "To: $a{sender}\r\n"
      . "Subject: Freshly generated DKIM2 message\r\n"
      . "Date: $date\r\n"
      . "Message-ID: $mid\r\n"
      . "MIME-Version: 1.0\r\n"
      . "Content-Type: text/plain; charset=utf-8\r\n"
      . "\r\n"
      . $body;

    # m=1 Message-Instance (hashes only, no previous version).
    my $mi = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($text));
    (my $miv = fold_header("Message-Instance: " . $mi->as_string)) =~ s/^Message-Instance:\s*//;
    $text = "Message-Instance: $miv\r\n" . $text;

    # i=1 DKIM2-Signature (mf= relaxed-matches d=; rt = [sender]; no predecessor).
    my $sig = _sign($text, %a);
    $text = "$sig\r\n" . $text;

    # X-DKIM2-Info provenance (action=generate), same format as the milter.
    my ($hc, $hn) = _header_list_for_hash(Email::MIME->new($text));
    (my $xi = fold_header("X-DKIM2-Info: " . _dkim2_info('generate', hc => $hc, hn => $hn))) =~ s/\r?\n\z//;
    $text = "$xi\r\n" . $text;

    return $text;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd brong && perl -I lib -I t/lib t/reflector.t 2>&1 | tail -15`
Expected: PASS — the new `fresh:` assertions all `ok`, `1..N` with no failures.

- [ ] **Step 5: Run the full suite (no regressions)**

Run: `cd brong && prove -I lib -I t/lib t/ 2>&1 | tail -4`
Expected: `All tests successful.` / `Result: PASS`.

- [ ] **Step 6: Commit**

```bash
git add brong/lib/Mail/DKIM2/Reflector.pm brong/t/reflector.t
git commit -m "feat(reflector): generate() — originate a fresh DKIM2 message

Builds and signs a brand-new message (single m=1 + single i=1, no chain)
back to the sender, From a <domain> identity. Separate from reflect()
(which transforms an incoming message). Injectable now/message_id for
deterministic tests.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `fresh` mode in the wrapper

**Files:**
- Modify: `brong/bin/dkim2-reflector.pl`
- Test: `brong/t/reflector-cli.t`

**Interfaces:**
- Consumes: `Mail::DKIM2::Reflector::generate(%args)` from Task 1.
- Produces: the wrapper accepts `fresh` (via `${user}=reflector-fresh` or a bare `fresh` arg) and submits the generated message to the injector exactly as the reflect path does.

- [ ] **Step 1: Write the failing test** (append to `brong/t/reflector-cli.t`, before `done_testing;`)

```perl
like($src, qr/\bfresh\b/, 'wrapper knows the fresh mode');
like($src, qr/Mail::DKIM2::Reflector::generate/, 'wrapper dispatches to generate() for fresh');
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd brong && perl -I lib -I t/lib t/reflector-cli.t 2>&1 | tail -6`
Expected: FAIL — the two new `like` checks report `not ok` (no `generate` reference yet).

- [ ] **Step 3: Implement the dispatch**

In `brong/bin/dkim2-reflector.pl`: add `fresh` to the valid-mode set, and branch before the `reflect()` call. Change:

```perl
my %VALID_MODE = map { $_ => 1 } qw(raw subject body both redacted damage);
```
to:
```perl
my %VALID_MODE = map { $_ => 1 } qw(raw subject body both redacted damage fresh);
```

Then replace the `my $result = eval { Mail::DKIM2::Reflector::reflect(...) };` block with a dispatch that calls `generate()` for the `fresh` mode and `reflect()` otherwise:

```perl
my $result = eval {
    if ($mode eq 'fresh') {
        my $msg = Mail::DKIM2::Reflector::generate(
            sender   => $sender,
            domain   => 'dkim2.com',
            selector => 'sel1',
            keyfile  => '/etc/dkim2/reflector/sel1.key',
            mailfrom => 'reflector-bounces@dkim2.com',
        );
        { message => $msg, signed => 1, basis => 'origin', mode => 'fresh' };
    } else {
        Mail::DKIM2::Reflector::reflect(
            message  => $message,
            mode     => $mode,
            sender   => $sender,
            domain   => 'dkim2.com',
            selector => 'sel1',
            keyfile  => '/etc/dkim2/reflector/sel1.key',
            mailfrom => 'reflector-bounces@dkim2.com',
            authserv_id => 'mail.dkim2.com',
        );
    }
};
```

(The existing `$result->{message}`, `$result->{signed}`, `$result->{basis}` consumers downstream — the injector and the syslog success line — work unchanged for the `fresh` hashref.)

- [ ] **Step 4: Run the cli test + compile check**

Run: `cd brong && perl -c -I lib bin/dkim2-reflector.pl 2>&1 | tail -1 && perl -I lib -I t/lib t/reflector-cli.t 2>&1 | tail -6`
Expected: `syntax OK`; all cli `ok`, including the two new checks.

- [ ] **Step 5: Commit**

```bash
git add brong/bin/dkim2-reflector.pl brong/t/reflector-cli.t
git commit -m "feat(reflector): wrapper 'fresh' mode dispatches to generate()

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Route `reflector-fresh` through the pipe transport + deploy

**Files:**
- Modify: `deploy/postfix-dkim2-transport`
- Server: `/etc/postfix/dkim2-transport`

**Interfaces:**
- Consumes: the deployed wrapper (`/usr/local/bin/dkim2-reflect`) from Tasks 1–2 and the existing `dkim2-reflect` `pipe(8)` service.
- Produces: `reflector-fresh@dkim2.com` accepted at RCPT and delivered via the pipe (mode `fresh`).

- [ ] **Step 1: Add the route to the committed map source**

Add this line to `deploy/postfix-dkim2-transport` (after the `reflector-damage` line):

```
reflector-fresh@dkim2.com    dkim2-reflect:
```

- [ ] **Step 2: Commit the map change**

```bash
git add deploy/postfix-dkim2-transport
git commit -m "feat(reflector): route reflector-fresh via the pipe transport

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push origin master
```

- [ ] **Step 3: Deploy to the server**

```bash
ssh dkim2 'set -e
cd /root/interop && git pull --ff-only
cd brong && perl Makefile.PL >/dev/null 2>&1 && make >/dev/null 2>&1 && make install 2>&1 | grep -E "Installing.*Reflector" || true
install -m 755 brong/bin/dkim2-reflector.pl /usr/local/bin/dkim2-reflect
install -m 644 deploy/postfix-dkim2-transport /etc/postfix/dkim2-transport
postmap /etc/postfix/dkim2-transport
postfix reload
echo "fresh route:"; postmap -q reflector-fresh@dkim2.com hash:/etc/postfix/dkim2-transport'
```
Expected: `make install` reinstalls `Reflector.pm`; `postmap -q` prints `dkim2-reflect:`; reload succeeds.

- [ ] **Step 4: Live smoke test**

Send a test from the server to `reflector-fresh@dkim2.com` (sender → the bounce mbox so we can read the result), then inspect the generated reply:

```bash
ssh dkim2 '
mbox=/var/spool/reflector-bounces/mbox; before=$(wc -c < "$mbox")
printf "From: tester@dkim2.com\nTo: reflector-fresh@dkim2.com\nSubject: x\n\nq\n" \
  | sendmail -f reflector-bounces@dkim2.com reflector-fresh@dkim2.com
sleep 40; postqueue -f 2>/dev/null; sleep 3
echo "mbox grew: before=$before after=$(wc -c < "$mbox")"
grep -E "dkim2-reflector\[.*mode=fresh|relay=dkim2-reflect" /var/log/mail.log | tail -3
grep -c "action=generate" "$mbox"'
```
Expected: the reflector logs `mode=fresh` delivered via `relay=dkim2-reflect`; the mbox grew; the captured reply contains `action=generate`.

- [ ] **Step 5: Final confirmation**

Send a real message from a mail account to `reflector-fresh@dkim2.com`; confirm the reply arrives in the **inbox** (not Junk) and validates **Overall: pass** with one `DKIM2-Signature i=1 (m=1)` and one `Message-Instance m=1`, both green.

---

## Self-Review

- **Spec coverage:** Behaviour (Task 2 dispatch + Task 1 origination), generated-message shape (Task 1 `generate`), deliverability (Task 3 steps 4–5 confirm inbox), code approach = separate `generate()` (Task 1), Postfix one-line map (Task 3), testing (Task 1 test group). All spec sections map to a task.
- **Placeholders:** none — all code and commands are concrete.
- **Type consistency:** `generate(%args) -> $text` defined in Task 1, consumed verbatim in Task 2; `_sign`/`_dkim2_info`/`_header_list_for_hash`/`fold_header` are existing names used as-is.
