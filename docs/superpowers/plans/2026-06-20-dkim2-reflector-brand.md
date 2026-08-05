# reflector-brand Delegated Two-Signature Demo — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `reflector-brand@dkim2.com` — when the sender delegates a key via a `dkim2test._domainkey` CNAME, originate a fresh message carrying two DKIM2-Signatures on one Message-Instance (`i=1` as the brand via the delegated key, `i=2` as `dkim2.com`); otherwise send the fresh message with a CNAME-error body.

**Architecture:** Refactor the fresh `generate()` into a reusable message builder + a general signer, then add `generate_brand()` (delegated → two sigs; not → fresh+error) and a live `Net::DNS` CNAME check. Wire `brand` into the wrapper and the pipe-transport map.

**Tech Stack:** Perl 5.20+, `Mail::DKIM2::{Reflector,Signer,MessageInstance,Common}`, `Email::MIME`, `Net::DNS::Resolver`, `POSIX::strftime`; `Test::More` + `DKIM2TestKeys`; Postfix `pipe(8)`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-06-20-dkim2-reflector-brand-design.md`.
- Delegated message: `From: <sender>` (the brand), `To: reflector-brand@<domain>`, `text/plain; charset=utf-8`, CRLF throughout, single `m=1`.
- `i=1`: `d=<sender domain>`, `s=dkim2test`, rsa-sha256, `mf=<sender>`, `rt=reflector-brand@<domain>`, signed with the delegated key. `i=2`: `d=<domain>`, `s=sel1`, rsa-sha256, `mf=reflector-bounces@<domain>`, `rt=<sender>`. Both stamped `m=1`.
- Provenance `X-DKIM2-Info … action=brand` (delegated) — reuse `_dkim2_info`. Not-delegated path is the fresh generator with an error body.
- CNAME target to match: `dkim2test._domainkey.dkim2.com`.
- The production `dkim2test` key is ALREADY on the server (`/etc/dkim2/reflector/dkim2test.key`, nobody:nogroup 0600) and its TXT is published; do not regenerate it.
- Reuse existing helpers; do not duplicate `_dkim2_info`, `_header_list_for_hash`, `fold_header`, `should_skip`.

---

## File Structure

- `brong/lib/Mail/DKIM2/Reflector.pm` — refactor `generate()`; add `_fresh_message_text`, `_sign_with`, `generate_brand`, `_dkim2test_cname_ok`.
- `brong/t/reflector.t` — brand test group.
- `keys/dkim2test._domainkey.test1.dkim2.com.pem` (new) + `dns.json` (regenerated) — test delegation key.
- `deploy/postfix-dkim2-transport` — add the `reflector-brand` route.
- `brong/bin/dkim2-reflector.pl` — add `brand` mode.

---

### Task 1: Refactor generate() into reusable builder + signer

Pure refactor — the existing `fresh:` tests in `reflector.t` are the safety net (behaviour must not change).

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Reflector.pm`

**Interfaces:**
- Produces: `_fresh_message_text(%a) -> $text_with_mi` (keys: `from`, `to`, `subject`, `body`, `now`, `message_id`, `domain`) — message headers + body + `m=1` MI, no signature. `_sign_with($text, %signer_args) -> $sig_header` (keys: `Domain`, `Selector`, `MailFrom`, `RcptTo` arrayref, `Key`/`KeyFile`, `Timestamp`). `generate(%a)` gains an optional `body` arg (defaults to the standard fresh body).

- [ ] **Step 1: Refactor — add the two helpers and rewrite `generate()` in terms of them**

Replace the current `generate()` in `brong/lib/Mail/DKIM2/Reflector.pm` with the following three subs (the `_rfc2822_date` helper above it stays):

```perl
# Low-level: sign $text with explicit Signer args, return the DKIM2-Signature
# header (folded, no trailing CRLF). i= is auto-assigned from existing sigs.
sub _sign_with {
    my ($text, %sa) = @_;
    my $signer = Mail::DKIM2::Signer->new(%sa);
    $signer->PRINT($text); $signer->CLOSE;
    croak "signing failed: " . $signer->result unless $signer->result eq 'signed';
    return $signer->as_string;   # "DKIM2-Signature: ..."
}

# Build a fresh message (headers + body) and prepend its m=1 Message-Instance.
# No signature. Used by generate() and generate_brand().
sub _fresh_message_text {
    my (%a) = @_;
    my $now  = $a{now} // time();
    my $mid  = $a{message_id} // sprintf('<fresh-%d-%d@%s>', $now, $$, $a{domain});
    my $date = _rfc2822_date($now);
    my $text =
        "From: $a{from}\r\n"
      . "To: $a{to}\r\n"
      . "Subject: $a{subject}\r\n"
      . "Date: $date\r\n"
      . "Message-ID: $mid\r\n"
      . "MIME-Version: 1.0\r\n"
      . "Content-Type: text/plain; charset=utf-8\r\n"
      . "\r\n"
      . $a{body};
    my $mi = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($text));
    (my $miv = fold_header("Message-Instance: " . $mi->as_string)) =~ s/^Message-Instance:\s*//;
    return "Message-Instance: $miv\r\n" . $text;
}

# Default explainer body for the fresh generator.
sub _fresh_body {
    my ($domain, $sender, $date) = @_;
    return
        "Hello,\r\n\r\n"
      . "This is a freshly-originated DKIM2 message from $domain, generated\r\n"
      . "because you sent mail to reflector-fresh\@$domain.\r\n\r\n"
      . "Unlike the other reflector addresses, this is NOT a forward of your\r\n"
      . "message: it is a brand-new message with a single Message-Instance (m=1)\r\n"
      . "and a single DKIM2-Signature (i=1), and no forwarding chain.\r\n\r\n"
      . "Paste it into https://$domain/validate/ to see it verify.\r\n\r\n"
      . "Requested by: $sender\r\n"
      . "Generated at: $date\r\n\r\n"
      . "-- \r\n"
      . "The DKIM2 reflector at $domain\r\n";
}

# generate(%args) — ORIGINATE a brand-new single-signature DKIM2 message back to
# the sender (single m=1 + single i=1, no chain), From a <domain> identity.
sub generate {
    my (%a) = @_;
    croak "need a sender" unless $a{sender};
    $a{domain}   //= 'dkim2.com';
    $a{selector} //= 'sel1';
    $a{mailfrom} //= "reflector-bounces\@$a{domain}";
    my $now = $a{now} // time();
    $a{timestamp} //= $now;
    my $body = $a{body} // _fresh_body($a{domain}, $a{sender}, _rfc2822_date($now));

    my $text = _fresh_message_text(
        from => "\"DKIM2 Generator\" <fresh\@$a{domain}>",
        to => $a{sender}, subject => 'Freshly generated DKIM2 message',
        body => $body, now => $now, message_id => $a{message_id}, domain => $a{domain},
    );

    my %sa = (Domain => $a{domain}, Selector => $a{selector},
              MailFrom => $a{mailfrom}, RcptTo => [ $a{sender} ], Timestamp => $a{timestamp});
    $sa{Key} = $a{key} if $a{key};
    $sa{KeyFile} = $a{keyfile} if $a{keyfile} && !$a{key};
    $text = _sign_with($text, %sa) . "\r\n" . $text;

    my ($hc, $hn) = _header_list_for_hash(Email::MIME->new($text));
    (my $xi = fold_header("X-DKIM2-Info: " . _dkim2_info('generate', hc => $hc, hn => $hn))) =~ s/\r?\n\z//;
    return "$xi\r\n" . $text;
}
```

(If the existing `_sign` reflect-helper is unchanged, leave it; this adds `_sign_with` alongside it.)

- [ ] **Step 2: Run the fresh tests to confirm no behaviour change**

Run: `cd brong && perl -I lib -I t/lib t/reflector.t 2>&1 | grep -E "fresh:|not ok" | head`
Expected: all `fresh:` lines `ok`, no `not ok`.

- [ ] **Step 3: Run the full suite**

Run: `cd brong && prove -I lib -I t/lib t/ 2>&1 | tail -3`
Expected: `All tests successful.`

- [ ] **Step 4: Commit**

```bash
git add brong/lib/Mail/DKIM2/Reflector.pm
git commit -m "refactor(reflector): extract _fresh_message_text and _sign_with from generate()

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `generate_brand()` + CNAME check + test key

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Reflector.pm`
- Create: `keys/dkim2test._domainkey.test1.dkim2.com.pem`
- Modify: `dns.json` (regenerated by `builddns.pl`)
- Test: `brong/t/reflector.t`

**Interfaces:**
- Consumes: `_fresh_message_text`, `_sign_with`, `generate`, `_dkim2_info`, `_header_list_for_hash`, `fold_header` (Task 1 + existing).
- Produces: `generate_brand(%a) -> $text` (keys: `sender` (required), `domain`/`selector`/`key`/`keyfile` for the `dkim2.com` i=2 sig, `mailfrom`, `delegated` (bool), `brand_selector` (default `dkim2test`), `brand_key`/`brand_keyfile` for the i=1 sig, `now`, `message_id`). `_dkim2test_cname_ok($domain) -> bool` (live DNS).

- [ ] **Step 1: Create the test delegation key and regenerate dns.json**

```bash
cd /Users/brong/src/interop
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/dkim2test._domainkey.test1.dkim2.com.pem
perl builddns.pl > dns.json.new && mv dns.json.new dns.json
grep -c '"dkim2test._domainkey"' dns.json   # expect >= 1 (under test1.dkim2.com)
```
Expected: the key file exists; `dns.json` now has a `dkim2test._domainkey` entry under `test1.dkim2.com`.

- [ ] **Step 2: Write the failing test** (append to `brong/t/reflector.t`, before `done_testing;`)

```perl
# --- brand: delegated two-signature message on a single MI ---
{
    my %common_brand = (
        sender   => 'brand@test1.dkim2.com',     # the brand
        domain   => 'test2.dkim2.com',           # the dkim2.com-role signer
        selector => 'sel1',
        key      => DKIM2TestKeys::private_key('test2.dkim2.com', 'sel1'),
        mailfrom => 'reflector-bounces@test2.dkim2.com',
        brand_selector => 'dkim2test',
        brand_key => DKIM2TestKeys::private_key('test1.dkim2.com', 'dkim2test'),
        now => 1740000000, message_id => '<brand-test@test2.dkim2.com>',
    );

    # delegated -> two signatures, one MI, verifies
    my $msg = Mail::DKIM2::Reflector::generate_brand(%common_brand, delegated => 1);
    my $em = Email::MIME->new($msg);
    is($em->header('From'), 'brand@test1.dkim2.com', 'brand: From is the brand');
    is($em->header('To'), 'reflector-brand@test2.dkim2.com', 'brand: To is reflector-brand');
    my @sigs = $em->header_raw('DKIM2-Signature');
    my @mis  = $em->header_raw('Message-Instance');
    is(scalar @sigs, 2, 'brand: two signatures');
    is(scalar @mis, 1, 'brand: one Message-Instance');
    like($msg, qr/^X-DKIM2-Info:.*action=brand/ms, 'brand: X-DKIM2-Info action=brand');
    like("@sigs", qr/\bd=test1\.dkim2\.com\b/, 'brand: i=1 signs as the brand domain');
    like("@sigs", qr/\bd=test2\.dkim2\.com\b/, 'brand: i=2 signs as dkim2.com role');
    is(reflected_verifies($msg), 'pass', 'brand: two-sig message verifies (chain of custody ok)');

    # not delegated -> fresh style with an error body, single signature
    my $err = Mail::DKIM2::Reflector::generate_brand(%common_brand, delegated => 0);
    my $eem = Email::MIME->new($err);
    is(scalar($eem->header_raw('DKIM2-Signature')), 1, 'brand(no cname): single signature');
    like($eem->header('From'), qr/<fresh\@test2\.dkim2\.com>/, 'brand(no cname): fresh From identity');
    like($err, qr/dkim2test\._domainkey/, 'brand(no cname): body explains the missing CNAME');
}
```

Note: `is(scalar($eem->header_raw(...)), 1, ...)` — `header_raw` in scalar context returns the first value, so assign to an array if a count is needed; here we just need "exactly one", and there is exactly one, so the scalar (the value) is truthy-checked by the structure — to be safe, the delegated case uses `my @sigs = ...; scalar @sigs`.

- [ ] **Step 3: Run to verify it fails**

Run: `cd brong && perl -I lib -I t/lib t/reflector.t 2>&1 | grep -E "brand:|not ok|Undefined" | head`
Expected: FAIL — `Undefined subroutine &Mail::DKIM2::Reflector::generate_brand`.

- [ ] **Step 4: Implement `generate_brand` and `_dkim2test_cname_ok`** (add after `generate` in `Reflector.pm`)

```perl
# Domain part of an email address.
sub _addr_domain { my ($a) = @_; $a =~ /\@([^>]+?)>?\s*$/ ? $1 : $a }

# True iff dkim2test._domainkey.$domain is a CNAME to dkim2test._domainkey.dkim2.com.
# Live DNS (kept out of generate_brand so the message logic is testable offline).
sub _dkim2test_cname_ok {
    my ($domain) = @_;
    require Net::DNS::Resolver;
    my $r = Net::DNS::Resolver->new;
    my $q = $r->query("dkim2test._domainkey.$domain", 'CNAME') or return 0;
    for my $rr ($q->answer) {
        next unless $rr->type eq 'CNAME';
        (my $t = $rr->cname) =~ s/\.\z//;
        return 1 if lc($t) eq 'dkim2test._domainkey.dkim2.com';
    }
    return 0;
}

# generate_brand(%args) — the reflector-brand behaviour. With delegated=1, build a
# fresh message From the brand and sign it twice (i=1 as the brand via the
# delegated key, i=2 as <domain>). With delegated=0, fall back to the fresh
# generator carrying a CNAME-setup error body.
sub generate_brand {
    my (%a) = @_;
    croak "need a sender" unless $a{sender};
    $a{domain}   //= 'dkim2.com';
    $a{selector} //= 'sel1';
    $a{mailfrom} //= "reflector-bounces\@$a{domain}";
    $a{brand_selector} //= 'dkim2test';
    my $now = $a{now} // time();
    my $bd  = _addr_domain($a{sender});

    unless ($a{delegated}) {
        my $err =
            "Hello,\r\n\r\n"
          . "You asked for the DKIM2 brand demo, but dkim2test._domainkey.$bd is not\r\n"
          . "a CNAME to dkim2test._domainkey.$a{domain}. Publish that CNAME and try\r\n"
          . "again to get a brand-signed (two-signature) message.\r\n\r\n"
          . "In the meantime, here is a plain freshly-generated DKIM2 message.\r\n\r\n"
          . "-- \r\n"
          . "The DKIM2 reflector at $a{domain}\r\n";
        return generate(sender => $a{sender}, domain => $a{domain}, selector => $a{selector},
                        key => $a{key}, keyfile => $a{keyfile}, mailfrom => $a{mailfrom},
                        now => $now, message_id => $a{message_id}, body => $err);
    }

    my $rcpt = "reflector-brand\@$a{domain}";
    my $body =
        "Hello,\r\n\r\n"
      . "This is a brand-signed DKIM2 message. It is freshly originated (a single\r\n"
      . "Message-Instance, m=1) but carries TWO DKIM2-Signatures:\r\n\r\n"
      . "  i=1  d=$bd  (signed with the key you delegated via the\r\n"
      . "       dkim2test._domainkey.$bd CNAME to dkim2test._domainkey.$a{domain})\r\n"
      . "  i=2  d=$a{domain}  (the platform hop out to you)\r\n\r\n"
      . "Paste it into https://$a{domain}/validate/ to see both signatures verify.\r\n\r\n"
      . "-- \r\n"
      . "The DKIM2 reflector at $a{domain}\r\n";

    my $text = _fresh_message_text(
        from => $a{sender}, to => $rcpt, subject => 'Brand-signed DKIM2 message',
        body => $body, now => $now, message_id => $a{message_id}, domain => $a{domain},
    );

    # i=1: sign AS the brand using the delegated key.
    my %b = (Domain => $bd, Selector => $a{brand_selector},
             MailFrom => $a{sender}, RcptTo => [ $rcpt ], Timestamp => $now);
    $b{Key} = $a{brand_key} if $a{brand_key};
    $b{KeyFile} = $a{brand_keyfile} if $a{brand_keyfile} && !$a{brand_key};
    $text = _sign_with($text, %b) . "\r\n" . $text;

    # i=2: the dkim2.com hop out to the sender.
    my %d = (Domain => $a{domain}, Selector => $a{selector},
             MailFrom => $a{mailfrom}, RcptTo => [ $a{sender} ], Timestamp => $now);
    $d{Key} = $a{key} if $a{key};
    $d{KeyFile} = $a{keyfile} if $a{keyfile} && !$a{key};
    $text = _sign_with($text, %d) . "\r\n" . $text;

    my ($hc, $hn) = _header_list_for_hash(Email::MIME->new($text));
    (my $xi = fold_header("X-DKIM2-Info: " . _dkim2_info('brand', hc => $hc, hn => $hn))) =~ s/\r?\n\z//;
    return "$xi\r\n" . $text;
}
```

- [ ] **Step 5: Run the brand tests**

Run: `cd brong && perl -I lib -I t/lib t/reflector.t 2>&1 | grep -E "brand:|not ok" | head -20`
Expected: all `brand:` lines `ok`, no `not ok`.

- [ ] **Step 6: Run the full suite**

Run: `cd brong && prove -I lib -I t/lib t/ 2>&1 | tail -3`
Expected: `All tests successful.`

- [ ] **Step 7: Commit**

```bash
git add brong/lib/Mail/DKIM2/Reflector.pm brong/t/reflector.t keys/dkim2test._domainkey.test1.dkim2.com.pem dns.json
git commit -m "feat(reflector): generate_brand() — delegated two-signature brand message

i=1 signs as the brand via the delegated dkim2test key, i=2 as the platform,
on one Message-Instance. Falls back to the fresh generator with a CNAME-error
body when not delegated. Live CNAME check in _dkim2test_cname_ok.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: `brand` mode in the wrapper

**Files:**
- Modify: `brong/bin/dkim2-reflector.pl`
- Test: `brong/t/reflector-cli.t`

**Interfaces:**
- Consumes: `generate_brand`, `_dkim2test_cname_ok` (Task 2).

- [ ] **Step 1: Write the failing test** (append to `brong/t/reflector-cli.t`, before `done_testing;`)

```perl
like($src, qr/\bbrand\b/, 'wrapper knows the brand mode');
like($src, qr/generate_brand/, 'wrapper dispatches to generate_brand()');
like($src, qr/_dkim2test_cname_ok/, 'wrapper does the delegation CNAME check');
like($src, qr{/etc/dkim2/reflector/dkim2test\.key}, 'wrapper uses the delegated dkim2test key');
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd brong && perl -I lib -I t/lib t/reflector-cli.t 2>&1 | tail -6`
Expected: the four new checks `not ok`.

- [ ] **Step 3: Implement the dispatch**

In `brong/bin/dkim2-reflector.pl`: add `brand` to the valid set —
```perl
my %VALID_MODE = map { $_ => 1 } qw(raw subject body both redacted damage fresh brand);
```
and add a `brand` branch to the dispatch `eval` (alongside the existing `fresh` branch, before the `reflect()` else):
```perl
    } elsif ($mode eq 'brand') {
        my ($bd = $sender) =~ s/.*\@//;
        my $delegated = Mail::DKIM2::Reflector::_dkim2test_cname_ok($bd);
        my $msg = Mail::DKIM2::Reflector::generate_brand(
            sender   => $sender,
            domain   => 'dkim2.com',
            selector => 'sel1',
            keyfile  => '/etc/dkim2/reflector/sel1.key',
            mailfrom => 'reflector-bounces@dkim2.com',
            delegated      => $delegated,
            brand_selector => 'dkim2test',
            brand_keyfile  => '/etc/dkim2/reflector/dkim2test.key',
        );
        { message => $msg, signed => ($delegated ? 1 : 1), basis => ($delegated ? 'brand' : 'origin'), mode => 'brand' };
```
(The `my ($bd = $sender) =~ ...` is not valid Perl — write it as two statements: `my $bd = $sender; $bd =~ s/.*\@//;`.)

- [ ] **Step 4: Compile + cli test**

Run: `cd brong && perl -c -I lib bin/dkim2-reflector.pl 2>&1 | tail -1 && perl -I lib -I t/lib t/reflector-cli.t 2>&1 | tail -6`
Expected: `syntax OK`; all cli checks `ok`.

- [ ] **Step 5: Commit**

```bash
git add brong/bin/dkim2-reflector.pl brong/t/reflector-cli.t
git commit -m "feat(reflector): wrapper 'brand' mode — CNAME check + generate_brand()

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Postfix route + deploy + smoke test

**Files:**
- Modify: `deploy/postfix-dkim2-transport`
- Server: `/etc/postfix/dkim2-transport`

The `dkim2test` signing key is already installed on the server (do not regenerate).

- [ ] **Step 1: Add the route to the committed map**

Append to `deploy/postfix-dkim2-transport` (after the `reflector-fresh` line):
```
reflector-brand@dkim2.com    dkim2-reflect:
```

- [ ] **Step 2: Commit + push**

```bash
git add deploy/postfix-dkim2-transport
git commit -m "feat(reflector): route reflector-brand via the pipe transport

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push origin master
```

- [ ] **Step 3: Deploy**

```bash
ssh dkim2 'set -e
cd /root/interop && git pull --ff-only
cd brong && perl Makefile.PL >/dev/null 2>&1 && make >/dev/null 2>&1 && make install 2>&1 | grep -E "Installing.*Reflector" || true
cd /root/interop
install -m 755 brong/bin/dkim2-reflector.pl /usr/local/bin/dkim2-reflect
install -m 644 deploy/postfix-dkim2-transport /etc/postfix/dkim2-transport
postmap /etc/postfix/dkim2-transport
postfix reload
echo "brand route:"; postmap -q reflector-brand@dkim2.com hash:/etc/postfix/dkim2-transport
perl -c /usr/local/bin/dkim2-reflect 2>&1 | tail -1'
```
Expected: `Reflector.pm` reinstalled; `postmap -q` prints `dkim2-reflect:`; wrapper `syntax OK`.

- [ ] **Step 4: Smoke test the not-delegated path (no CNAME needed)**

Send from a domain with no `dkim2test` CNAME and confirm the error-fresh reply:
```bash
ssh dkim2 '
mbox=/var/spool/reflector-bounces/mbox; before=$(wc -c < "$mbox")
printf "From: nobody@example.com\nTo: reflector-brand@dkim2.com\nSubject: x\n\nq\n" \
  | sendmail -f reflector-bounces@dkim2.com reflector-brand@dkim2.com
sleep 40; postqueue -f 2>/dev/null; sleep 3
echo "mbox grew: before=$before after=$(wc -c < "$mbox")"
grep -E "dkim2-reflector\[.*mode=brand|relay=dkim2-reflect" /var/log/mail.log | tail -2
last=$(grep -n "^From " "$mbox" | tail -1 | cut -d: -f1); sed -n "${last},\$p" "$mbox" | grep -iE "action=generate|dkim2test._domainkey|^DKIM2-Signature: i=" | head'
```
Expected: `mode=brand` via `relay=dkim2-reflect`; the captured reply has one signature and a body mentioning `dkim2test._domainkey` (the CNAME error).

- [ ] **Step 5: Final delegated confirmation (needs the brand CNAME live)**

Once `dkim2test._domainkey.brong.net` CNAME is published: send a real message from `brong@brong.net` to `reflector-brand@dkim2.com`. Paste the reply into `https://dkim2.com/validate/`. Expected: **Overall: pass**, `DKIM2-Signature i=2 (m=1)` pass, `DKIM2-Signature i=1 (m=1)` pass (d=brong.net, chain-of-custody ok), `Message-Instance m=1` pass. (Likely lands in Junk — `From: brong.net` fails classic DMARC — which is expected.)

---

## Self-Review

- **Spec coverage:** flow + CNAME gate (Task 2 `generate_brand`/`_dkim2test_cname_ok`, Task 3 wrapper), two-signature delegated message (Task 2), not-delegated fresh+error (Task 2), keys/DNS (already done + test key in Task 2 step 1), Postfix route (Task 4), testing (Task 2 steps 2/5; Task 4 smoke). All mapped.
- **Placeholders:** none — all code/commands concrete. Two inline Perl-gotcha notes (scalar `header_raw`, the `my (...) =~` split) are called out so the implementer writes valid code.
- **Type consistency:** `generate_brand`/`_dkim2test_cname_ok`/`_fresh_message_text`/`_sign_with` names and arg keys match between Task 1 (definitions), Task 2 (definitions + test), and Task 3 (wrapper consumption). `brand_keyfile`/`brand_selector` used consistently.
