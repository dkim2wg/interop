# DKIM2 reflector-delayedbounce / Postfix bounce signing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Postfix DKIM2-sign the (delayed) bounces it originates itself, and add `reflector-delayedbounce@dkim2.com` as a live demo that produces a real, signed, verifiable bounce.

**Architecture:** A message to `reflector-delayedbounce@` is accepted then routed to Postfix's built-in `error:` transport, so `bounce(8)` originates a real `multipart/report` DSN (`MAIL FROM <>`). `internal_mail_filter_classes = bounce` plus an outbound-only `non_smtpd_milters` passes that DSN through our outbound DKIM2 milter, which we teach to origin-sign null-sender messages (`m=1`, `i=1`, `mf=<>`). The signing logic lives in two parallel, kept-in-sync codepaths — the deployed `bin/dkim2-milter.pl` and the unit-tested `Mail::Milter::Authentication::Handler::DKIM2Sign` — so both are changed together.

**Tech Stack:** Perl 5.20+, `Mail::DKIM2::*` (CryptX only), `Sendmail::PMilter` (deployed milter), `Mail::Milter::Authentication` handler framework (tested milter), `Test::More`/`prove`, Postfix.

## Global Constraints

- Target spec: **draft-ietf-dkim-dkim2-spec-02** (`spec/draft-ietf-dkim-dkim2-spec-02.txt`); §11 governs DSNs.
- EXPERIMENTAL — not for production; do not weaken that framing in any doc.
- No new CPAN dependencies (crypto is CryptX only).
- Null sender is represented as the literal string `'<>'` at the Signer API (NOT empty string). `'<>'` base64-encodes to `PD4=`; the verifier skips `d=`/`mf=` alignment when `mf` decodes to `'<>'`.
- Tests run **from the `brong/` directory** (they `use lib 'lib'; use lib 't/lib'`). Shared keys live in `keys/`, DNS in `dns.json`; test domains with keys: `test1.dkim2.com`, `test2.dkim2.com` (selector `rsa1024`).
- Header folding rules in `brong/CLAUDE.md` are binding: never refold a header once it is in the message.
- The deployed milter is `bin/dkim2-milter.pl` (per `deploy/dkim2-milter-outbound.service`). `DKIM2Sign.pm` is not deployed but is kept in sync and is the only unit-testable signing path.

---

### Task 1: Library contract — null `MailFrom` round-trips to `mf=<>` and verifies

Characterise (and, if broken, fix) the library behaviour the milter change depends on: signing an origin message with `MailFrom => '<>'` yields a `DKIM2-Signature` whose `mf` decodes to `<>`, whose `rt` decodes to the recipient, and which the verifier passes. `Mail::DKIM2::DSN` already relies on this (see `t/dsn.t`), so the test is expected to PASS as-is; the fix steps apply only if it does not.

**Files:**
- Test: `brong/t/null-mailfrom.t` (create)
- (only if test fails) Modify: `brong/lib/Mail/DKIM2/Signature.pm`, `brong/lib/Mail/DKIM2/Verifier.pm`

**Interfaces:**
- Consumes: `Mail::DKIM2::Signer->new(Domain,Selector,Key,MailFrom,RcptTo,Timestamp)`, `Mail::DKIM2::MessageInstance->calculate($email_mime)`, `Mail::DKIM2::Verifier`, `DKIM2TestKeys::private_key`/`pubkey_callback`, `Mail::DKIM2::Signature->mail_from`/`rcpt_to`.
- Produces: the verified contract "null `MailFrom` ⇒ `mf=<>`, verifier `pass`" that Task 2 relies on.

- [ ] **Step 1: Write the test**

Create `brong/t/null-mailfrom.t`:

```perl
#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More;
use lib 'lib';
use lib 't/lib';
use Email::MIME;
use Mail::DKIM2::Signer;
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Verifier;
use Mail::DKIM2::Signature;
use DKIM2TestKeys;

my $TS = 1740000000;

# A fresh origin message signed with a null envelope sender, as a
# Postfix-generated bounce/DSN would be.
my $raw = "From: Mail Delivery System <MAILER-DAEMON\@test1.dkim2.com>\r\n"
        . "To: sender\@origin.example\r\n"
        . "Subject: Undelivered Mail Returned to Sender\r\n"
        . "\r\n"
        . "delivery failed\r\n";

my $mi = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($raw));
my $with_mi = "Message-Instance: " . $mi->as_string . "\r\n" . $raw;

my $signer = Mail::DKIM2::Signer->new(
    Domain    => 'test1.dkim2.com',
    Selector  => 'rsa1024',
    Key       => DKIM2TestKeys::private_key('test1.dkim2.com', 'rsa1024'),
    MailFrom  => '<>',
    RcptTo    => ['sender@origin.example'],
    Timestamp => $TS,
);
$signer->PRINT($with_mi);
$signer->CLOSE;
is($signer->result, 'signed', 'null-MailFrom message signs');

my $sig_hdr = $signer->as_string;
my $signed  = $sig_hdr . "\r\n" . $with_mi;

# Parse the signature and confirm mf=<> and rt=recipient.
(my $sig_only = $sig_hdr) =~ s/^DKIM2-Signature:\s*//s;
my $sig = Mail::DKIM2::Signature->parse($sig_only);
is($sig->mail_from, '<>', 'mf decodes to <>');
is_deeply($sig->rcpt_to, ['sender@origin.example'], 'rt decodes to recipient');

my $v = Mail::DKIM2::Verifier->new;
$v->set_pubkey_callback(DKIM2TestKeys::pubkey_callback());
$v->PRINT($signed);
$v->CLOSE;
is($v->result, 'pass', 'null-MailFrom signed message verifies pass');

done_testing;
```

- [ ] **Step 2: Run the test**

Run: `cd /Users/brong/src/interop/brong && prove -lv t/null-mailfrom.t`
Expected: PASS (this characterises existing library behaviour that `Mail::DKIM2::DSN` already uses).

- [ ] **Step 2a (only if Step 2 FAILS): fix the library**

If `mf` is not `<>`: in `brong/lib/Mail/DKIM2/Signature.pm`, ensure a `MailFrom` of `'<>'` is encoded verbatim (`encode_base64('<>','')` → `PD4=`) rather than dropped.
If verification fails on alignment: in `brong/lib/Mail/DKIM2/Verifier.pm`, confirm the guard `if ($mf && $mf ne '<>')` (around line 308) skips alignment for the null sender; widen it to also skip when `$mf` is empty.
Re-run Step 2 until PASS. (If the `Signature->parse` API name differs, adjust the test to the actual accessor used in `t/dsn.t`.)

- [ ] **Step 3: Commit**

```bash
cd /Users/brong/src/interop
git add brong/t/null-mailfrom.t brong/lib/Mail/DKIM2/Signature.pm brong/lib/Mail/DKIM2/Verifier.pm
git commit -m "test: lock null-MailFrom => mf=<> verify contract for bounce signing"
```
(If no library files changed, only `git add brong/t/null-mailfrom.t`.)

---

### Task 2: Sign null-sender (bounce) messages in the milter

Teach both signing codepaths to sign a `MAIL FROM <>` message by deriving the signing domain from the `From:` header (gated on a held key) and emitting `mf=<>`. TDD through the unit-testable handler; mirror the identical change into the deployed standalone milter.

**Files:**
- Modify: `brong/lib/Mail/Milter/Authentication/Handler/DKIM2Sign.pm` (handler, tested)
- Modify: `brong/bin/dkim2-milter.pl` (deployed standalone — `_get_sign_config`, `_do_sign`, `cb_eom`)
- Test: `brong/t/milter.t` (extend `run_sign`; add bounce-signing tests)

**Interfaces:**
- Consumes: Task 1's null-`MailFrom` contract; existing `run_sign($raw,%opts)` harness; `DKIM2TestKeys::private_key_pem`.
- Produces: a milter that, for an internally-injected null-sender message whose `From:` domain has a key, prepends `Message-Instance: m=1` and `DKIM2-Signature: i=1` with `d=<from-domain>`, `mf=PD4=` (`<>`), `rt=<original sender>`.

- [ ] **Step 1: Make `run_sign` accept a custom envelope**

In `brong/t/milter.t`, change `run_sign` so the envelope sender/recipient are overridable (default unchanged). Replace the config build and the two hardcoded envelope calls:

```perl
sub run_sign {
    my ($raw, %opts) = @_;
    my $env_from = exists $opts{env_from} ? delete $opts{env_from} : '<sender@test1.dkim2.com>';
    my $env_rcpt = exists $opts{env_rcpt} ? delete $opts{env_rcpt} : '<recipient@test2.dkim2.com>';
    my $config = {
        domains => {},
        sign_authenticated => 1,
        sign_local => 1,
        add_message_instance => 1,
        record_smtp_params => 1,
        snapshot_directory => undef,
        _authenticated => 1,
        %opts,
    };
    # ... (unchanged handler construction + header parsing) ...
    $handler->envfrom_callback($env_from);
    $handler->envrcpt_callback($env_rcpt);
    # ... (unchanged: header_callback loop, eoh, body, eom, addheader) ...
}
```

(Keep the rest of `run_sign` exactly as-is; only the two `envfrom_callback`/`envrcpt_callback` argument values and the new `delete`d options change.)

- [ ] **Step 2: Write the failing tests**

Add to `brong/t/milter.t` (after the existing sign tests):

```perl
# Bounce signing: a Postfix-style null-sender DSN gets origin-signed.
{
    my $raw = join("\r\n",
        'From: Mail Delivery System <MAILER-DAEMON@test1.dkim2.com>',
        'To: sender@origin.example',
        'Subject: Undelivered Mail Returned to Sender',
        'Content-Type: multipart/report; report-type=delivery-status; boundary="B"',
        'MIME-Version: 1.0',
        '',
        '--B',
        'Content-Type: text/plain',
        '',
        'This is the mail system. Delivery permanently failed.',
        '--B',
        'Content-Type: message/delivery-status',
        '',
        'Reporting-MTA: dns; mail.test1.dkim2.com',
        'Action: failed',
        'Status: 5.1.1',
        '--B',
        'Content-Type: message/rfc822',
        '',
        'From: orig@elsewhere.example',
        'Subject: greetings',
        '',
        'hello',
        '--B--',
        '');

    my ($handler, $mock) = run_sign($raw,
        env_from => '<>',
        env_rcpt => '<sender@origin.example>',
        domains  => {
            'test1.dkim2.com' => {
                selector => 'rsa1024',
                key => DKIM2TestKeys::private_key_pem('test1.dkim2.com', 'rsa1024'),
            },
        },
    );

    my @pre = @{$mock->{pre_headers}};
    my @dk2 = grep { $_->{field} eq 'DKIM2-Signature' } @pre;
    ok(@dk2 > 0, "bounce: DKIM2-Signature added for null sender");
    my $sig = $dk2[0]->{value};
    like($sig, qr/i=1/,                  "bounce: i=1");
    like($sig, qr/d=test1\.dkim2\.com/,  "bounce: d= from From: header");
    like($sig, qr/mf=PD4=/,              "bounce: mf=<> (base64 PD4=)");
    my @mi = grep { $_->{field} eq 'Message-Instance' } @pre;
    ok(@mi > 0, "bounce: Message-Instance m=1 added");
    like($mi[0]->{value}, qr/m=1/, "bounce: MI is m=1");
}

# Negative: null sender whose From: domain has no key is left unsigned.
{
    my $raw = join("\r\n",
        'From: Mail Delivery System <MAILER-DAEMON@unknown.example>',
        'To: sender@origin.example',
        'Subject: bounce',
        '', 'x', '');
    my ($handler, $mock) = run_sign($raw,
        env_from => '<>',
        env_rcpt => '<sender@origin.example>',
        domains  => {
            'test1.dkim2.com' => {
                selector => 'rsa1024',
                key => DKIM2TestKeys::private_key_pem('test1.dkim2.com', 'rsa1024'),
            },
        },
    );
    my @dk2 = grep { $_->{field} eq 'DKIM2-Signature' } @{$mock->{pre_headers}};
    is(scalar @dk2, 0, "bounce: unknown From: domain not signed");
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /Users/brong/src/interop/brong && prove -lv t/milter.t`
Expected: the new "bounce: DKIM2-Signature added for null sender" assertion FAILS (no signature added, because `sign_domain` is undef for `<>`).

- [ ] **Step 4: Implement the handler change**

In `brong/lib/Mail/Milter/Authentication/Handler/DKIM2Sign.pm`, in `addheader_callback`, replace the signing-domain block:

```perl
    # Determine the signing domain from the envelope sender.
    my $env_from = $self->{'env_from'} || '';
    $env_from =~ s/^<//;
    $env_from =~ s/>$//;
    my $sign_domain;
    if ( $env_from =~ /\@(.+)$/ ) {
        $sign_domain = lc $1;
    }
    # Null sender (MAIL FROM <>) — e.g. a Postfix-generated bounce/DSN. There is
    # no envelope domain to sign for, so fall back to the From: header domain
    # (typically MAILER-DAEMON@<host>). We only sign if it resolves to a key,
    # i.e. it is genuinely one of our own bounces.
    if ( !$sign_domain && $env_from eq '' ) {
        $sign_domain = $self->_from_header_domain();
    }
    return unless $sign_domain;
```

Change the `MailFrom` assignment (the `... = $env_from if $env_from;` line) to:

```perl
        $signer_args{MailFrom} = ( $env_from ne '' ) ? $env_from : '<>';
```

Add the helper (near the other private subs, e.g. before `_get_sign_config`):

```perl
# Domain of the From: header (lower-cased) from the stored raw header chunks,
# or undef. Used to pick a signing domain for null-sender bounces/DSNs.
sub _from_header_domain {
    my ($self) = @_;
    for my $h ( @{ $self->{'headers'} || [] } ) {
        next unless $h =~ /^From:/i;
        return lc $1 if $h =~ /\@([\w.-]+)/;
        last;
    }
    return;
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/brong/src/interop/brong && prove -lv t/milter.t`
Expected: PASS, including both new blocks. If `mf=PD4=` is absent but a `mf=` (empty) appears, the `MailFrom => '<>'` assignment did not take effect — recheck Step 4.

- [ ] **Step 6: Mirror the change into the deployed milter**

In `brong/bin/dkim2-milter.pl`:

(a) `_get_sign_config` — accept a From-domain fallback. Replace its first lines:

```perl
sub _get_sign_config {
    my ($env_from, $from_domain_fallback) = @_;
    my ($from_domain) = ($env_from || '') =~ /\@(.+)$/;
    # Null sender (bounce/DSN): no envelope domain — fall back to the From:
    # header domain so our own Postfix-generated bounces still get signed.
    $from_domain = $from_domain_fallback
        if (!$from_domain && defined $from_domain_fallback && length $from_domain_fallback);
    return unless $from_domain;
    $from_domain = lc($from_domain);
    # ... rest of sub unchanged ...
```

(b) In `cb_eom`, extract the From: domain BEFORE the `_get_sign_config` call and pass it in. Replace `my $sign_config = _get_sign_config($priv->{env_from});` with:

```perl
            # From: domain — needed for the null-sender signing fallback and for
            # alignment logging below.
            my $from_hdr_domain = '';
            for my $hdr (@{$priv->{headers}}) {
                if (lc($hdr->[0]) eq 'from') {
                    ($from_hdr_domain) = $hdr->[1] =~ /\@([\w.-]+)/;
                    $from_hdr_domain = lc($from_hdr_domain // '');
                    last;
                }
            }
            my $sign_config = _get_sign_config($priv->{env_from}, $from_hdr_domain);
```

Then delete the now-duplicate `$from_hdr_domain` extraction loop that currently sits inside the `if ($sign_config)` block (the `my $from_hdr_domain = '';` ... `last; } }` block used only for alignment logging), since `$from_hdr_domain` is now already in scope.

(c) `_do_sign` — emit `mf=<>` for a null sender. Change the `MailFrom => $priv->{env_from},` line in the `Mail::DKIM2::Signer->new(...)` call to:

```perl
        MailFrom  => ( length($priv->{env_from} // '') ? $priv->{env_from} : '<>' ),
```

- [ ] **Step 7: Compile-check the deployed milter**

Run: `cd /Users/brong/src/interop/brong && perl -c -Ilib bin/dkim2-milter.pl`
Expected: `bin/dkim2-milter.pl syntax OK`.

- [ ] **Step 8: Run the full brong test suite (no regressions)**

Run: `cd /Users/brong/src/interop/brong && prove -l t/`
Expected: all tests PASS.

- [ ] **Step 9: Commit**

```bash
cd /Users/brong/src/interop
git add brong/lib/Mail/Milter/Authentication/Handler/DKIM2Sign.pm brong/bin/dkim2-milter.pl brong/t/milter.t
git commit -m "milter: origin-sign null-sender bounces (From: domain fallback, mf=<>)"
```

---

### Task 3: Postfix deploy artifacts

Add the routing map that turns `reflector-delayedbounce@` into a genuine delayed bounce, and the two `main.cf` settings that make Postfix's own bounces flow through the outbound signing milter. Config only — verification is by `postconf`/`postmap`, not a unit test.

**Files:**
- Create: `deploy/postfix-dkim2-delayedbounce`
- Modify: `deploy/postfix-main.cf.patch`

**Interfaces:**
- Consumes: the outbound milter socket `unix:var/run/dkim2-milter-out.sock`.
- Produces: deploy artifacts referenced by Task 4's docs.

- [ ] **Step 1: Create the routing map**

Create `deploy/postfix-dkim2-delayedbounce`:

```text
# DKIM2 delayed-bounce demo address.
#
# reflector-delayedbounce@dkim2.com is accepted at RCPT, then deliberately
# fails delivery so that Postfix's own bounce(8) originates a real DSN. That
# DSN is then DKIM2-signed by the outbound milter (see main.cf:
# internal_mail_filter_classes = bounce). This demonstrates draft-02 §11 with a
# genuinely Postfix-generated bounce — NOT the hand-built reflector-dsn path.
#
# This map is referenced by BOTH:
#   transport_maps       - route the recipient to the error: transport so a
#                          permanent failure (and thus a bounce) is generated.
#   local_recipient_maps - so the address is accepted at RCPT TO (the value's
#                          key is all that matters for acceptance).
#
# Install:
#   cp deploy/postfix-dkim2-delayedbounce /etc/postfix/dkim2-delayedbounce
#   postmap /etc/postfix/dkim2-delayedbounce
# Append "hash:/etc/postfix/dkim2-delayedbounce" to BOTH transport_maps and
# local_recipient_maps in main.cf, then: postfix reload
reflector-delayedbounce@dkim2.com  error:5.1.1 DKIM2 delayed-bounce demo: address intentionally undeliverable; this triggers a Postfix-generated, milter-signed DKIM2 bounce
```

- [ ] **Step 2: Add the bounce-signing settings to the main.cf patch**

In `deploy/postfix-main.cf.patch`, append (and reconcile `non_smtpd_milters` to outbound-only — the operative split config lives in `SERVER.md`, but record the bounce-signing intent here):

```text
# --- DKIM2 delayed-bounce signing (draft-02 §11) ---
# Run non_smtpd_milters (and content filters) on Postfix-originated bounce
# messages so the outbound DKIM2 milter signs them. Off by default.
internal_mail_filter_classes = bounce

# Internally-injected mail (bounces, local submissions) must hit ONLY the
# outbound (signing) milter — never the inbound (verify + MI-stamp) milter,
# which would otherwise add Authentication-Results and a spurious
# Message-Instance to the bounce before it is signed. Inbound DSNs from
# outside still reach the inbound milter via smtpd_milters on port 25.
non_smtpd_milters = unix:var/run/dkim2-milter-out.sock

# Route the demo address to a permanent failure (generates a real bounce) and
# accept it at RCPT. (hash:/etc/postfix/dkim2-delayedbounce — see that file.)
transport_maps = hash:/etc/postfix/dkim2-transport, hash:/etc/postfix/dkim2-delayedbounce
local_recipient_maps = $alias_maps, hash:/etc/postfix/dkim2-transport, hash:/etc/postfix/dkim2-delayedbounce
```

(If `transport_maps`/`local_recipient_maps` already appear in the patch with the `dkim2-transport` map, add `hash:/etc/postfix/dkim2-delayedbounce` to the existing line instead of duplicating it.)

- [ ] **Step 3: Verify the map syntax locally**

Run: `postmap -q reflector-delayedbounce@dkim2.com hash:deploy/postfix-dkim2-delayedbounce 2>/dev/null || awk 'NF && $1!~/^#/' deploy/postfix-dkim2-delayedbounce`
Expected: prints the `error:5.1.1 …` value (or, without a local Postfix, the single non-comment line). Confirms exactly one routable entry.

- [ ] **Step 4: Commit**

```bash
cd /Users/brong/src/interop
git add deploy/postfix-dkim2-delayedbounce deploy/postfix-main.cf.patch
git commit -m "deploy: reflector-delayedbounce routing + bounce-signing Postfix config"
```

---

### Task 4: Docs and mailing-list recipe

Document the operator recipe (the substance of the list reply) and register the new demo address everywhere the other reflector addresses appear.

**Files:**
- Modify: `deploy/SERVER.md`, `deploy/README.md`, `deploy/reflector-aliases`, `docs/dkim2-implementer-guide.md`

**Interfaces:**
- Consumes: Task 2's milter behaviour and Task 3's config artifacts.
- Produces: copy-pasteable "sign Postfix-generated DKIM2 bounces" recipe + address registration.

- [ ] **Step 1: Add the operator recipe to SERVER.md**

In `deploy/SERVER.md`, add a section "Signing Postfix-generated (delayed) DKIM2 bounces" containing:
- Why: Postfix runs no milters on its own bounces by default; a delayed bounce (`bounce(8)`, `MAIL FROM <>`) would otherwise go out unsigned.
- The recipe: `internal_mail_filter_classes = bounce`; `non_smtpd_milters = unix:var/run/dkim2-milter-out.sock` (outbound-only, and why); the `dkim2-delayedbounce` map appended to `transport_maps` + `local_recipient_maps`.
- The milter requirement: the outbound milter signs null-sender messages by falling back to the `From:` header domain and emitting `mf=<>` (Task 2) — so any operator using the stock `bin/dkim2-milter.pl` gets this automatically.
- §11 notes/limits: DSN addressed to the envelope `MAIL FROM` (= top `mf=`); DSN's own `mf=<>` (can't bounce a bounce); embedded-original verification is receiver-side and may not hold if Postfix truncates the body.

- [ ] **Step 2: Register the demo address**

- `deploy/README.md`: add `reflector-delayedbounce@dkim2.com` to the reflector address list with a one-line description ("accept-then-bounce; demonstrates a Postfix-originated, DKIM2-signed delayed bounce").
- `deploy/reflector-aliases`: extend the header comment to mention that `reflector-delayedbounce` is delivered via the `error:` transport (the `dkim2-delayedbounce` map), not the `dkim2-reflect` pipe and not an alias.
- `docs/dkim2-implementer-guide.md`: add a short subsection pointing to the SERVER.md recipe and contrasting `reflector-delayedbounce` (Postfix-originated bounce) with `reflector-dsn` (hand-built DSN).

- [ ] **Step 3: Verify the docs reference real artifacts**

Run: `cd /Users/brong/src/interop && grep -rl 'reflector-delayedbounce' deploy/ docs/ && grep -c 'internal_mail_filter_classes' deploy/SERVER.md`
Expected: lists `deploy/SERVER.md`, `deploy/README.md`, `deploy/reflector-aliases`, `docs/dkim2-implementer-guide.md`, and a non-zero count for the recipe knob.

- [ ] **Step 4: Commit**

```bash
cd /Users/brong/src/interop
git add deploy/SERVER.md deploy/README.md deploy/reflector-aliases docs/dkim2-implementer-guide.md
git commit -m "docs: how to sign Postfix-generated DKIM2 bounces + register reflector-delayedbounce"
```

---

## Self-Review

**Spec coverage:**
- Component 1 (force a genuine bounce, `error:` transport) → Task 3 Step 1.
- Component 2 (`internal_mail_filter_classes = bounce` + outbound-only `non_smtpd_milters`) → Task 3 Step 2.
- Component 3 (null-sender signing: From-domain fallback + `mf=<>`) → Task 2 Steps 4 & 6.
- Library round-trip (folded in per spec) → Task 1.
- §11 conformance/limits (documented) → Task 4 Step 1.
- Tests → Task 1 (`null-mailfrom.t`), Task 2 (`milter.t` bounce + negative).
- Docs/recipe + address registration → Task 4.
- New map file decision → Task 3 Step 1.

**Placeholder scan:** No TBD/TODO; every code/edit step shows concrete content; verification commands have expected output.

**Type/name consistency:** `run_sign(env_from/env_rcpt)` added in Task 2 Step 1 and used in Steps 2; `_from_header_domain` defined and called in Task 2 Step 4; `_get_sign_config($env_from, $from_domain_fallback)` 2-arg form defined and called in Task 2 Step 6; `mf=PD4=` (base64 of `<>`) used consistently with the Global Constraints. The standalone-milter change (Task 2 Step 6) mirrors the handler change (Step 4) that the tests in Step 2 exercise.

**Known judgement calls flagged for the implementer:**
- `Mail::DKIM2::Signature->parse` accessor name in Task 1 Step 1 — adjust to the real API if it differs (check `t/dsn.t`).
- `deploy/postfix-main.cf.patch` may already contain `transport_maps`/`local_recipient_maps`; merge rather than duplicate (noted inline).
