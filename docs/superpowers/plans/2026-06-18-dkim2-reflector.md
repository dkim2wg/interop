# DKIM2 Reflector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add six DKIM2 "reflector" addresses to the dkim2.com demo server that verify an incoming message, transform it per mode, and reflect it back to the sender — signing as dkim2.com only when the incoming DKIM2 chain verified.

**Architecture:** A reusable `Mail::DKIM2::Reflector` module holds the verify/transform/MI/sign logic (testable without real mail). A thin `bin/dkim2-reflector.pl` wrapper reads the message from stdin and the envelope from postfix's `$SENDER`/`$RECIPIENT` env vars, calls `reflect()`, and submits the result over SMTP to a milter-free postfix injection port. One small enhancement to `Mail::DKIM2::MessageInstance` adds the spec §4.2 null body recipe (`"b": null`).

**Tech Stack:** Perl 5.20+, existing `Mail::DKIM2::{Verifier,Signer,MessageInstance,Common}`, `Email::MIME`, `Net::SMTP`; postfix aliases + a no-milter `master.cf` service; tests via `Test::More` + `DKIM2TestKeys`.

## Global Constraints

- DKIM2-only auth: `passed` = the incoming DKIM2 chain verified (`Verifier->result eq 'pass'`). SPF/DKIM1 are never consulted.
- Transformations are applied **always**; the reflector signature is added **only when passed**.
- Signing: single `DKIM2-Signature`, `d=dkim2.com`, selector `sel1`, `rsa-sha256`, key `/etc/dkim2/keys/dkim2.com/sel1.key`.
- Envelope: reply MAIL FROM = `reflector-bounces@dkim2.com`; RCPT TO = incoming `$SENDER`.
- Modes: `raw` `subject` `body` `both` `redacted` `damage`.
- `raw` and `damage` add a signature with **no new Message-Instance** (reuse top `m=`). `subject`/`body`/`both` add a new MI with recipes. `redacted` adds a new MI with `r={"b": null}`.
- Explanation headers `Authentication-Results` and `X-DKIM2-Reflector` are excluded from the DKIM2 header hash by `should_skip()` (already true for `^x-` and `authentication-results`) — they never affect the signature.
- Subject prefix: `[DKIM2] `. Footer (the "signature line"):
  ```
  -- 
  Reflected and signed by the DKIM2 reflector at dkim2.com
  ```
  Damage line: `damage line, breaks the signature`.
- Tests run from the `brong/` directory (`cd brong && prove -l t/...`).

---

### Task 1: Null body recipe in MessageInstance (spec §4.2)

**Files:**
- Modify: `brong/lib/Mail/DKIM2/MessageInstance.pm` (`as_string`, add `set_null_body_recipe`)
- Test: `brong/t/mi-null-recipe.t` (create)

**Interfaces:**
- Consumes: nothing new.
- Produces: `$mi->set_null_body_recipe()` — marks the body recipe as null so `as_string()` emits `; r={"b":null};`.

- [ ] **Step 1: Write the failing test** — create `brong/t/mi-null-recipe.t`:

```perl
#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More;
use lib 'lib';
use Mail::DKIM2::MessageInstance;

my $orig = "Subject: hi\r\nMessage-Instance: m=1; h=sha256:AAA:BBB;\r\n\r\nbody line one\r\n";
my $new  = "Subject: hi\r\nMessage-Instance: m=1; h=sha256:AAA:BBB;\r\n\r\nbody line one\r\nfooter\r\n";

my $mi = Mail::DKIM2::MessageInstance->calculate($new, $orig);
$mi->set_null_body_recipe;
my $str = $mi->as_string;

like($str, qr/"b"\s*:\s*null/, 'emits b:null in r= tag');
unlike($str, qr/"c"\s*:/, 'no copy steps remain in body recipe');
like($str, qr/^m=2;/, 'still increments the instance number');

done_testing;
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd brong && prove -l t/mi-null-recipe.t`
Expected: FAIL — `set_null_body_recipe` is an unknown method (`Can't locate object method`).

- [ ] **Step 3: Implement** — in `brong/lib/Mail/DKIM2/MessageInstance.pm`, add the method after `get_tag` (around line 73):

```perl
# Mark the body recipe as null per spec-02 §4.2: the body changed but the
# previous state cannot be recreated. as_string() emits "b": null.
sub set_null_body_recipe {
    my ($self) = @_;
    $self->{bits}{rb} = \'null';   # scalar-ref sentinel
}
```

Then in `as_string`, replace the existing `rb` block (the `if (exists $data{rb}) { $recipe_json{b} = _encode_recipe_list(delete $data{rb}); }`) with:

```perl
    if (exists $data{rb}) {
        if (ref $data{rb} eq 'SCALAR' && ${$data{rb}} eq 'null') {
            $recipe_json{b} = undef;          # encodes as JSON null
            delete $data{rb};
        } else {
            $recipe_json{b} = _encode_recipe_list(delete $data{rb});
        }
    }
```

Note: `encode_tag_json({ b => undef })` serializes to `{"b":null}` (a hash key with an undef value). `keys %recipe_json` still counts `b`, so the `r=` tag is emitted.

- [ ] **Step 4: Run it, verify it passes**

Run: `cd brong && prove -l t/mi-null-recipe.t`
Expected: PASS (3 subtests).

- [ ] **Step 5: Verify no regression in the existing MI/full-chain tests**

Run: `cd brong && prove -l t/full-chain.t t/body-canon.t`
Expected: PASS (no change to non-null recipe output).

- [ ] **Step 6: Commit**

```bash
cd /Users/brong/src/interop
git add brong/lib/Mail/DKIM2/MessageInstance.pm brong/t/mi-null-recipe.t
git commit -m "feat(mi): support null body recipe (b:null) per spec-02 §4.2"
```

---

### Task 2: Reflector module — verify, auth decision, raw mode, headers

**Files:**
- Create: `brong/lib/Mail/DKIM2/Reflector.pm`
- Test: `brong/t/reflector.t` (create)

**Interfaces:**
- Consumes: `Mail::DKIM2::{Verifier,Signer,MessageInstance,Common}`, `Email::MIME`.
- Produces:
  ```
  Mail::DKIM2::Reflector::reflect(%args) -> \%result
    args: message, mode, sender, domain='dkim2.com', selector='sel1',
          keyfile|key, mailfrom='reflector-bounces@dkim2.com',
          pubkey_cb (optional sub), timestamp (optional), skip_timestamp_check (optional)
    result keys: message (string, CRLF), auth ('pass'|'fail'|'none'), signed (0|1), mode
  ```
  Constants: `$FOOTER`, `$DAMAGE_LINE`, `$SUBJECT_PREFIX`.
  Internal subs used by later tasks: `_verify`, `_transform`, `_build_mi`, `_sign`.

- [ ] **Step 1: Write the failing test** — create `brong/t/reflector.t`:

```perl
#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More;
use Path::Tiny;
use lib 'lib', 't/lib';
use Mail::DKIM2::Verifier;
use Mail::DKIM2::MessageInstance;
use DKIM2TestKeys;
use Mail::DKIM2::Reflector;

# A message already DKIM2-signed by test1.dkim2.com (i=1) — reuse the
# full-chain originator output as a known-good signed input.
my $signed_in = path('tests/emails/brong-orig.eml')->slurp;
$signed_in =~ s/\r?\n/\r\n/g;
# brong-orig.eml is the unsigned source; sign it for test input:
$signed_in = sign_as($signed_in, 'test1.dkim2.com', 'sel1',
                     'brong@test1.dkim2.com', ['reflector-raw@dkim2.com']);

my $cb = DKIM2TestKeys::pubkey_callback();
my %common = (
    sender   => 'brong@test1.dkim2.com',
    domain   => 'dkim2.com',
    selector => 'sel1',
    key      => DKIM2TestKeys::private_key('dkim2.com', 'sel1'),
    pubkey_cb => $cb,
    skip_timestamp_check => 1,
);

# raw + passing input -> signed, no new MI, content unchanged
{
    my $r = Mail::DKIM2::Reflector::reflect(%common, mode => 'raw', message => $signed_in);
    is($r->{auth}, 'pass', 'raw: incoming verified');
    is($r->{signed}, 1, 'raw: signed because auth passed');
    like($r->{message}, qr/^DKIM2-Signature:/m, 'raw: has a DKIM2-Signature');
    like($r->{message}, qr/^X-DKIM2-Reflector:.*mode=raw.*signed=yes/m, 'raw: X- header');
    like($r->{message}, qr/^Authentication-Results:/m, 'raw: A-R header');
    my @mi = (Email::MIME->new($r->{message}))->header_raw('Message-Instance');
    is(scalar @mi, 1, 'raw: no NEW MI added (still just the i=1 era MI)');
    # the reflected message verifies at the recipient under dkim2.com's new sig
    my $v = Mail::DKIM2::Verifier->new; $v->skip_timestamp_check(1);
    $v->set_pubkey_callback($cb); $v->PRINT($r->{message}); $v->CLOSE;
    is($v->result, 'pass', 'raw: reflected message verifies');
}

# failing input (no DKIM2) -> not signed, but headers + (no-op) transform present
{
    my $unsigned = "From: x\@example.org\r\nTo: reflector-raw\@dkim2.com\r\nSubject: hi\r\n\r\nhello\r\n";
    my $r = Mail::DKIM2::Reflector::reflect(%common, mode => 'raw', message => $unsigned);
    isnt($r->{auth}, 'pass', 'no-DKIM2 input does not pass');
    is($r->{signed}, 0, 'not signed when auth fails');
    unlike($r->{message}, qr/^DKIM2-Signature:/m, 'no reflector signature on fail');
    like($r->{message}, qr/^X-DKIM2-Reflector:.*signed=no/m, 'X- header shows signed=no');
}

sub sign_as {
    my ($msg, $domain, $sel, $mf, $rcpt) = @_;
    require Mail::DKIM2::Signer;
    my $s = Mail::DKIM2::Signer->new(
        Domain => $domain, Selector => $sel,
        Key => DKIM2TestKeys::private_key($domain, $sel),
        MailFrom => $mf, RcptTo => $rcpt, Timestamp => 1700000000,
    );
    $s->PRINT($msg); $s->CLOSE;
    my $sig = $s->as_string;  # "DKIM2-Signature: ..."
    # prepend a fresh m=1 MI then the signature
    my $mi = Mail::DKIM2::MessageInstance->calculate($msg);
    return "$sig\r\nMessage-Instance: " . $mi->as_string . "\r\n" . $msg;
}

done_testing;
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd brong && prove -l t/reflector.t`
Expected: FAIL — `Can't locate Mail/DKIM2/Reflector.pm`.

- [ ] **Step 3: Implement the module** — create `brong/lib/Mail/DKIM2/Reflector.pm`:

```perl
package Mail::DKIM2::Reflector;
use strict; use warnings;
use 5.020;

use Email::MIME;
use Carp;
use Mail::DKIM2::Verifier;
use Mail::DKIM2::Signer;
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Common qw(fold_header);

our $SUBJECT_PREFIX = '[DKIM2] ';
our $FOOTER         = "-- \r\nReflected and signed by the DKIM2 reflector at dkim2.com\r\n";
our $DAMAGE_LINE    = "damage line, breaks the signature\r\n";

my %VALID = map { $_ => 1 } qw(raw subject body both redacted damage);

sub reflect {
    my (%a) = @_;
    croak "unknown mode $a{mode}" unless $VALID{ $a{mode} // '' };
    my $mode = $a{mode};
    $a{domain}   //= 'dkim2.com';
    $a{selector} //= 'sel1';
    $a{mailfrom} //= 'reflector-bounces@dkim2.com';

    # Normalise to CRLF.
    (my $incoming = $a{message}) =~ s/\r?\n/\r\n/g;

    # 1. Verify (DKIM2-only).
    my $auth = _verify($incoming, $a{pubkey_cb}, $a{skip_timestamp_check});
    my $passed = ($auth eq 'pass') ? 1 : 0;

    # 2. Transform (always, except damage which mutates after signing).
    my $prev_text = $incoming;
    my $cur_mime  = Email::MIME->new($incoming);
    _transform($cur_mime, $mode) unless $mode eq 'damage';
    my $cur_text  = $cur_mime->as_string;
    $cur_text =~ s/\r?\n/\r\n/g;

    my $signed = 0;
    if ($passed) {
        # 3. MI (none for raw/damage; new MI for the rest).
        my $mi = _build_mi($cur_text, $prev_text, $mode);
        if ($mi) {
            my $val = fold_header("Message-Instance: " . $mi->as_string);
            $val =~ s/^Message-Instance:\s*//;
            $cur_text = "Message-Instance: $val\r\n" . $cur_text;
        }
        # 4. Sign.
        my $sig = _sign($cur_text, %a);
        $cur_text = "$sig\r\n" . $cur_text;
        $signed = 1;
        # 5. Damage: append the breaking line after signing.
        if ($mode eq 'damage') {
            $cur_text .= $DAMAGE_LINE;
        }
    }

    # 6. Explanation headers (excluded from the hash; safe to prepend last).
    my $verdict = ($auth eq 'pass') ? 'pass' : ($auth eq 'fail' ? 'fail' : 'none');
    my $ar  = "Authentication-Results: $a{domain}; dkim2=$verdict\r\n";
    my $xr  = "X-DKIM2-Reflector: mode=$mode; auth=$verdict; "
            . "signed=" . ($signed ? 'yes' : 'no') . "; "
            . "note=reflected-to-sender\r\n";
    $cur_text = $ar . $xr . $cur_text;

    return { message => $cur_text, auth => $auth, signed => $signed, mode => $mode };
}

sub _verify {
    my ($text, $cb, $skip_ts) = @_;
    my $v = Mail::DKIM2::Verifier->new;
    $v->skip_timestamp_check(1) if $skip_ts;
    if ($cb) {
        $v->set_pubkey_callback($cb);
    } else {
        # Real DNS via the Signature object's own fetch.
        $v->set_pubkey_callback(sub {
            my ($sig, $idx) = @_; $idx //= 0;
            return $sig->fetch_public_key($idx);
        });
    }
    $v->PRINT($text); $v->CLOSE;
    my $r = $v->result // 'none';
    return $r;
}

sub _transform {
    my ($mime, $mode) = @_;
    return if $mode eq 'raw';
    if ($mode eq 'subject' || $mode eq 'both') {
        my $subj = $mime->header('Subject') // '';
        $mime->header_str_set('Subject', $SUBJECT_PREFIX . $subj);
    }
    if ($mode eq 'body' || $mode eq 'both' || $mode eq 'redacted') {
        my $body = $mime->body_raw;
        $body =~ s/\r?\n/\r\n/g;
        $body .= "\r\n" unless $body =~ /\r\n\z/;
        $mime->body_set($body . $FOOTER);
    }
}

# Returns a MessageInstance object (new MI) or undef (no new MI).
sub _build_mi {
    my ($cur_text, $prev_text, $mode) = @_;
    return undef if $mode eq 'raw' || $mode eq 'damage';   # reuse top m=
    my $mi = Mail::DKIM2::MessageInstance->calculate(
        Email::MIME->new($cur_text), Email::MIME->new($prev_text));
    $mi->set_null_body_recipe if $mode eq 'redacted';
    return $mi;
}

sub _sign {
    my ($text, %a) = @_;
    my %sa = (
        Domain   => $a{domain},
        Selector => $a{selector},
        MailFrom => $a{mailfrom},
        RcptTo   => [ $a{sender} ],
    );
    $sa{Key}     = $a{key}     if $a{key};
    $sa{KeyFile} = $a{keyfile} if $a{keyfile} && !$a{key};
    $sa{Timestamp} = $a{timestamp} if $a{timestamp};
    my $signer = Mail::DKIM2::Signer->new(%sa);
    $signer->PRINT($text); $signer->CLOSE;
    croak "signing failed: " . $signer->result unless $signer->result eq 'signed';
    return $signer->as_string;   # "DKIM2-Signature: ..."
}

1;
```

- [ ] **Step 4: Run it, verify it passes**

Run: `cd brong && prove -l t/reflector.t`
Expected: PASS (raw pass + fail blocks).

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop
git add brong/lib/Mail/DKIM2/Reflector.pm brong/t/reflector.t
git commit -m "feat(reflector): module with verify, auth-gated raw mode, headers"
```

---

### Task 3: subject / body / both transforms + MI recipes

**Files:**
- Modify: `brong/t/reflector.t` (add subtests)
- (No module change expected — `_transform`/`_build_mi` already cover these; this task proves them and fixes any gaps.)

**Interfaces:**
- Consumes: `reflect()` from Task 2.
- Produces: verified behaviour for `subject`/`body`/`both`.

- [ ] **Step 1: Add failing subtests** to `brong/t/reflector.t` before `done_testing`:

```perl
# subject/body/both: new MI with recipes; reflected msg verifies; undo restores.
for my $case (
    { mode => 'subject', restores_subject => 1, restores_body => 0 },
    { mode => 'body',    restores_subject => 0, restores_body => 1 },
    { mode => 'both',    restores_subject => 1, restores_body => 1 },
) {
    my $in = sign_as(
        "From: a\@test1.dkim2.com\r\nTo: reflector-$case->{mode}\@dkim2.com\r\nSubject: hello\r\n\r\noriginal body\r\n",
        'test1.dkim2.com', 'sel1', 'a@test1.dkim2.com', ["reflector-$case->{mode}\@dkim2.com"]);
    my $r = Mail::DKIM2::Reflector::reflect(%common, mode => $case->{mode}, message => $in);
    is($r->{signed}, 1, "$case->{mode}: signed");

    my $msg = Email::MIME->new($r->{message});
    my @mi  = $msg->header_raw('Message-Instance');
    is(scalar @mi, 2, "$case->{mode}: a new MI was added (now 2)");

    if ($case->{mode} ne 'body') {
        like($msg->header('Subject'), qr/^\Q[DKIM2]\E /, "$case->{mode}: subject prefixed");
    }
    if ($case->{mode} ne 'subject') {
        like($r->{message}, qr/Reflected and signed by the DKIM2 reflector/, "$case->{mode}: footer added");
    }

    my $v = Mail::DKIM2::Verifier->new; $v->skip_timestamp_check(1);
    $v->set_pubkey_callback($cb); $v->PRINT($r->{message}); $v->CLOSE;
    is($v->result, 'pass', "$case->{mode}: reflected verifies");

    my $undone = Mail::DKIM2::MessageInstance->undo(Email::MIME->new($r->{message}));
    if ($case->{restores_subject}) {
        is($undone->header('Subject'), 'hello', "$case->{mode}: undo restores subject");
    }
    if ($case->{restores_body}) {
        unlike($undone->body_raw, qr/Reflected and signed/, "$case->{mode}: undo restores body");
    }
}
```

- [ ] **Step 2: Run it**

Run: `cd brong && prove -l t/reflector.t`
Expected: most pass; if `undo` of the subject/header recipe or body recipe reveals a gap (e.g. footer line counting), fix `_transform`/`_build_mi` minimally so all pass. Likely passes as written.

- [ ] **Step 3: If any subtest failed**, adjust `_transform` (body footer must be appended as whole CRLF-terminated lines so the body diff produces clean ranges) and re-run until PASS. No other files change.

- [ ] **Step 4: Commit**

```bash
cd /Users/brong/src/interop
git add brong/t/reflector.t brong/lib/Mail/DKIM2/Reflector.pm
git commit -m "test(reflector): subject/body/both transforms + MI recipe undo"
```

---

### Task 4: redacted (null recipe) + damage (post-sign break)

**Files:**
- Modify: `brong/t/reflector.t` (add subtests)

**Interfaces:**
- Consumes: `reflect()`, `set_null_body_recipe` (Task 1).
- Produces: verified `redacted` and `damage` behaviour.

- [ ] **Step 1: Add failing subtests** to `brong/t/reflector.t`:

```perl
# redacted: footer added, MI body recipe is null, message still verifies,
# but undo cannot recreate the original body.
{
    my $in = sign_as(
        "From: a\@test1.dkim2.com\r\nTo: reflector-redacted\@dkim2.com\r\nSubject: hi\r\n\r\nsecret body\r\n",
        'test1.dkim2.com', 'sel1', 'a@test1.dkim2.com', ['reflector-redacted@dkim2.com']);
    my $r = Mail::DKIM2::Reflector::reflect(%common, mode => 'redacted', message => $in);
    is($r->{signed}, 1, 'redacted: signed');
    my @mi = (Email::MIME->new($r->{message}))->header_raw('Message-Instance');
    my ($top) = sort { (Mail::DKIM2::MessageInstance->parse($b)->get_tag('m'))
                   <=> (Mail::DKIM2::MessageInstance->parse($a)->get_tag('m')) } @mi;
    like($top, qr/"b"\s*:\s*null/, 'redacted: top MI has null body recipe');

    my $v = Mail::DKIM2::Verifier->new; $v->skip_timestamp_check(1);
    $v->set_pubkey_callback($cb); $v->PRINT($r->{message}); $v->CLOSE;
    is($v->result, 'pass', 'redacted: reflected verifies (current content)');

    my $undone = Mail::DKIM2::MessageInstance->undo(Email::MIME->new($r->{message}));
    like($undone->body_raw, qr/Reflected and signed/, 'redacted: body NOT recoverable (footer remains)');
}

# damage: signed correctly, then a line appended -> recipient verification FAILS.
{
    my $in = sign_as(
        "From: a\@test1.dkim2.com\r\nTo: reflector-damage\@dkim2.com\r\nSubject: hi\r\n\r\nclean body\r\n",
        'test1.dkim2.com', 'sel1', 'a@test1.dkim2.com', ['reflector-damage@dkim2.com']);
    my $r = Mail::DKIM2::Reflector::reflect(%common, mode => 'damage', message => $in);
    is($r->{signed}, 1, 'damage: a signature was produced');
    like($r->{message}, qr/damage line, breaks the signature/, 'damage: breaking line appended');

    my $v = Mail::DKIM2::Verifier->new; $v->skip_timestamp_check(1);
    $v->set_pubkey_callback($cb); $v->PRINT($r->{message}); $v->CLOSE;
    isnt($v->result, 'pass', 'damage: reflected message FAILS verification');
}
```

- [ ] **Step 2: Run it, verify it passes**

Run: `cd brong && prove -l t/reflector.t`
Expected: PASS. (`redacted` verifies because hashes are of the current footered body; `undo` is a no-op for `b:null`, so the footer stays. `damage` fails because the appended line changes the body hash after signing.)

- [ ] **Step 3: If `redacted` undo errors** (parse of `b:null`), confirm `MessageInstance::parse` treats a null `b` as "no body recipe" (undo leaves the body unchanged). If `undo` dies, guard it in `parse`/`undo` so a null `b` yields no `rb` (no code change expected — `$recipe_data->{b}` is falsy for null). Re-run until PASS.

- [ ] **Step 4: Commit**

```bash
cd /Users/brong/src/interop
git add brong/t/reflector.t
git commit -m "test(reflector): redacted null-recipe + damage post-sign break"
```

---

### Task 5: CLI wrapper + SMTP injection

**Files:**
- Create: `brong/bin/dkim2-reflector.pl`
- Test: `brong/t/reflector-cli.t` (create — arg/env parsing only; injection is manual)

**Interfaces:**
- Consumes: `Mail::DKIM2::Reflector::reflect`.
- Produces: an executable that reads stdin + `$ENV{SENDER}`, calls `reflect`, and submits to `127.0.0.1:10588`.

- [ ] **Step 1: Write the wrapper** — create `brong/bin/dkim2-reflector.pl`:

```perl
#!/usr/bin/perl
use 5.020; use strict; use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Mail::DKIM2::Reflector;
use Net::SMTP;

# Usage (from postfix alias):  dkim2-reflector.pl <mode>
# Reads the message on stdin; envelope sender from $ENV{SENDER}.
my $mode   = $ARGV[0] or die "usage: $0 <mode>\n";
my $sender = $ENV{SENDER} // '';

# Null return-path (bounce) -> nothing to reflect; drop quietly.
if ($sender eq '' || $sender eq '<>') {
    warn "dkim2-reflector: empty SENDER, dropping\n";
    exit 0;
}

local $/; my $message = <STDIN>;

my $result = eval {
    Mail::DKIM2::Reflector::reflect(
        message  => $message,
        mode     => $mode,
        sender   => $sender,
        domain   => 'dkim2.com',
        selector => 'sel1',
        keyfile  => '/etc/dkim2/keys/dkim2.com/sel1.key',
        mailfrom => 'reflector-bounces@dkim2.com',
    );
};
if (my $err = $@) {
    warn "dkim2-reflector: reflect failed: $err\n";
    exit 0;   # never bounce
}

# Inject to the milter-free postfix service so we do not get re-signed.
my $smtp = Net::SMTP->new('127.0.0.1', Port => 10588, Timeout => 30)
    or do { warn "dkim2-reflector: cannot connect to injector\n"; exit 0; };
$smtp->mail('reflector-bounces@dkim2.com');
$smtp->recipient($sender);
$smtp->data();
$smtp->datasend($result->{message});
$smtp->dataend();
$smtp->quit;
exit 0;
```

- [ ] **Step 2: Write a parsing/smoke test** — create `brong/t/reflector-cli.t`:

```perl
#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More;
use Path::Tiny;

my $script = path('bin/dkim2-reflector.pl');
ok($script->exists, 'wrapper exists');
like($script->slurp, qr/Mail::DKIM2::Reflector/, 'wrapper uses the module');
like($script->slurp, qr/Port\s*=>\s*10588/, 'wrapper injects to the no-milter port');

# Compiles cleanly.
my $out = qx{perl -c -Ilib bin/dkim2-reflector.pl 2>&1};
like($out, qr/syntax OK/, 'wrapper compiles');

done_testing;
```

- [ ] **Step 3: Run it**

Run: `cd brong && prove -l t/reflector-cli.t`
Expected: PASS (after `chmod +x bin/dkim2-reflector.pl`).

- [ ] **Step 4: Make executable + commit**

```bash
cd /Users/brong/src/interop
chmod +x brong/bin/dkim2-reflector.pl
git add brong/bin/dkim2-reflector.pl brong/t/reflector-cli.t
git commit -m "feat(reflector): CLI wrapper that injects via the no-milter port"
```

---

### Task 6: Deploy (aliases, no-milter injector, docs) + end-to-end

**Files:**
- Create: `deploy/reflector-aliases` (reference snippet)
- Modify: `deploy/SERVER.md`
- Server (documented, applied at deploy): `/etc/postfix/master.cf`, `/etc/aliases`

**Interfaces:**
- Consumes: the deployed `Mail::DKIM2` libs + wrapper (via `cd brong && make install` + script copy).
- Produces: live `reflector-*@dkim2.com` addresses.

- [ ] **Step 1: Create the aliases snippet** — `deploy/reflector-aliases`:

```
# Append to /etc/aliases on the dkim2.com server, then run `newaliases`.
reflector-raw:      |"/usr/local/bin/dkim2-reflect raw"
reflector-subject:  |"/usr/local/bin/dkim2-reflect subject"
reflector-body:     |"/usr/local/bin/dkim2-reflect body"
reflector-both:     |"/usr/local/bin/dkim2-reflect both"
reflector-redacted: |"/usr/local/bin/dkim2-reflect redacted"
reflector-damage:   |"/usr/local/bin/dkim2-reflect damage"
```

- [ ] **Step 2: Add the no-milter injector to `master.cf`** (on the server):

```bash
ssh dkim2 'grep -q "^127.0.0.1:10588" /etc/postfix/master.cf || cat >> /etc/postfix/master.cf <<EOF

# DKIM2 reflector injection: no milters (the reflector signs itself).
127.0.0.1:10588 inet n  -  y  -  -  smtpd
  -o syslog_name=postfix/reflector-inject
  -o smtpd_milters=
  -o non_smtpd_milters=
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o smtpd_recipient_restrictions=permit_mynetworks,reject_unauth_destination
EOF
postfix check && systemctl reload postfix && echo INJECTOR_OK'
```
Expected: `INJECTOR_OK`.

- [ ] **Step 3: Deploy the libs + wrapper** (the milter lib is installed system-wide per SERVER.md):

```bash
ssh dkim2 'cd /root/interop && git pull --ff-only && \
  cd brong && perl Makefile.PL >/dev/null && make >/dev/null && make install >/dev/null && \
  install -m 755 bin/dkim2-reflector.pl /usr/local/bin/dkim2-reflect && echo DEPLOYED'
```
Expected: `DEPLOYED`. (Push local commits first: `git push origin master`.)

- [ ] **Step 4: Install the aliases**

```bash
ssh dkim2 'grep -q "^reflector-raw:" /etc/aliases || cat /root/interop/deploy/reflector-aliases >> /etc/aliases; newaliases && echo ALIASES_OK'
```
Expected: `ALIASES_OK`.

- [ ] **Step 5: End-to-end — send a DKIM2-signed message to each reflector and check the reply**

For each mode, send from an address you can receive at (or use the existing `looper`/a test mailbox). Minimum viable check using the server's own tooling on a captured reply:

```bash
# Example for one mode; repeat for raw/subject/body/both/redacted/damage.
swaks --to reflector-raw@dkim2.com --from <you@your-test-domain> \
      --server mail.dkim2.com --h-Subject 'reflector test'
# Then inspect the reflected message you receive:
#   raw/subject/body/both/redacted -> verifies; X-DKIM2-Reflector: signed=yes
#   damage -> fails verification at your end; reply still has the appended line
```
Expected per mode (verify with `verify-sig.pl` on the saved reply):
- `raw`,`subject`,`body`,`both`,`redacted` → `result_detail` shows pass.
- `subject`/`body`/`both` → `undo` restores the prior version.
- `redacted` → top MI shows `"b":null`; body not recoverable.
- `damage` → verification fails (body-hash mismatch).
- Unsigned input → reply has `X-DKIM2-Reflector: ... signed=no` and no `DKIM2-Signature`.

- [ ] **Step 6: Document in SERVER.md** — add a "DKIM2 Reflector" subsection covering: the six addresses and behaviours, the `/usr/local/bin/dkim2-reflect` wrapper + `Mail::DKIM2::Reflector` module, the `127.0.0.1:10588` no-milter injector, the aliases, and the deploy/update commands. Commit:

```bash
cd /Users/brong/src/interop
git add deploy/reflector-aliases deploy/SERVER.md
git commit -m "docs+deploy: DKIM2 reflector addresses, injector, and deploy steps"
git push origin master
```

---

## Self-Review

**1. Spec coverage:**
- Auth model (verify always, sign only on DKIM2 pass, transform always) → Task 2 (`reflect`/`_verify`), Global Constraints. ✓
- DKIM2-only → `_verify` uses only `Verifier`. ✓
- `raw` (sign, no new MI) → Task 2 + test. ✓
- `subject`/`body`/`both` (new MI + recipes) → Task 3. ✓
- `redacted` (`b:null`) → Task 1 (lib) + Task 4 (test). ✓
- `damage` (post-sign append) → Task 2 (`reflect`) + Task 4 (test). ✓
- Single `sel1`/`rsa-sha256` signature → `_sign`, Global Constraints. ✓
- Envelope (to MAIL FROM, from reflector-bounces) → `_sign` RcptTo + Task 5 wrapper. ✓
- Explanation headers `Authentication-Results` + `X-DKIM2-Reflector`, hash-excluded → Task 2; relies on existing `should_skip`. ✓
- No-milter injection port → Task 5 (wrapper) + Task 6 (master.cf). ✓
- Aliases / transport → Task 6. ✓
- Empty-sender / never-bounce error handling → Task 5 wrapper. ✓
- Tests (unit per mode + MI null + e2e) → Tasks 1–4 (unit), Task 6 (e2e). ✓

**2. Placeholder scan:** No TBD/TODO. Code blocks complete for every code step. Task 6 Step 6 describes a free-form doc edit (acceptable for documentation). Task 3 Step 3 is a conditional fix-up, with the concrete fix named (footer as whole CRLF lines). ✓

**3. Type consistency:** `reflect()` keys (`message`/`auth`/`signed`/`mode`) used consistently across Tasks 2–5. `set_null_body_recipe` defined in Task 1, used in Task 2 (`_build_mi`) and asserted in Task 4. `_sign` accepts `Key`/`KeyFile` matching `Signer->new` (`Key`/`KeyFile`). Wrapper passes `keyfile` → `_sign` maps to `KeyFile`. Injector port `10588` consistent in Tasks 5 and 6. ✓
