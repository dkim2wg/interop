# DKIM2-DSN Singleton-Header Prototype — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prototype a dedicated `DKIM2-DSN` header — `reflector-dsn` emits it when the bounced message has a legit DKIM2 chain, and `dkim2-bounces@` verifies it, undoes the chain, and relays the reconstructed original to its originator.

**Architecture:** A small new library unit (`Mail::DKIM2::DSNHeader`) builds/signs/parses/verifies the singleton header (mirrors `Signature.pm`'s fold-then-sign discipline, but signs over just itself). The generator (`Mail::DKIM2::DSN` + `reflector-dsn`) verifies the incoming chain and emits a headers-only DSN carrying that header. A new pipe processor (`dkim2-bounces@`) verifies + undoes + relays. Prototype-first; the -03 spec text is a later cycle.

**Tech Stack:** Perl (`Mail::DKIM2::*`, CryptX: `Crypt::PK::RSA`/`Crypt::PK::Ed25519`/`Crypt::Digest::SHA256`), `prove`, Postfix `pipe(8)` + the milter-free injector (`127.0.0.1:10588`).

## Global Constraints

- **`DKIM2-DSN` header (the format this prototype defines):**
  ```
  DKIM2-DSN: d=<domain>; rt=<base64(<rcpt>)>; h=sha256:<headerhash>; s=<sel>:<alg>:<base64sig>
  ```
  - `d=` signing domain (bouncing hop). `rt=` = base64 of the angle-bracketed RFC5321 forward-path (per §7.6, same encoding as `Signature` `rt=`), whose value equals the bounced message's **top-hop `mf=`**. `h=` = `sha256:` + the **header-hash component** of the bounced message's **top `Message-Instance`** (no body-hash half). `s=` = `selector:algorithm:base64sig`.
  - **No `t=`.** Envelope **`MAIL FROM <>`**. The DSN carries **only** this header — no `DKIM2-Signature`/`Message-Instance` of its own. Embedded original is **headers-only** (`text/rfc822-headers`, `encoding => 7bit`), body discarded & unsigned.
- **Signing input:** the `DKIM2-DSN` header with the `s=` signature blanked (`<sel>:<alg>:`), canonicalized with the **same relaxed header canonicalization the signer/verifier already use** (`Mail::DKIM2::Common::dkim2_canonicalize_header`), folded at 72 chars before signing (`fold_header`), never refolded after. RSA: `$key->sign_message($input,'SHA256','v1.5')`; Ed25519: `$key->sign_message(sha256($input))`.
- **Verification (4 checks):** (1) `rt=` decodes to the bounced message's top-hop `mf=`; (2) `d=` relaxed-domain-matches (`relaxed_domain_match`) a top-hop `rt=` domain; (3) `h=` equals the header-hash recomputed over the included headers (= their top MI's header-hash); (4) `s=` verifies over the sig-blanked canonical header with the `d=`/selector key.
- **Generator rule:** legit incoming chain → emit `DKIM2-DSN` (headers-only); no legit chain → plain RFC3464 DSN, **no** `DKIM2-DSN`.
- **Handler rule:** verify → undo chain → relay to reconstructed originator; **never relay what it can't authenticate** (capture to the `reflector-bounces` mbox + log instead).
- Perl tests run from `brong/`: `cd /Users/brong/src/interop/brong && prove -lv t/<file>.t`; full suite `prove -l t/`. Keys/DNS: `DKIM2TestKeys` (`t/lib`), `private_key($domain,'rsa1024')`, `pubkey_callback()`.
- Follow `brong/CLAUDE.md` header-folding rules. Reference: design doc `docs/superpowers/specs/2026-07-01-dkim2-dsn-header-prototype-design.md`.

---

### Task 1: `Mail::DKIM2::DSNHeader` — build / sign / parse / verify

**Files:**
- Create: `brong/lib/Mail/DKIM2/DSNHeader.pm`
- Test: `brong/t/dsn-header.t`

**Interfaces:**
- Consumes: `Mail::DKIM2::Common::{dkim2_canonicalize_header, fold_header, load_private_key, parse_dkim_pubkey}`; `MIME::Base64`; `Crypt::PK::RSA`/`Ed25519`; `Crypt::Digest::SHA256::sha256`.
- Produces:
  - `Mail::DKIM2::DSNHeader->new(Domain=>$d, RcptTo=>$addr, HeaderHash=>$hh, Selector=>$s, Key=>$pk, Algorithm=>'rsa-sha256')` → object; `$hh` is the bare header-hash (base64, no `sha256:` prefix); `$addr` is a bare/bracketed address.
  - `->as_string()` → the full `DKIM2-DSN: …` header line, folded, signature filled in.
  - `Mail::DKIM2::DSNHeader->parse($header_value)` → object with `->domain`, `->rcpt_to` (decoded, brackets kept), `->header_hash` (`sha256:<hh>`), `->selector`, `->algorithm`, `->signature` (raw bytes).
  - `->verify($pubkey)` → boolean.

- [ ] **Step 1: Write the failing test** — `brong/t/dsn-header.t`:

```perl
#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More; use lib 'lib'; use lib 't/lib';
use Mail::DKIM2::DSNHeader; use DKIM2TestKeys;
use MIME::Base64 qw(encode_base64);

my $hh = encode_base64('fakeheaderhashbytes', '');  # stand-in header hash
my $h  = Mail::DKIM2::DSNHeader->new(
    Domain => 'dkim2.com', RcptTo => 'bounce@sender.example',
    HeaderHash => $hh, Selector => 'rsa1024',
    Key => DKIM2TestKeys::private_key('dkim2.com','rsa1024'), Algorithm => 'rsa-sha256');
my $line = $h->as_string;
like($line, qr/^DKIM2-DSN:/,            'emits a DKIM2-DSN header');
like($line, qr/d=dkim2\.com/,           'has d=');
like($line, qr/h=sha256:\Q$hh\E/,       'has h=sha256:<hh>');
like($line, qr/s=rsa1024:rsa-sha256:/,  'has s=sel:alg:sig');

(my $val = $line) =~ s/^DKIM2-DSN:\s*//s;
my $p = Mail::DKIM2::DSNHeader->parse($val);
is($p->domain, 'dkim2.com',                 'parse d=');
is($p->rcpt_to, '<bounce@sender.example>',  'parse rt= (bracketed forward-path)');
is($p->header_hash, "sha256:$hh",           'parse h=');

my $pub = DKIM2TestKeys::pubkey_callback()->(_fakesig('dkim2.com','rsa1024'));
ok($p->verify($pub),                        'signature verifies');

# tamper the header hash -> verify fails
(my $bad = $val) =~ s/\Q$hh\E/Ym9ndXM=/;
ok(!Mail::DKIM2::DSNHeader->parse($bad)->verify($pub), 'tampered h= fails verify');

sub _fakesig { my($d,$s)=@_; my $o=bless {},'Mail::DKIM2::Signature';
  $o->{tags}={d=>$d}; $o->{_items}=[[$s,'rsa-sha256','']]; return $o }  # minimal shim for pubkey_callback
done_testing;
```

(If `pubkey_callback`'s shim is awkward, fetch the pubkey directly: `DKIM2TestKeys::private_key('dkim2.com','rsa1024')` is a `Crypt::PK::RSA` that can also `verify_message`, so `$p->verify($that_key)` works for a round-trip test. Use whichever the existing tests use — see `t/null-mailfrom.t`.)

- [ ] **Step 2: Run — expect FAIL**

Run: `cd brong && prove -lv t/dsn-header.t`
Expected: FAIL — `Can't locate Mail/DKIM2/DSNHeader.pm`.

- [ ] **Step 3: Implement `DSNHeader.pm`**

```perl
package Mail::DKIM2::DSNHeader;
use strict; use warnings;
use MIME::Base64 qw(encode_base64 decode_base64);
use Crypt::Digest::SHA256 qw(sha256);
use Mail::DKIM2::Common qw(dkim2_canonicalize_header fold_header to_rfc5321_path);

# Build the header value with the s= signature blanked (signing input form).
sub _value_blank_sig {
    my ($d, $rt_b64, $hh, $sel, $alg) = @_;
    return "d=$d; rt=$rt_b64; h=sha256:$hh; s=$sel:$alg:";
}

sub new {
    my ($class, %a) = @_;
    my $self = bless { d => $a{Domain}, hh => $a{HeaderHash},
                       sel => $a{Selector}, alg => $a{Algorithm} || 'rsa-sha256' }, $class;
    $self->{rt_b64} = encode_base64(to_rfc5321_path($a{RcptTo}), '');
    # signing input: canonicalized "DKIM2-DSN: <value with blank sig>"
    my $blank = "DKIM2-DSN: " . _value_blank_sig($self->{d}, $self->{rt_b64}, $self->{hh}, $self->{sel}, $self->{alg});
    my $input = dkim2_canonicalize_header($blank);
    my $key = $a{Key};
    my $sig = ($self->{alg} =~ /^ed25519/)
        ? $key->sign_message(sha256($input))
        : $key->sign_message($input, 'SHA256', 'v1.5');
    $self->{sig_b64} = encode_base64($sig, '');
    return $self;
}

sub as_string {
    my ($self) = @_;
    my $val = "d=$self->{d}; rt=$self->{rt_b64}; h=sha256:$self->{hh}; "
            . "s=$self->{sel}:$self->{alg}:$self->{sig_b64}";
    return fold_header("DKIM2-DSN: $val");
}

sub parse {
    my ($class, $value) = @_;
    my $self = bless {}, $class;
    my %t; for my $p (split /\s*;\s*/, $value) { $p =~ /^(\w+)\s*=\s*(.*)/s or next;
        my ($k,$v)=($1,$2); $v =~ s/\s//gs; $t{$k}=$v; }
    $self->{d}   = $t{d};
    $self->{rt_b64} = $t{rt};
    ($self->{hh_full} = $t{h} // '') ;                 # "sha256:<hh>"
    ($self->{sel},$self->{alg},$self->{sig_b64}) = split /:/, ($t{s} // ''), 3;
    return $self;
}

sub domain      { $_[0]->{d} }
sub rcpt_to     { decode_base64($_[0]->{rt_b64} // '') }
sub header_hash { $_[0]->{hh_full} }                    # "sha256:<hh>"
sub selector    { $_[0]->{sel} }
sub algorithm   { $_[0]->{alg} }
sub signature   { decode_base64($_[0]->{sig_b64} // '') }

sub verify {
    my ($self, $pubkey) = @_;
    my ($hh) = ($self->{hh_full} // '') =~ /^sha256:(.*)$/ or return 0;
    my $blank = "DKIM2-DSN: " . _value_blank_sig($self->{d}, $self->{rt_b64}, $hh, $self->{sel}, $self->{alg});
    my $input = dkim2_canonicalize_header($blank);
    my $sig = $self->signature;
    return $self->{alg} =~ /^ed25519/
        ? $pubkey->verify_message($sig, sha256($input))
        : $pubkey->verify_message($sig, $input, 'SHA256', 'v1.5');
}
1;
```

Confirm `dkim2_canonicalize_header`'s exact call form against `Signer.pm`/`Signature.pm` usage (it is imported and used there); if it expects a different argument shape, match that exact usage so sign and verify agree. `to_rfc5321_path` is the helper added this session (wraps bare address in `<…>`).

- [ ] **Step 4: Run — expect PASS**

Run: `cd brong && prove -lv t/dsn-header.t`
Expected: PASS (round-trip + tampered-hash-fails).

- [ ] **Step 5: Commit**

```bash
git add brong/lib/Mail/DKIM2/DSNHeader.pm brong/t/dsn-header.t
git commit -m "dkim2: Mail::DKIM2::DSNHeader — build/sign/parse/verify the DKIM2-DSN singleton"
```

---

### Task 2: Generator — emit `DKIM2-DSN` when the bounced chain is legit

**Files:**
- Modify: `brong/lib/Mail/DKIM2/MessageInstance.pm` (add a `header_hash` accessor)
- Modify: `brong/lib/Mail/DKIM2/DSN.pm` (add `generate_dkim2_dsn`)
- Modify: `brong/lib/Mail/DKIM2/Reflector.pm` (`generate_dsn` chooses DKIM2-DSN vs plain)
- Test: `brong/t/dsn-generate.t`

**Interfaces:**
- Consumes: `Mail::DKIM2::DSNHeader` (Task 1); `Mail::DKIM2::Verifier`; `Mail::DKIM2::MessageInstance`; `Mail::DKIM2::Signature`.
- Produces: `Mail::DKIM2::DSN::generate_dkim2_dsn(%args)` → `{ raw => $dsn_text, send_to => $rt }`; args: `raw` (incoming message), `domain`, `selector`, `key`/`keyfile`. `Mail::DKIM2::MessageInstance->header_hash` → the `h1` header-hash (base64, no prefix) of the parsed top MI.

- [ ] **Step 1: Add the `header_hash` accessor to `MessageInstance.pm`**

Near the other accessors:

```perl
# The header-hash component (base64) of this Message-Instance's h= tag.
sub header_hash { return $_[0]->{bits}{h1} }
```

- [ ] **Step 2: Write the failing test** — `brong/t/dsn-generate.t`:

```perl
#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More; use lib 'lib'; use lib 't/lib';
use Email::MIME; use Mail::DKIM2::Signer; use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::DSN; use Mail::DKIM2::DSNHeader; use Mail::DKIM2::Signature;
use DKIM2TestKeys; use MIME::Base64 qw(decode_base64);
my $TS = 1740000000;

# a legit single-hop DKIM2 message from test1 to a dkim2.com recipient
my $raw = "From: s\@test1.dkim2.com\r\nTo: r\@dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n";
my $mi  = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($raw));
my $with= "Message-Instance: ".$mi->as_string."\r\n".$raw;
my $sgn = Mail::DKIM2::Signer->new(Domain=>'test1.dkim2.com',Selector=>'rsa1024',
    Key=>DKIM2TestKeys::private_key('test1.dkim2.com','rsa1024'),
    MailFrom=>'sender@test1.dkim2.com', RcptTo=>['r@dkim2.com'], Timestamp=>$TS);
$sgn->PRINT($with); $sgn->CLOSE;
my $signed = $sgn->as_string."\r\n".$with;

my $out = Mail::DKIM2::DSN::generate_dkim2_dsn(raw=>$signed, domain=>'dkim2.com',
    selector=>'rsa1024', key=>DKIM2TestKeys::private_key('dkim2.com','rsa1024'));
my $dsn = $out->{raw};
like($dsn, qr/^DKIM2-DSN:/m,               'DKIM2-DSN header present');
like($dsn, qr{text/rfc822-headers}i,       'embedded original is headers-only');
unlike($dsn, qr/^DKIM2-Signature:/m,       'no DKIM2-Signature of its own');
unlike($dsn, qr/^Message-Instance:/m,      'no Message-Instance of its own');

# rt= must equal the bounced message's top-hop mf=
my ($dsnhdr) = $dsn =~ /^(DKIM2-DSN:.*?)(?=\r\n\S)/ms;
(my $v=$dsnhdr)=~s/^DKIM2-DSN:\s*//s; $v=~s/\r\n[ \t]+//g;
my $p = Mail::DKIM2::DSNHeader->parse($v);
is($p->rcpt_to, '<sender@test1.dkim2.com>', 'rt= == top-hop mf=');
# h= must equal the signed message's top-MI header-hash
my ($topmi) = $signed =~ /^Message-Instance:\s*(.*?)(?=\r\n\S)/ms; $topmi=~s/\r\n[ \t]+//g;
is($p->header_hash, "sha256:".Mail::DKIM2::MessageInstance->parse($topmi)->header_hash,
   'h= == top-MI header-hash');
# signature verifies with dkim2.com key
ok($p->verify(DKIM2TestKeys::private_key('dkim2.com','rsa1024')), 's= verifies');

# no legit chain -> plain DSN, no DKIM2-DSN
my $plain = Mail::DKIM2::DSN::generate_dkim2_dsn(raw=>"From: x\@y\r\nTo: r\@dkim2.com\r\n\r\nb\r\n",
    domain=>'dkim2.com', selector=>'rsa1024', key=>DKIM2TestKeys::private_key('dkim2.com','rsa1024'));
unlike($plain->{raw}, qr/^DKIM2-DSN:/m, 'unsigned input -> no DKIM2-DSN header');
done_testing;
```

- [ ] **Step 3: Run — expect FAIL**

Run: `cd brong && prove -lv t/dsn-generate.t`
Expected: FAIL — `generate_dkim2_dsn` undefined.

- [ ] **Step 4: Implement `generate_dkim2_dsn` in `DSN.pm`**

```perl
use Mail::DKIM2::Verifier;
use Mail::DKIM2::DSNHeader;
use Mail::DKIM2::Signature;
use Mail::DKIM2::MessageInstance;

# Build a DSN for $args->{raw}. If the incoming message has a verifiable DKIM2
# chain, emit a headers-only DSN carrying a DKIM2-DSN header; otherwise a plain
# RFC3464 DSN (delegate to generate()). Returns { raw, send_to }.
sub generate_dkim2_dsn {
    my (%args) = @_;
    my $raw = $args{raw} or croak "generate_dkim2_dsn: need raw";
    my $key = $args{key} // load_private_key($args{keyfile});

    my $v = Mail::DKIM2::Verifier->new;
    $v->set_pubkey_callback($args{pubkey_cb}) if $args{pubkey_cb};
    $v->skip_timestamp_check(1) if $args{skip_timestamp_check};
    $v->PRINT($raw); $v->CLOSE;

    # No legit chain -> plain DSN (existing path), no DKIM2-DSN.
    unless ($v->result =~ /^pass/) {
        return generate({ raw => $raw, signer => _plain_signer(\%args), %args });
    }

    my $msg = Email::MIME->new($raw);
    # top (highest i=) DKIM2-Signature -> its mf= is the bounce destination (rt=)
    my @sigs = map { Mail::DKIM2::Signature->parse($_) } $msg->header_raw('DKIM2-Signature');
    my ($top) = sort { $b->sequence <=> $a->sequence } @sigs;
    my $rt = $top->mail_from;                       # bracketed per this session's work
    # top (highest m=) Message-Instance -> its header-hash is h=
    my @mis = $msg->header_raw('Message-Instance');
    my ($topmi) = sort { ($b=~/m=(\d+)/)[0] <=> ($a=~/m=(\d+)/)[0] } @mis;
    my $hh = Mail::DKIM2::MessageInstance->parse($topmi)->header_hash;

    # Build the DSN: headers-only embedded original + human notice + delivery-status,
    # then the DKIM2-DSN header. Reuse the headers-only construction from propagate().
    my $dsn_text = _build_headers_only_dsn($msg, $rt, \%args);  # multipart/report, text/rfc822-headers
    my $hdr = Mail::DKIM2::DSNHeader->new(
        Domain => $args{domain}, RcptTo => $rt, HeaderHash => $hh,
        Selector => $args{selector}, Key => $key, Algorithm => $args{algorithm} || 'rsa-sha256');
    $dsn_text = $hdr->as_string . "\r\n" . $dsn_text;   # prepend the singleton; no MI/DKIM2-Signature
    return { raw => $dsn_text, send_to => $rt };
}
```

Factor the headers-only DSN body construction (`multipart/report` with a human-readable `text/plain`, a `message/delivery-status`, and a `text/rfc822-headers` part carrying `$msg->header_obj->as_string`) into `_build_headers_only_dsn` by lifting the existing headers-only branch from `propagate` (DSN.pm:214-233) so both share it (DRY). `_plain_signer` builds a `MailFrom => '<>'` signer for the fallback (as the existing `generate` expects).

- [ ] **Step 5: Wire `Reflector::generate_dsn` to use it**

In `brong/lib/Mail/DKIM2/Reflector.pm` `generate_dsn`, replace the current unconditional DSN build with a call to `Mail::DKIM2::DSN::generate_dkim2_dsn` (passing `raw => $args{message}`, `domain`, `selector`, `keyfile`, and the pubkey callback / `skip_timestamp_check` the reflector already uses). Keep the return contract (`{message=>..., send_to=>...}`) that `bin/dkim2-reflector.pl` consumes.

- [ ] **Step 6: Run — expect PASS + full suite**

Run: `cd brong && prove -lv t/dsn-generate.t` then `cd brong && prove -l t/`
Expected: PASS; no regressions (existing `t/dsn.t` still green — adjust only if it asserted the old unconditional behaviour, and only to match the legit-vs-plain split, not weaker).

- [ ] **Step 7: Commit**

```bash
git add brong/lib/Mail/DKIM2/MessageInstance.pm brong/lib/Mail/DKIM2/DSN.pm brong/lib/Mail/DKIM2/Reflector.pm brong/t/dsn-generate.t
git commit -m "dkim2: reflector-dsn emits a DKIM2-DSN header when the bounced chain is legit"
```

---

### Task 3: Handler — verify + undo + relay

**Files:**
- Create: `brong/bin/dkim2-bounces.pl` (the pipe processor)
- Create: `brong/lib/Mail/DKIM2/BounceHandler.pm` (verify + undo + relay logic; keeps the CLI thin/testable)
- Test: `brong/t/dsn-handler.t`

**Interfaces:**
- Consumes: `Mail::DKIM2::DSNHeader` (parse/verify), `Mail::DKIM2::MessageInstance` (`undo`/`chain_verifies`), `Mail::DKIM2::Signature`, `Mail::DKIM2::Common::relaxed_domain_match`.
- Produces: `Mail::DKIM2::BounceHandler::process(%args)` → `{ action => 'relay'|'capture', relay_to => $addr, message => $reconstructed }`. Args: `raw` (the inbound bounce), `pubkey_cb` (for DSNHeader verify).

- [ ] **Step 1: Write the failing test** — `brong/t/dsn-handler.t`:

```perl
#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More; use lib 'lib'; use lib 't/lib';
use Mail::DKIM2::BounceHandler; use Mail::DKIM2::DSN; use DKIM2TestKeys;
use Email::MIME; use Mail::DKIM2::Signer; use Mail::DKIM2::MessageInstance;
my $TS = 1740000000;

# build a legit signed message, then a DKIM2-DSN for it (reuse Task 2)
my $raw = "From: s\@test1.dkim2.com\r\nTo: r\@dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n";
my $mi  = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($raw));
my $with= "Message-Instance: ".$mi->as_string."\r\n".$raw;
my $s = Mail::DKIM2::Signer->new(Domain=>'test1.dkim2.com',Selector=>'rsa1024',
    Key=>DKIM2TestKeys::private_key('test1.dkim2.com','rsa1024'),
    MailFrom=>'sender@test1.dkim2.com',RcptTo=>['r@dkim2.com'],Timestamp=>$TS);
$s->PRINT($with);$s->CLOSE; my $signed=$s->as_string."\r\n".$with;
my $dsn = Mail::DKIM2::DSN::generate_dkim2_dsn(raw=>$signed, domain=>'dkim2.com',
    selector=>'rsa1024', key=>DKIM2TestKeys::private_key('dkim2.com','rsa1024'))->{raw};

my $out = Mail::DKIM2::BounceHandler::process(raw=>$dsn, pubkey_cb=>DKIM2TestKeys::pubkey_callback());
is($out->{action}, 'relay',                     'verified DKIM2-DSN -> relay');
is($out->{relay_to}, 'sender@test1.dkim2.com',  'relays to reconstructed originator (top-hop mf=)');
like($out->{message}, qr/From: s\@test1\.dkim2\.com/, 'reconstructed original headers present');

# a bounce we cannot authenticate -> capture, not relay
my $bad = $dsn; $bad =~ s/(h=sha256:)[^;]+/$1YmFk/;   # break h=
my $cap = Mail::DKIM2::BounceHandler::process(raw=>$bad, pubkey_cb=>DKIM2TestKeys::pubkey_callback());
is($cap->{action}, 'capture', 'unverifiable bounce -> capture (not relayed)');
done_testing;
```

- [ ] **Step 2: Run — expect FAIL**

Run: `cd brong && prove -lv t/dsn-handler.t`
Expected: FAIL — `Mail/DKIM2/BounceHandler.pm` missing.

- [ ] **Step 3: Implement `BounceHandler.pm`**

```perl
package Mail::DKIM2::BounceHandler;
use strict; use warnings;
use Email::MIME;
use Mail::DKIM2::DSNHeader;
use Mail::DKIM2::Signature;
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Common qw(relaxed_domain_match extract_domain);

# Verify a DKIM2-DSN bounce, undo the enclosed chain, and decide relay vs capture.
sub process {
    my (%a) = @_;
    my $msg = eval { Email::MIME->new($a{raw}) } or return { action => 'capture' };
    my ($dhv) = $msg->header_raw('DKIM2-DSN');
    return { action => 'capture' } unless defined $dhv;   # not a DKIM2-DSN
    my $d = Mail::DKIM2::DSNHeader->parse($dhv);

    # locate the embedded original (headers-only)
    my $emb = _embedded_headers($msg) or return { action => 'capture' };
    my $eom = Email::MIME->new($emb);

    # (2) d= must relaxed-match a top-hop rt= domain of the enclosed message
    my @sigs = map { Mail::DKIM2::Signature->parse($_) } $eom->header_raw('DKIM2-Signature');
    my ($top) = sort { $b->sequence <=> $a->sequence } @sigs;
    return { action => 'capture' } unless $top;
    my $rts = $top->rcpt_to || [];
    my $d_ok = grep { relaxed_domain_match(extract_domain($_), $d->domain) } @$rts;
    return { action => 'capture' } unless $d_ok;

    # (3) h= must equal the enclosed top-MI header-hash
    my ($topmi) = sort { ($b=~/m=(\d+)/)[0] <=> ($a=~/m=(\d+)/)[0] } $eom->header_raw('Message-Instance');
    my $hh = $topmi ? Mail::DKIM2::MessageInstance->parse($topmi)->header_hash : '';
    return { action => 'capture' } unless $d->header_hash eq "sha256:$hh";

    # (4) s= must verify with d=/selector key
    my $pub = $a{pubkey_cb} ? $a{pubkey_cb}->(_sig_shim($d)) : $d->_fetch;  # reuse DNS path
    return { action => 'capture' } unless $pub && $d->verify($pub);

    # undo the chain to reconstruct the original as delivered to the top hop
    my $reconstructed = _undo_to_origin($eom->as_string);

    # relay to the reconstructed originator: the top-hop mf= (== the DSN rt=)
    (my $to = $d->rcpt_to) =~ s/^<(.*)>$/$1/;
    return { action => 'relay', relay_to => $to, message => $reconstructed };
}

sub _embedded_headers {  # return the message/rfc822 or text/rfc822-headers part body
    my ($msg) = @_;
    for my $part ($msg->parts) {
        my $ct = $part->content_type // '';
        return $part->body if $ct =~ m{(?:message/rfc822|text/rfc822-headers)}i;
    }
    return;
}

sub _undo_to_origin {   # reverse the MI chain as far as it cleanly undoes
    my ($text) = @_;
    my $cur = $text;
    while (1) {
        my $prev = eval { Mail::DKIM2::MessageInstance->undo(Email::MIME->new($cur)) };
        last unless $prev;
        $cur = ref($prev) ? $prev->as_string : $prev;
    }
    return $cur;
}

sub _sig_shim {  # let a Signature-style pubkey_cb resolve d=/selector for the DSN header
    my ($d) = @_; my $o = bless {}, 'Mail::DKIM2::Signature';
    $o->{tags} = { d => $d->domain };
    $o->{_items} = [[ $d->selector, $d->algorithm, '' ]];
    return $o;
}
1;
```

Match `_undo_to_origin` to the actual `MessageInstance->undo` return contract (Task-2/`MessageInstance.pm:720` — confirm whether it returns an `Email::MIME`, a string, or `(msg,why)`), and `_sig_shim` to what `DKIM2TestKeys::pubkey_callback` / the live `Signature->fetch_public_key` expect (see how `Verifier`/`Signature` call the callback). If `DSNHeader` needs a real DNS fetch in production, add a `->_fetch` that queries `<selector>._domainkey.<d>` exactly as `Signature::fetch_public_key` does (reuse that code).

- [ ] **Step 4: Implement the thin CLI `bin/dkim2-bounces.pl`**

Mirror `bin/dkim2-reflector.pl`'s pipe(8) shape: read the raw bounce from STDIN, call `Mail::DKIM2::BounceHandler::process(raw=>$msg)`, and on `action=>'relay'` submit `message` to the milter-free injector (`127.0.0.1:10588`) with envelope `MAIL FROM <>` / `RCPT TO <relay_to>`; on `action=>'capture'` append to the `reflector-bounces` mbox and log. Reuse the reflector's injector/SMTP submission code.

- [ ] **Step 5: Run — expect PASS + full suite**

Run: `cd brong && prove -lv t/dsn-handler.t` then `cd brong && prove -l t/`
Expected: PASS; no regressions.

- [ ] **Step 6: Commit**

```bash
git add brong/lib/Mail/DKIM2/BounceHandler.pm brong/bin/dkim2-bounces.pl brong/t/dsn-handler.t
git commit -m "dkim2: dkim2-bounces handler — verify DKIM2-DSN, undo chain, relay to originator"
```

---

### Task 4: Deploy wiring — `dkim2-bounces@` address + repoint MAIL FROM

**Files:**
- Modify: `deploy/postfix-dkim2-transport` (route `dkim2-bounces@dkim2.com`)
- Modify: `brong/bin/dkim2-reflector.pl` (envelope `MAIL FROM` → `dkim2-bounces@dkim2.com`)
- Modify: `deploy/reflector-aliases` and `deploy/SERVER.md` (document the address + that unverifiable bounces still fall to the `reflector-bounces` mbox)

**Interfaces:**
- Consumes: `bin/dkim2-bounces.pl` (Task 3).

- [ ] **Step 1: Route the address to a pipe that runs the handler**

Add `reflector-delayedbounce`-style entries: in `deploy/postfix-dkim2-transport` add `dkim2-bounces@dkim2.com  dkim2-bounces:` and add a `dkim2-bounces` `pipe(8)` service to `deploy/postfix-dkim2-reflect.master.cf` whose `argv` runs `/usr/local/bin/dkim2-bounces` with `${sender}`/`${recipient}`, `flags=q user=nobody:nogroup` (mirror the `dkim2-reflect` service). `local_recipient_maps` already covers the map.

- [ ] **Step 2: Repoint the reflector's envelope sender**

In `brong/bin/dkim2-reflector.pl`, change the four `mailfrom => 'reflector-bounces@dkim2.com'` / `$smtp->mail('reflector-bounces@dkim2.com')` sites (lines ~59,74,100,133) to `dkim2-bounces@dkim2.com`, so bounces of reflector-sent mail return to the new handler. Leave the `reflector-bounces` mbox alias in place as the capture sink for unverifiable/unhandled bounces.

- [ ] **Step 3: Verify + document**

Run: `awk 'NF && $1!~/^#/' deploy/postfix-dkim2-transport | grep dkim2-bounces` — expect the new entry. Add a short section to `deploy/SERVER.md` (the reflector setup) describing `dkim2-bounces@`: it is the envelope `MAIL FROM` on reflector-sent mail, verifies+undoes+relays DKIM2-DSN bounces to the reconstructed originator, and falls back to the `reflector-bounces` mbox for anything it can't authenticate. Note in `deploy/reflector-aliases` that `dkim2-bounces` is delivered by the pipe (not an alias).

- [ ] **Step 4: Commit**

```bash
git add deploy/postfix-dkim2-transport deploy/postfix-dkim2-reflect.master.cf brong/bin/dkim2-reflector.pl deploy/reflector-aliases deploy/SERVER.md
git commit -m "deploy: dkim2-bounces@ pipe + repoint reflector MAIL FROM to it"
```

---

## Self-Review

**Spec coverage:**
- `DKIM2-DSN` header format (d=, rt=<b64 bracketed>, h=sha256:headerhash, s=, no t=, MAIL FROM <>, headers-only) → Task 1 (`DSNHeader`) + Global Constraints.
- 4 verification checks → Task 3 `process` (rt/d/h/s) + Task 1 `verify` (s=).
- Generator legit→DKIM2-DSN / no-sig→plain → Task 2 `generate_dkim2_dsn` + Reflector wiring.
- Handler verify+undo+relay, capture-if-unverifiable → Task 3.
- `dkim2-bounces@` = MAIL FROM, supersedes reflector-bounces as source, mbox kept for debug → Task 4.
- Testing (round-trip, tamper, no-sig, handler relay + capture) → tests in Tasks 1–3.
- Out of scope (-03 spec text; Postfix delayed-bounce as DKIM2-DSN) → not in any task (correct).

**Placeholder scan:** No TBD/TODO. Two integration points are named, not hand-waved: (a) exact form of `dkim2_canonicalize_header` (Task 1 Step 3 says match `Signer.pm`'s usage); (b) `MessageInstance->undo`'s return shape and the pubkey-callback shim (Task 3 Step 3 says match the real contract). Both cite the exact file/line to read; full code is given, to be reconciled to the existing signatures.

**Type/name consistency:** `DSNHeader->new(Domain,RcptTo,HeaderHash,Selector,Key,Algorithm)`, `->as_string`, `parse`, `->{domain,rcpt_to,header_hash,selector,algorithm,signature,verify}` used identically in Tasks 1–3; `generate_dkim2_dsn` returns `{raw,send_to}` (Task 2) consumed by Reflector/handler tests; `BounceHandler::process` returns `{action,relay_to,message}` used in Task 3 test and Task 3 Step 4 CLI; `MessageInstance->header_hash` defined in Task 2 Step 1 and used in Tasks 2 & 3.
