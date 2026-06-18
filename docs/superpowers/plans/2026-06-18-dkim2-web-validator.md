# DKIM2 Web Validator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A web form at `https://dkim2.com/validate/` where pasting an email returns a per-level breakdown — the DKIM2-Signature check at each hop and the Message-Instance check at each hop (with undo) — rendered two-column (paste left, outcome right).

**Architecture:** A reusable reporter `Mail::DKIM2::Validate::report()` walks the chain top-down (the `bin/validate.pl` algorithm) collecting structured per-level results without dying. A Perl CGI (`bin/validate.cgi`) exposes it as a JSON API behind nginx+fcgiwrap. A static page + vanilla JS posts the pasted message and renders the JSON.

**Tech Stack:** Perl 5.20+, existing `Mail::DKIM2::{Verifier,MessageInstance,Signature,Common}`, `Email::MIME`, `JSON`; nginx + `fcgiwrap`; static HTML/CSS + dependency-free JS.

## Global Constraints

- DKIM2 + MI only; live DNS for any domain (dns.json override for interop test domains, then `Signature->fetch_public_key` real-DNS fallback).
- The reporter NEVER dies: parse/verify/DNS errors become recorded `fail`/`not-checked` with a `detail`.
- Reuse existing verification logic: per-signature crypto via `Mail::DKIM2::Verifier`; MI hashes via `Mail::DKIM2::MessageInstance` (`h_digest`/`b_digest`/`verify`/`undo`); chain-of-custody/timestamp display via `Common::{extract_domain,relaxed_domain_match}` and `Signature->timestamp`.
- API: `POST /validate/api`, raw `text/plain` body, JSON response, always HTTP 200 (errors inside JSON) except oversize → JSON error. Input cap 256 KB (CGI) + nginx `client_max_body_size`.
- Page at `/validate/`, two-column, responsive, links from the landing page. Right column: verdict banner + one card per level in chain order (top hop first).
- Result schema (see spec `docs/superpowers/specs/2026-06-18-dkim2-web-validator-design.md`): `overall` (`pass|fail|none`), `summary`, `counts{signatures,instances}`, `levels[]` of `kind=signature` or `kind=mi`.
- Tests run from `brong/` (`cd brong && prove -l t/...`).

---

### Task 1: `Mail::DKIM2::Validate` reporter + unit tests

**Files:**
- Create: `brong/lib/Mail/DKIM2/Validate.pm`
- Test: `brong/t/validate-report.t`

**Interfaces:**
- Produces: `Mail::DKIM2::Validate::report($text, %opts) -> \%result` where `%opts` may include `pubkey_cb` (sub) and `skip_timestamp_check` (bool). Result schema as in Global Constraints.

- [ ] **Step 1: Write the failing test** — `brong/t/validate-report.t`:

```perl
#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More;
use Email::MIME;
use lib 'lib', 't/lib';
use Mail::DKIM2::Common qw(fold_header);
use Mail::DKIM2::Signer;
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Reflector;     # reuse to build varied inputs
use DKIM2TestKeys;
use Mail::DKIM2::Validate;

my $cb = DKIM2TestKeys::pubkey_callback();

# Build a signed i=1 message from test1.dkim2.com addressed to test2.
sub signed_input {
    my ($raw) = @_; $raw =~ s/\r?\n/\r\n/g;
    my $m = Email::MIME->new($raw);
    my $mi = Mail::DKIM2::MessageInstance->calculate($m);
    (my $f = fold_header("Message-Instance: ".$mi->as_string)) =~ s/^Message-Instance:\s*//;
    $m->header_raw_prepend('Message-Instance', $f);
    my $s = Mail::DKIM2::Signer->new(
        Domain=>'test1.dkim2.com', Selector=>'sel1',
        Key=>DKIM2TestKeys::private_key('test1.dkim2.com','sel1'),
        MailFrom=>'a@test1.dkim2.com', RcptTo=>['reflector@test2.dkim2.com'],
        Timestamp=>1740000000);
    $s->PRINT($m->as_string); $s->CLOSE;
    (my $sig=$s->as_string)=~s/^DKIM2-Signature:\s*//;
    $m->header_raw_prepend('DKIM2-Signature',$sig);
    return $m->as_string;
}

my %common = (
    sender=>'a@test1.dkim2.com', domain=>'test2.dkim2.com', selector=>'sel1',
    key=>DKIM2TestKeys::private_key('test2.dkim2.com','sel1'),
    mailfrom=>'reflector-bounces@test2.dkim2.com',
    pubkey_cb=>$cb, skip_timestamp_check=>1);
my %ropt = (pubkey_cb=>$cb, skip_timestamp_check=>1);

# 1) Valid 2-hop chain (reflect 'body' -> i=2 + new MI m=2)
{
    my $in = signed_input("From: a\@test1.dkim2.com\r\nTo: reflector-body\@test2.dkim2.com\r\nSubject: hi\r\n\r\norig body\r\n");
    my $r2 = Mail::DKIM2::Reflector::reflect(%common, mode=>'body', message=>$in);
    my $rep = Mail::DKIM2::Validate::report($r2->{message}, %ropt);
    is($rep->{overall}, 'pass', 'valid chain overall pass');
    is($rep->{counts}{signatures}, 2, 'two signatures');
    my @sig = grep { $_->{kind} eq 'signature' } @{$rep->{levels}};
    my @mi  = grep { $_->{kind} eq 'mi' } @{$rep->{levels}};
    is(scalar @sig, 2, 'two signature levels');
    ok(@mi >= 2, 'at least two MI levels');
    is_deeply([map {$_->{result}} @sig], ['pass','pass'], 'both sigs pass');
    my ($topmi) = grep { $_->{m} == 2 } @mi;
    is($topmi->{header_hash}, 'match', 'top MI header hash match');
    is($topmi->{body_hash}, 'match', 'top MI body hash match');
    is($topmi->{undo}, 'clean', 'top MI undo clean');
}

# 2) Post-sign body tamper (damage)
{
    my $in = signed_input("From: a\@test1.dkim2.com\r\nTo: reflector-damage\@test2.dkim2.com\r\nSubject: hi\r\n\r\nclean body\r\n");
    my $r2 = Mail::DKIM2::Reflector::reflect(%common, mode=>'damage', message=>$in);
    my $rep = Mail::DKIM2::Validate::report($r2->{message}, %ropt);
    is($rep->{overall}, 'fail', 'damaged chain overall fail');
    my ($top) = grep { $_->{kind} eq 'mi' } @{$rep->{levels}};
    is($top->{body_hash}, 'mismatch', 'top MI body hash mismatch on damage');
}

# 3) redacted null recipe
{
    my $in = signed_input("From: a\@test1.dkim2.com\r\nTo: reflector-redacted\@test2.dkim2.com\r\nSubject: hi\r\n\r\nsecret\r\n");
    my $r2 = Mail::DKIM2::Reflector::reflect(%common, mode=>'redacted', message=>$in);
    my $rep = Mail::DKIM2::Validate::report($r2->{message}, %ropt);
    is($rep->{overall}, 'pass', 'redacted overall pass (current content valid)');
    my ($top) = grep { $_->{kind} eq 'mi' && $_->{m}==2 } @{$rep->{levels}};
    is($top->{recipe}, 'null', 'redacted top MI recipe=null');
    is($top->{undo}, 'unrecoverable', 'redacted top MI undo=unrecoverable');
}

# 4) no DKIM2 at all
{
    my $rep = Mail::DKIM2::Validate::report("From: x\@a.test\r\nSubject: hi\r\n\r\nhello\r\n", %ropt);
    is($rep->{overall}, 'none', 'no signatures -> none');
    is(scalar @{$rep->{levels}}, 0, 'no levels');
}

# 5) missing DNS key -> signature fails
{
    my $in = signed_input("From: a\@test1.dkim2.com\r\nTo: reflector-raw\@test2.dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n");
    my $r2 = Mail::DKIM2::Reflector::reflect(%common, mode=>'raw', message=>$in);
    my $nokey = sub { return undef };   # no key for anyone
    my $rep = Mail::DKIM2::Validate::report($r2->{message}, pubkey_cb=>$nokey, skip_timestamp_check=>1);
    is($rep->{overall}, 'fail', 'no key -> fail');
    ok((grep { $_->{kind} eq 'signature' && $_->{result} eq 'fail' } @{$rep->{levels}}), 'a signature level failed');
}

done_testing;
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd brong && prove -l t/validate-report.t`
Expected: FAIL — `Can't locate Mail/DKIM2/Validate.pm`.

- [ ] **Step 3: Implement `brong/lib/Mail/DKIM2/Validate.pm`**

```perl
package Mail::DKIM2::Validate;
use strict; use warnings; use 5.020;

use Email::MIME;
use List::Util qw(max);
use Mail::DKIM2::Common qw(extract_mi_version extract_domain relaxed_domain_match parse_dkim_pubkey);
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Verifier;
use Mail::DKIM2::Signature;

sub _i { my $h = shift // ''; $h =~ /\bi=(\d+)/ ? 0 + $1 : 0 }
sub _m { my $h = shift // ''; $h =~ /\bm=(\d+)/ ? 0 + $1 : 0 }

# Default live-DNS pubkey callback (dns.json override if $dns_path given).
sub _default_cb {
    my ($dns_path) = @_;
    my $dns;
    if ($dns_path && -r $dns_path) {
        require JSON;
        open my $fh, '<', $dns_path or undef $fh;
        $dns = $fh ? JSON::decode_json(do { local $/; <$fh> }) : undef;
    }
    return sub {
        my ($sig, $idx) = @_; $idx //= 0;
        my $sel = $sig->selector($idx); my $dom = $sig->domain;
        if ($dns && $dom && $sel) {
            my $t = $dns->{$dom}{"$sel._domainkey"}[0][1];
            return parse_dkim_pubkey($t) if $t;
        }
        return eval { $sig->fetch_public_key($idx) };
    };
}

sub report {
    my ($text, %opts) = @_;
    $text //= '';
    $text =~ s/\r?\n/\r\n/g;
    my $cb = $opts{pubkey_cb} || _default_cb($opts{dns_path});
    my $skip_ts = $opts{skip_timestamp_check} ? 1 : 0;

    my %res = (overall => 'none', summary => '',
               counts => { signatures => 0, instances => 0 }, levels => []);

    my $msg = eval { Email::MIME->new($text) };
    return { %res, overall => 'fail', summary => "could not parse message: $@" }
        if $@ || !$msg;

    my @sig_hdrs = $msg->header('DKIM2-Signature');
    my @mi_hdrs  = $msg->header('Message-Instance');
    $res{counts} = { signatures => scalar @sig_hdrs, instances => scalar @mi_hdrs };
    return { %res, overall => 'none', summary => 'no DKIM2-Signature headers found' }
        unless @sig_hdrs;

    # Overall verdict from the full verifier (includes §10.7 deep MI walk).
    my $v = Mail::DKIM2::Verifier->new;
    $v->skip_timestamp_check(1) if $skip_ts;
    $v->set_pubkey_callback($cb);
    eval { $v->PRINT($text); $v->CLOSE; 1 } or do {};
    my $ov = $v->result // 'fail';
    $res{summary} = $v->result_detail // '';
    $res{overall} = $ov eq 'pass' ? 'pass' : ($ov eq 'none' ? 'none' : 'fail');

    # Per-hop signatures (raw values) for custody comparison.
    my %sig_by_i = map { _i($_) => $_ } @sig_hdrs;

    my @levels;
    my $work = Email::MIME->new($text);
    my $stopped;

    while (1) {
        my %sigmap = map { _i($_) => $_ } $work->header('DKIM2-Signature');
        my %mimap  = map { extract_mi_version($_) => $_ } $work->header('Message-Instance');
        my $num  = %sigmap ? max(keys %sigmap) : 0;
        last unless $num;
        my $sig_m = _m($sigmap{$num});
        my $inst  = %mimap ? max(keys %mimap) : 0;

        # MI levels above this signature's m=, undoing as we go.
        while ($inst > $sig_m) {
            my ($lvl, $undo_after) = _mi_level($work, $inst, $mimap{$inst});
            push @levels, $lvl;
            if ($lvl->{undo} eq 'clean') {
                Mail::DKIM2::MessageInstance->undo($work);
                $work = Email::MIME->new($work->as_string);   # reset Email::MIME caches
                %mimap = map { extract_mi_version($_) => $_ } $work->header('Message-Instance');
                $inst--;
            } else {
                $stopped = "stopped below m=$inst ($lvl->{undo})";
                last;
            }
        }
        last if $stopped;

        push @levels, _sig_level($work, $num, \%sig_by_i, $cb, $skip_ts);

        $work->header_raw_set('DKIM2-Signature',
            grep { _i($_) < $num } $work->header('DKIM2-Signature'));
        last if $num <= 1;
    }

    # Note any hops not reached.
    if ($stopped) {
        $res{summary} = ($res{summary} ? "$res{summary}; " : '') . $stopped;
    }
    $res{levels} = \@levels;
    return \%res;
}

# Returns ($level_hashref) for the top Message-Instance m=$inst of $msg.
sub _mi_level {
    my ($msg, $inst, $mi_raw) = @_;
    my $mi = eval { Mail::DKIM2::MessageInstance->parse($mi_raw) };
    my %lvl = (kind => 'mi', m => $inst, result => 'fail',
               header_hash => 'mismatch', body_hash => 'mismatch',
               recipe => 'none', undo => 'n/a', detail => '');
    unless ($mi) { $lvl{detail} = "unparseable Message-Instance"; return \%lvl; }

    my $h1 = $mi->get_tag('h1'); my $b1 = $mi->get_tag('b1');
    my $hd = Mail::DKIM2::MessageInstance::h_digest($msg);
    my $bd = Mail::DKIM2::MessageInstance::b_digest($msg);
    $lvl{header_hash} = (defined $h1 && $h1 eq $hd) ? 'match' : 'mismatch';
    $lvl{body_hash}   = (defined $b1 && $b1 eq $bd) ? 'match' : 'mismatch';
    $lvl{recipe} = $mi->unrecoverable ? 'null'
                 : ($mi->get_tag('rb') || $mi->get_tag('rh')) ? 'diff' : 'none';

    if ($inst <= 1) {
        $lvl{undo} = 'n/a';
    } elsif ($mi->unrecoverable) {
        $lvl{undo} = 'unrecoverable';
    } else {
        # Probe undo cleanliness on a clone so the caller controls the real undo.
        my $clone = Email::MIME->new($msg->as_string);
        my $ok = eval { Mail::DKIM2::MessageInstance->undo($clone) };
        $lvl{undo} = ($ok && !$@) ? 'clean' : 'failed';
    }

    $lvl{result} = ($lvl{header_hash} eq 'match' && $lvl{body_hash} eq 'match')
                 ? 'pass' : 'fail';
    return \%lvl;
}

# Returns a signature-level hashref for i=$num, verifying the chain prefix on
# the (already MI-reduced) $work message.
sub _sig_level {
    my ($work, $num, $sig_by_i, $cb, $skip_ts) = @_;
    my $raw = $sig_by_i->{$num};
    my $sig = eval { Mail::DKIM2::Signature->parse($raw =~ s/^[^:]*:\s*//r) };
    my %lvl = (kind => 'signature', i => $num, m => _m($raw),
               domain => ($sig ? ($sig->domain // '') : ''),
               items => [], timestamp => { ok => 1, detail => '' },
               custody => { ok => 1, detail => '' }, result => 'fail', detail => '');

    if ($sig) {
        my $n = $sig->sig_count || 0;
        for my $idx (0 .. $n - 1) {
            push @{$lvl{items}}, {
                selector  => ($sig->selector($idx)  // ''),
                algorithm => ($sig->algorithm($idx) // ''),
            };
        }
        # Timestamp (§10.3) — display only.
        unless ($skip_ts) {
            my $ts = $sig->timestamp;
            if (defined $ts && $ts > 0) {
                my $now = time();
                if ($ts > $now + 300) { $lvl{timestamp} = { ok => 0, detail => 'timestamp in the future' }; }
                elsif ($now > $ts + 14*24*3600) { $lvl{timestamp} = { ok => 0, detail => 'older than 14 days' }; }
            }
        }
        # Chain of custody (§8.2) vs previous hop — display only.
        if ($num > 1 && $sig_by_i->{$num - 1}) {
            my $prev = eval { Mail::DKIM2::Signature->parse($sig_by_i->{$num-1} =~ s/^[^:]*:\s*//r) };
            my $mf = $sig->mail_from;
            if ($prev && $mf && $mf ne '<>') {
                my $mfd = extract_domain($mf);
                my @rts = do { my $rt = $prev->rcpt_to; ref $rt eq 'ARRAY' ? @$rt : ($rt // ()) };
                my $ok = grep { relaxed_domain_match($mfd // '', extract_domain($_) // '') } @rts;
                $lvl{custody} = $ok ? { ok => 1, detail => '' }
                                    : { ok => 0, detail => "mf domain $mfd not in previous rt domains" };
            }
        }
    } else {
        $lvl{detail} = 'unparseable DKIM2-Signature';
    }

    # Crypto verdict for the chain prefix through i=$num on the reduced message.
    my $vv = Mail::DKIM2::Verifier->new;
    $vv->skip_timestamp_check(1) if $skip_ts;
    $vv->set_pubkey_callback($cb);
    eval { $vv->PRINT($work->as_string); $vv->CLOSE; 1 } or do {};
    my $r = $vv->result // 'fail';
    $lvl{result} = ($r eq 'pass') ? 'pass' : 'fail';
    $lvl{detail} = $vv->result_detail // $lvl{detail} unless $r eq 'pass';
    $_->{result} = $lvl{result} for @{$lvl{items}};
    return \%lvl;
}

1;

__END__

=head1 NAME

Mail::DKIM2::Validate - structured per-level DKIM2 + Message-Instance report

=head1 DESCRIPTION

C<report($message_text, %opts)> walks a DKIM2 message top-down and returns a
structured breakdown of each DKIM2-Signature and Message-Instance level
(including MI undo), for display by the web validator. Never dies. See
C<docs/superpowers/specs/2026-06-18-dkim2-web-validator-design.md>.

B<EXPERIMENTAL> — implements draft-ietf-dkim-dkim2-spec-02.

=cut
```

- [ ] **Step 4: Run it, verify it passes**

Run: `cd brong && prove -l t/validate-report.t`
Expected: PASS. If the `s///r` non-destructive substitution on a possibly-undef value warns, guard with `($raw // '')`. Adjust only as needed to get green.

- [ ] **Step 5: Full suite regression**

Run: `cd brong && prove -lq t/`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
cd /Users/brong/src/interop
git add brong/lib/Mail/DKIM2/Validate.pm brong/t/validate-report.t
git commit -m "feat(validate): structured per-level DKIM2+MI reporter"
```

---

### Task 2: `validate.cgi` JSON endpoint

**Files:**
- Create: `brong/bin/validate.cgi`
- Test: `brong/t/validate-cgi.t`

**Interfaces:**
- Consumes: `Mail::DKIM2::Validate::report`.
- Produces: a CGI that reads a raw message on STDIN (POST body) and prints a JSON HTTP response.

- [ ] **Step 1: Write `brong/bin/validate.cgi`**

```perl
#!/usr/bin/perl
use 5.020; use strict; use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use JSON ();
use Mail::DKIM2::Validate;

binmode STDIN; binmode STDOUT;
my $MAX = 256 * 1024;
my $dns_path = $ENV{DKIM2_DNS_JSON} || '/root/interop/dns.json';

my $len = $ENV{CONTENT_LENGTH} // 0;
my $body = '';
if ($len) {
    if ($len > $MAX) {
        print "Status: 413 Payload Too Large\r\nContent-Type: application/json\r\n\r\n";
        print JSON::encode_json({ overall => 'fail', summary => 'message too large (max 256 KB)', levels => [] });
        exit 0;
    }
    read(STDIN, $body, $len);
} else {
    local $/; $body = <STDIN> // '';
}

my $rep = eval { Mail::DKIM2::Validate::report($body, dns_path => $dns_path) };
if (my $err = $@) {
    $rep = { overall => 'fail', summary => "internal error: $err", counts => {}, levels => [] };
}

my $json = JSON->new->canonical(1)->encode($rep);
print "Status: 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
print $json;
exit 0;
```

- [ ] **Step 2: Write `brong/t/validate-cgi.t`**

```perl
#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More;
use Path::Tiny;
use JSON ();

my $cgi = path('bin/validate.cgi');
ok($cgi->exists, 'cgi exists');

# Compiles.
my $c = qx{perl -c -Ilib bin/validate.cgi 2>&1};
like($c, qr/syntax OK/, 'cgi compiles');

# Pipe a no-DKIM2 message as a POST body; expect valid JSON with overall=none.
my $body = "From: x\@a.test\r\nSubject: hi\r\n\r\nhello\r\n";
local $ENV{CONTENT_LENGTH} = length($body);
local $ENV{DKIM2_DNS_JSON} = '../dns.json';
my $out = do {
    open my $fh, '|-', "perl -Ilib bin/validate.cgi > /tmp/vcgi.$$.out" or die;
    print $fh $body; close $fh;
    path("/tmp/vcgi.$$.out")->slurp;
};
unlink "/tmp/vcgi.$$.out";
like($out, qr/Content-Type: application\/json/, 'emits json content-type');
my ($json) = $out =~ /\r?\n\r?\n(.*)/s;
my $data = eval { JSON::decode_json($json) };
ok($data, 'body is valid JSON');
is($data->{overall}, 'none', 'no-DKIM2 body -> overall none');

done_testing;
```

- [ ] **Step 3: Run + make executable**

Run: `cd brong && chmod +x bin/validate.cgi && prove -l t/validate-cgi.t`
Expected: PASS. (Adjust the pipe invocation only if your environment needs it; the key asserts are JSON content-type + valid JSON + `overall=none`.)

- [ ] **Step 4: Commit**

```bash
cd /Users/brong/src/interop
chmod +x brong/bin/validate.cgi
git add brong/bin/validate.cgi brong/t/validate-cgi.t
git commit -m "feat(validate): CGI JSON endpoint wrapping the reporter"
```

---

### Task 3: Front-end page (HTML/CSS/JS) + landing link

**Files:**
- Create: `deploy/www/validate/index.html`, `deploy/www/validate/validate.css`, `deploy/www/validate/validate.js`
- Modify: `deploy/www/index.html` (link to the validator)

**Interfaces:**
- Consumes: `POST /validate/api` returning the result JSON.

- [ ] **Step 1: Write `deploy/www/validate/index.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DKIM2 validator</title>
  <meta name="description" content="Paste an email and see a per-level DKIM2 and Message-Instance validation breakdown.">
  <link rel="stylesheet" href="validate.css">
</head>
<body>
  <header>
    <h1>DKIM2 validator</h1>
    <p>Paste a complete email below. Each DKIM2-Signature and Message-Instance
       level is checked, including undo of each instance.
       <a href="/">About DKIM2</a></p>
  </header>
  <main class="cols">
    <section class="pane">
      <label for="msg">Email source</label>
      <textarea id="msg" spellcheck="false" placeholder="Paste the full message, including headers..."></textarea>
      <div class="actions">
        <button id="go">Validate</button>
        <a href="#" id="example">load example</a>
      </div>
    </section>
    <section class="pane">
      <div id="out" class="out"><p class="muted">Results appear here.</p></div>
    </section>
  </main>
  <script src="validate.js"></script>
</body>
</html>
```

- [ ] **Step 2: Write `deploy/www/validate/validate.css`**

```css
:root { --fg:#1a1a1a; --muted:#5a5a5a; --accent:#1d6fb8; --rule:#e2e2e2;
        --pass:#1a7f37; --fail:#c12; --none:#777; --bg:#fff; }
* { box-sizing: border-box; }
body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       color:var(--fg); background:var(--bg); line-height:1.5; }
header { max-width:72rem; margin:0 auto; padding:1.5rem 1.25rem 0.5rem; }
header h1 { margin:0 0 .25rem; }
a { color:var(--accent); }
.cols { max-width:72rem; margin:0 auto; padding:1rem 1.25rem 3rem;
        display:grid; grid-template-columns:1fr 1fr; gap:1.25rem; }
.pane { min-width:0; }
label { display:block; font-weight:600; margin-bottom:.4rem; }
textarea { width:100%; height:60vh; font-family:ui-monospace,Menlo,Consolas,monospace;
           font-size:.85rem; padding:.6rem; border:1px solid var(--rule); border-radius:6px; }
.actions { margin-top:.6rem; display:flex; gap:1rem; align-items:center; }
button { background:var(--accent); color:#fff; border:0; border-radius:6px;
         padding:.5rem 1.1rem; font-size:1rem; cursor:pointer; }
.out { border:1px solid var(--rule); border-radius:6px; padding:1rem; min-height:60vh; }
.muted { color:var(--muted); }
.verdict { font-weight:700; padding:.5rem .8rem; border-radius:6px; color:#fff; margin:0 0 1rem; }
.verdict.pass { background:var(--pass); } .verdict.fail { background:var(--fail); } .verdict.none { background:var(--none); }
.card { border:1px solid var(--rule); border-left-width:5px; border-radius:5px; padding:.6rem .8rem; margin:.6rem 0; }
.card.pass { border-left-color:var(--pass); } .card.fail { border-left-color:var(--fail); }
.card.notchecked { border-left-color:var(--none); }
.card h3 { margin:0 0 .3rem; font-size:1rem; }
.card .kv { font-size:.85rem; color:var(--muted); }
.card code { font-family:ui-monospace,Menlo,Consolas,monospace; }
@media (max-width:48rem){ .cols{ grid-template-columns:1fr; } textarea{height:40vh;} .out{min-height:auto;} }
```

- [ ] **Step 3: Write `deploy/www/validate/validate.js`**

```javascript
(function () {
  var out = document.getElementById('out');
  var ta = document.getElementById('msg');

  function el(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }
  function kv(label, val) { var p = el('div', 'kv'); p.textContent = label + ': ' + val; return p; }

  function render(rep) {
    out.innerHTML = '';
    var verdict = el('p', 'verdict ' + (rep.overall || 'none'), 'Overall: ' + (rep.overall || 'none'));
    out.appendChild(verdict);
    if (rep.summary) out.appendChild(el('p', 'muted', rep.summary));
    (rep.levels || []).forEach(function (lvl) {
      var cls = lvl.result === 'pass' ? 'pass' : (lvl.result === 'not-checked' ? 'notchecked' : 'fail');
      var card = el('div', 'card ' + cls);
      if (lvl.kind === 'signature') {
        card.appendChild(el('h3', null, 'DKIM2-Signature i=' + lvl.i + ' (m=' + lvl.m + ') — ' + lvl.result));
        card.appendChild(kv('domain', lvl.domain || ''));
        (lvl.items || []).forEach(function (it) { card.appendChild(kv('item', it.selector + ' / ' + it.algorithm + ' → ' + (it.result || ''))); });
        if (lvl.timestamp) card.appendChild(kv('timestamp', lvl.timestamp.ok ? 'ok' : ('FAIL — ' + lvl.timestamp.detail)));
        if (lvl.custody) card.appendChild(kv('chain-of-custody', lvl.custody.ok ? 'ok' : ('FAIL — ' + lvl.custody.detail)));
      } else {
        card.appendChild(el('h3', null, 'Message-Instance m=' + lvl.m + ' — ' + lvl.result));
        card.appendChild(kv('header hash', lvl.header_hash));
        card.appendChild(kv('body hash', lvl.body_hash));
        card.appendChild(kv('recipe', lvl.recipe));
        card.appendChild(kv('undo', lvl.undo));
      }
      if (lvl.detail) card.appendChild(kv('detail', lvl.detail));
      out.appendChild(card);
    });
  }

  function validate() {
    out.innerHTML = '<p class="muted">Validating…</p>';
    fetch('/validate/api', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: ta.value })
      .then(function (r) { return r.json(); })
      .then(render)
      .catch(function (e) { out.innerHTML = ''; out.appendChild(el('p', 'verdict fail', 'Request failed: ' + e)); });
  }

  document.getElementById('go').addEventListener('click', validate);
  document.getElementById('example').addEventListener('click', function (ev) {
    ev.preventDefault();
    ta.value = 'Paste a real DKIM2-signed message here.\n(Tip: send mail through one of the reflector addresses, then paste the reply.)\n';
  });
})();
```

- [ ] **Step 4: Add a link from the landing page** — in `deploy/www/index.html`, inside the "Learn more" `<ul>`, add as the first item:

```html
        <li><a href="/validate/">Validate a DKIM2 message</a> — paste an email
          for a per-level breakdown</li>
```

- [ ] **Step 5: Validate HTML + commit**

Run:
```bash
cd /Users/brong/src/interop
xmllint --html --noout deploy/www/validate/index.html 2>&1 | grep -v "Tag .* invalid" ; echo "checked"
git add deploy/www/validate/ deploy/www/index.html
git commit -m "feat(validate): two-column validator front-end + landing link"
```
(HTML5 sectioning-tag warnings from the old libxml DTD are expected/benign.)

---

### Task 4: Deploy (fcgiwrap + nginx) + end-to-end

**Files:**
- Modify: `deploy/SERVER.md`
- Server (documented): install `fcgiwrap`; nginx `/validate/` + `/validate/api`; deploy CGI + static.

**Interfaces:**
- Consumes: deployed libs (`make install`), CGI, static files.
- Produces: live `https://dkim2.com/validate/`.

- [ ] **Step 1: Install fcgiwrap on the server**

```bash
ssh dkim2 'DEBIAN_FRONTEND=noninteractive apt-get install -y fcgiwrap >/dev/null 2>&1; \
  systemctl enable --now fcgiwrap.socket 2>/dev/null; \
  ls -l /run/fcgiwrap.socket 2>/dev/null || ls -l /var/run/fcgiwrap.socket 2>/dev/null; echo done'
```
Expected: a fcgiwrap socket path printed. Note the actual socket path for nginx.

- [ ] **Step 2: Deploy libs, CGI, and static files**

```bash
cd /Users/brong/src/interop && git push origin master
ssh dkim2 'set -e
  cd /root/interop && git pull --ff-only
  cd brong && perl Makefile.PL >/dev/null && make >/dev/null && make install >/dev/null
  install -m 755 bin/validate.cgi /usr/local/bin/dkim2-validate.cgi
  install -d /var/www/dkim2.com/validate
  install -m 644 ../deploy/www/validate/index.html ../deploy/www/validate/validate.css ../deploy/www/validate/validate.js /var/www/dkim2.com/validate/
  install -m 644 ../deploy/www/index.html /var/www/dkim2.com/index.html
  echo DEPLOYED'
```

- [ ] **Step 3: Add nginx locations to the dkim2.com 443 server block**

Edit `/etc/nginx/sites-available/dkim2.com` — inside the `listen 443 ssl default_server` block (the apex), add before the `location / {` block (use the fcgiwrap socket path from Step 1, e.g. `unix:/run/fcgiwrap.socket`):
```
    location = /validate/api {
        client_max_body_size 512k;
        include /etc/nginx/fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /usr/local/bin/dkim2-validate.cgi;
        fastcgi_param DKIM2_DNS_JSON  /root/interop/dns.json;
        fastcgi_pass unix:/run/fcgiwrap.socket;
    }
    location /validate/ {
        alias /var/www/dkim2.com/validate/;
        index index.html;
    }
```
Then:
```bash
ssh dkim2 'nginx -t && systemctl reload nginx && echo NGINX_OK'
```
Expected: `NGINX_OK`.

- [ ] **Step 4: End-to-end checks**

```bash
# page loads
curl -sS -o /dev/null -w "page %{http_code}\n" https://dkim2.com/validate/
# API: no-DKIM2 body -> overall none
curl -sS -X POST --data-binary $'From: x@a.test\r\nSubject: hi\r\n\r\nhello\r\n' \
  -H 'Content-Type: text/plain' https://dkim2.com/validate/api | head -c 400; echo
# API: a real signed message -> pass (build one on the server and post it)
ssh dkim2 'cd /root/interop/brong && perl -e '"'"'
use lib "lib","t/lib"; use Email::MIME; use Mail::DKIM2::Common qw(fold_header);
use Mail::DKIM2::Signer; use Mail::DKIM2::MessageInstance; use DKIM2TestKeys;
my $m=Email::MIME->new("From: a\@test1.dkim2.com\r\nTo: x\@test2.dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n");
my $mi=Mail::DKIM2::MessageInstance->calculate($m); (my $f=fold_header("Message-Instance: ".$mi->as_string))=~s/^Message-Instance:\s*//; $m->header_raw_prepend("Message-Instance",$f);
my $s=Mail::DKIM2::Signer->new(Domain=>"test1.dkim2.com",Selector=>"sel1",Key=>DKIM2TestKeys::private_key("test1.dkim2.com","sel1"),MailFrom=>"a\@test1.dkim2.com",RcptTo=>["x\@test2.dkim2.com"],Timestamp=>time());
$s->PRINT($m->as_string);$s->CLOSE;(my $sig=$s->as_string)=~s/^DKIM2-Signature:\s*//;$m->header_raw_prepend("DKIM2-Signature",$sig);
open my $fh,">","/tmp/signed.eml"; print $fh $m->as_string; '"'"' && \
  curl -sS -X POST --data-binary @/tmp/signed.eml -H "Content-Type: text/plain" https://dkim2.com/validate/api | head -c 300; echo; rm -f /tmp/signed.eml'
```
Expected: page `200`; first API call shows `"overall":"none"`; signed message shows `"overall":"pass"` with signature + MI levels.

- [ ] **Step 5: Document in SERVER.md + commit**

Add a "DKIM2 Validator" subsection to `deploy/SERVER.md`: the `/validate/` page + `/validate/api` endpoint, fcgiwrap + the nginx locations, the `dkim2-validate.cgi` path, `Mail::DKIM2::Validate`, and the deploy commands. Then:
```bash
cd /Users/brong/src/interop
git add deploy/SERVER.md
git commit -m "docs: document DKIM2 validator endpoint and deploy"
git push origin master
```

---

## Self-Review

**1. Spec coverage:**
- Reporter with structured per-level output (signature + MI incl. undo) → Task 1. ✓
- Live DNS (dns.json + fetch_public_key) → `_default_cb`, CGI `DKIM2_DNS_JSON`. ✓
- Never dies → eval guards throughout Task 1/2. ✓
- JSON API `/validate/api`, raw POST, 256 KB cap, always-200-except-oversize → Task 2. ✓
- Two-column page, verdict banner + per-level cards, responsive, landing link → Task 3. ✓
- nginx + fcgiwrap, input caps → Task 4 + Task 2. ✓
- Overall pass/fail/none incl. redacted=pass with lower not-checked → Task 1 (overall from Verifier; `_mi_level` undo=unrecoverable stops descent). ✓
- Tests: good chain, body tamper, broken/missing sig (missing key), redacted, none → Task 1; CGI JSON → Task 2; server e2e → Task 4. ✓

**2. Placeholder scan:** No TBD/TODO; full code for module, CGI, HTML/CSS/JS, nginx snippets, deploy commands. Task 3 Step 4 and Task 4 Steps 3/5 are concrete edits/snippets. ✓

**3. Type consistency:** Result keys (`overall`/`summary`/`counts`/`levels`) and level fields (`kind`,`i`,`m`,`domain`,`items`,`timestamp`,`custody`,`header_hash`,`body_hash`,`recipe`,`undo`,`result`,`detail`) are produced in Task 1 and consumed identically by the JS in Task 3 and the CGI passthrough in Task 2. `report()` opts (`pubkey_cb`,`skip_timestamp_check`,`dns_path`) consistent across module, tests, CGI. ✓
