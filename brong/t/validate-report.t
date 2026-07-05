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
    my ($sig2) = grep { $_->{i} == 2 } @sig;
    is($sig2->{domain}, 'test2.dkim2.com', 'sig i=2 domain parsed');
    ok(@{$sig2->{items}} >= 1, 'sig i=2 has at least one item');
    like($sig2->{items}[0]{algorithm}, qr/sha256/, 'sig item algorithm parsed');
    my ($topmi) = grep { $_->{m} == 2 } @mi;
    is($topmi->{header_hash}, 'match', 'top MI header hash match');
    is($topmi->{body_hash}, 'match', 'top MI body hash match');
    is($topmi->{undo}, 'clean', 'top MI undo clean');
}

# 1b) nd= imaginary-hop chain: i=1 carries nd= instead of mf=/rt=. The report's
# per-signature chain-of-custody must recognise nd= and report ok (regression:
# it previously did only the mf/rt check and wrongly showed FAIL on i=2 while
# the overall verdict was pass).
{
    my $msg = Mail::DKIM2::Reflector::generate_brand(
        sender=>'brand@test1.dkim2.com', domain=>'test2.dkim2.com', selector=>'sel1',
        key=>DKIM2TestKeys::private_key('test2.dkim2.com','sel1'),
        mailfrom=>'reflector-bounces@test2.dkim2.com',
        brand_selector=>'dkim2test', brand_key=>DKIM2TestKeys::private_key('test1.dkim2.com','dkim2test'),
        now=>1740000000, delegated=>1, nd=>1);
    my $rep = Mail::DKIM2::Validate::report($msg, %ropt);
    is($rep->{overall}, 'pass', 'nd= chain overall pass');
    my ($sig2) = grep { $_->{kind} eq 'signature' && $_->{i}==2 } @{$rep->{levels}};
    ok($sig2->{custody}{ok}, 'nd= hop: i=2 custody ok (not the stale mf/rt FAIL)');
    like($sig2->{custody}{detail}, qr/nd=test2\.dkim2\.com matches/, 'custody detail explains the nd= match');

    # parsed-tag breakdown for the UI: every tag present, decoded.
    my ($sig1) = grep { $_->{kind} eq 'signature' && $_->{i}==1 } @{$rep->{levels}};
    ok($sig1->{tags} && @{$sig1->{tags}}, 'i=1 has a parsed tag list');
    ok((grep { $_->{tag} eq 'nd' && $_->{value} eq 'test2.dkim2.com' } @{$sig1->{tags}}),
       'i=1 tags include nd=test2.dkim2.com');
    ok(!(grep { $_->{tag} eq 'mf' } @{$sig1->{tags}}), 'i=1 tags omit mf= (nd= hop)');
    # The i=1 sub-verify runs against a partial view (higher DKIM2-Signature
    # headers stripped for the top-down walk), where nd= at i=1 *looks*
    # locally topmost. That must NOT trip the top-nd= rejection -- this is a
    # legitimate non-top nd= hop, not the real top of the chain.
    isnt($sig1->{result}, 'fail', 'i=1 legitimate non-top nd= hop is not flagged fail');
    unlike($sig1->{detail} // '', qr/unexpected nd= tag/,
        'i=1 detail does not wrongly report the top-nd rejection');
    my ($mi1) = grep { $_->{kind} eq 'mi' && $_->{m}==1 } @{$rep->{levels}};
    ok((grep { $_->{tag} eq 'h' && $_->{value} =~ /^sha256:/ } @{$mi1->{tags}}),
       'MI tags expose the full sha256 hash values');
    # The real top-of-chain signature (i=2, no nd=) must never be flagged by
    # the new top-nd check; only the highest-numbered DKIM2-Signature in the
    # whole chain is eligible.
    unlike($sig2->{detail} // '', qr/unexpected nd= tag/,
        'top-of-chain hop (no nd=) is not flagged by the new top-nd check');
}

# 1c) top-level nd=: the highest-numbered DKIM2-Signature carries nd= instead
# of mf=/rt=. Local policy (spec-04, stricter than the letter of the draft;
# matches the Verifier.pm permerror added for Task 2.1) rejects this: the
# report must surface a failing level whose detail matches the same message
# as the Verifier's permerror.
sub signed_input_nd {
    my ($raw, $next_domain) = @_; $raw =~ s/\r?\n/\r\n/g;
    my $m = Email::MIME->new($raw);
    my $mi = Mail::DKIM2::MessageInstance->calculate($m);
    (my $f = fold_header("Message-Instance: ".$mi->as_string)) =~ s/^Message-Instance:\s*//;
    $m->header_raw_prepend('Message-Instance', $f);
    my $s = Mail::DKIM2::Signer->new(
        Domain=>'test1.dkim2.com', Selector=>'sel1',
        Key=>DKIM2TestKeys::private_key('test1.dkim2.com','sel1'),
        NextDomain=>$next_domain,
        Timestamp=>1740000000);
    $s->PRINT($m->as_string); $s->CLOSE;
    (my $sig=$s->as_string)=~s/^DKIM2-Signature:\s*//;
    $m->header_raw_prepend('DKIM2-Signature',$sig);
    return $m->as_string;
}
{
    my $msg = signed_input_nd(
        "From: a\@test1.dkim2.com\r\nTo: r\@test2.dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n",
        'test2.dkim2.com');
    my $rep = Mail::DKIM2::Validate::report($msg, %ropt);
    is($rep->{overall}, 'fail', 'top nd= chain overall fail');
    my ($lvl) = grep { ($_->{result}//'') eq 'fail' && $_->{kind} eq 'signature' }
                @{$rep->{levels}};
    ok($lvl, 'validator reports a failing signature level for top nd=');
    like($lvl->{detail}, qr/unexpected nd= tag/,
         'detail names the top nd= rule');
    is($lvl->{detail}, "DKIM2-Signature i=1 unexpected nd= tag",
       'detail matches the exact canonical message');
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

# 6) old timestamp is a soft warn, not a hard fail
{
    # signed_input uses Timestamp=1740000000 (well over 14 days ago).
    my $in = signed_input("From: a\@test1.dkim2.com\r\nTo: x\@test2.dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n");
    my $rep = Mail::DKIM2::Validate::report($in, pubkey_cb => $cb);  # NO skip_timestamp_check
    is($rep->{overall}, 'warn', 'old signature -> overall warn (not fail)');
    my ($sig1) = grep { $_->{kind} eq 'signature' && $_->{i} == 1 } @{$rep->{levels}};
    is($sig1->{result}, 'warn', 'old signature level is warn');
    is($sig1->{timestamp}{status}, 'old', 'timestamp marked old');
    is($sig1->{items}[0]{result}, 'pass', 'the crypto item still passes');
}

# 7) Received-SPF added by a receiving MTA breaks the hash; report() should
#    strip it and retry, recovering the verdict and saying so.
{
    my $in = signed_input("From: a\@test1.dkim2.com\r\nTo: reflector-body\@test2.dkim2.com\r\nSubject: hi\r\n\r\norig body\r\n");
    my $r2 = Mail::DKIM2::Reflector::reflect(%common, mode=>'body', message=>$in);
    my $good = $r2->{message};

    # sanity: clean message verifies
    is(Mail::DKIM2::Validate::report($good, %ropt)->{overall}, 'pass', 'clean reflected verifies');

    # a folded Received-SPF prepended by the receiver pollutes the header hash
    my $polluted = "Received-SPF: pass\r\n (test.example: 1.2.3.4 authorized)\r\n" . $good;
    my $rep = Mail::DKIM2::Validate::report($polluted, %ropt);
    is($rep->{overall}, 'pass', 'recovered after stripping Received-SPF');
    is_deeply($rep->{stripped_headers}, ['Received-SPF'], 'reports which header was stripped');
    like($rep->{summary}, qr/Received-SPF/, 'summary explains the Received-SPF removal');

    # a genuinely broken message must NOT be rescued just by stripping Received-SPF
    my $broken = $good; $broken =~ s/orig body/evil body/;
    $broken = "Received-SPF: pass\r\n" . $broken;
    is(Mail::DKIM2::Validate::report($broken, %ropt)->{overall}, 'fail',
       'tampered body still fails even with Received-SPF stripped');
}

# 9) mf= decoding to a BARE address (missing RFC5321 angle brackets) must be
#    reported as a failing level whose detail cites the spec 7.5 rule.
{
    use MIME::Base64 qw(encode_base64);
    my $build_signed_message_bare_mf = sub {
        my $in = signed_input("From: a\@test1.dkim2.com\r\nTo: r\@test2.dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n");
        my $bare_b64 = encode_base64('a@test1.dkim2.com', '');
        my $brkt_b64 = encode_base64('<a@test1.dkim2.com>', '');
        (my $bad = $in) =~ s/\Q$brkt_b64\E/$bare_b64/;
        return $bad;
    };
    my $signed = $build_signed_message_bare_mf->();
    my $rep = Mail::DKIM2::Validate::report($signed, %ropt);
    my ($lvl) = grep { ($_->{result}//'') eq 'fail' } @{$rep->{levels}};
    ok($lvl, 'validator reports a failing level for bare mf=');
    like($lvl->{detail}, qr/mf=.*7\.5|bracket/i, 'detail names the mf= bracket rule');
}

# 8) per-hop details: signature From/To + recovered MI recipe values
{
    my $in = signed_input("From: a\@test1.dkim2.com\r\nTo: reflector-both\@test2.dkim2.com\r\nSubject: hi\r\n\r\norig body\r\n");
    my $r2 = Mail::DKIM2::Reflector::reflect(%common, mode=>'both', message=>$in);
    my $rep = Mail::DKIM2::Validate::report($r2->{message}, %ropt);

    my ($sig2) = grep { $_->{kind} eq 'signature' && $_->{i} == 2 } @{$rep->{levels}};
    ok($sig2->{mail_from}, 'sig i=2 has mail_from');
    is(ref $sig2->{rcpt_to}, 'ARRAY', 'sig i=2 rcpt_to is a list');
    ok(scalar @{$sig2->{rcpt_to}}, 'sig i=2 has at least one rcpt_to');

    my ($topmi) = grep { $_->{kind} eq 'mi' && $_->{m} == 2 } @{$rep->{levels}};
    is($topmi->{body_recipe}, 'diff', 'top MI body_recipe is diff');
    my ($subj) = grep { $_->{name} eq 'subject' } @{$topmi->{header_recipes} || []};
    ok($subj, 'top MI has a subject header recipe');
    like($subj->{current},  qr/\Q[DKIM2]\E/, 'subject recipe current is the prefixed subject');
    is($subj->{previous}, 'hi', 'subject recipe previous is the original subject');
}

done_testing;
