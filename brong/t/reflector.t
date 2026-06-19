#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More;
use Email::MIME;
use MIME::Base64 qw(decode_base64);
use lib 'lib', 't/lib';
use Mail::DKIM2::Common qw(fold_header);
use Mail::DKIM2::Verifier;
use Mail::DKIM2::Signer;
use Mail::DKIM2::MessageInstance;
use DKIM2TestKeys;
use Mail::DKIM2::Reflector;

# Build a known-good DKIM2-signed message (i=1) from test1.dkim2.com.
# Mirrors the full-chain.t pattern: add MI, then sign over it.
sub signed_input {
    my ($raw) = @_;
    $raw =~ s/\r?\n/\r\n/g;
    my $msg = Email::MIME->new($raw);
    my $mi  = Mail::DKIM2::MessageInstance->calculate($msg);
    my $folded = fold_header("Message-Instance: " . $mi->as_string);
    $folded =~ s/^Message-Instance:\s*//;
    $msg->header_raw_prepend('Message-Instance', $folded);
    my $signer = Mail::DKIM2::Signer->new(
        Domain => 'test1.dkim2.com', Selector => 'sel1',
        Key => DKIM2TestKeys::private_key('test1.dkim2.com', 'sel1'),
        MailFrom => 'a@test1.dkim2.com', RcptTo => ['reflector@test2.dkim2.com'],
        Timestamp => 1740000000,
    );
    $signer->PRINT($msg->as_string); $signer->CLOSE;
    (my $sig = $signer->as_string) =~ s/^DKIM2-Signature:\s*//;
    $msg->header_raw_prepend('DKIM2-Signature', $sig);
    return $msg->as_string;
}

my $cb = DKIM2TestKeys::pubkey_callback();
my %common = (
    sender    => 'a@test1.dkim2.com',         # reflect target (rt of our sig)
    domain    => 'test2.dkim2.com',           # reflector identity (test key)
    selector  => 'sel1',
    mailfrom  => 'reflector-bounces@test2.dkim2.com',  # d= must suffix mf domain
    key       => DKIM2TestKeys::private_key('test2.dkim2.com', 'sel1'),
    pubkey_cb => $cb,
    skip_timestamp_check => 1,
);

sub reflected_verifies {
    my ($text) = @_;
    my $v = Mail::DKIM2::Verifier->new; $v->skip_timestamp_check(1);
    $v->set_pubkey_callback($cb); $v->PRINT($text); $v->CLOSE;
    return $v->result;
}

# --- raw + passing input -> signed, no new MI, verifies at the recipient ---
{
    my $in = signed_input("From: a\@test1.dkim2.com\r\nTo: reflector-raw\@dkim2.com\r\nSubject: hi\r\n\r\noriginal body\r\n");
    my $r = Mail::DKIM2::Reflector::reflect(%common, mode => 'raw', message => $in);
    is($r->{auth}, 'pass', 'raw: incoming verified');
    is($r->{signed}, 1, 'raw: signed because auth passed');
    like($r->{message}, qr/^DKIM2-Signature:/m, 'raw: has a DKIM2-Signature');
    like($r->{message}, qr/^X-DKIM2-Reflector:.*mode=raw.*signed=yes/m, 'raw: X- header');
    like($r->{message}, qr/^Authentication-Results:/m, 'raw: A-R header');
    my @mi = (Email::MIME->new($r->{message}))->header_raw('Message-Instance');
    is(scalar @mi, 1, 'raw: no NEW MI added (still just m=1)');
    is(reflected_verifies($r->{message}), 'pass', 'raw: reflected message verifies');
}

# --- failing input (no DKIM2) -> not signed, headers present ---
{
    my $unsigned = "From: x\@example.org\r\nTo: reflector-raw\@dkim2.com\r\nSubject: hi\r\n\r\nhello\r\n";
    my $r = Mail::DKIM2::Reflector::reflect(%common, mode => 'raw', message => $unsigned);
    isnt($r->{auth}, 'pass', 'no-DKIM2 input does not pass');
    is($r->{signed}, 0, 'not signed when auth fails');
    unlike($r->{message}, qr/^DKIM2-Signature:/m, 'no reflector signature on fail');
    like($r->{message}, qr/^X-DKIM2-Reflector:.*signed=no/m, 'X- header shows signed=no');
}

# --- subject / body / both: new MI with recipes; verifies; undo restores ---
for my $case (
    { mode => 'subject', restores_subject => 1, restores_body => 0 },
    { mode => 'body',    restores_subject => 0, restores_body => 1 },
    { mode => 'both',    restores_subject => 1, restores_body => 1 },
) {
    my $m = $case->{mode};
    my $in = signed_input(
        "From: a\@test1.dkim2.com\r\nTo: reflector-$m\@test2.dkim2.com\r\nSubject: hello\r\n\r\noriginal body\r\n");
    my $r = Mail::DKIM2::Reflector::reflect(%common, mode => $m, message => $in);
    is($r->{signed}, 1, "$m: signed");

    my $msg = Email::MIME->new($r->{message});
    my @mi  = $msg->header_raw('Message-Instance');
    is(scalar @mi, 2, "$m: a new MI was added (now 2)");

    like($msg->header('Subject'), qr/^\Q[DKIM2]\E /, "$m: subject prefixed")
        if $m ne 'body';
    like($r->{message}, qr/Reflected and signed by the DKIM2 reflector/, "$m: footer added")
        if $m ne 'subject';

    is(reflected_verifies($r->{message}), 'pass', "$m: reflected verifies");

    my $undone = Mail::DKIM2::MessageInstance->undo(Email::MIME->new($r->{message}));
    is($undone->header('Subject'), 'hello', "$m: undo restores subject")
        if $case->{restores_subject};
    unlike($undone->body_raw, qr/Reflected and signed/, "$m: undo restores body")
        if $case->{restores_body};
}

# --- redacted: footer added, MI body recipe null, verifies, but undo can't recover ---
{
    my $in = signed_input(
        "From: a\@test1.dkim2.com\r\nTo: reflector-redacted\@test2.dkim2.com\r\nSubject: hi\r\n\r\nsecret body\r\n");
    my $r = Mail::DKIM2::Reflector::reflect(%common, mode => 'redacted', message => $in);
    is($r->{signed}, 1, 'redacted: signed');

    # Find the highest-m MI and check its recipe is b:null (base64 JSON).
    my @mi = (Email::MIME->new($r->{message}))->header_raw('Message-Instance');
    my ($top) = sort {
        Mail::DKIM2::MessageInstance->parse($b)->get_tag('m')
            <=> Mail::DKIM2::MessageInstance->parse($a)->get_tag('m')
    } @mi;
    my ($rtag) = $top =~ /r=([^;\s]+)/;
    ok($rtag, 'redacted: top MI has an r= tag');
    like(decode_base64($rtag), qr/"b"\s*:\s*null/, 'redacted: null body recipe');

    is(reflected_verifies($r->{message}), 'pass', 'redacted: reflected verifies (current content)');

    my $undone = Mail::DKIM2::MessageInstance->undo(Email::MIME->new($r->{message}));
    like($undone->body_raw, qr/Reflected and signed/, 'redacted: body NOT recoverable (footer remains)');
}

# --- damage: signed correctly, then a line appended -> recipient verify FAILS ---
{
    my $in = signed_input(
        "From: a\@test1.dkim2.com\r\nTo: reflector-damage\@test2.dkim2.com\r\nSubject: hi\r\n\r\nclean body\r\n");
    my $r = Mail::DKIM2::Reflector::reflect(%common, mode => 'damage', message => $in);
    is($r->{signed}, 1, 'damage: a signature was produced');
    like($r->{message}, qr/damage line, breaks the signature/, 'damage: breaking line appended');
    # The signature crypto is intact, but the verifier now enforces §10.7:
    # the top MI body hash no longer matches the post-sign body -> reject.
    is(reflected_verifies($r->{message}), 'fail',
       'damage: verifier rejects (MI body hash mismatch, §10.7)');
    ok(!Mail::DKIM2::MessageInstance->verify(Email::MIME->new($r->{message})),
       'damage: top MI body hash no longer matches content');
}

# --- Postfix local(8) pipe prologue: a leading mbox "From " line is stripped ---
# Postfix prepends a Unix mailbox "From sender timestamp" envelope line (no
# colon) when piping a message to an alias command. If it survives into the
# reflected message it prematurely terminates the header block when the reply
# is re-injected, dumping every real header into the body.
{
    my $prologue = "From a\@test1.dkim2.com  Fri Jun 19 05:07:56 2026\r\n";
    my $in = signed_input(
        "From: a\@test1.dkim2.com\r\nTo: reflector-raw\@dkim2.com\r\nSubject: hi\r\n\r\noriginal body\r\n");
    my $r = Mail::DKIM2::Reflector::reflect(%common, mode => 'raw', message => $prologue . $in);
    unlike($r->{message}, qr/^From [^\r\n]*\r\n/m,
        'mbox From_ prologue line stripped (no bare "From " line survives)');
    is(reflected_verifies($r->{message}), 'pass',
        'reflected message still verifies after prologue stripped');
}

done_testing;
