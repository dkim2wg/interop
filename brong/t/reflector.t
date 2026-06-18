#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More;
use Email::MIME;
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

done_testing;
