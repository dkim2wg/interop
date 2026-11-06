#!/usr/bin/perl -w
# RFC 5322's obsolete syntax lets WSP sit between a field name and its colon
# ("From : x"), and -09 section 6.2 deletes it: the name is the name without
# it. Taking the WSP as part of the name made "From : ceo@paypal.example" a
# field called "from " -- hashed, so intact, but invisible to the From check,
# which saw only the other From. A reader that shows the first From showed
# paypal.example as authenticated.
use 5.020;
use strict;
use warnings;
use Test::More;
use lib 'lib', 't/lib';
use DKIM2TestKeys;
use Mail::DKIM2::Common qw(dkim2_canonicalize_header);
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Signer;
use Mail::DKIM2::Verifier;

is(dkim2_canonicalize_header("Subject : hi\r\n"), "subject:hi\r\n",
   'canonical form: WSP before the colon is deleted');
is(dkim2_canonicalize_header("Subject\t:  hi\r\n"), "subject:hi\r\n", '  ... tab too');

# Sign as test1.dkim2.com with its own From check off, as a signer that does
# not check (or another implementation) would.
sub signed {
    my ($raw) = @_;
    my $mi  = Mail::DKIM2::MessageInstance->calculate($raw);
    my $msg = "Message-Instance: " . $mi->as_string . "\r\n$raw";
    no warnings 'redefine';
    local *Mail::DKIM2::Common::from_pair_error = sub { undef };
    my $s = Mail::DKIM2::Signer->new(
        Domain => 'test1.dkim2.com', Selector => 'sel1',
        Key => DKIM2TestKeys::private_key('test1.dkim2.com', 'sel1'),
        MailFrom => 'a@test1.dkim2.com', RcptTo => ['b@test2.dkim2.com'],
        Timestamp => 1740000000,
    );
    $s->PRINT($msg); $s->CLOSE;
    (my $sig = $s->as_string) =~ s/\r?\n\z//;
    return "$sig\r\n$msg";
}

sub verify {
    my ($msg, $stream) = @_;
    my $v = Mail::DKIM2::Verifier->new(
        PubkeyCallback => DKIM2TestKeys::pubkey_callback(), StreamBody => $stream);
    $v->skip_timestamp_check(1);
    $v->PRINT($msg); $v->CLOSE;
    return ($v->result, $v->result_detail);
}

for my $ws (' ', "\t") {
    my $label = $ws eq ' ' ? 'space' : 'tab';
    my $msg = signed("From${ws}: CEO <ceo\@paypal.example>\r\n"
                   . "From: a\@test1.dkim2.com\r\nTo: b\@test2.dkim2.com\r\n"
                   . "Subject: pay\r\n\r\nbody\r\n");
    for my $stream (1, 0) {
        my ($r, $d) = verify($msg, $stream);
        isnt($r, 'pass', "From${label}: is a second From (StreamBody=$stream)");
        like($d, qr/From/, '  ... and the From check says so') or diag $d;
    }
}

# The name without its WSP is the name: "Subject :" hashes as Subject, so a
# Subject written either way verifies, and either way written by a hop
# that rewrote it is the same field.
{
    my $msg = signed("From: a\@test1.dkim2.com\r\nTo: b\@test2.dkim2.com\r\n"
                   . "Subject : hello\r\n\r\nbody\r\n");
    for my $stream (1, 0) {
        my ($r, $d) = verify($msg, $stream);
        is($r, 'pass', "Subject with WSP before the colon verifies (StreamBody=$stream)") or diag $d;
    }
    (my $respelled = $msg) =~ s/^Subject : hello/Subject: hello/m;
    my ($r, $d) = verify($respelled, 1);
    is($r, 'pass', 'and is the same field without the WSP') or diag $d;
}

done_testing;
