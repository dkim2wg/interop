#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More; use lib 'lib'; use lib 't/lib';
use Mail::DKIM2::BounceHandler; use Mail::DKIM2::DSN; use DKIM2TestKeys;
use Email::MIME; use Mail::DKIM2::Signer; use Mail::DKIM2::MessageInstance;
my $TS = 1740000000;

# Build a legit signed message from test1.dkim2.com to a recipient at
# test2.dkim2.com, then a DKIM2-DSN for it (reuse Task 2's generator). There
# is no dkim2.com test key/DNS entry, so the bouncing domain (which must
# relaxed-match the top-hop rt=) is test2.dkim2.com, not dkim2.com.
my $raw = "From: s\@test1.dkim2.com\r\nTo: r\@test2.dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n";
my $mi  = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($raw));
my $with= "Message-Instance: ".$mi->as_string."\r\n".$raw;
my $s = Mail::DKIM2::Signer->new(Domain=>'test1.dkim2.com',Selector=>'rsa1024',
    Key=>DKIM2TestKeys::private_key('test1.dkim2.com','rsa1024'),
    MailFrom=>'sender@test1.dkim2.com',RcptTo=>['r@test2.dkim2.com'],Timestamp=>$TS);
$s->PRINT($with);$s->CLOSE; my $signed=$s->as_string."\r\n".$with;
my $dsn = Mail::DKIM2::DSN::generate_dkim2_dsn(raw=>$signed, domain=>'test2.dkim2.com',
    selector=>'rsa1024', key=>DKIM2TestKeys::private_key('test2.dkim2.com','rsa1024'),
    pubkey_cb=>DKIM2TestKeys::pubkey_callback(), skip_timestamp_check=>1)->{raw};

my $out = Mail::DKIM2::BounceHandler::process(raw=>$dsn, pubkey_cb=>DKIM2TestKeys::pubkey_callback());
is($out->{action}, 'relay',                     'verified DKIM2-DSN -> relay');
is($out->{relay_to}, 'sender@test1.dkim2.com',  'relays to reconstructed originator (top-hop mf=)');
like($out->{message}, qr/From: s\@test1\.dkim2\.com/, 'reconstructed original headers present');

# a bounce we cannot authenticate -> capture, not relay
my $bad = $dsn; $bad =~ s/(h=sha256:)[^;]+/$1YmFk/;   # break h=
my $cap = Mail::DKIM2::BounceHandler::process(raw=>$bad, pubkey_cb=>DKIM2TestKeys::pubkey_callback());
is($cap->{action}, 'capture', 'unverifiable bounce -> capture (not relayed)');
done_testing;
