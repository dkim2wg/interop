#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More; use lib 'lib'; use lib 't/lib';
use Email::MIME; use Mail::DKIM2::Signer; use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::DSN; use Mail::DKIM2::DSNHeader; use Mail::DKIM2::Signature;
use DKIM2TestKeys; use MIME::Base64 qw(decode_base64);
my $TS = 1740000000;

# a legit single-hop DKIM2 message from test1 to a test2.dkim2.com recipient.
# (There is no dkim2.com test key/DNS entry, so the top hop's recipient -- and
# therefore the bouncing domain, which must relaxed-match the top-hop rt= -- is
# test2.dkim2.com here instead of dkim2.com.)
my $raw = "From: s\@test1.dkim2.com\r\nTo: r\@test2.dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n";
my $mi  = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($raw));
my $with= "Message-Instance: ".$mi->as_string."\r\n".$raw;
my $sgn = Mail::DKIM2::Signer->new(Domain=>'test1.dkim2.com',Selector=>'rsa1024',
    Key=>DKIM2TestKeys::private_key('test1.dkim2.com','rsa1024'),
    MailFrom=>'sender@test1.dkim2.com', RcptTo=>['r@test2.dkim2.com'], Timestamp=>$TS);
$sgn->PRINT($with); $sgn->CLOSE;
my $signed = $sgn->as_string."\r\n".$with;

my $out = Mail::DKIM2::DSN::generate_dkim2_dsn(raw=>$signed, domain=>'test2.dkim2.com',
    selector=>'rsa1024', key=>DKIM2TestKeys::private_key('test2.dkim2.com','rsa1024'),
    pubkey_cb=>DKIM2TestKeys::pubkey_callback(), skip_timestamp_check=>1);
my $dsn = $out->{raw};
like($dsn, qr/^DKIM2-DSN:/m,               'DKIM2-DSN header present');
like($dsn, qr{text/rfc822-headers}i,       'embedded original is headers-only');
# Scope the "of its own" checks to the DSN's OWN top-level header block (before
# the first MIME part boundary) -- the embedded original's headers (including
# its own DKIM2-Signature/Message-Instance) are legitimately present verbatim
# further down, inside the text/rfc822-headers part.
my ($dsn_own_headers) = $dsn =~ /\A(.*?)\r\n\r\n/s;
unlike($dsn_own_headers, qr/^DKIM2-Signature:/m,  'no DKIM2-Signature of its own');
unlike($dsn_own_headers, qr/^Message-Instance:/m, 'no Message-Instance of its own');

# rt= must equal the bounced message's top-hop mf=
my ($dsnhdr) = $dsn =~ /^(DKIM2-DSN:.*?)(?=\r\n\S)/ms;
(my $v=$dsnhdr)=~s/^DKIM2-DSN:\s*//s; $v=~s/\r\n[ \t]+//g;
my $p = Mail::DKIM2::DSNHeader->parse($v);
is($p->rcpt_to, '<sender@test1.dkim2.com>', 'rt= == top-hop mf=');
# h= must equal the signed message's top-MI header-hash
my ($topmi) = $signed =~ /^Message-Instance:\s*(.*?)(?=\r\n\S)/ms; $topmi=~s/\r\n[ \t]+//g;
is($p->header_hash, "sha256:".Mail::DKIM2::MessageInstance->parse($topmi)->header_hash,
   'h= == top-MI header-hash');
# signature verifies with test2.dkim2.com key
ok($p->verify(DKIM2TestKeys::private_key('test2.dkim2.com','rsa1024')), 's= verifies');

# no legit chain -> plain DSN, no DKIM2-DSN
my $plain = Mail::DKIM2::DSN::generate_dkim2_dsn(raw=>"From: x\@y\r\nTo: r\@test2.dkim2.com\r\n\r\nb\r\n",
    domain=>'test2.dkim2.com', selector=>'rsa1024', key=>DKIM2TestKeys::private_key('test2.dkim2.com','rsa1024'),
    pubkey_cb=>DKIM2TestKeys::pubkey_callback(), skip_timestamp_check=>1);
unlike($plain->{raw}, qr/^DKIM2-DSN:/m, 'unsigned input -> no DKIM2-DSN header');
done_testing;
