#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More; use lib 'lib'; use lib 't/lib';
use Mail::DKIM2::DSNHeader; use DKIM2TestKeys;
use Email::MIME; use Mail::DKIM2::Signer; use Mail::DKIM2::MessageInstance;

# The DKIM2-DSN signs the returned message's Message-Instance + DKIM2-Signature
# chain, so build a real signed returned message to sign/verify over. The
# shared fixtures only publish keys for test1.dkim2.com .. test5.dkim2.com.
my $DOMAIN = 'test1.dkim2.com';
my $TS = 1740000000;

my $raw  = "From: s\@test1.dkim2.com\r\nTo: r\@test2.dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n";
my $mi   = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($raw));
my $with = "Message-Instance: ".$mi->as_string."\r\n".$raw;
my $s = Mail::DKIM2::Signer->new(Domain=>$DOMAIN, Selector=>'rsa1024',
    Key=>DKIM2TestKeys::private_key($DOMAIN,'rsa1024'),
    MailFrom=>'sender@test1.dkim2.com', RcptTo=>['r@test2.dkim2.com'], Timestamp=>$TS);
$s->PRINT($with); $s->CLOSE;
my $eom = Email::MIME->new($s->as_string."\r\n".$with);

my $h  = Mail::DKIM2::DSNHeader->new(
    Domain => $DOMAIN, RcptTo => 'bounce@sender.example',
    Selector => 'rsa1024',
    Key => DKIM2TestKeys::private_key($DOMAIN,'rsa1024'), Algorithm => 'rsa-sha256',
    Returned => $eom);
my $line = $h->as_string;
like($line,   qr/^DKIM2-DSN:/,           'emits a DKIM2-DSN header');
like($line,   qr/d=\Q$DOMAIN\E/,         'has d=');
like($line,   qr/s=rsa1024:rsa-sha256:/, 'has s=sel:alg:sig');
unlike($line, qr/(?:^|;\s*)h=/,          'no h= tag (signature covers the returned chain)');

(my $val = $line) =~ s/^DKIM2-DSN:\s*//s;
my $p = Mail::DKIM2::DSNHeader->parse($val);
is($p->domain, $DOMAIN,                     'parse d=');
is($p->rcpt_to, '<bounce@sender.example>',  'parse rt= (bracketed forward-path)');

# Round-trip verify using the private key object directly (Crypt::PK::RSA
# supports verify_message as well as sign_message) — avoids needing a
# pubkey_callback/Signature shim just to exercise this standalone header.
my $pub = DKIM2TestKeys::private_key($DOMAIN,'rsa1024');
ok($p->verify($pub, $eom),                  'signature verifies over the returned chain');

# tamper the DKIM2-DSN header (rt=) -> signing input differs -> verify fails
(my $bad_rt = $val) =~ s/rt=[^;]+/rt=Ym9ndXM=/;
ok(!Mail::DKIM2::DSNHeader->parse($bad_rt)->verify($pub, $eom), 'tampered rt= fails verify');

# tamper the returned chain (mutate the Message-Instance) -> verify fails
my $tampered = Email::MIME->new($eom->as_string);
$tampered->header_raw_set('Message-Instance',
    ($tampered->header_raw('Message-Instance'))[0] =~ s/h=/h=x/r);
ok(!$p->verify($pub, $tampered), 'tampered returned chain fails verify');

done_testing;
