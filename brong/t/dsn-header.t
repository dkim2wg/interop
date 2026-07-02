#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More; use lib 'lib'; use lib 't/lib';
use Mail::DKIM2::DSNHeader; use DKIM2TestKeys;
use MIME::Base64 qw(encode_base64);

# NOTE: the brief's example used Domain => 'dkim2.com', but the shared test
# key fixtures only publish keys for test1.dkim2.com .. test5.dkim2.com (see
# keys/rsa1024._domainkey.test1.dkim2.com.pem and dns.json). Use
# test1.dkim2.com so the round-trip below signs/verifies against a real key.
my $DOMAIN = 'test1.dkim2.com';

my $hh = encode_base64('fakeheaderhashbytes', '');  # stand-in header hash
my $h  = Mail::DKIM2::DSNHeader->new(
    Domain => $DOMAIN, RcptTo => 'bounce@sender.example',
    HeaderHash => $hh, Selector => 'rsa1024',
    Key => DKIM2TestKeys::private_key($DOMAIN,'rsa1024'), Algorithm => 'rsa-sha256');
my $line = $h->as_string;
like($line, qr/^DKIM2-DSN:/,            'emits a DKIM2-DSN header');
like($line, qr/d=\Q$DOMAIN\E/,          'has d=');
like($line, qr/h=sha256:\Q$hh\E/,       'has h=sha256:<hh>');
like($line, qr/s=rsa1024:rsa-sha256:/,  'has s=sel:alg:sig');

(my $val = $line) =~ s/^DKIM2-DSN:\s*//s;
my $p = Mail::DKIM2::DSNHeader->parse($val);
is($p->domain, $DOMAIN,                     'parse d=');
is($p->rcpt_to, '<bounce@sender.example>',  'parse rt= (bracketed forward-path)');
is($p->header_hash, "sha256:$hh",           'parse h=');

# Round-trip verify using the private key object directly (Crypt::PK::RSA
# supports verify_message as well as sign_message) — avoids needing a
# pubkey_callback/Signature shim just to exercise this standalone header.
my $pub = DKIM2TestKeys::private_key($DOMAIN,'rsa1024');
ok($p->verify($pub),                        'signature verifies');

# tamper the header hash -> verify fails
(my $bad = $val) =~ s/\Q$hh\E/Ym9ndXM=/;
ok(!Mail::DKIM2::DSNHeader->parse($bad)->verify($pub), 'tampered h= fails verify');

done_testing;
