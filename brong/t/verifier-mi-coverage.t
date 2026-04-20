#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/lib";
use Mail::DKIM2::Verifier;
use Mail::DKIM2::Signer;
use Mail::DKIM2::MessageInstance;
use Email::MIME;
use DKIM2TestKeys;

# Fixed timestamp for reproducible signing
my $TIMESTAMP = 1740000000;

my $RAW_EMAIL = join("\r\n",
    'MIME-Version: 1.0',
    'Message-Id: <test-mi-coverage@example.com>',
    'Date: Thu, 21 Mar 2024 12:09:37 +1000',
    'From: sender@test1.example.com',
    'To: recipient@test2.example.com',
    'Subject: MI coverage test',
    'Content-Type: text/plain',
    '',
    'Test body for MI coverage verification.',
    '',
);

# Helper: sign a message and return Email::MIME object with the new DKIM2-Signature prepended
sub sign_msg {
    my ($msg, %hop) = @_;
    my $signer = Mail::DKIM2::Signer->new(
        Domain    => $hop{domain},
        Selector  => $hop{selector},
        Key       => DKIM2TestKeys::private_key($hop{domain}, $hop{selector}),
        MailFrom  => $hop{mailfrom},
        RcptTo    => $hop{rcptto},
        Timestamp => $TIMESTAMP,
    );
    $signer->PRINT($msg->as_string());
    $signer->CLOSE;
    my $header = $signer->as_string();
    $header =~ s{^DKIM2-Signature:\s*}{};
    $msg->header_raw_prepend('DKIM2-Signature', $header);
    return $signer;
}

# Helper: verify a message using test key callback
sub verify_msg {
    my ($msg) = @_;
    my $v = Mail::DKIM2::Verifier->new();
    $v->set_pubkey_callback(DKIM2TestKeys::pubkey_callback());
    $v->PRINT($msg->as_string());
    $v->CLOSE;
    return $v;
}

# Build a signed message: add MI m=1, sign i=1 m=1
my $msg = Email::MIME->new($RAW_EMAIL);

# Add MI m=1
my $mi = Mail::DKIM2::MessageInstance->calculate($msg->as_string());
$msg->header_raw_prepend('Message-Instance', $mi->as_string());

# Sign with i=1, m=1
sign_msg($msg,
    domain   => 'test1.example.com',
    selector => 'sel1',
    mailfrom => 'sender@test1.example.com',
    rcptto   => ['recipient@test2.example.com'],
);

# Verify the original signed message passes
{
    my $signed_with_mi = $msg->as_string();
    like($signed_with_mi, qr/m=1/i, 'signed message contains m=1 reference');
    my $v = verify_msg($msg);
    is($v->result, 'pass', 'original message with MI m=1 covered by i=1 m=1 verifies');
}

# Tamper: prepend an uncovered MI m=2 header (fake hashes, not signed by any signature)
{
    my $tampered = Email::MIME->new($msg->as_string());
    $tampered->header_raw_prepend('Message-Instance',
        ' m=2; h=sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
    );

    my $v = verify_msg($tampered);
    is($v->result, 'fail', 'uncovered MI m=2 prepended without new signature must fail');
    like($v->result_detail, qr/not cover|cover/i, 'result_detail mentions coverage gap');
}

done_testing;
