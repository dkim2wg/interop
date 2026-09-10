#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/lib";
use Crypt::PK::RSA;
use MIME::Base64 qw(encode_base64);
use Mail::DKIM2::Signer;
use Mail::DKIM2::Verifier;
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Common qw(parse_dkim_pubkey should_skip ignore_header_prefixes);

# An operator's own header fields sit on the wrong side of the signature at
# both ends: its border adds them after the sender signed, and strips them
# before the mail reaches anyone else. ignore_header_prefixes() names them, so
# the operator's signers hash the message its recipients will actually get and
# its verifiers accept mail its own systems have annotated. It is local policy:
# a verifier elsewhere still hashes those fields, which is why the operator has
# to strip them at the border as well.

my $EOL = "\015\012";

my $priv = Crypt::PK::RSA->new;
$priv->generate_key(256, 65537);
my $KEY_TXT = 'v=DKIM1; k=rsa; p=' . encode_base64($priv->export_key_der('public'), '');

my $MESSAGE = join($EOL,
    'Message-Id: <ours@sender.example.com>',
    'Date: Thu, 21 Mar 2024 12:09:37 +1000',
    'From: <author@sender.example.com>',
    'To: <user@example.net>',
    'Subject: our own fields',
    '', 'Body text.', '');

my $OURS = "Fastmail-MaskedEmail: id=masked-1; state=enabled$EOL";

sub sign {
    my ($text) = @_;
    my $mi = Mail::DKIM2::MessageInstance->calculate($text);
    my $with_mi = 'Message-Instance: ' . $mi->as_string() . $EOL . $text;
    my $signer = Mail::DKIM2::Signer->new(
        Domain   => 'sender.example.com',
        Selector => 'sel',
        Key      => $priv,
        MailFrom => 'author@sender.example.com',
        RcptTo   => ['user@example.net'],
    );
    $signer->PRINT($with_mi);
    $signer->CLOSE;
    return $signer->sign_for_recipient('user@example.net') . $EOL . $with_mi;
}

sub verify {
    my ($text) = @_;
    my $v = Mail::DKIM2::Verifier->new();
    $v->set_pubkey_callback(sub { return parse_dkim_pubkey($KEY_TXT) });
    $v->PRINT($text);
    $v->CLOSE;
    return $v->result;
}

subtest 'should_skip honours the configured prefixes' => sub {
    ignore_header_prefixes();
    ok(!should_skip('Fastmail-MaskedEmail'), 'nothing configured: hashed like any other field');

    ignore_header_prefixes('FASTMAIL-');
    ok(should_skip('fastmail-maskedemail'),    'configured prefix, any case: ignored');
    ok(should_skip('Fastmail-Sender-Identity'), '  ... along with every other name under it');
    ok(!should_skip('Fastmailish'),             'a prefix, not a substring');
    ok(!should_skip('Subject'),                 'other fields are unaffected');
    ok(should_skip('X-Anything'),               "the spec's own exclusions still apply");

    ignore_header_prefixes();
    ok(!should_skip('Fastmail-MaskedEmail'), 'calling with no arguments clears the list');
};

subtest 'a signer with the list signs what the recipient will get' => sub {
    ignore_header_prefixes('fastmail-');
    my $signed = sign($OURS . $MESSAGE);
    (my $delivered = $signed) =~ s/^Fastmail-MaskedEmail:[^\015]*\015\012//m;
    unlike($delivered, qr/^Fastmail-/m, 'the border stripped our field');

    # The recipient's verifier knows nothing of our list.
    ignore_header_prefixes();
    is(verify($delivered), 'pass', 'the stripped copy verifies elsewhere');
    isnt(verify($signed), 'pass', '  ... and the unstripped one would not, so the border strip is not optional');
};

subtest 'a verifier with the list accepts its own annotation' => sub {
    ignore_header_prefixes();
    my $signed = sign($MESSAGE);
    my $annotated = $OURS . $signed;
    isnt(verify($annotated), 'pass', 'without the list the field our border added breaks the hash');

    ignore_header_prefixes('fastmail-');
    is(verify($annotated), 'pass', 'with it the field is invisible');
    is(verify($signed), 'pass', '  ... and mail without the field still verifies');
};

done_testing;
