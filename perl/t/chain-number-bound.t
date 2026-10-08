#!/usr/bin/perl
# Every DKIM2-Signature i= and m=, and every Message-Instance m=, is bounded
# by MAX_CHAIN_LENGTH (32): a value above it, or one too long to be one, is a
# PERMERROR found while the header fields are read, before anything walks
# 1..i= or 1..m= looking for gaps.  i=99999999999999999999 used to kill the
# Verifier with "Range iterator outside integer range".
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/lib";
use lib "$FindBin::Bin/../lib";
use Email::MIME;
use Mail::DKIM2::Common qw(MAX_CHAIN_LENGTH chain_number_error);
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Signer;
use Mail::DKIM2::Verifier;
use DKIM2TestKeys;

my $EOL = "\015\012";
my $PLAIN = join($EOL,
    'Message-Id: <bound@test1.dkim2.com>',
    'Date: Thu, 10 Sep 2026 15:47:11 +1000',
    'From: Author <author@test1.dkim2.com>',
    'To: user@test2.dkim2.com',
    'Subject: bound',
    '',
    'hello',
    '');

is(MAX_CHAIN_LENGTH, 32, 'MAX_CHAIN_LENGTH is 32');
is(chain_number_error('DKIM2-Signature', 'i', $_), undef, "i=$_ is in range")
    for qw(1 9 32 01);
like(chain_number_error('DKIM2-Signature', 'i', $_) // '',
     qr/^PERMERROR DKIM2-Signature i= exceeds the maximum chain length of 32$/,
     "i=$_ is out of range")
    for qw(33 99 100 001 4294967297 99999999999999999999);
is(chain_number_error('Message-Instance', 'm', $_), undef, "non-digits '$_' left to the syntax checks")
    for ('abc', '', '1.5');

my $mi = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($PLAIN));
my $unsigned = "Message-Instance: " . $mi->as_string . $EOL . $PLAIN;
my $s = Mail::DKIM2::Signer->new(
    Domain => 'test1.dkim2.com', Selector => 'sel1',
    Key => DKIM2TestKeys::private_key('test1.dkim2.com', 'sel1'),
    MailFrom => 'author@test1.dkim2.com', RcptTo => ['user@test2.dkim2.com'],
    Timestamp => time());
$s->PRINT($unsigned); $s->CLOSE;
my $sig = $s->as_string;
my $signed = $sig . $EOL . $unsigned;

sub verify {
    my ($msg) = @_;
    my $v = Mail::DKIM2::Verifier->new(
        PubkeyCallback => DKIM2TestKeys::pubkey_callback());
    $v->PRINT($msg); $v->CLOSE;
    return $v;
}

is(verify($signed)->result, 'pass', 'control: the signed message passes');

my $range = 'exceeds the maximum chain length of 32';
my %cases = (
    'signature i=33' => [ sub { $_[0] =~ s/^(DKIM2-Signature: i=)1;/${1}33;/m }, "DKIM2-Signature i= $range" ],
    'signature i=huge' => [ sub { $_[0] =~ s/^(DKIM2-Signature: i=)1;/${1}99999999999999999999;/m }, "DKIM2-Signature i= $range" ],
    'signature i=2^32+1' => [ sub { $_[0] =~ s/^(DKIM2-Signature: i=)1;/${1}4294967297;/m }, "DKIM2-Signature i= $range" ],
    'signature m=huge' => [ sub { $_[0] =~ s/^(DKIM2-Signature: i=1; m=)1;/${1}99999999999999999999;/m }, "DKIM2-Signature m= $range" ],
    'instance m=huge' => [ sub { $_[0] =~ s/^(Message-Instance: m=)1;/${1}99999999999999999999;/m }, "Message-Instance m= $range" ],
    'instance m=33' => [ sub { $_[0] =~ s/^(Message-Instance: m=)1;/${1}33;/m }, "Message-Instance m= $range" ],
    'extra junk i=huge' => [ sub { $_[0] = "DKIM2-Signature: i=99999999999999999999; m=2; d=evil.example$EOL$_[0]" }, "DKIM2-Signature i= $range" ],
);
for my $name (sort keys %cases) {
    my ($edit, $detail) = @{$cases{$name}};
    my $msg = $signed;
    $edit->($msg);
    isnt($msg, $signed, "$name: fixture edited");
    my @warn;
    local $SIG{__WARN__} = sub { push @warn, @_ };
    my $v = eval { verify($msg) };
    is($@, '', "$name: the Verifier does not die");
    is($v && $v->result, 'permerror', "$name: permerror");
    is($v && $v->result_detail, "permerror (PERMERROR $detail)", "$name: says why");

    my $s2 = Mail::DKIM2::Signer->new(
        Domain => 'test2.dkim2.com', Selector => 'sel1',
        Key => DKIM2TestKeys::private_key('test2.dkim2.com', 'sel1'),
        MailFrom => 'user@test2.dkim2.com', RcptTo => ['x@test3.dkim2.com'],
        Timestamp => time());
    eval { $s2->PRINT($msg); $s2->CLOSE; };
    is($@, '', "$name: the Signer does not die");
    isnt($s2->result, 'pass', "$name: the Signer does not sign over it");
    like($s2->result_detail // '', qr/\Q$detail\E/, "$name: the Signer says why");
    is_deeply(\@warn, [], "$name: no warnings");
}

done_testing;
