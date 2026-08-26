#!/usr/bin/perl -w
#
# spec-05 §11.2: "errors in a JSON object specifying Recipes should be
# called out specifically" -- a malformed r= payload must produce
#   PERMERROR Message-Instance m=<x> contains invalid JSON
# distinct from a generic syntax error.

use 5.020;
use strict;
use warnings;
use Test::More;
use MIME::Base64 qw(encode_base64 decode_base64);
use Email::MIME;
use lib 'lib', 't/lib';
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Signer;
use Mail::DKIM2::Verifier;
use DKIM2TestKeys;

# --- unit level: MessageInstance->parse() dies with the exact string ------

eval {
    my $bad_r = encode_base64('{"h": ', '');
    Mail::DKIM2::MessageInstance->parse("m=2; h=sha256:AAA:BBB; r=$bad_r;");
};
like($@, qr/^PERMERROR Message-Instance m=2 contains invalid JSON/,
     'spec-05 §11.2: MessageInstance::parse dies with the exact PERMERROR string on malformed r= JSON');

# A well-formed-but-empty JSON object is not a JSON error at all.
ok(eval {
    my $ok_r = encode_base64('{}', '');
    Mail::DKIM2::MessageInstance->parse("m=2; h=sha256:AAA:BBB; r=$ok_r;");
    1;
}, 'valid (empty) recipe JSON still parses cleanly');

# --- end to end: feed a complete, validly-signed two-hop message with a  --
# --- corrupted r= payload through the REAL verifier entry point          --
# --- (Mail::DKIM2::Verifier's PRINT/CLOSE streaming API -- what every    --
# --- production caller, the CLI and the milter, actually uses), not just --
# --- the recipe-parsing helper. Guards against the error being raised    --
# --- deep in parse() but never reaching the caller (cf. the C            --
# --- duplicate-h= lesson in commit 66bd3e6).                             --

my $keyfile1 = '../keys/sel1._domainkey.test1.dkim2.com.pem';
my $keyfile2 = '../keys/sel1._domainkey.test2.dkim2.com.pem';
plan skip_all => 'shared ../keys not available' unless -e $keyfile1 && -e $keyfile2;

my $orig = "From: sender\@test1.dkim2.com\r\n"
         . "To: rcpt\@test2.dkim2.com\r\n"
         . "Subject: hi\r\n\r\n"
         . "body line\r\n";

# Hop 1: sign the original message.
my $msg1 = Email::MIME->new($orig);
my $mi1  = Mail::DKIM2::MessageInstance->calculate($msg1);
$msg1->header_raw_prepend('Message-Instance', $mi1->as_string);

my $signer1 = Mail::DKIM2::Signer->new(
    Selector  => 'sel1',
    Domain    => 'test1.dkim2.com',
    KeyFile   => $keyfile1,
    MailFrom  => '<sender@test1.dkim2.com>',
    RcptTo    => ['<rcpt@test2.dkim2.com>'],
    Timestamp => 1740000000,
);
$signer1->PRINT($msg1->as_string);
$signer1->CLOSE;
is($signer1->result // '', 'signed', 'hop1 signs cleanly');
(my $sig1 = $signer1->as_string) =~ s/^DKIM2-Signature:\s*//;
$msg1->header_raw_prepend('DKIM2-Signature', $sig1);

my $with1 = $msg1->as_string;

# Hop 2: relay adds a List-Unsubscribe header; the recipe records how to
# undo that. This is exactly the case that puts a real r= tag on the wire.
my $current = Email::MIME->new($with1);
$current->header_raw_prepend('List-Unsubscribe', '<mailto:unsub@relay.example.com>');

my $mi2 = Mail::DKIM2::MessageInstance->calculate($current, Email::MIME->new($with1));
my $mi2_str = $mi2->as_string;
like($mi2_str, qr/r=/, 'sanity: hop2 recipe carries a real r= tag');

# Corrupt the r= payload to base64-decode to malformed JSON, leaving m=/h=
# untouched. Signing hop2 over this corrupted header means the signature
# legitimately covers it -- so the failure must come from the JSON check,
# not a signature mismatch.
my $bad_json_b64 = encode_base64('{"h": ', '');
(my $corrupted_mi2 = $mi2_str) =~ s/r=[^;]+;/r=$bad_json_b64;/
    or die "failed to locate r= tag to corrupt in: $mi2_str";
unlike($corrupted_mi2, qr/r=\Q$mi2_str\E/, 'sanity: r= payload actually changed');

$current->header_raw_prepend('Message-Instance', $corrupted_mi2);

my $signer2 = Mail::DKIM2::Signer->new(
    Selector  => 'sel1',
    Domain    => 'test2.dkim2.com',
    KeyFile   => $keyfile2,
    MailFrom  => '<relay@test2.dkim2.com>',
    RcptTo    => ['<recipient@example.com>'],
    Timestamp => 1740001000,
);
$signer2->PRINT($current->as_string);
$signer2->CLOSE;
is($signer2->result // '', 'signed', 'hop2 signs the corrupted-but-well-formed-header content');
(my $sig2 = $signer2->as_string) =~ s/^DKIM2-Signature:\s*//;
$current->header_raw_prepend('DKIM2-Signature', $sig2);

my $final = $current->as_string;

# This is the real production entry point: stream the complete message
# through Mail::DKIM2::Verifier exactly as bin/verify-sig.pl and the milter
# handler do.
my $v = Mail::DKIM2::Verifier->new;
$v->skip_timestamp_check(1);
$v->set_pubkey_callback(DKIM2TestKeys::pubkey_callback());
$v->PRINT($final);
$v->CLOSE;

is($v->result, 'permerror',
   'end-to-end: a malformed r= JSON payload is rejected as permerror by the real Verifier')
    or diag($v->result_detail);
like($v->details // '', qr/^PERMERROR Message-Instance m=2 contains invalid JSON/,
     'end-to-end: the specific §11.2 invalid-JSON message reaches the caller, verbatim');

done_testing();
