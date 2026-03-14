#!/usr/bin/perl -w

use 5.020;
use strict;
use warnings;
use Test::More;
use Path::Tiny;
use Email::MIME;
use JSON;
use MIME::Base64;
use lib 'lib';

use Mail::DKIM::PublicKey;
use Mail::DKIM::TextWrap;
use Mail::DKIM2::Common qw(dkim2_canonicalize_header);
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Signature;
use Mail::DKIM2::Signer;
use Mail::DKIM2::Verifier;

# Load DNS keys
my $dns = decode_json(path('../dns.json')->slurp);

sub find_key {
    my $signature = shift;
    my $sel = $signature->selector(0);
    my $dom = $signature->domain;
    my $key_txt = $dns->{$dom}{"$sel._domainkey"}[0][1];
    return unless $key_txt;
    return Mail::DKIM::PublicKey->parse($key_txt);
}

# ============================================================
# The progression: 5 hops, each with a different domain/selector
#
#   brong-orig.eml  -- originator at test1.dkim2.com (sel1)
#   brong-mm.eml    -- mailing list at test2.dkim2.com (sel2)
#   brong-mm2.eml   -- relay adds header at test3.dkim2.com (sel3)
#   brong-mm3.eml   -- relay removes header at test4.dkim2.com (sel1)
#   brong-final.eml -- final delivery at test5.dkim2.com (sel2)
# ============================================================

my @hops = (
    {
        name     => 'originator',
        file     => 'brong-orig.eml',
        domain   => 'test1.dkim2.com',
        selector => 'sel1',
        mailfrom => 'brong@test1.dkim2.com',
        rcptto   => ['list@test2.dkim2.com'],
    },
    {
        name     => 'mailing list',
        file     => 'brong-mm.eml',
        domain   => 'test2.dkim2.com',
        selector => 'sel2',
        mailfrom => 'bounces@test2.dkim2.com',
        rcptto   => ['user@test3.dkim2.com'],
    },
    {
        name     => 'relay adds Extra-Header',
        file     => 'brong-mm2.eml',
        domain   => 'test3.dkim2.com',
        selector => 'sel3',
        mailfrom => 'relay@test3.dkim2.com',
        rcptto   => ['user@test4.dkim2.com'],
    },
    {
        name     => 'relay removes Extra-Header',
        file     => 'brong-mm3.eml',
        domain   => 'test4.dkim2.com',
        selector => 'sel1',
        mailfrom => 'relay@test4.dkim2.com',
        rcptto   => ['user@test5.dkim2.com'],
    },
    {
        name     => 'final delivery',
        file     => 'brong-final.eml',
        domain   => 'test5.dkim2.com',
        selector => 'sel2',
        mailfrom => 'forwarder@test5.dkim2.com',
        rcptto   => ['brong@fastmailteam.com'],
    },
);

# Strip all existing MI/DKIM2 headers from the base files
sub strip_msg {
    my $msg = shift;
    $msg->header_raw_set('Message-Instance');
    $msg->header_raw_set('DKIM2-Signature');
    $msg->header_raw_set('MailVersion');
    $msg->header_raw_set('Mail-Version');
    return $msg;
}

sub add_mi {
    my ($msg, $prev_msg) = @_;

    # Skip if the message already has an MI that matches current content
    if ( Mail::DKIM2::MessageInstance->verify($msg) ) {
        return undef;
    }

    my $mi = Mail::DKIM2::MessageInstance->calculate($msg, $prev_msg);
    my $output = '';
    my $tw = Mail::DKIM::TextWrap->new(
        Margin    => 72,
        Break     => qr/./,
        Separator => "\r\n\t",
        Swallow   => qr/\s+/,
        Output    => \$output,
    );
    $tw->add("Message-Instance: " . $mi->as_string());
    $tw->finish;
    $output =~ s/^Message-Instance: //;
    $msg->header_raw_prepend('Message-Instance', $output);
    return $mi;
}

sub sign_msg {
    my ($msg, $hop) = @_;
    my $keyfile = "../keys/$hop->{selector}._domainkey.$hop->{domain}.pem";
    my $signer = Mail::DKIM2::Signer->new(
        Domain   => $hop->{domain},
        Selector => $hop->{selector},
        KeyFile  => $keyfile,
        MailFrom => $hop->{mailfrom},
        RcptTo   => $hop->{rcptto},
    );
    $signer->PRINT($msg->as_string());
    $signer->CLOSE;
    my $header = $signer->as_string();
    $header =~ s{^DKIM2-Signature:\s*}{};
    $msg->header_raw_prepend('DKIM2-Signature', $header);
    return $signer;
}

sub verify_msg {
    my ($msg) = @_;
    my $verifier = Mail::DKIM2::Verifier->new();
    $verifier->set_pubkey_callback(\&find_key);
    $verifier->PRINT($msg->as_string());
    $verifier->CLOSE;
    return $verifier;
}

# ============================================================
# Phase 1: Build the full chain, verifying at each step
# ============================================================

diag("=== Building chain ===");

my $current_msg;

for my $i (0..$#hops) {
    my $hop = $hops[$i];
    my $label = "hop " . ($i + 1) . " ($hop->{name})";

    # Load the raw message for this hop
    my $raw = path($hop->{file})->slurp;
    my $msg = Email::MIME->new($raw);
    strip_msg($msg);

    if ($i == 0) {
        # First hop: calculate v=1 MI (no previous message)
        my $mi = add_mi($msg);
        ok($mi->get_tag('v') == 1, "$label: MI version is 1");
    } else {
        # Graft MI and DKIM2-Sig headers from the accumulated chain
        # onto this new message version
        my @mi_headers = $current_msg->header_raw('Message-Instance');
        my @dk2_headers = $current_msg->header_raw('DKIM2-Signature');

        # Prepend in reverse order (bottom-up, so first prepended = bottom)
        for my $h (reverse @dk2_headers) {
            $msg->header_raw_prepend('DKIM2-Signature', $h);
        }
        for my $h (reverse @mi_headers) {
            $msg->header_raw_prepend('Message-Instance', $h);
        }

        # Re-parse to get clean state
        $msg = Email::MIME->new($msg->as_string);

        # Calculate MI diff: $msg is the new version (with modified content
        # but same MI chain), $current_msg is the previous version
        my $mi = add_mi($msg, $current_msg);
        ok($mi->get_tag('v') == $i + 1, "$label: MI version is " . ($i + 1));
    }

    # Re-parse before signing (Email::MIME caching)
    $msg = Email::MIME->new($msg->as_string);

    # Verify MI hashes before signing
    my $mi_check = Mail::DKIM2::MessageInstance->verify($msg);
    ok($mi_check == $i + 1, "$label: MI verify passes at v=" . ($i + 1));

    # Sign
    sign_msg($msg, $hop);

    # Re-parse after signing
    $msg = Email::MIME->new($msg->as_string);

    # Verify the DKIM2 signature
    my $v = verify_msg($msg);
    is($v->result, 'pass', "$label: DKIM2-Signature verifies");

    # Count headers to make sure we accumulated correctly
    my @mi = $msg->header_raw('Message-Instance');
    my @dk2 = $msg->header_raw('DKIM2-Signature');
    is(scalar @mi, $i + 1, "$label: has " . ($i + 1) . " MI headers");
    is(scalar @dk2, $i + 1, "$label: has " . ($i + 1) . " DKIM2-Signature headers");

    $current_msg = $msg;
}

# ============================================================
# Phase 2: Full chain unwind — validate all MIs + sigs top-down
# ============================================================

diag("=== Full chain validation (unwind) ===");

{
    my $msg = Email::MIME->new($current_msg->as_string);

    my @mi = $msg->header_raw('Message-Instance');
    my @dk2 = $msg->header_raw('DKIM2-Signature');
    is(scalar @mi, 5, "final message has 5 MI headers");
    is(scalar @dk2, 5, "final message has 5 DKIM2-Signature headers");

    # Unwind from the top
    for my $step (reverse 1..5) {
        my $label = "unwind step $step";

        # Verify DKIM2 signature at current top
        my $v = verify_msg($msg);
        is($v->result, 'pass', "$label: DKIM2-Signature i=$step verifies");

        # Verify MI
        my $mi_check = Mail::DKIM2::MessageInstance->verify($msg);
        is($mi_check, $step, "$label: MI v=$step verifies");

        if ($step > 1) {
            # Remove top DKIM2-Signature
            my @dk2 = $msg->header_raw('DKIM2-Signature');
            $msg->header_raw_set('DKIM2-Signature',
                grep { $_ !~ /\bi=$step\b/ } @dk2);

            # Undo the MI
            Mail::DKIM2::MessageInstance->undo($msg);
            $msg = Email::MIME->new($msg->as_string);
        }
    }
}

# ============================================================
# Phase 3: Negative tests
# ============================================================

diag("=== Negative tests ===");

# Tamper with a header and verify MI fails
{
    my $msg = Email::MIME->new($current_msg->as_string);
    # Modify the Subject header
    $msg->header_raw_set('Subject', 'TAMPERED');
    $msg = Email::MIME->new($msg->as_string);

    my ($result, $error) = Mail::DKIM2::MessageInstance->verify($msg);
    is($result, 0, "MI verify returns 0 on tampered header");
    like($error, qr/header hash mismatch/, "MI verify reports hash mismatch");
}

# Tamper with the signature and verify DKIM2 fails
{
    my $msg = Email::MIME->new($current_msg->as_string);
    my @dk2 = $msg->header_raw('DKIM2-Signature');
    # Corrupt the s= tag by replacing its base64 content with different valid JSON
    # that has a garbage signature value
    my $bad_sigs = encode_base64(
        encode_json([["sel1", "rsa-sha256", "AAAA"]]), '');
    $dk2[0] =~ s/s=\S+/s=$bad_sigs/;
    $msg->header_raw_set('DKIM2-Signature', @dk2);
    $msg = Email::MIME->new($msg->as_string);

    my $v = verify_msg($msg);
    isnt($v->result, 'pass', "DKIM2 verify fails on tampered signature");
}

# Remove a middle MI header and verify chain fails
{
    my $msg = Email::MIME->new($current_msg->as_string);
    my @mi = $msg->header_raw('Message-Instance');
    # Remove v=3
    my @filtered = grep { $_ !~ /^\s*v=3\b/ } @mi;
    $msg->header_raw_set('Message-Instance', @filtered);
    $msg = Email::MIME->new($msg->as_string);

    # Verifier should detect the gap (the signing input no longer matches
    # because the set of MI headers changed)
    my $v = verify_msg($msg);
    isnt($v->result, 'pass', "verifier detects missing MI v=3 in chain");
}

# ============================================================
# Phase 4: Unchanged message re-sign — no new MI added
# ============================================================

diag("=== Unchanged message re-sign ===");

{
    # Take the final 5-hop message and re-sign without modifications
    my $msg = Email::MIME->new($current_msg->as_string);

    my @mi_before = $msg->header_raw('Message-Instance');
    my @dk2_before = $msg->header_raw('DKIM2-Signature');
    is(scalar @mi_before, 5, "before re-sign: 5 MI headers");
    is(scalar @dk2_before, 5, "before re-sign: 5 DKIM2-Signature headers");

    # Verify the topmost MI still matches — message is unchanged
    my $mi_v = Mail::DKIM2::MessageInstance->verify($msg);
    ok($mi_v, "topmost MI still verifies (v=$mi_v)");

    # add_mi should return undef (skip) since message is unchanged
    my $mi = add_mi($msg);
    ok(!defined $mi, "add_mi returns undef for unchanged message");

    my @mi_after = $msg->header_raw('Message-Instance');
    is(scalar @mi_after, 5, "after add_mi: still 5 MI headers (no new MI added)");

    # Sign with a new hop — signature is added but MI count stays the same
    my $hop6 = {
        name     => 'unchanged re-sign',
        domain   => 'test5.dkim2.com',
        selector => 'sel2',
        mailfrom => 'relay@fastmailteam.com',
        rcptto   => ['dest@test1.dkim2.com'],
    };
    sign_msg($msg, $hop6);
    $msg = Email::MIME->new($msg->as_string);

    my @mi_final = $msg->header_raw('Message-Instance');
    my @dk2_final = $msg->header_raw('DKIM2-Signature');
    is(scalar @mi_final, 5, "after re-sign: still 5 MI headers");
    is(scalar @dk2_final, 6, "after re-sign: 6 DKIM2-Signature headers");

    # Full chain should still verify
    my $v = verify_msg($msg);
    is($v->result, 'pass', "full chain still verifies after unchanged re-sign");
}

done_testing();
