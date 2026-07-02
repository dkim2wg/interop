#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More; use lib 'lib'; use lib 't/lib';
use Mail::DKIM2::BounceHandler; use Mail::DKIM2::DSN; use DKIM2TestKeys;
use Email::MIME; use Mail::DKIM2::Signer; use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::DSNHeader;
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

# a bounce we cannot authenticate -> capture, not relay. Corrupt the first
# base64 char of the DKIM2-DSN signature (the DKIM2-DSN is the first header, so
# its s= is the first one in the message) so the signature no longer verifies.
my $bad = $dsn;
$bad =~ s{(s=rsa1024:rsa-sha256:\s*)([A-Za-z0-9+/])}{$1 . ($2 eq 'A' ? 'B' : 'A')}es;
my $cap = Mail::DKIM2::BounceHandler::process(raw=>$bad, pubkey_cb=>DKIM2TestKeys::pubkey_callback());
is($cap->{action}, 'capture', 'unverifiable bounce -> capture (not relayed)');

# --- check (1): rt= must decode to the enclosed message's top-hop mf= -----
# Build a DKIM2-DSN header that is otherwise identical/valid (same d=, same
# h=, properly signed by test2.dkim2.com) but whose rt= names a different
# address ("attacker@test1.dkim2.com") than the enclosed top-hop mf=
# ("sender@test1.dkim2.com"). This isolates check (1): d= still
# relaxed-matches the top-hop rt= domain (2), h= still matches (3), and the
# signature over this (different) rt= still verifies cleanly (4) -- only the
# rt=-vs-mf= equality check can reject it. Anti-misdirection: without check
# (1), a bounce could be redirected to an address that never sent the
# original message.
{
    # A DKIM2-DSN that is valid in every way except rt=: same d=, signed over
    # the same returned chain (so checks 2, 3 and 4 all pass), but rt= names a
    # different address ("attacker@test1.dkim2.com") than the enclosed top-hop
    # mf= ("sender@test1.dkim2.com"). Only the rt=-vs-mf= equality check (1)
    # can reject it.
    my $tamper_hdr = Mail::DKIM2::DSNHeader->new(
        Domain => 'test2.dkim2.com', RcptTo => 'attacker@test1.dkim2.com',
        Selector => 'rsa1024',
        Key => DKIM2TestKeys::private_key('test2.dkim2.com', 'rsa1024'),
        Algorithm => 'rsa-sha256', Returned => Email::MIME->new($signed));

    (my $rt_tampered = $dsn) =~ s/^DKIM2-DSN:.*?\r?\n(?!\s)/$tamper_hdr->as_string . "\r\n"/es;

    my $cap_rt = Mail::DKIM2::BounceHandler::process(
        raw => $rt_tampered, pubkey_cb => DKIM2TestKeys::pubkey_callback());
    is($cap_rt->{action}, 'capture',
        'rt= disagreeing with enclosed top-hop mf= -> capture (check 1: anti-misdirection)');
}

# --- check (2): d= must relaxed-match a top-hop rt= domain of the enclosed
# message (anti-backscatter) --------------------------------------------
# The enclosed message's top-hop rt= domain is test2.dkim2.com (it was sent
# to r@test2.dkim2.com). Generate a DKIM2-DSN signed as test1.dkim2.com
# instead -- a domain that was never a recipient of the original send, so
# d=test1.dkim2.com cannot relaxed-match test2.dkim2.com. Everything else
# (rt=, h=, and the signature itself) is internally consistent and valid for
# the domain that actually signed it; only the d=-vs-rt=-domain check can
# reject it. Without check (2), any domain could vouch for (and trigger a
# relay of) a bounce for a message it never received -- a backscatter vector.
{
    my $dsn_wrong_domain = Mail::DKIM2::DSN::generate_dkim2_dsn(
        raw => $signed, domain => 'test1.dkim2.com', selector => 'rsa1024',
        key => DKIM2TestKeys::private_key('test1.dkim2.com', 'rsa1024'),
        pubkey_cb => DKIM2TestKeys::pubkey_callback(), skip_timestamp_check => 1)->{raw};

    my $cap_d = Mail::DKIM2::BounceHandler::process(
        raw => $dsn_wrong_domain, pubkey_cb => DKIM2TestKeys::pubkey_callback());
    is($cap_d->{action}, 'capture',
        'd= not matching any top-hop rt= domain -> capture (check 2: anti-backscatter)');
}

# --- check (3): the enclosed headers must validate against the enclosed top
# Message-Instance (anti-content-substitution / bounce-relay backscatter) ----
# Take the VALID $dsn verbatim -- its signed DKIM2-DSN header (d=, rt=, s=) is
# untouched -- but swap the enclosed text/rfc822-headers payload for
# attacker-controlled content while copying the *same* Message-Instance and
# DKIM2-Signature header lines across verbatim. Because the DKIM2-DSN signs
# only the enclosed Message-Instance/DKIM2-Signature chain (not the other
# header fields), copying those lines verbatim leaves the DKIM2-DSN signature
# check (4) passing. Only recomputing the header hash over the actual enclosed
# headers and comparing it to the enclosed top Message-Instance (check 3)
# catches this: hashing "Subject: PWNED" et al yields a different digest than
# the copied Message-Instance records, so validation fails.
{
    my $dsn_msg = Email::MIME->new($dsn);
    my @parts = $dsn_msg->subparts;
    my ($orig_idx) = grep { ($parts[$_]->content_type // '') =~ m{text/rfc822-headers}i } 0..$#parts;
    die "test setup: no text/rfc822-headers part found" unless defined $orig_idx;

    # The genuine enclosed original's Message-Instance/DKIM2-Signature header
    # lines, copied out VERBATIM -- copying them keeps the DKIM2-DSN signature
    # (which covers exactly these lines) verifying over the forged message.
    my $enclosed = Email::MIME->new($parts[$orig_idx]->body);
    my ($mi_line)  = $enclosed->header_raw('Message-Instance');
    my ($sig_line) = $enclosed->header_raw('DKIM2-Signature');
    die "test setup: enclosed original missing MI/sig lines"
        unless defined $mi_line && defined $sig_line;

    # Forged enclosed original: attacker content, but the Message-Instance
    # and DKIM2-Signature header lines are copied verbatim from the genuine
    # enclosed message (so the DKIM2-DSN signature over that chain still
    # verifies -- only the header-hash validation can catch the swap).
    my $forged_body = "DKIM2-Signature: $sig_line\r\n"
                     . "Message-Instance: $mi_line\r\n"
                     . "From: attacker\@evil.example\r\n"
                     . "To: victim\@example.com\r\n"
                     . "Subject: PWNED\r\n";
    $parts[$orig_idx]->body_set($forged_body);
    $dsn_msg->parts_set(\@parts);
    my $forged = $dsn_msg->as_string;

    # Sanity: the forgery actually landed, and Email::MIME's reserialization
    # left the signed DKIM2-DSN singleton header byte-for-byte untouched
    # (otherwise this test would pass/fail for the wrong reason).
    my ($orig_dsn_line)   = Email::MIME->new($dsn)->header_raw('DKIM2-DSN');
    my ($forged_dsn_line) = $dsn_msg->header_raw('DKIM2-DSN');
    like($forged, qr/Subject: PWNED/, 'forged DSN contains attacker payload (sanity check)');
    is($forged_dsn_line, $orig_dsn_line,
        'forged DSN still carries the genuine (unmodified) DKIM2-DSN header (sanity check)');

    my $forged_out = Mail::DKIM2::BounceHandler::process(
        raw => $forged, pubkey_cb => DKIM2TestKeys::pubkey_callback());
    is($forged_out->{action}, 'capture',
        'enclosed payload swapped for attacker content (MI/sig lines copied verbatim) -> capture (check 3: recomputed header-hash)');
}

done_testing;
