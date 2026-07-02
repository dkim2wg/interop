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

# a bounce we cannot authenticate -> capture, not relay
my $bad = $dsn; $bad =~ s/(h=sha256:)[^;]+/$1YmFk/;   # break h=
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
    my $orig_msg = Email::MIME->new($dsn);
    my ($orig_hdr) = $orig_msg->header_raw('DKIM2-DSN');
    my $parsed = Mail::DKIM2::DSNHeader->parse($orig_hdr);
    my ($hh) = $parsed->header_hash =~ /^sha256:(.*)$/;

    my $tamper_hdr = Mail::DKIM2::DSNHeader->new(
        Domain => 'test2.dkim2.com', RcptTo => 'attacker@test1.dkim2.com',
        HeaderHash => $hh, Selector => 'rsa1024',
        Key => DKIM2TestKeys::private_key('test2.dkim2.com', 'rsa1024'),
        Algorithm => 'rsa-sha256');

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

# --- check (3): h= must be the header-hash RECOMPUTED over the enclosed
# headers, not a value merely parsed out of the enclosed Message-Instance
# text (anti-content-substitution / bounce-relay backscatter) ---------------
# Take the VALID $dsn verbatim -- its signed DKIM2-DSN header (d=, rt=, h=,
# s=) is untouched, so checks (1), (2), and (4) all still pass -- but swap
# the enclosed text/rfc822-headers payload for attacker-controlled content
# while copying the *same* Message-Instance/DKIM2-Signature header lines
# across verbatim. A parse-based check (3) would happily extract h1 from the
# copied Message-Instance text and find it matches the DSN's h=, since that
# text was never re-hashed against the new content. Only recomputing the
# header-hash over the actual enclosed headers can catch this: recomputing
# over "Subject: PWNED" et al yields a different digest than the one bound
# into d='s signature.
{
    my $dsn_msg = Email::MIME->new($dsn);
    my @parts = $dsn_msg->subparts;
    my ($orig_idx) = grep { ($parts[$_]->content_type // '') =~ m{text/rfc822-headers}i } 0..$#parts;
    die "test setup: no text/rfc822-headers part found" unless defined $orig_idx;

    # The genuine enclosed original's Message-Instance/DKIM2-Signature header
    # lines, copied out VERBATIM -- these are exactly the bytes a parse-based
    # check (3) would extract h1= from and find "matching" the DSN's h=.
    my $enclosed = Email::MIME->new($parts[$orig_idx]->body);
    my ($mi_line)  = $enclosed->header_raw('Message-Instance');
    my ($sig_line) = $enclosed->header_raw('DKIM2-Signature');
    die "test setup: enclosed original missing MI/sig lines"
        unless defined $mi_line && defined $sig_line;

    # Forged enclosed original: attacker content, but the Message-Instance
    # and DKIM2-Signature header lines are copied verbatim from the genuine
    # enclosed message (so a parse-based check on those lines would still
    # "match" the DSN's h=/signature).
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
