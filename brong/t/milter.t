#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use Path::Tiny;
use JSON;
use Email::MIME;
use File::Temp qw(tempdir);

# --- Mock the Mail::Milter::Authentication framework ---
# Must happen in BEGIN before the handler modules are loaded.

BEGIN {
    # Stub Pragmas (just enables strict/warnings, imports LOG_* constants)
    $INC{'Mail/Milter/Authentication/Pragmas.pm'} = 1;
    package Mail::Milter::Authentication::Pragmas;
    sub import {
        my $caller = caller;
        no strict 'refs';
        *{"${caller}::LOG_DEBUG"} = sub { 'debug' };
        *{"${caller}::LOG_INFO"}  = sub { 'info' };
        *{"${caller}::LOG_ERR"}   = sub { 'err' };
    }

    # Stub base handler
    $INC{'Mail/Milter/Authentication/Handler.pm'} = 1;
    package Mail::Milter::Authentication::Handler;
    sub new {
        my ($class, %args) = @_;
        return bless {
            _config  => $args{config} || {},
            _objects => {},
            _auth_headers => [],
            _pre_headers  => [],
            _prepended    => [],
            _log => [],
            _metrics => {},
        }, $class;
    }
    sub handler_config     { return $_[0]->{_config} }
    sub is_authenticated   { return $_[0]->{_config}{_authenticated} || 0 }
    sub is_local_ip_address { return $_[0]->{_config}{_local} || 0 }
    sub set_object         { $_[0]->{_objects}{$_[1]} = $_[2] }
    sub get_object         { return $_[0]->{_objects}{$_[1]} }
    sub destroy_object     { delete $_[0]->{_objects}{$_[1]} }
    sub check_timeout      { }
    sub handle_exception   { }
    sub dbgout             { push @{$_[0]->{_log}}, [@_[1..$#_]] }
    sub log_error          { push @{$_[0]->{_log}}, ['ERROR', $_[1]] }
    sub metric_count       { $_[0]->{_metrics}{$_[1]} = ($_[0]->{_metrics}{$_[1]} || 0) + 1 }
    sub add_auth_header    { push @{$_[0]->{_auth_headers}}, $_[1] }
    sub prepend_header     { push @{$_[0]->{_prepended}}, { field => $_[1], value => $_[2] } }

    # Stub AuthenticationResults classes
    $INC{'Mail/AuthenticationResults/Header/Entry.pm'} = 1;
    package Mail::AuthenticationResults::Header::Entry;
    sub new       { bless {key => '', value => '', children => []}, shift }
    sub set_key   { $_[0]->{key} = $_[1]; $_[0] }
    sub safe_set_value { $_[0]->{value} = $_[1]; $_[0] }
    sub add_child { push @{$_[0]->{children}}, $_[1]; $_[0] }

    $INC{'Mail/AuthenticationResults/Header/Comment.pm'} = 1;
    package Mail::AuthenticationResults::Header::Comment;
    sub new            { bless {value => ''}, shift }
    sub safe_set_value { $_[0]->{value} = $_[1]; $_[0] }

    $INC{'Mail/AuthenticationResults/Header/SubEntry.pm'} = 1;
    package Mail::AuthenticationResults::Header::SubEntry;
    sub new            { bless {key => '', value => ''}, shift }
    sub set_key        { $_[0]->{key} = $_[1]; $_[0] }
    sub safe_set_value { $_[0]->{value} = $_[1]; $_[0] }
}

use lib 'lib';
use Mail::Milter::Authentication::Handler::DKIM2Verify;
use Mail::Milter::Authentication::Handler::DKIM2Sign;
use Mail::DKIM2::Common qw(parse_dkim_pubkey);

my $dns = decode_json(path("../dns.json")->slurp);
my $keydir = path("../keys")->realpath;

# Helper: feed a raw message through milter verify callbacks
sub run_verify {
    my ($raw, %opts) = @_;
    my $config = {
        hide_none => 0,
        dns_overrides => undef,
        add_message_instance => 0,
        snapshot_directory => undef,
        %opts,
    };

    my $handler = Mail::Milter::Authentication::Handler::DKIM2Verify->new(
        config => $config,
    );

    # Set up pubkey callback using dns.json
    # (We can't use dns_overrides config because it requires File::Slurp)

    $raw =~ s/\r//gs;
    $raw =~ s/\n/\r\n/gs;

    # Parse headers and body
    my ($header_block, $body) = split /\r\n\r\n/, $raw, 2;
    my @header_lines;
    my $current = '';
    for my $line (split /\r\n/, $header_block) {
        if ($line =~ /^\s/ && $current ne '') {
            $current .= "\r\n$line";
        } else {
            push @header_lines, $current if $current ne '';
            $current = $line;
        }
    }
    push @header_lines, $current if $current ne '';

    # Run callbacks
    $handler->envfrom_callback('<sender@test1.dkim2.com>');

    for my $hline (@header_lines) {
        my ($name, $value) = $hline =~ /^([^\s:]+)\s*:\s*(.*)/s;
        $handler->header_callback($name, $value, $hline);
    }

    $handler->eoh_callback();

    # Now set up the pubkey callback on the verifier object
    my $verifier = $handler->get_object('dkim2_verifier');
    if ($verifier) {
        $verifier->set_pubkey_callback(sub {
            my ($sig, $idx) = @_;
            $idx //= 0;
            my $sel = $sig->selector($idx);
            my $dom = $sig->domain;
            my $key_txt = $dns->{$dom}{"$sel._domainkey"}[0][1];
            return parse_dkim_pubkey($key_txt);
        });

        # Re-feed headers to the verifier (the handler already fed them)
        # Actually the handler already called PRINT with headers, so we just
        # need to feed the body
    }

    # Feed body in chunks
    if (defined $body) {
        my @chunks = ($body =~ /(.{1,256})/gs);
        for my $chunk (@chunks) {
            $handler->body_callback($chunk);
        }
    }

    $handler->eom_callback();

    return $handler;
}

# Helper: feed a raw message through milter sign callbacks
sub run_sign {
    my ($raw, %opts) = @_;
    my $config = {
        domains => {},
        sign_authenticated => 1,
        sign_local => 1,
        add_message_instance => 1,
        record_smtp_params => 1,
        snapshot_directory => undef,
        _authenticated => 1,
        %opts,
    };

    my $handler = Mail::Milter::Authentication::Handler::DKIM2Sign->new(
        config => $config,
    );

    $raw =~ s/\r//gs;
    $raw =~ s/\n/\r\n/gs;

    my ($header_block, $body) = split /\r\n\r\n/, $raw, 2;
    my @header_lines;
    my $current = '';
    for my $line (split /\r\n/, $header_block) {
        if ($line =~ /^\s/ && $current ne '') {
            $current .= "\r\n$line";
        } else {
            push @header_lines, $current if $current ne '';
            $current = $line;
        }
    }
    push @header_lines, $current if $current ne '';

    $handler->envfrom_callback('<sender@test1.dkim2.com>');
    $handler->envrcpt_callback('<recipient@example.com>');

    for my $hline (@header_lines) {
        my ($name, $value) = $hline =~ /^([^\s:]+)\s*:\s*(.*)/s;
        $handler->header_callback($name, $value, $hline);
    }

    $handler->eoh_callback();

    if (defined $body) {
        my @chunks = ($body =~ /(.{1,256})/gs);
        for my $chunk (@chunks) {
            $handler->body_callback($chunk);
        }
    }

    $handler->eom_callback();

    # Simulate addheader phase
    my $mock_handler = {
        pre_headers => [],
        add_headers => [],
    };
    $handler->addheader_callback($mock_handler);

    return ($handler, $mock_handler);
}


# === Tests ===

diag("=== DKIM2Verify milter tests ===");

# Test 1: Verify a signed message through milter callbacks
{
    my $raw = path("tests/expected/chain-hop1-originator.eml")->slurp;
    my $handler = run_verify($raw);
    my @auth = @{$handler->{_auth_headers}};
    ok(@auth > 0, "verify hop1: auth header added");
    is($auth[0]->{value}, 'pass', "verify hop1: result is pass");
}

# Test 2: Verify a multi-hop message
{
    my $raw = path("tests/expected/chain-hop3-relay-adds-Extra-Header.eml")->slurp;
    my $handler = run_verify($raw);
    my @auth = @{$handler->{_auth_headers}};
    ok(@auth > 0, "verify hop3: auth header added");
    is($auth[0]->{value}, 'pass', "verify hop3: result is pass");
}

# Test 3: Message with no DKIM2-Signature
{
    my $raw = path("tests/emails/brong-orig.eml")->slurp;
    my $handler = run_verify($raw);
    my @auth = @{$handler->{_auth_headers}};
    ok(@auth > 0, "no-sig: auth header added");
    is($auth[0]->{value}, 'none', "no-sig: result is none");
}

# Test 4: Verify Python interop file
{
    my $raw = path("../python/tests/expected/simple-ed25519.eml")->slurp;
    my $handler = run_verify($raw);
    my @auth = @{$handler->{_auth_headers}};
    ok(@auth > 0, "python ed25519: auth header added");
    is($auth[0]->{value}, 'pass', "python ed25519: result is pass");
}

diag("=== DKIM2Sign milter tests ===");

# Test 5: Sign a message through milter callbacks
{
    my $raw = path("tests/emails/brong-orig.eml")->slurp;
    my ($handler, $mock) = run_sign($raw,
        domains => {
            'test1.dkim2.com' => {
                selector => 'rsa1024',
                keyfile  => "$keydir/rsa1024._domainkey.test1.dkim2.com.pem",
            },
        },
    );

    my @pre = @{$mock->{pre_headers}};
    my @dk2 = grep { $_->{field} eq 'DKIM2-Signature' } @pre;
    ok(@dk2 > 0, "sign: DKIM2-Signature header added");

    # Check the signature has expected structure
    my $sig_value = $dk2[0]->{value};
    like($sig_value, qr/i=1/, "sign: signature has i=1");
    like($sig_value, qr/d=test1\.dkim2\.com/, "sign: signature has correct domain");
    like($sig_value, qr/s=/, "sign: signature has s= tag");

    # Check MI was also added
    my @mi = grep { $_->{field} eq 'Message-Instance' } @pre;
    ok(@mi > 0, "sign: Message-Instance header added");
}

# Test 6: Sign should not fire for unauthenticated senders
{
    my $raw = path("tests/emails/brong-orig.eml")->slurp;
    my ($handler, $mock) = run_sign($raw,
        _authenticated => 0,
        _local => 0,
        domains => {
            'test1.dkim2.com' => {
                selector => 'rsa1024',
                keyfile  => "$keydir/rsa1024._domainkey.test1.dkim2.com.pem",
            },
        },
    );

    my @pre = @{$mock->{pre_headers}};
    my @dk2 = grep { $_->{field} eq 'DKIM2-Signature' } @pre;
    is(scalar @dk2, 0, "unauth: no signature added");
}

# Test 7: Sign should not fire when domain has no config
{
    my $raw = path("tests/emails/brong-orig.eml")->slurp;
    my ($handler, $mock) = run_sign($raw,
        domains => {},  # no domains configured
    );

    my @pre = @{$mock->{pre_headers}};
    my @dk2 = grep { $_->{field} eq 'DKIM2-Signature' } @pre;
    is(scalar @dk2, 0, "no-config: no signature added");
}

# Test 8: Round-trip: sign then verify
{
    my $raw = path("tests/emails/brong-orig.eml")->slurp;
    my ($sign_handler, $mock) = run_sign($raw,
        domains => {
            'test1.dkim2.com' => {
                selector => 'rsa1024',
                keyfile  => "$keydir/rsa1024._domainkey.test1.dkim2.com.pem",
            },
        },
    );

    # Build the signed message from pre_headers + original
    my @pre = @{$mock->{pre_headers}};
    my $EOL = "\r\n";
    my $signed_msg = '';
    for my $h (reverse @pre) {
        $signed_msg .= "$h->{field}: $h->{value}$EOL";
    }
    $raw =~ s/\r//gs;
    $raw =~ s/\n/\r\n/gs;
    $signed_msg .= $raw;

    # Now verify it
    my $verify_handler = run_verify($signed_msg);
    my @auth = @{$verify_handler->{_auth_headers}};
    ok(@auth > 0, "round-trip: auth header added");
    is($auth[0]->{value}, 'pass', "round-trip: verify passes after sign");
}

diag("=== Forwarding flow tests ===");

# These tests simulate a complete inbound→processing→outbound flow through
# a forwarding MTA that uses DKIM2Verify on inbound and DKIM2Sign on outbound.
#
# INBOUND (DKIM2Verify):
#   1. Message arrives with DKIM2-Signature i=1 + Message-Instance v=1
#   2. Verify checks signatures and MI — passes
#   3. Since MI v=1 already matches content, no new MI is added
#   4. The message is stored as a snapshot, keyed by the MI v=1 value
#
# LOCAL PROCESSING:
#   The MTA may modify the message (add headers, rewrite body, etc.)
#   It may or may not add its own Message-Instance header.
#
# OUTBOUND (DKIM2Sign):
#   1. Sign reconstructs the message from headers+body seen in callbacks
#   2. If add_message_instance is on, checks if topmost MI matches content
#   3. If MI matches → no new MI needed (Case 1 and 3)
#      If MI doesn't match → looks up snapshot for any MI, computes diff
#      MI v=2 with recipes (Case 2)
#   4. Creates DKIM2-Signature i=2

# Helper: create a signed originator message for forwarding tests
sub make_originator_message {
    use Mail::DKIM2::Signer;
    use Mail::DKIM2::MessageInstance;

    my $raw = path("tests/emails/brong-orig.eml")->slurp;
    my $keyfile = path("../keys/rsa1024._domainkey.test1.dkim2.com.pem")->realpath;

    $raw =~ s/\r//gs;
    $raw =~ s/\n/\r\n/gs;

    # Calculate MI v=1
    my $msg = Email::MIME->new($raw);
    my $mi = Mail::DKIM2::MessageInstance->calculate($msg);
    my $mi_str = "Message-Instance: " . $mi->as_string() . "\r\n";

    # Prepend MI to message, then sign
    my $with_mi = $mi_str . $raw;
    my $signer = Mail::DKIM2::Signer->new(
        Domain    => 'test1.dkim2.com',
        Selector  => 'rsa1024',
        KeyFile   => "$keyfile",
        MailFrom  => 'sender@test1.dkim2.com',
        RcptTo    => ['foo@example.com'],
        Timestamp => 1740000000,
    );
    $signer->PRINT($with_mi);
    $signer->CLOSE();

    my $result = $signer->as_string() . "\r\n" . $with_mi;

    # Write the originator message for interop testing
    path("tests/expected")->child("milter-originator.eml")->spew($result);

    return $result;
}

# Helper: run the full inbound verify with snapshot storage
sub run_inbound_verify {
    my ($raw, $snapshot_dir) = @_;
    return run_verify($raw,
        add_message_instance => 1,
        snapshot_directory   => $snapshot_dir,
    );
}

# Helper: run the full outbound sign with snapshot lookup
sub run_outbound_sign {
    my ($raw, $snapshot_dir) = @_;
    my ($handler, $mock) = run_sign($raw,
        domains => {
            'example.com' => {
                selector => 'rsa1024',
                keyfile  => path("../keys/rsa1024._domainkey.test2.dkim2.com.pem")->realpath . "",
            },
        },
        add_message_instance => 1,
        snapshot_directory   => $snapshot_dir,
        _authenticated       => 0,
        _local               => 1,
    );
    # Override env_from for the forwarding domain
    $handler->{'env_from'} = '<forwarder@example.com>';
    # Re-run addheader with corrected env_from
    $mock = { pre_headers => [], add_headers => [] };
    $handler->addheader_callback($mock);
    return ($handler, $mock);
}

# Helper: assemble the final outbound message from sign mock output.
# pre_headers are prepended (in reverse, as milters do) to the message
# that was fed to the signer.
sub assemble_outbound {
    my ($input_msg, $mock) = @_;
    my $EOL = "\r\n";
    my $result = '';
    for my $h (reverse @{$mock->{pre_headers}}) {
        my $val = $h->{value};
        $val =~ s/\r?\n/\r\n/gs;
        $result .= "$h->{field}: $val$EOL";
    }
    $input_msg =~ s/\r//gs;
    $input_msg =~ s/\n/\r\n/gs;
    $result .= $input_msg;
    return $result;
}

my $expected_dir = path("tests/expected");

# Case 1: Unchanged forwarding
#
# Email arrives at foo@example.com and is forwarded to bar@example.net
# with no changes made.
#
# Flow:
#   Inbound:  DK2-Sig i=1 + MI v=1 arrives → verify pass → MI v=1
#             matches → no new MI → snapshot stored keyed by MI v=1
#   Processing: nothing changes
#   Outbound: MI v=1 still matches → no new MI → sign with DK2-Sig i=2
{
    my $snapshot_dir = tempdir(CLEANUP => 1);
    my $signed_msg = make_originator_message();

    # Inbound
    my $verify_handler = run_inbound_verify($signed_msg, $snapshot_dir);
    is($verify_handler->{_auth_headers}[0]{value}, 'pass',
        'case1: inbound verify passes');
    my @mi_prepended = grep { $_->{field} eq 'Message-Instance' }
                       @{$verify_handler->{_prepended}};
    is(scalar @mi_prepended, 0,
        'case1: inbound did not add MI (v=1 already matches)');

    # No modifications — forward as-is

    # Outbound
    my ($sign_handler, $mock) = run_outbound_sign($signed_msg, $snapshot_dir);
    my @dk2 = grep { $_->{field} eq 'DKIM2-Signature' } @{$mock->{pre_headers}};
    my @mi  = grep { $_->{field} eq 'Message-Instance' } @{$mock->{pre_headers}};

    ok(@dk2 > 0,        'case1: outbound added DKIM2-Signature i=2');
    is(scalar @mi, 0,   'case1: outbound did NOT add MI (unchanged)');

    # Write the final outbound message for interop testing
    my $outbound = assemble_outbound($signed_msg, $mock);
    $expected_dir->child("milter-case1-unchanged-forward.eml")->spew($outbound);
}

# Case 2: Modified message, no intermediate MI
#
# Email arrives, local processing adds a List-Id header, but the code
# that added it did not add a Message-Instance header.  The outbound
# sign handler detects the change, finds the snapshot from inbound,
# computes a diff MI v=2 with recipes, and signs.
#
# Flow:
#   Inbound:  verify pass → snapshot stored keyed by MI v=1
#   Processing: List-Id header added (changes header hash)
#   Outbound: MI v=1 doesn't match → finds snapshot for MI v=1 →
#             computes diff MI v=2 with header recipe → signs with i=2
{
    my $snapshot_dir = tempdir(CLEANUP => 1);
    my $signed_msg = make_originator_message();

    # Inbound — stores snapshot
    my $verify_handler = run_inbound_verify($signed_msg, $snapshot_dir);
    is($verify_handler->{_auth_headers}[0]{value}, 'pass',
        'case2: inbound verify passes');

    # Local processing adds a header
    my $modified = $signed_msg;
    $modified =~ s/\r\n\r\n/\r\nList-Id: test.list\r\n\r\n/;

    # Outbound — should detect change and compute diff MI
    my ($sign_handler, $mock) = run_outbound_sign($modified, $snapshot_dir);
    my @dk2 = grep { $_->{field} eq 'DKIM2-Signature' } @{$mock->{pre_headers}};
    my @mi  = grep { $_->{field} eq 'Message-Instance' } @{$mock->{pre_headers}};

    ok(@dk2 > 0,      'case2: outbound added DKIM2-Signature');
    ok(@mi > 0,        'case2: outbound added MI v=2 (message was modified)');
    if (@mi) {
        like($mi[0]{value}, qr/^v=2/, 'case2: new MI is version 2');
        like($mi[0]{value}, qr/r=/,   'case2: new MI has recipes (diff from snapshot)');
    }

    # Write the final outbound message for interop testing
    my $outbound = assemble_outbound($modified, $mock);
    $expected_dir->child("milter-case2-modified-no-intermediate-mi.eml")->spew($outbound);
}

# Case 3: Modified message, intermediate code already added MI v=2
#
# Same as case 2, but the code that added List-Id also correctly added
# its own Message-Instance v=2 describing the change.  The outbound
# sign handler sees MI v=2 matches current content and does NOT add
# another MI — it just signs.
#
# Flow:
#   Inbound:  verify pass → snapshot stored keyed by MI v=1
#   Processing: List-Id added + MI v=2 (with recipes) added by app code
#   Outbound: MI v=2 matches → no new MI → signs with i=2
{
    my $snapshot_dir = tempdir(CLEANUP => 1);
    my $signed_msg = make_originator_message();

    # Inbound — stores snapshot
    run_inbound_verify($signed_msg, $snapshot_dir);

    # Local processing adds header + computes MI v=2
    my $modified = $signed_msg;
    $modified =~ s/\r\n\r\n/\r\nList-Id: test.list\r\n\r\n/;

    my $orig_msg = Email::MIME->new($signed_msg);
    my $mod_msg  = Email::MIME->new($modified);
    my $mi2 = Mail::DKIM2::MessageInstance->calculate($mod_msg, $orig_msg);
    my $with_mi2 = "Message-Instance: " . $mi2->as_string() . "\r\n" . $modified;

    # Sanity check: MI v=2 should match the modified message
    my $check = Email::MIME->new($with_mi2);
    is(Mail::DKIM2::MessageInstance->verify($check), 2,
        'case3: intermediate MI v=2 matches modified message');

    # Outbound — MI v=2 matches, no new MI needed
    my ($sign_handler, $mock) = run_outbound_sign($with_mi2, $snapshot_dir);
    my @dk2 = grep { $_->{field} eq 'DKIM2-Signature' } @{$mock->{pre_headers}};
    my @mi  = grep { $_->{field} eq 'Message-Instance' } @{$mock->{pre_headers}};

    ok(@dk2 > 0,       'case3: outbound added DKIM2-Signature');
    is(scalar @mi, 0,  'case3: outbound did NOT add MI (v=2 already matches)');

    # Write the final outbound message for interop testing
    my $outbound = assemble_outbound($with_mi2, $mock);
    $expected_dir->child("milter-case3-modified-with-intermediate-mi.eml")->spew($outbound);
}

done_testing();
