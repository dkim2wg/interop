#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More;
use lib 'lib';
use lib 't/lib';
use Email::MIME;
use Mail::DKIM2::DSN;
use Mail::DKIM2::Signer;
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Verifier;
use Mail::DKIM2::Reflector;
use DKIM2TestKeys;

my $TS = 1740000000;

sub mk_signer {
    my (%o) = @_;
    return Mail::DKIM2::Signer->new(
        Domain    => $o{domain},
        Selector  => 'rsa1024',
        Key       => DKIM2TestKeys::private_key($o{domain}, 'rsa1024'),
        MailFrom  => $o{mailfrom} // '<>',
        RcptTo    => $o{rcptto}   // ['x@example.com'],
        Timestamp => $TS,
    );
}

# Build a v=1 signed inbound message from a sender.
sub signed_inbound {
    my $raw = "From: Sender <sender\@origin.example>\r\n"
            . "To: user\@test1.dkim2.com\r\n"
            . "Subject: hello\r\n"
            . "\r\n"
            . "body line\r\n";
    my $mi = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($raw));
    my $with_mi = "Message-Instance: " . $mi->as_string . "\r\n" . $raw;
    my $signer = mk_signer(domain => 'test1.dkim2.com',
                           mailfrom => 'sender@origin.example',
                           rcptto => ['user@test1.dkim2.com']);
    $signer->PRINT($with_mi); $signer->CLOSE;
    my $sig = $signer->as_string; $sig =~ s/\r?\n$//;
    return $sig . "\r\n" . $with_mi;
}

# Build a 2-hop message: origin signs i=1; forwarder (test2) appends a footer,
# records MI v=2, and signs i=2.
sub forwarded_twohop {
    my $h1 = signed_inbound();                 # MI v=1 + sig i=1
    my $prev = Email::MIME->new($h1);
    my $cur  = Email::MIME->new($h1);
    $cur->body_set($cur->body_raw . "-- \r\nforwarder footer\r\n");
    my $mi = Mail::DKIM2::MessageInstance->calculate($cur, $prev);
    $cur->header_raw_prepend('Message-Instance', $mi->as_string);
    my $signer = mk_signer(domain => 'test2.dkim2.com',
                           mailfrom => 'user@test2.dkim2.com',
                           rcptto => ['dest@test3.dkim2.com']);
    $signer->PRINT($cur->as_string); $signer->CLOSE;
    my $sig = $signer->as_string; $sig =~ s/\r?\n$//;
    $sig =~ s{^DKIM2-Signature:\s*}{};
    $cur->header_raw_prepend('DKIM2-Signature', $sig);
    return $cur->as_string;
}

# === propagate: forwarder returns a received DSN upstream (§12.1.1) ===
{
    my $embedded = forwarded_twohop();
    my $dsn = Email::MIME->create(
        attributes => { content_type => 'multipart/report', encoding => '7bit' },
        header_str => [ From => 'postmaster@test3.dkim2.com',
                        To => 'user@test2.dkim2.com',
                        Subject => 'failure' ],
        parts => [
            Email::MIME->create(attributes => { content_type => 'text/plain', charset=>'UTF-8', encoding=>'7bit' },
                                body_str => "delivery failed\n"),
            Email::MIME->create(attributes => { content_type => 'message/delivery-status' },
                                body => "Reporting-MTA: dns; test3.dkim2.com\r\n\r\n"
                                      . "Final-Recipient: rfc822; dest\@test3.dkim2.com\r\n"
                                      . "Action: failed\r\nStatus: 5.1.1\r\n"),
            Email::MIME->create(attributes => { content_type => 'message/rfc822' },
                                body => $embedded),
        ],
    );

    my $signer = mk_signer(domain => 'test2.dkim2.com');
    my $out = Mail::DKIM2::DSN->propagate({
        raw => $dsn->as_string, forwarder_domain => 'test2.dkim2.com', signer => $signer,
    });
    ok($out->{raw}, 'propagate returned a DSN');
    # After stripping the forwarder hop (i=2), the now-top sig is i=1 with
    # mf=sender@origin.example.
    is($out->{upstream_mailfrom}, '<sender@origin.example>',
       'propagated DSN addressed to upstream MAIL FROM');
    my $m = Email::MIME->new($out->{raw});
    like($m->header('Content-Type'), qr{multipart/report}i, 'still multipart/report');
    is(scalar(() = $m->header_raw('Message-Instance')),  1, 'exactly one MI (new message)');
    is(scalar(() = $m->header_raw('DKIM2-Signature')), 1, 'exactly one DKIM2-Signature');
}

# Build a 2-hop message where the second hop forwards UNCHANGED: no new
# Message-Instance is recorded (body/headers untouched), just a second
# DKIM2-Signature (i=2) stacked on top of the origin's (i=1). Unlike
# forwarded_twohop(), this carries no body-diff ('rb') Recipe, so undo() is a
# clean no-op -- useful for exercising propagate() without also touching the
# unrelated undo/rebuild machinery.
sub forwarded_unchanged {
    my $h1 = signed_inbound();                 # MI v=1 + sig i=1
    my $cur = Email::MIME->new($h1);
    my $signer = mk_signer(domain => 'test2.dkim2.com',
                           mailfrom => 'user@test2.dkim2.com',
                           rcptto => ['dest@test3.dkim2.com']);
    $signer->PRINT($cur->as_string); $signer->CLOSE;
    my $sig = $signer->as_string; $sig =~ s/\r?\n$//;
    $sig =~ s{^DKIM2-Signature:\s*}{};
    $cur->header_raw_prepend('DKIM2-Signature', $sig);
    return $cur->as_string;
}

# === propagate: rejects a multipart/report with >=3 parts but no
# message/delivery-status part (RFC 6522 structural validation, not just a
# bare part count) ===
{
    my $embedded = forwarded_twohop();
    my $dsn = Email::MIME->create(
        attributes => { content_type => 'multipart/report', encoding => '7bit' },
        header_str => [ From => 'postmaster@test3.dkim2.com',
                        To => 'user@test2.dkim2.com',
                        Subject => 'failure' ],
        parts => [
            Email::MIME->create(attributes => { content_type => 'text/plain', charset=>'UTF-8', encoding=>'7bit' },
                                body_str => "delivery failed\n"),
            # No message/delivery-status part here -- just a second text/plain,
            # so @parts >= 3 but the RFC 6522 structure is not satisfied.
            Email::MIME->create(attributes => { content_type => 'text/plain', charset=>'UTF-8', encoding=>'7bit' },
                                body_str => "not a delivery-status part\n"),
            Email::MIME->create(attributes => { content_type => 'message/rfc822' },
                                body => $embedded),
        ],
    );

    my $signer = mk_signer(domain => 'test2.dkim2.com');
    eval {
        Mail::DKIM2::DSN->propagate({
            raw => $dsn->as_string, forwarder_domain => 'test2.dkim2.com', signer => $signer,
        });
    };
    like($@, qr/propagate/i,
         'propagate rejects a >=3-part DSN lacking a message/delivery-status part');
}

# === propagate: accepts a well-formed 3-part DSN whose embedded original is
# text/rfc822-headers (the other half of the message/rfc822 OR
# text/rfc822-headers structural requirement) ===
{
    my $embedded = forwarded_unchanged();
    my $dsn = Email::MIME->create(
        attributes => { content_type => 'multipart/report', encoding => '7bit' },
        header_str => [ From => 'postmaster@test3.dkim2.com',
                        To => 'user@test2.dkim2.com',
                        Subject => 'failure' ],
        parts => [
            Email::MIME->create(attributes => { content_type => 'text/plain', charset=>'UTF-8', encoding=>'7bit' },
                                body_str => "delivery failed\n"),
            Email::MIME->create(attributes => { content_type => 'message/delivery-status' },
                                body => "Reporting-MTA: dns; test3.dkim2.com\r\n\r\n"
                                      . "Final-Recipient: rfc822; dest\@test3.dkim2.com\r\n"
                                      . "Action: failed\r\nStatus: 5.1.1\r\n"),
            Email::MIME->create(attributes => { content_type => 'text/rfc822-headers' },
                                body => Email::MIME->new($embedded)->header_obj->as_string),
        ],
    );

    my $signer = mk_signer(domain => 'test2.dkim2.com');
    my $out = Mail::DKIM2::DSN->propagate({
        raw => $dsn->as_string, forwarder_domain => 'test2.dkim2.com', signer => $signer,
    });
    ok($out->{raw}, 'propagate accepts a valid 3-part DSN (text/rfc822-headers variant)');
    is($out->{upstream_mailfrom}, '<sender@origin.example>',
       'propagated DSN (headers-only variant) addressed to upstream MAIL FROM');
}

# === generate: reflector-dsn behaviour ===
{
    my $inbound = signed_inbound();
    my $bouncer = mk_signer(domain => 'test2.dkim2.com');
    my $out = Mail::DKIM2::DSN->generate({
        raw => $inbound, signer => $bouncer, reporting_mta => 'test2.dkim2.com',
    });
    ok($out->{raw}, 'generate returned a DSN');
    is($out->{send_to}, '<sender@origin.example>', 'DSN addressed to original sender');

    my $m = Email::MIME->new($out->{raw});
    like($m->header('Content-Type'), qr{multipart/report}i, 'is multipart/report');
    like($m->header('Content-Type'), qr{report-type=delivery-status}i, 'has report-type');

    my @mi  = $m->header_raw('Message-Instance');
    my @sig = $m->header_raw('DKIM2-Signature');
    is(scalar(@mi),  1, 'exactly one Message-Instance (new message)');
    is(scalar(@sig), 1, 'exactly one DKIM2-Signature (new message)');

    # The generated DSN verifies as a fresh DKIM2 message.
    my $v = Mail::DKIM2::Verifier->new();
    $v->set_pubkey_callback(DKIM2TestKeys::pubkey_callback());
    $v->skip_timestamp_check(1);
    $v->PRINT($m->as_string); $v->CLOSE;
    is($v->result, 'pass', 'generated DSN verifies (pass)');
}

# === generate: works for UNSIGNED inbound too (bounce regardless) ===
{
    my $inbound = "From: nobody\@origin.example\r\nTo: user\@test1.dkim2.com\r\n"
                . "Subject: unsigned\r\n\r\nhi\r\n";
    my $bouncer = mk_signer(domain => 'test2.dkim2.com');
    my $out = Mail::DKIM2::DSN->generate({
        raw => $inbound, signer => $bouncer, to => 'nobody@origin.example',
    });
    is($out->{send_to}, 'nobody@origin.example', 'unsigned mail: bounced to envelope sender');
    my $m = Email::MIME->new($out->{raw});
    my @sig = $m->header_raw('DKIM2-Signature');
    is(scalar(@sig), 1, 'unsigned-source DSN is DKIM2-signed');
}

# === reflector-dsn: Reflector::generate_dsn end to end -> a fresh DKIM2 DSN
# (per spec: MAIL FROM <>, one Message-Instance + one DKIM2-Signature on the
# top message, embedding the original as message/rfc822) that verifies. ===
{
    my $inbound = signed_inbound();
    my $out = Mail::DKIM2::Reflector::generate_dsn(
        sender   => 'sender@origin.example',
        message  => $inbound,
        domain   => 'test2.dkim2.com',
        selector => 'rsa1024',
        key      => DKIM2TestKeys::private_key('test2.dkim2.com', 'rsa1024'),
        now      => $TS,
    );
    ok($out, 'generate_dsn produced a DSN');
    my $m = Email::MIME->new($out);
    like($m->header('Content-Type'), qr{multipart/report}i, 'reflector-dsn is multipart/report');
    is($m->header('To'), 'sender@origin.example', 'reflector-dsn returned to the sender');
    like($out, qr/^DKIM2-Signature:/m,  'DSN carries its own DKIM2-Signature (top message)');
    like($out, qr/^Message-Instance:/m, 'DSN carries its own Message-Instance (top message)');
    like($out, qr{message/rfc822}i,     'DSN embeds the original as message/rfc822');

    my $v = Mail::DKIM2::Verifier->new();
    $v->set_pubkey_callback(DKIM2TestKeys::pubkey_callback());
    $v->skip_timestamp_check(1);
    $v->PRINT($m->as_string); $v->CLOSE;
    is($v->result, 'pass', 'reflector-dsn output verifies (pass)');
}

# === reflector-dsn: the embedded original round-trips -- the message/rfc822
# part holds the inbound message verbatim, so the sender can see what bounced. ===
{
    my $raw = "From: Sender <sender\@test1.dkim2.com>\r\n"
            . "To: user\@test2.dkim2.com\r\n"
            . "Subject: hello\r\n"
            . "\r\n"
            . "body line\r\n";
    my $mi = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($raw));
    my $with_mi = "Message-Instance: " . $mi->as_string . "\r\n" . $raw;
    my $signer = mk_signer(domain => 'test1.dkim2.com',
                           mailfrom => 'sender@test1.dkim2.com',
                           rcptto   => ['user@test2.dkim2.com']);
    $signer->PRINT($with_mi); $signer->CLOSE;
    my $sig = $signer->as_string; $sig =~ s/\r?\n$//;
    my $inbound = $sig . "\r\n" . $with_mi;

    my $out = Mail::DKIM2::Reflector::generate_dsn(
        sender   => 'sender@test1.dkim2.com',
        message  => $inbound,
        domain   => 'test2.dkim2.com',
        selector => 'rsa1024',
        key      => DKIM2TestKeys::private_key('test2.dkim2.com', 'rsa1024'),
        now      => $TS,
    );
    ok($out, 'generate_dsn produced a DSN');
    my $m = Email::MIME->new($out);
    is($m->header('To'), 'sender@test1.dkim2.com', 'reflector-dsn returned to the sender');
    like($out, qr{message/rfc822}i, 'DSN embeds the original as message/rfc822');
    like($out, qr/Subject: hello/,  'embedded original message is present verbatim');

    my $v = Mail::DKIM2::Verifier->new();
    $v->set_pubkey_callback(DKIM2TestKeys::pubkey_callback());
    $v->skip_timestamp_check(1);
    $v->PRINT($out); $v->CLOSE;
    is($v->result, 'pass', 'reflector-dsn DSN verifies (pass)');
}

done_testing;
