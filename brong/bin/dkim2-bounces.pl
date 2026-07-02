#!/usr/bin/perl
use 5.020; use strict; use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Mail::DKIM2::BounceHandler;
use Net::SMTP;
use Sys::Syslog qw(:standard :macros);

# Usage:
#   Postfix pipe(8):  dkim2-bounces ${user} ${sender}
# Reads the DKIM2-DSN bounce message on stdin.
#
# Verifies the incoming DKIM2-DSN bounce (see Mail::DKIM2::BounceHandler),
# undoes the enclosed Message-Instance chain to reconstruct the original as
# delivered to the top hop, and either:
#   - relays it to the reconstructed originator (the DKIM2-DSN's rt=, which
#     the handler has confirmed equals the enclosed chain's top-hop mf=), by
#     submitting to the milter-free injection service so it is not re-signed;
#   - or, if any authentication check fails, captures it into the
#     reflector-bounces mailbox rather than relaying an unverifiable bounce.
#
# This handler never bounces itself; problems are logged to syslog (LOG_MAIL)
# so they are not silently lost (postfix discards a piped command's stderr on
# exit 0).

openlog('dkim2-bounces', 'pid', LOG_MAIL);
sub logmsg { my $m = shift; warn "dkim2-bounces: $m\n"; syslog(LOG_WARNING, '%s', $m); }

my $message = do { local $/; <STDIN> };

my $out = eval { Mail::DKIM2::BounceHandler::process(raw => $message) };
if (my $err = $@) {
    chomp(my $e = $err);
    logmsg("process failed: $e");
    exit 0;
}

my $smtp = Net::SMTP->new('127.0.0.1', Port => 10588, Timeout => 30)
    or do { logmsg("cannot connect to injector on 127.0.0.1:10588"); exit 0; };

if ($out->{action} eq 'relay') {
    $smtp->mail('<>');
    $smtp->recipient($out->{relay_to});
    $smtp->data();
    $smtp->datasend($out->{message});
    $smtp->dataend();
    $smtp->quit;
    logmsg("relayed bounce to $out->{relay_to}");
} else {
    # Capture: could not authenticate this bounce, so do not relay it. File
    # it into the reflector-bounces mailbox (a real alias/mbox on this
    # system, not code we write) via the same injector, and log it.
    $smtp->mail('<>');
    $smtp->recipient('reflector-bounces@dkim2.com');
    $smtp->data();
    $smtp->datasend($message);
    $smtp->dataend();
    $smtp->quit;
    logmsg("captured unverifiable bounce (not relayed)");
}
exit 0;
