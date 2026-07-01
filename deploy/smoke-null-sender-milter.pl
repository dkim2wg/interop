#!/usr/bin/perl
#
# Post-deploy smoke test: verify the outbound DKIM2 milter ANSWERS a
# null-sender envelope (MAIL FROM:<>) instead of hanging.
#
# This guards against regression of the Sendmail::PMilter null-sender bug: its
# SMFIC_MAIL handler skips the envfrom hook (and sends no reply) when the sender
# arg list is empty, so Postfix blocks until milter_command_timeout (30s). The
# fix is deploy/patches/pmilter-null-sender-envfrom.patch, applied by deploy.sh.
# Without the patch this script fails in ~8s instead of the MTA's 30s, so a
# broken deploy is caught loudly rather than silently shipping unsigned bounces.
#
# Speaks just enough of the milter protocol (as the MTA side) to negotiate and
# then send one SMFIC_MAIL with an empty sender, asserting a reply comes back.
#
# Usage: smoke-null-sender-milter.pl [socket-path]

use strict;
use warnings;
use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);

my $path = shift || '/var/spool/postfix/var/run/dkim2-milter-out.sock';

# The milter may be a moment behind a systemctl restart; retry the connect.
my $sock;
for my $try (1 .. 10) {
    $sock = IO::Socket::UNIX->new(Peer => $path, Type => SOCK_STREAM);
    last if $sock;
    sleep 1;
}
$sock or die "SMOKE TEST FAILED: cannot connect milter socket $path: $!\n";
$sock->autoflush(1);

sub send_cmd {
    my ($cmd, $data) = @_;
    $data //= '';
    my $pkt = pack('N', 1 + length $data) . $cmd . $data;
    defined syswrite($sock, $pkt) or die "SMOKE TEST FAILED: write: $!\n";
}

# Read exactly $n bytes, dying on an 8s stall (the hang we are testing for).
sub read_n {
    my ($n) = @_;
    my $buf = '';
    local $SIG{ALRM} = sub { die "TIMEOUT\n" };
    alarm(8);
    while (length($buf) < $n) {
        my $got = sysread($sock, my $chunk, $n - length $buf);
        die "SMOKE TEST FAILED: EOF from milter (closed connection)\n"
            if defined $got && $got == 0;
        die "SMOKE TEST FAILED: read: $!\n" unless defined $got;
        $buf .= $chunk;
    }
    alarm(0);
    return $buf;
}

sub read_reply {
    my $len = unpack('N', read_n(4));
    return $len > 0 ? read_n($len) : '';
}

# 1. Negotiate: milter protocol v6, offer all actions, request no step skips.
send_cmd('O', pack('NNN', 6, 0x1FF, 0));
eval { read_reply() };   # milter's SMFIC_OPTNEG reply (contents unused)
die "SMOKE TEST FAILED: no OPTNEG reply from milter: $@" if $@;

# 2. The exact bug trigger: SMFIC_MAIL with an empty (null) sender argument.
send_cmd('M', "\0");
my $reply = eval { read_reply() };
if ($@) {
    die "SMOKE TEST FAILED: milter did not answer MAIL FROM:<> "
      . "(Sendmail::PMilter null-sender bug — patch not applied?): $@";
}

my $action = length($reply) ? substr($reply, 0, 1) : '(none)';
print "   smoke: milter answered null-sender MAIL FROM:<> (action=$action) — ok\n";
close $sock;
exit 0;
