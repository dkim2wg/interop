#!/usr/bin/perl
use 5.020; use strict; use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Mail::DKIM2::Reflector;
use Net::SMTP;

# Usage (from a postfix alias):  dkim2-reflector.pl <mode>
# Reads the message on stdin; envelope sender from $ENV{SENDER}.
#
# Verifies the incoming DKIM2 chain, applies the per-mode transformation, signs
# as dkim2.com (only if the incoming chain verified), and submits the reply to
# the milter-free injection service so it is not re-signed on the way out.

my $mode   = $ARGV[0] or die "usage: $0 <mode>\n";
my $sender = $ENV{SENDER} // '';

# Null return-path (e.g. a bounce) -> nothing to reflect; drop quietly.
if ($sender eq '' || $sender eq '<>') {
    warn "dkim2-reflector: empty SENDER, dropping\n";
    exit 0;
}

my $message = do { local $/; <STDIN> };

my $result = eval {
    Mail::DKIM2::Reflector::reflect(
        message  => $message,
        mode     => $mode,
        sender   => $sender,
        domain   => 'dkim2.com',
        selector => 'sel1',
        keyfile  => '/etc/dkim2/keys/dkim2.com/sel1.key',
        mailfrom => 'reflector-bounces@dkim2.com',
        authserv_id => 'mail.dkim2.com',
    );
};
if (my $err = $@) {
    warn "dkim2-reflector: reflect failed: $err\n";
    exit 0;   # never bounce
}

# Inject to the milter-free postfix service (see deploy/SERVER.md) so we do not
# get re-signed by the outbound milter.
my $smtp = Net::SMTP->new('127.0.0.1', Port => 10588, Timeout => 30)
    or do { warn "dkim2-reflector: cannot connect to injector\n"; exit 0; };
$smtp->mail('reflector-bounces@dkim2.com');
$smtp->recipient($sender);
$smtp->data();
$smtp->datasend($result->{message});
$smtp->dataend();
$smtp->quit;
exit 0;
