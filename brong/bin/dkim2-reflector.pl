#!/usr/bin/perl
use 5.020; use strict; use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Mail::DKIM2::Reflector;
use Net::SMTP;
use Sys::Syslog qw(:standard :macros);

# Usage (from a postfix alias):  dkim2-reflector.pl <mode>
# Reads the message on stdin; envelope sender from $ENV{SENDER}.
#
# Verifies the incoming message, applies the per-mode transformation, signs as
# dkim2.com (when the incoming DKIM2 chain verified, or as a DKIM1 bridge), and
# submits the reply to the milter-free injection service so it is not re-signed.
#
# The reflector never bounces; problems are logged to syslog (LOG_MAIL) so they
# are not silently lost (postfix discards a piped command's stderr on exit 0).

openlog('dkim2-reflector', 'pid', LOG_MAIL);
sub logmsg { my $m = shift; warn "dkim2-reflector: $m\n"; syslog(LOG_WARNING, '%s', $m); }

my $mode   = $ARGV[0] or die "usage: $0 <mode>\n";
my $sender = $ENV{SENDER} // '';

# Null return-path (e.g. a bounce) -> nothing to reflect; drop quietly.
if ($sender eq '' || $sender eq '<>') {
    logmsg("empty SENDER, dropping");
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
    chomp(my $e = $err);
    logmsg("reflect failed for sender=$sender mode=$mode: $e");
    # Keep the offending message for debugging (single overwritten file).
    if (open my $fh, '>', '/var/tmp/dkim2-reflector-lasterror.eml') {
        print $fh $message; close $fh;
        logmsg("wrote failing message to /var/tmp/dkim2-reflector-lasterror.eml");
    }
    exit 0;   # never bounce
}

# Inject to the milter-free postfix service (see deploy/SERVER.md) so we do not
# get re-signed by the outbound milter.
my $smtp = Net::SMTP->new('127.0.0.1', Port => 10588, Timeout => 30)
    or do { logmsg("cannot connect to injector on 127.0.0.1:10588"); exit 0; };
$smtp->mail('reflector-bounces@dkim2.com');
$smtp->recipient($sender);
$smtp->data();
$smtp->datasend($result->{message});
$smtp->dataend();
$smtp->quit;
logmsg("reflected mode=$mode sender=$sender signed=$result->{signed} basis=$result->{basis}");
exit 0;
