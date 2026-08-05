#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use Getopt::Long::Descriptive;
use lib 'lib';
use Mail::DKIM2::Signer;

my ($opt, $usage) = describe_options(
  '%c %o file',
  [ 'key|k=s', 'override keyfile for signing' ],
  [ 'algorithm|a=s', 'algorithm', { default => 'rsa-sha256' } ],
  [ 'selector|s=s', 'selector', { default => 'sel1' } ],
  [ 'domain|d=s', 'domain', { default => 'test1.dkim2.com' } ],
  [ 'mailfrom|mf=s', 'return-path address' ],
  [ 'quiet|q', "Quiet mode - only print the new DKIM2 header" ],
  [ 'rcptto|rt=s@', 'rcpt-to address (comma separated, or specify multiple times)' ],
  [ 'help|h', "print usage message and exit", { shortcircuit => 1 } ],
);

print($usage->text), exit if ($opt->help or not @ARGV);

my $f1 = shift;
my $msg1 = Email::MIME->new(path($f1)->slurp);

my $keyfile = $opt->key || "../keys/" . $opt->selector . "._domainkey." . $opt->domain . ".pem";

my $signer = Mail::DKIM2::Signer->new(
  Domain    => $opt->domain,
  Selector  => $opt->selector,
  KeyFile   => $keyfile,
  Algorithm => $opt->algorithm,
  MailFrom  => $opt->mailfrom,
  RcptTo    => $opt->rcptto,
);

$signer->PRINT($msg1->as_string());
$signer->CLOSE;

my $header = $signer->as_string();

if ($opt->quiet) {
  say "$header";
} else {
  $header =~ s{^DKIM2-Signature:\s*}{};
  $msg1->header_raw_prepend('DKIM2-Signature', $header);
  print $msg1->as_string();
}
