#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use Email::Address;
use Mail::DKIM::Signer;
use Mail::DKIM::TextWrap;
use List::Util qw(max);
use Getopt::Long::Descriptive;

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

my $alg = $opt->algorithm;
my $sel = $opt->selector;
my $dom = $opt->domain;
my $key = $opt->key || "../keys/$sel._domainkey.$dom.pem";
$alg = 'es25519' if -s $key < 500;

my %interesting;
# we're going to sign everything except trace headers and DKIM-Signature and X-Headers:
for my $header ($msg1->header_names) {
  $interesting{lc($header)} = '+' unless should_skip($header);
}

my %map = map { geti($_) => $_ } $msg1->header('DKIM2-Signature');
my $num = %map ? max(keys %map) : 0;
$num++;
my %vmap = map { getv($_) => $_ } $msg1->header('MailVersion');
my $version = %vmap ? max(keys %vmap) : 0;

my $eml = $msg1->as_string();
my $signer = Mail::DKIM::Signer->new(
  Algorithm => $alg,
  Method => 'relaxed',
  Domain => $dom,
  Selector => $sel,
  KeyFile => $key,
);
$signer->extended_headers(\%interesting);
$signer->PRINT($eml);
$signer->CLOSE();
my $signature = $signer->signature;
$signature->set_tag('v', $version) if $version;
# remove the generated 'h=' tag 
$signature->set_tag('h', undef);
my $from = $opt->mailfrom || extract_from($msg1);
$signature->set_tag('mf', $from);
my $rt;
if (my $val = $opt->rcptto) {
  $rt = join(',', @$val);
}
$rt ||= extract_to($msg1);
$signature->set_tag('rt', $rt);
$signature->prefix("i=$num;");
if ($opt->quiet) {
  say "DKIM2-Signature: " . $signature->as_string;
} else {
  $msg1->header_raw_prepend('DKIM2-Signature', $signature->as_string);
  print $msg1->as_string();
} 

sub geti {
  my $arg = shift;
  return 0 unless $arg =~ m/i=(\d+)/;
  return 0 + $1;
}

sub getv {
  my $arg = shift;
  return 0 unless $arg =~ m/v=(\d+)/;
  return 0 + $1;
}

sub should_skip {
  my $hname = lc(shift);
  # Trace Headers
  return 1 if $hname eq 'received';
  return 1 if $hname eq 'return-path';
  return 1 if $hname eq 'mailversion';
  return 1 if $hname eq 'dkim-signature';
  # X headers
  return 1 if $hname =~ m/^x-/;
}

sub extract_from {
  my $msg = shift;
  my @addrs = extract_addrs($msg->header('Sender'), $msg->header('From'));
  return $addrs[0];
}

sub extract_to {
  my $msg = shift;
  my @addrs = extract_addrs($msg->header('To'), $msg->header('Cc'), $msg->header('Bcc'));
  return unless @addrs;
  return join(',', @addrs);
}

sub extract_addrs {
  my %res;
  for my $item (@_) {
    next unless $item;
    my @addrs = Email::Address->parse($item);
    for my $one (@addrs) {
      next unless $one->address;
      $res{lc($one->address)} = 1;
    }
  }
  return sort keys %res;
}
