#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use lib 'lib';
use Mail::DKIM2::Common qw(extract_mi_version);
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Verifier;
use Mail::DKIM::PublicKey;
use List::Util qw(max);
use JSON;

my $f1 = shift;
my $data = path($f1)->slurp;
$data =~ s/\r//gs;
$data =~ s/\n/\r\n/gs;
my $msg1 = Email::MIME->new($data);

my $dns = decode_json(path('../dns.json')->slurp);

my %map = map { _geti($_) => $_ } $msg1->header('DKIM2-Signature');
my $num = %map ? max(keys %map) : 0;
my %mimap = map { extract_mi_version($_) => $_ } $msg1->header('Message-Instance');
my $instance = %mimap ? max(keys %mimap) : 0;

while (1) {
  my $hi = $num ? _getv($map{$num}) : 0;
  while ($instance > $hi) {
    my ($check, $error) = Mail::DKIM2::MessageInstance->verify($msg1);
    die "ERROR: failed to verify instance $instance: $error\n" unless $check;
    die "DIDN'T FIND TOP $instance <> $check" unless $instance == $check;
    say "OK Message-Instance: v=$check";
    die "Failed to undo" unless Mail::DKIM2::MessageInstance->undo($msg1);
    # Email::MIME keeps internal caches which get broken by replacing the body
    $instance--;
    last unless $instance;
    $msg1 = Email::MIME->new($msg1->as_string);
    %mimap = map { Mail::DKIM2::MessageInstance::getmi($_) => $_ } $msg1->header('Message-Instance');
    %map = map { _geti($_) => $_ } $msg1->header('DKIM2-Signature');
    my $newnum = %map ? max(keys %map) : 0;
    my $newinstance = %mimap ? max(keys %mimap) : 0;
    die "MISMATCH TOP DKIM" unless $num == $newnum;
    die "MISMATCH TOP VERSION $instance <> $newinstance" unless $instance == $newinstance;
    die "NO SUCH Message-Instance v=$instance" unless $mimap{$instance};
  }
  last unless $num;
  my $h = $map{$num};
  die "NO SUCH DKIM2-Header i=$num" unless $h;

  # Create a verifier for this specific signature
  my $verifier = Mail::DKIM2::Verifier->new();
  $verifier->set_pubkey_callback(sub { find_key(@_) });
  $verifier->PRINT($msg1->as_string());
  $verifier->CLOSE;

  if ($verifier->result eq 'pass') {
    say "OK DKIM2-Signature: i=$num; v=$instance";
  } else {
    die "DKIM2-Signature i=$num: " . $verifier->result_detail();
  }
  $msg1->header_raw_set('DKIM2-Signature', grep { _geti($_) < $num } $msg1->header('DKIM2-Signature'));
  $num--;
}

sub _geti {
  my $arg = shift;
  return 0 unless $arg =~ m/\bi=(\d+)/;
  return 0 + $1;
}

sub _getv {
  my $arg = shift;
  return 0 unless $arg =~ m/\bv=(\d+)/;
  return 0 + $1;
}

sub find_key {
  my $signature = shift;
  my $sel = $signature->selector(0);
  my $dom = $signature->domain;
  my $key_txt = $dns->{$dom}{"$sel._domainkey"}[0][1];
  return unless $key_txt;
  return Mail::DKIM::PublicKey->parse($key_txt);
}
