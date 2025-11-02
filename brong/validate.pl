#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use lib '.';
use DKIM2;
use List::Util qw(max);
use JSON;


my $f1 = shift;
my $msg1 = Email::MIME->new(path($f1)->slurp);

my $dns = decode_json(path('../dns.json')->slurp);

my %map = map { DKIM2::geti($_) => $_ } $msg1->header('DKIM2-Signature');
my $num = %map ? max(keys %map) : 0;
my %vmap = map { DKIM2::getv($_) => $_ } $msg1->header('Mail-Version');
my $version = %vmap ? max(keys %vmap) : 0;

while (1) {
  my $hv = $num ? DKIM2::getv($map{$num}) : 0;
  while ($version > $hv) {
    my $check = DKIM2::validate($msg1);
    die "ERROR: $check->{error}\n" unless $check->{valid};
    die "DIDN'T FIND TOP $version <> $check->{mv}" unless $version == $check->{mv};
    say "mv=$check->{mv} OK";
    die "Failed to undo" unless DKIM2::undo($msg1);
    # Email::MIME keeps internal caches which get broken by replacing the body
    $version--;
    last unless $version;
    $msg1 = Email::MIME->new($msg1->as_string);
    %vmap = map { DKIM2::getv($_) => $_ } $msg1->header('Mail-Version');
    %map = map { DKIM2::geti($_) => $_ } $msg1->header('DKIM2-Signature');
    my $newnum = %map ? max(keys %map) : 0;
    my $newversion = %vmap ? max(keys %vmap) : 0;
    die "MISMATCH TOP DKIM" unless $num == $newnum;
    die "MISMATCH TOP VERSION $version <> $newversion" unless $version == $newversion;
    die "NO SUCH Mail-Version mv=$version" unless $vmap{$version};
  }
  last unless $num;
  my $h = $map{$num};
  die "NO SUCH DKIM2-Header i=$num" unless $h;
  my $res = DKIM2::verify($msg1, sub { find_key(@_) } );
  if ($res->{result} eq 'pass') {
    say "i=$num OK (mv=$version)";
  } else {
    use Data::Dumper;
    die Dumper($res);
  }
  $msg1->header_raw_set('DKIM2-Signature', grep { DKIM2::geti($_) < $num } $msg1->header('DKIM2-Signature'));
  $num--;
}

sub find_key {
  my $signature = shift;
  return $dns->{$signature->domain}{$signature->selector . "._domainkey"}[0][1];
}
