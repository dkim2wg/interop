#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use lib '.';
use DKIM2;
use List::Util qw(max);
use JSON;


my $f1 = shift;
my $data = path($f1)->slurp;
$data =~ s/\r//gs;
$data =~ s/\n/\r\n/gs;
my $msg1 = Email::MIME->new($data);

my $dns = decode_json(path('../dns.json')->slurp);

my %map = map { DKIM2::geti($_) => $_ } $msg1->header('DKIM2-Signature');
my $num = %map ? max(keys %map) : 0;
my %mimap = map { DKIM2::getmi($_) => $_ } $msg1->header('Message-Instance');
my $instance = %mimap ? max(keys %mimap) : 0;

while (1) {
  my $hi = $num ? DKIM2::getmi($map{$num}) : 0;
  while ($instance > $hi) {
    my $check = DKIM2::validate($msg1);
    die "ERROR: $check->{error}\n" unless $check->{valid};
    die "DIDN'T FIND TOP $instance <> $check->{mi}" unless $instance == $check->{mi};
    say "OK Message-Instance: mi=$check->{mi}";
    die "Failed to undo" unless DKIM2::undo($msg1);
    # Email::MIME keeps internal caches which get broken by replacing the body
    $instance--;
    last unless $instance;
    $msg1 = Email::MIME->new($msg1->as_string);
    %mimap = map { DKIM2::getmi($_) => $_ } $msg1->header('Message-Instance');
    %map = map { DKIM2::geti($_) => $_ } $msg1->header('DKIM2-Signature');
    my $newnum = %map ? max(keys %map) : 0;
    my $newinstance = %mimap ? max(keys %mimap) : 0;
    die "MISMATCH TOP DKIM" unless $num == $newnum;
    die "MISMATCH TOP VERSION $instance <> $newinstance" unless $instance == $newinstance;
    die "NO SUCH Message-Instance mi=$instance" unless $mimap{$instance};
  }
  last unless $num;
  my $h = $map{$num};
  die "NO SUCH DKIM2-Header i=$num" unless $h;
  my $res = DKIM2::verify($msg1, sub { find_key(@_) } );
  if ($res->{result} eq 'pass') {
    say "OK DKIM2-Signature: i=$num; mi=$instance; s=$res->{s}; d=$res->{d}";
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
