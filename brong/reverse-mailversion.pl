#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use Email::Address;
use List::Util qw(max);
use Mail::DKIM::KeyValueList;
use MIME::Base64 qw(decode_base64);

my $f1 = shift;
my $msg1 = Email::MIME->new(path($f1)->slurp);

my @mv = $msg1->header_raw('MailVersion');
my %vmap = map { getv($_) => $_ } @mv;
my $version = %vmap ? max(keys %vmap) : 0;

die "No MailVersion header" unless $version;

$msg1->header_raw_set('MailVersion', grep { getv($_) < $version } @mv);

my $header = $vmap{$version};

my $data = Mail::DKIM::KeyValueList->parse($header);

for my $tag (@{$data->{tags}}) {
  if ($tag->{name} =~ m/^h\.(.*)/) {
    my $h = $1;
    my @program = split /,/, $tag->{value};
    for my $cmd (@program) {
      if ($cmd =~ m/d:(.*)/) {
        my $rem = $1;
	if ($rem eq '*') {
	  $msg1->header_raw_set($h);
	}
	else {
	  my @vals = $msg1->header_raw($h);
	  splice(@vals, $rem-1, 1);
	  $msg1->header_raw_set($h, @vals);
	}
      } elsif ($cmd =~ m/t:(.*)/) {
	$msg1->header_raw_prepend($h, $1);
      } elsif ($cmd =~ m/b:(.*)/) {
	$msg1->header_raw_prepend($h, decode_base64($1));
      }
    }
  } elsif ($tag->{name} eq 'b') {
    my @l1 = split /\r?\n/, $msg1->body_raw;
    my @program = split /,/, $tag->{value};
    my @outlist;
    for my $cmd (@program) {
      if ($cmd =~ m/c:(\d+)-(\d+)/) {
	my ($from, $to) = ($1-1, $2-1);
	push @outlist, @l1[$from..$to];
      } elsif ($cmd =~ m/t:(.*)/) {
	push @outlist, $1;
      } elsif ($cmd =~ m/b:(.*)/) {
	push @outlist, decode_base64($1);
      }
    }
    $msg1->body_set(join("\r\n", @outlist));
  }
}



say $msg1->as_string();

sub getv {
  my $arg = shift;
  return 0 unless $arg =~ m/v=(\d+)/;
  return 0 + $1;
}
