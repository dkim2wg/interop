#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use lib '.';
use DKIM2;

my $f1 = shift;
my $msg1 = Email::MIME->new(path($f1)->slurp);

while (1) {
  my $check = DKIM2::validate($msg1);
  die "ERROR: $check->{error}\n" unless $check->{valid};
  say "mv=$check->{mv} OK";
  last if $check->{mv} < 2;
  last unless DKIM2::undo($msg1);
  # Email::MIME keeps internal caches which get broken by replacing the body
  $msg1 = Email::MIME->new($msg1->as_string);
}
