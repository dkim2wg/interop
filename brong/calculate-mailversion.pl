#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use lib '.';
use DKIM2;

my $f1 = shift;
my $f2 = shift || die "need two files";

my $msg1 = Email::MIME->new(path($f1)->slurp);
my $msg2 = Email::MIME->new(path($f2)->slurp);

my ($num, $header) = DKIM2::diff($msg1, $msg2);

if ($num) {
  $msg1->header_raw_prepend('MailVersion', $header);
}

print $msg1->as_string();
