#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use lib 'lib';
use Mail::DKIM2::MessageInstance;

my $f1 = shift;
my $data = path($f1)->slurp;
$data =~ s/\r//gs;
$data =~ s/\n/\r\n/gs;
my $msg1 = Email::MIME->new($data);

while (1) {
  my ($res, $error) = Mail::DKIM2::MessageInstance->verify($msg1);
  if (!$res) {
    die "verification failed: $error\n" if $error;
    last;
  }
  say "valid at $res";

  Mail::DKIM2::MessageInstance->undo($msg1);
  $msg1 = Email::MIME->new($msg1->as_string);
}
