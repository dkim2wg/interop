#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use lib 'lib';
use Mail::DKIM2::MessageInstance;

my $f1 = shift;
my $msg1 = Email::MIME->new(path($f1)->slurp);

Mail::DKIM2::MessageInstance->undo($msg1);

print $msg1->as_string();
