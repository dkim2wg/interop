#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use lib '.';
use DKIM2;

my $f1 = shift;
my $msg1 = Email::MIME->new(path($f1)->slurp);

my $num = DKIM2::undo($msg1);

say $msg1->as_string();
