#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use lib '.';
use DKIM2;
use Mail::DKIM::TextWrap;

my $f1 = shift;
my $f2 = shift || die "need two files";

my $msg1 = Email::MIME->new(path($f1)->slurp);
my $msg2 = Email::MIME->new(path($f2)->slurp);
$msg1->header_raw_set('MailVersion');

my ($num, $header) = DKIM2::diff($msg1, $msg2);

if ($num) {
  my $output = '';
  my $tw = Mail::DKIM::TextWrap->new(
	     Margin => 72,
	     Break => qr/[,;\s]/,
	     Separator => "\n\t",
	     Swallow => qr/\s+/,
             Output => \$output,
          );
  $tw->add("MailVersion: " . $header);
  $tw->finish;
  $output =~ s/^MailVersion: //;
  $msg1->header_raw_prepend('MailVersion', $output);
}

print $msg1->as_string();
