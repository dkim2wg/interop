#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use lib '.';
use DKIM2;
use Mail::DKIM::TextWrap;

my $f1 = shift || die;
my $f2 = shift;

my $msg1 = Email::MIME->new(path($f1)->slurp);
my $num = 1;
my @bits;
$msg1->header_raw_set('MailVersion');
if ($f2) {
  my $msg2 = Email::MIME->new(path($f2)->slurp);
  ($num, @bits) = DKIM2::diff($msg1, $msg2);
}
elsif ($msg1->header_raw('Mail-Version')) {
  warn "Removing all exisiting Mail-Version headers";
  $msg1->header_raw_set('Mail-Version');
}
unshift @bits, DKIM2::calc($msg1);

my $output = '';
my $tw = Mail::DKIM::TextWrap->new(
	     Margin => 72,
	     Break => qr/[,;\s]/,
	     Separator => "\n\t",
	     Swallow => qr/\s+/,
             Output => \$output,
          );
$tw->add("Mail-Version: " . join('; ', "mv=$num", @bits));
$tw->finish;
$output =~ s/^Mail-Version: //;
$msg1->header_raw_prepend('Mail-Version', $output);

print $msg1->as_string();
