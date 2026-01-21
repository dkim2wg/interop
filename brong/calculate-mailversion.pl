#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use lib 'lib';
use Mail::DKIM::TextWrap;
use Mail::DKIM::DKIM2::MessageInstance;

my $f1 = shift || die;
my $f2 = shift;

my $msg1 = Email::MIME->new(path($f1)->slurp);
my $msg2;
if ($f2) {
  $msg2 = Email::MIME->new(path($f2)->slurp);
}

my $mi = Mail::DKIM::DKIM2::MessageInstance->calculate($msg1, $msg2);
my $output = '';
my $tw = Mail::DKIM::TextWrap->new(
            Margin => 72,
            Break => qr/[\,\;\|\:\s]/,
            Separator => "\r\n\t",
            Swallow => qr/\s+/,
            Output => \$output,
          );
$tw->add("Message-Instance:" . $mi->as_string());
$tw->finish;
$output =~ s/^Message-Instance: //;
$msg1->header_raw_prepend('Message-Instance', $output);

print $msg1->as_string();
