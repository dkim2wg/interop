#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More;
use MIME::Base64 qw(decode_base64);
use lib 'lib';
use Mail::DKIM2::MessageInstance;

my $orig = "Subject: hi\r\nMessage-Instance: m=1; h=sha256:AAA:BBB;\r\n\r\nbody line one\r\n";
my $new  = "Subject: hi\r\nMessage-Instance: m=1; h=sha256:AAA:BBB;\r\n\r\nbody line one\r\nfooter\r\n";

my $mi = Mail::DKIM2::MessageInstance->calculate($new, $orig);
$mi->set_null_body_recipe;
my $str = $mi->as_string;

like($str, qr/^m=2;/, 'still increments the instance number');

# The r= tag value is base64-encoded JSON; decode it to inspect the recipe.
my ($r) = $str =~ /r=([^;]+)/;
ok($r, 'has an r= tag');
my $json = decode_base64($r);
like($json, qr/"b"\s*:\s*null/, 'recipe JSON has b:null (non-recreatable body)');
unlike($json, qr/"c"\s*:/, 'no copy steps remain in body recipe');

done_testing;
