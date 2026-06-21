#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More;
use Path::Tiny;

my $script = path('bin/dkim2-reflector.pl');
ok($script->exists, 'wrapper exists');
my $src = $script->slurp;
like($src, qr/Mail::DKIM2::Reflector/, 'wrapper uses the reflector module');
like($src, qr/Port\s*=>\s*10588/, 'wrapper injects to the no-milter port 10588');
like($src, qr/reflector-bounces\@dkim2\.com/, 'wrapper uses the reflector bounce sender');
like($src, qr{/etc/dkim2/reflector/sel1\.key}, 'wrapper signs with the reflector key copy');
like($src, qr/authserv_id\s*=>\s*'mail\.dkim2\.com'/,
    'wrapper passes the configured authserv-id');
like($src, qr/Sys::Syslog/, 'wrapper logs failures to syslog');
like($src, qr/\bfresh\b/, 'wrapper knows the fresh mode');
like($src, qr/Mail::DKIM2::Reflector::generate/, 'wrapper dispatches to generate() for fresh');

# Compiles cleanly.
my $out = qx{perl -c -Ilib bin/dkim2-reflector.pl 2>&1};
like($out, qr/syntax OK/, 'wrapper compiles');

done_testing;
