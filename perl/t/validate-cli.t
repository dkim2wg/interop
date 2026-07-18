#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More;

# A fixed-timestamp (2026-02-20) vector: expired relative to "now", so it
# should fail without --ignore-timestamps and pass with it.
my $eml = 'tests/expected/chain-hop1-originator.eml';
plan skip_all => "vector not found" unless -e $eml;

my $with = system("perl -Ilib bin/validate.pl --ignore-timestamps $eml >/dev/null 2>&1");
is($with, 0, '--ignore-timestamps: validates an old-timestamp message');

my $without = system("perl -Ilib bin/validate.pl $eml >/dev/null 2>&1");
isnt($without, 0, 'without the flag: old-timestamp message is rejected');

done_testing;
