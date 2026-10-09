#!/usr/bin/perl
# Regenerate vectors/body-diff.json from the Perl reference
# (Mail::DKIM2::MessageInstance::_body_diff). Every implementation's body
# diff must produce exactly these Recipes; see
# docs/superpowers/specs/2026-10-09-capped-myers-body-diff-design.md.
#
#   perl util/build-body-diff-vectors.pl > vectors/body-diff.json
#
# Each case: {name, cur, prev, max_literals, expect}. expect is "identical",
# "too_big", or the Recipe: [from,to] copy ranges (1-based into cur) and
# literal lines. Cases too large for a JSON file (the work budget, timing)
# live in each implementation's own tests.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../perl/lib";
use JSON::PP;
use Mail::DKIM2::MessageInstance;

my @cases;
sub add {
    my ($name, $cur, $prev, $max) = @_;
    $max //= 1000;
    my $r = Mail::DKIM2::MessageInstance::_body_diff($cur, $prev, $max);
    push @cases, {
        name => $name, cur => $cur, prev => $prev, max_literals => $max + 0,
        expect => !defined $r ? 'identical' : ref $r ? $r : $r,
    };
}

add('identical', [qw(a b c)], [qw(a b c)]);
add('both empty', [], []);
add('line added at the top', [qw(x a b c)], [qw(a b c)]);
add('line removed at the end', [qw(a b c)], [qw(a b c d)]);
add('changed middle line', [qw(a B c)], [qw(a b c)]);
add('empty current body', [], [qw(a b)]);
add('empty previous body', [qw(a b)], []);
add('swap', [qw(a b)], [qw(b a)]);
add('blank lines', ['', 'a', '', '', 'b', ''], ['', '', 'a', 'b', '', '']);
add('list wrap', ['header', '--b', '', 'x', 'y', '--b--', 'footer'], [qw(x y)]);

{
    my @tail = map { "tail $_" } 1 .. 60;
    my @prev = ((map { "old $_" } 1 .. 7), @tail);
    my @cur  = ((map { "new $_" } 1 .. 11), @tail);
    $cur[40] = 'edited';
    add('front replaced + mid edit', \@cur, \@prev);
}
{
    my @prev = map { $_ % 3 ? '' : "p$_" } 1 .. 60;
    my @cur  = map { $_ % 3 ? '' : "c$_" } 1 .. 60;
    add('blank-heavy', \@cur, \@prev);
}
{
    my @cur  = map { "c$_" } 1 .. 5;
    my @prev = ((map { "p$_" } 1 .. 1000), @cur);
    add('exactly 1000 literals', \@cur, \@prev);
    add('1001 literals', \@cur, [@prev, 'one more']);
}
add('cap 2 exceeded', [qw(a b c)], [qw(a x y z c)], 2);
add('cap 3 met', [qw(a b c)], [qw(a x y z c)], 3);
add('alternating', [('a', 'b') x 50], [('b', 'a') x 50]);
add('line-count floor', [('x', 'y') x 10], [('y', 'y', 'x') x 10], 5);
add('repeated block', [qw(a b c a b c a b c)], [qw(c b a c b a)]);

# The work budget, either side of where it runs out. A one-literal Recipe
# exists for both; only the work count (one per snake step, one per
# diagonal, checked after each diagonal) separates them.
add('work budget: just enough', [('x', 'y') x 1413, 'z'], [qw(z x y)]);
add('work budget: exceeded',    [('x', 'y') x 1414, 'z'], [qw(z x y)]);

# Seeded random cases over small alphabets pin the tie-breaking. A
# deterministic LCG, not Perl's rand, so the file regenerates identically.
my $seed = 20261009;
sub rnd { $seed = ($seed * 1103515245 + 12345) % 2**31; return $seed % $_[0] }
for my $t (1 .. 150) {
    my $alpha = 1 + rnd(5);
    my @c = map { chr(97 + rnd($alpha)) } 1 .. rnd(16);
    my @p = map { chr(97 + rnd($alpha)) } 1 .. rnd(16);
    add("random $t", \@c, \@p, $t % 10 == 0 ? 2 : 1000);
}

print JSON::PP->new->canonical->indent->space_after->encode({
    description => 'Capped Myers body diff vectors; regenerate with util/build-body-diff-vectors.pl',
    cases => \@cases,
});
