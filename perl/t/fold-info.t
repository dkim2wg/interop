#!/usr/bin/perl -w
#
# fold_header() on an X-DKIM2-Info line must only break at tag boundaries
# ("; ") or after a "," inside a list-valued tag, never in the middle of a
# token. The hn= list of hashed header names has no spaces and routinely runs
# to 200+ characters; the old fallback was a hard break at the margin, which
# produced continuation lines like "lis\n\tt-help" -- a header name that does
# not exist, in the very field meant to show which names were hashed.
#
# Unfolding per RFC 5322 removes only the CRLF, so a consumer sees "lis\tt-help"
# unless the break lands after the comma. Signed headers (Message-Instance,
# DKIM2-Signature) are unaffected: their base64 values contain no commas and
# still fall through to the hard break, which their parsers tolerate.

use 5.020;
use strict;
use warnings;
use Test::More;
use lib 'lib';

use Mail::DKIM2::Common qw(fold_header);

my @names = qw(
    archived-at content-type date errors-to from list-archive list-help
    list-id list-owner list-post list-subscribe list-unsubscribe message-id
    mime-version precedence subject to x-original-to
);
my $hn  = join(',', @names);
my $val = "draft=ietf-dkim-dkim2-spec-06; repo=github.com/dkim2wg/interop; "
        . "date=2026-09-18; sw=dkim2-milter.pl; action=mi-m2; "
        . "hc=" . scalar(@names) . "; hn=$hn";

my $folded = fold_header("X-DKIM2-Info: $val");
my @lines  = split /\r\n/, $folded;

ok(scalar(@lines) > 2, 'a long hn= list is folded across several lines');

for my $i (0 .. $#lines - 1) {
    like($lines[$i], qr/[;,]\z/,
        "line " . ($i + 1) . " breaks at a tag or list boundary: '$lines[$i]'");
}

for my $i (1 .. $#lines) {
    like($lines[$i], qr/^\t\S/, "line " . ($i + 1) . " is a continuation line");
    ok(length($lines[$i]) <= 78, "line " . ($i + 1) . " is within 78 chars");
}

# Unfold the RFC 5322 way (drop CRLF only), then drop the whitespace a
# consumer is told to ignore next to "," and ";", and confirm every hashed
# header name survives intact.
(my $unfolded = $folded) =~ s/\r\n//g;
$unfolded =~ s/([,;])[ \t]+/$1/g;
my ($got_hn) = $unfolded =~ /hn=(\S+)\z/;
is($got_hn, $hn, 'hn= list is intact once unfolded');

# The existing preferences are unchanged: a short line is left alone, and a
# line with "; " boundaries breaks there rather than at a comma.
is(fold_header("X-DKIM2-Info: draft=x; sw=y"), "X-DKIM2-Info: draft=x; sw=y",
    'short line untouched');
my @tagged = split /\r\n/,
    fold_header("X-DKIM2-Info: " . join('; ', map { "tag$_=a,b,c,d,e,f,g,h" } 1 .. 6));
ok(scalar(@tagged) > 1, 'tagged line is folded');
for my $l (@tagged[0 .. $#tagged - 1]) {
    like($l, qr/;\z/, "prefers the tag boundary over a comma: '$l'");
}

done_testing;
