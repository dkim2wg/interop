use strict;
use warnings;
use Test::More;
use FindBin;

# The operator guide names files in this repository and settings the rest
# of the repository implements; this keeps it from drifting.

my $root = "$FindBin::Bin/../..";
my $guide = "$root/docs/dkim2-postfix-list-host-guide.md";
ok(-f $guide, 'the guide exists') or BAIL_OUT('no guide');
my $text = do { local (@ARGV, $/) = $guide; <> };

my %seen;
for my $path ($text =~ /`((?:perl|deploy|mailman|sympa|util|docs)\/[A-Za-z0-9_.\/-]+)`/g) {
    next if $seen{$path}++;
    ok(-e "$root/$path", "guide path $path exists in the repo");
}
like($text, qr/^## .*Mailman/m, 'has a Mailman section');
like($text, qr/^## .*Sympa/m,   'has a Sympa section');
like($text, qr/max_recipients: 1/, 'tells Mailman to deliver one recipient per transaction');
like($text, qr/\bnrcpt 1\b/,     'tells Sympa the same');
like($text, qr/disable_mime_output_conversion = yes/, 'warns about transport conversion');
like($text, qr/pmilter-null-sender-envfrom\.patch/, 'covers the PMilter null-sender patch');
like($text, qr/DKIM2Sign/ && qr/DKIM2Verify/, 'covers the authentication_milter handlers');
unlike($text, qr{/root/interop|/opt/dkim2}, 'no dkim2.com box paths');

my $index = do { local (@ARGV, $/) = "$root/deploy/www/index.html"; <> };
like($index, qr{docs/dkim2-postfix-list-host-guide\.md}, 'dkim2.com links to the guide');
my $opguide = do { local (@ARGV, $/) = "$root/docs/dkim2-operator-guide.md"; <> };
like($opguide, qr{dkim2-postfix-list-host-guide\.md}, 'the operator guide links to it');
done_testing;
