use strict;
use warnings;
use Test::More;
use Time::HiRes qw(time);
use lib 'lib';
use Mail::DKIM2::MessageInstance;

# The header recipe matches each previous field to the next unused current
# field with the same canonical value. Scanning that value's whole index list
# per field made N repeats cost N^2 (follow-up review F1: 16,000 repeated
# Comments fields took ~3 s). Doubling N must roughly double the time.

sub calc_time {
    my ($n) = @_;
    my $previous = "From: a\@example.com\r\n" . ("Comments: same\r\n" x $n) . "\r\nbody\r\n";
    my $mi = Mail::DKIM2::MessageInstance->calculate($previous)->as_string;
    $previous = "Message-Instance: $mi\r\n" . $previous;
    (my $current = $previous) =~ s/From:/Comments: changed\r\nFrom:/;
    my $start = time;
    my $out = Mail::DKIM2::MessageInstance->calculate($current, $previous);
    return (time - $start, $out);
}

calc_time(500);    # warm up
my ($small) = calc_time(4000);
my ($large, $mi) = calc_time(16000);
cmp_ok($large / ($small || 1e-6), '<', 8, sprintf('4x the fields takes < 8x the time (%.3fs vs %.3fs)', $large, $small));
is_deeply($mi->{bits}{rh}{comments}, [[1, 16000]], 'the recipe copies the 16,000 original fields and drops the new one');

done_testing;
