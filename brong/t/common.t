use strict;
use warnings;
use Test::More;
use lib 'lib';
use Mail::DKIM2::Common qw(should_skip);

is(should_skip('authentication-results'), 1, 'authentication-results is skipped');
is(should_skip('Authentication-Results'), 1, 'Authentication-Results (mixed case) is skipped');
is(should_skip('subject'), 0, 'subject is NOT skipped');
is(should_skip('from'), 0, 'from is NOT skipped');
is(should_skip('received'), 1, 'received is still skipped');

done_testing;
