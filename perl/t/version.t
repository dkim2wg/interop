use strict; use warnings;
use Test::More;
use Mail::DKIM2::Common qw(DKIM2_DRAFT DKIM2_DATE);
is(DKIM2_DRAFT, 'ietf-dkim-dkim2-spec-05', 'draft constant is -05');
is(DKIM2_DATE, '2026-08-25', 'draft date is the -05 date');
done_testing;
