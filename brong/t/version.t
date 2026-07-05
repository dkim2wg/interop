use strict; use warnings;
use Test::More;
use Mail::DKIM2::Common qw(DKIM2_DRAFT DKIM2_DATE);
is(DKIM2_DRAFT, 'ietf-dkim-dkim2-spec-04', 'draft constant is -04');
is(DKIM2_DATE, '2026-07-05', 'draft date is the -04 date');
done_testing;
