use strict; use warnings;
use Test::More;
use Mail::DKIM2::Common qw(DKIM2_DRAFT DKIM2_DATE);
is(DKIM2_DRAFT, 'ietf-dkim-dkim2-spec-06', 'draft constant is -06');
is(DKIM2_DATE, '2026-08-28', 'draft date is the -06 date');
done_testing;
