use strict; use warnings;
use Test::More;
use Mail::DKIM2::Common qw(DKIM2_DRAFT DKIM2_DATE);
is(DKIM2_DRAFT, 'ietf-dkim-dkim2-spec-06', 'draft constant is -06');
is(DKIM2_DATE, '2026-09-30', 'software date is the last DKIM2 behaviour change (debug-header-01 form)');
done_testing;
