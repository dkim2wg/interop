use strict;
use warnings;
use Test::More;
use lib 'lib';
use Mail::DKIM2::Signature;

# A transient DNS failure (timeout / SERVFAIL / network unreachable) MUST be
# reported as TEMPERROR (retryable), per draft-ietf-dkim-dkim2-spec-04 §10 —
# NOT as a permanent "no verifiable signature items". A genuine NXDOMAIN /
# no-record IS permanent and returns undef (no key). fetch_public_key signals
# the transient case by dying, which the verifier's eval maps to temperror.

# Minimal mock resolver: query() always returns no reply; errorstring() is
# whatever we set. Injected via $sig->{_resolver}.
package MockResolver;
sub new { my ($c, %a) = @_; bless {%a}, $c }
sub query { return undef }
sub errorstring { $_[0]{err} }

package main;

my $tmpl = 'i=1; m=1; t=1; d=example.com; '
         . 'mf=PHNAZXhhbXBsZS5jb20+; rt=PHJAZXhhbXBsZS5jb20+; '
         . 's=sel1:rsa-sha256:AAAA;';

# 1. Transient failures die (→ temperror in the verifier).
for my $err ('query timed out', 'SERVFAIL', 'connection failed', 'network unreachable') {
    my $sig = Mail::DKIM2::Signature->parse($tmpl);
    $sig->{_resolver} = MockResolver->new(err => $err);
    my $ok = eval { $sig->fetch_public_key(0); 1 };
    ok(!$ok, "transient DNS failure '$err' dies (temperror, not silent undef)");
    like($@, qr/temperror/i, "  ... and the die message is tagged TEMPERROR");
}

# 2. NXDOMAIN / no-record does NOT die; returns undef (genuinely no key → permerror).
for my $err ('NXDOMAIN', 'NOERROR') {
    my $sig = Mail::DKIM2::Signature->parse($tmpl);
    $sig->{_resolver} = MockResolver->new(err => $err);
    my $r = eval { $sig->fetch_public_key(0) };
    ok(!$@, "no-record '$err' does not die");
    is($r, undef, "  ... and returns undef (no key)");
}

done_testing;
