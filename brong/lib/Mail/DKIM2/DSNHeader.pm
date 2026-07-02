package Mail::DKIM2::DSNHeader;
use strict;
use warnings;

use MIME::Base64 qw(encode_base64 decode_base64);
use Crypt::Digest::SHA256 qw(sha256);
use Mail::DKIM2::Common qw(fold_header to_rfc5321_path build_signing_input extract_mi_version);
use Mail::DKIM2::Signature;

# The DKIM2-DSN signature is computed the same way a DKIM2-Signature is
# (Common::build_signing_input, spec Section 9.6): over the returned message's
# Message-Instance header fields, then its DKIM2-Signature header fields, then
# the DKIM2-DSN header itself with the s= signature blanked -- i.e. the
# DKIM2-DSN signs the returned chain as though it were the last DKIM2-Signature
# appended to it. As long as sign and verify build the identical signing input
# (same returned message, same blanked-signature line), the two stay in step;
# that is the only correctness requirement for this header.

# The header value with the s= signature blanked (signing-input form).
sub _value_blank_sig {
    my ($d, $rt_b64, $sel, $alg) = @_;
    return "d=$d; rt=$rt_b64; s=$sel:$alg:";
}

# Extract the returned message's Message-Instance and DKIM2-Signature header
# fields, in the shapes build_signing_input expects, plus the notional next
# sequence number (one past the highest DKIM2-Signature i=) used as signing_i
# so that every real signature is included and none is skipped. Used
# identically by sign (new) and verify.
sub _returned_chain {
    my ($eom) = @_;
    my (@mi, @dk2);
    for my $val ($eom->header_raw('Message-Instance')) {
        my $v = extract_mi_version($val);
        push @mi, { v => $v, raw => "Message-Instance: $val" } if $v;
    }
    for my $val ($eom->header_raw('DKIM2-Signature')) {
        my $sig = eval { Mail::DKIM2::Signature->parse($val) };
        push @dk2, { i => $sig->sequence, raw => "DKIM2-Signature: $val" }
            if $sig && $sig->sequence;
    }
    @mi  = sort { $a->{v} <=> $b->{v} } @mi;
    @dk2 = sort { $a->{i} <=> $b->{i} } @dk2;
    my $next_i = @dk2 ? $dk2[-1]{i} + 1 : 1;
    return (\@mi, \@dk2, $next_i);
}

# The signing input: returned MI + DKIM2-Signature fields, then the blanked
# DKIM2-DSN header as the (last) incomplete signature.
sub _signing_input {
    my ($eom, $blank_line) = @_;
    my ($mi, $dk2, $next_i) = _returned_chain($eom);
    return build_signing_input(
        mi_headers     => $mi,
        dk2_headers    => $dk2,
        signing_i      => $next_i,   # matches no real i= -> all real sigs included
        signing_header => $blank_line,
    );
}

sub new {
    my ($class, %a) = @_;
    my $self = bless { d => $a{Domain}, sel => $a{Selector},
                       alg => $a{Algorithm} || 'rsa-sha256' }, $class;
    $self->{rt_b64} = encode_base64(to_rfc5321_path($a{RcptTo}), '');
    my $blank = "DKIM2-DSN: " . _value_blank_sig($self->{d}, $self->{rt_b64}, $self->{sel}, $self->{alg});
    my $input = _signing_input($a{Returned}, $blank);
    my $key = $a{Key};
    my $sig = ($self->{alg} =~ /^ed25519/)
        ? $key->sign_message(sha256($input))
        : $key->sign_message($input, 'SHA256', 'v1.5');
    $self->{sig_b64} = encode_base64($sig, '');
    return $self;
}

sub as_string {
    my ($self) = @_;
    my $val = "d=$self->{d}; rt=$self->{rt_b64}; "
            . "s=$self->{sel}:$self->{alg}:$self->{sig_b64}";
    return fold_header("DKIM2-DSN: $val");
}

sub parse {
    my ($class, $value) = @_;
    my $self = bless {}, $class;
    my %t; for my $p (split /\s*;\s*/, $value) { $p =~ /^(\w+)\s*=\s*(.*)/s or next;
        my ($k,$v)=($1,$2); $v =~ s/\s//gs; $t{$k}=$v; }
    $self->{d}      = $t{d};
    $self->{rt_b64} = $t{rt};
    ($self->{sel},$self->{alg},$self->{sig_b64}) = split /:/, ($t{s} // ''), 3;
    return $self;
}

sub domain    { $_[0]->{d} }
sub rcpt_to   { decode_base64($_[0]->{rt_b64} // '') }
sub selector  { $_[0]->{sel} }
sub algorithm { $_[0]->{alg} }
sub signature { decode_base64($_[0]->{sig_b64} // '') }

# Verify the DKIM2-DSN signature over the returned message ($eom), rebuilding
# the identical signing input new() signed.
sub verify {
    my ($self, $pubkey, $returned) = @_;
    return 0 unless $returned;
    my $blank = "DKIM2-DSN: " . _value_blank_sig($self->{d}, $self->{rt_b64}, $self->{sel}, $self->{alg});
    my $input = _signing_input($returned, $blank);
    my $sig = $self->signature;
    return $self->{alg} =~ /^ed25519/
        ? $pubkey->verify_message($sig, sha256($input))
        : $pubkey->verify_message($sig, $input, 'SHA256', 'v1.5');
}

1;

__END__

=head1 NAME

Mail::DKIM2::DSNHeader - Build/sign/parse/verify the DKIM2-DSN singleton header

=head1 SYNOPSIS

    use Mail::DKIM2::DSNHeader;

    my $h = Mail::DKIM2::DSNHeader->new(
        Domain    => 'example.com',
        RcptTo    => 'bounce@sender.example',
        Selector  => 'sel1',
        Key       => $private_key,        # Crypt::PK::RSA or ::Ed25519
        Algorithm => 'rsa-sha256',
        Returned  => $email_mime,         # the returned (bounced) message
    );
    print $h->as_string, "\n";            # "DKIM2-DSN: d=...; rt=...; s=...\r\n\t..."

    my $p = Mail::DKIM2::DSNHeader->parse($header_value);
    $p->domain; $p->rcpt_to; $p->selector; $p->algorithm;
    $p->verify($pubkey, $returned_email_mime) or die "bad DKIM2-DSN signature";

=head1 DESCRIPTION

B<EXPERIMENTAL> - prototype support for the standalone C<DKIM2-DSN> header,
which authenticates the Delivery Status Notification for a DKIM2 message.

The C<DKIM2-DSN> header takes the place of the C<DKIM2-Signature> and
C<Message-Instance> header fields a non-DSN message would carry. Its
signature is computed exactly as a C<DKIM2-Signature>'s would be
(L<Mail::DKIM2::Common/build_signing_input>, spec Section 9.6), over the
B<returned> (bounced) message's C<Message-Instance> header fields, then its
C<DKIM2-Signature> header fields, then the C<DKIM2-DSN> header itself with the
C<s=> signature value blanked -- so the C<DKIM2-DSN> signs the returned chain
as though it were the last C<DKIM2-Signature> appended to it.

Tags:

=over 4

=item C<d=> - signing domain (the DSN-generating recipient)

=item C<rt=> - base64-encoded RFC 5321 forward-path (bracketed address): the
returned message's top-hop C<mf=>, i.e. the DSN's destination

=item C<s=> - C<selector:algorithm:signature> triple, base64 signature

=back

There is no C<h=> tag (the returned C<Message-Instance> header fields the
signature covers already carry the header hashes), no C<t=> (freshness is
bounded by the returned message's own signatures) and no C<i=> (the
C<DKIM2-DSN> is a distinct header field, not a numbered member of the chain).

Both C<new> and C<verify> require the returned message (C<Returned> /
the second argument to C<verify>) because the signing input is built over
its C<Message-Instance>/C<DKIM2-Signature> header fields.

=head1 AUTHOR

Bron Gondwana E<lt>brong@fastmailteam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 Fastmail Pty Ltd.  This is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
