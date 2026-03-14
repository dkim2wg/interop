package Mail::DKIM2::Common;
use 5.20.0;
use strict;
use warnings;

our $VERSION = '0.01';

use Digest::SHA;
use MIME::Base64 qw(encode_base64 decode_base64);
use JSON::XS;
use Mail::DKIM::Canonicalization::relaxed;
use Mail::DKIM::PublicKey;

use Exporter 'import';
our @EXPORT_OK = qw(
    should_skip
    dkim2_canonicalize_header
    digest64
    encode_tag_json
    decode_tag_json
    build_signing_input
    extract_mi_version
    extract_domain
    relaxed_domain_match
    parse_dkim_pubkey
);

# Headers excluded from hashing per the DKIM2 spec
sub should_skip {
    my $hname = lc(shift);
    return 1 if $hname eq 'received';
    return 1 if $hname eq 'return-path';
    return 1 if $hname eq 'message-instance';
    return 1 if $hname eq 'dkim2-signature';
    return 1 if $hname =~ m/^x-/;
    return 1 if $hname eq 'dkim-signature';
    return 1 if $hname eq 'arc-authentication-results';
    return 1 if $hname eq 'arc-message-signature';
    return 1 if $hname eq 'arc-seal';
    return 0;
}

# DKIM2-specific canonicalization: like DKIM relaxed but also removes
# WSP around the colon separating header name from value
{
    my $relaxed = Mail::DKIM::Canonicalization::relaxed->new(Signature => 'dummy');

    sub dkim2_canonicalize_header {
        my ($line) = @_;
        my $canon = $relaxed->canonicalize_header($line);
        # DKIM relaxed already lowercases, unfolds, collapses WSP, strips trailing WSP.
        # We additionally remove WSP around the colon.
        # After relaxed, format is "name:value\r\n" (with possible SP around colon)
        $canon =~ s/\s*:\s*/:/;
        return $canon;
    }
}

# Base64-encode a Digest::SHA with proper padding
sub digest64 {
    my ($sha) = @_;
    my $res = $sha->b64digest;
    $res .= '=' while length($res) % 4;
    return $res;
}

# Encode data as base64 JSON for a tag value
sub encode_tag_json {
    my ($data) = @_;
    return encode_base64(JSON::XS->new->canonical(1)->encode($data), '');
}

# Decode a base64 JSON tag value
sub decode_tag_json {
    my ($b64) = @_;
    return JSON::XS->new->decode(decode_base64($b64));
}

# Extract the version number from a Message-Instance header value
sub extract_mi_version {
    my ($header) = @_;
    $header = $header->[0] if ref($header) eq 'ARRAY';
    $header = $$header if ref($header);
    return unless $header =~ m/^\s*v=(\d+)/;
    return $1;
}

# Extract the domain from an email address (handles <user@domain> and user@domain)
sub extract_domain {
    my ($addr) = @_;
    return unless $addr;
    $addr =~ s/^.*<//;
    $addr =~ s/>.*$//;
    return unless $addr =~ /\@(.+)$/;
    return $1;
}

# Check if mf_domain is a subdomain of (or equal to) check_domain
sub relaxed_domain_match {
    my ($mf_domain, $check_domain) = @_;
    return 0 unless $mf_domain && $check_domain;
    $mf_domain = lc($mf_domain);
    $check_domain = lc($check_domain);
    while ($mf_domain) {
        return 1 if $mf_domain eq $check_domain;
        $mf_domain =~ s/^[^.]+\.// or return 0;
    }
    return 0;
}

# Build the signing input for DKIM2 signature signing/verification.
# Args (hash):
#   mi_headers  => arrayref of { v => N, raw => "..." } sorted by v ascending
#   dk2_headers => arrayref of { i => N, raw => "...", sig => $sig_obj } sorted by i ascending
#   signing_i   => the i= value being signed/verified (gets empty b= values)
#   signature   => the Signature object for the entry being signed/verified
#
# MI headers are interleaved before DKIM2-Sig headers based on version.
# When we reach signing_i, remaining MI headers are flushed and the signature
# is serialized with empty b= values. Headers beyond signing_i are excluded.
sub build_signing_input {
    my (%args) = @_;
    my @mi_headers  = @{$args{mi_headers}  || []};
    my @dk2_headers = @{$args{dk2_headers} || []};
    my $signing_i   = $args{signing_i};
    my $signature   = $args{signature};

    my $signing_input = '';
    my $mi_idx = 0;

    for my $dk2 (@dk2_headers) {
        my $dk2_v = $dk2->{sig}->version || 0;
        # Add MI headers up to this DKIM2-Sig's version
        while ($mi_idx < @mi_headers && $mi_headers[$mi_idx]{v} <= $dk2_v) {
            $signing_input .= dkim2_canonicalize_header($mi_headers[$mi_idx]{raw});
            $mi_idx++;
        }
        if ($dk2->{i} == $signing_i) {
            # Flush remaining MI headers before the signing entry
            while ($mi_idx < @mi_headers) {
                $signing_input .= dkim2_canonicalize_header($mi_headers[$mi_idx]{raw});
                $mi_idx++;
            }
            my $sig_header = $signature->as_string_without_data();
            $signing_input .= dkim2_canonicalize_header("$sig_header\r\n");
            last;
        } else {
            $signing_input .= dkim2_canonicalize_header($dk2->{raw});
        }
    }

    return $signing_input;
}

# Parse a DKIM TXT record and return the appropriate key object.
# For RSA keys (k=rsa or no k= tag): returns a Mail::DKIM::PublicKey object.
# For ed25519 keys (k=ed25519): returns the raw 32-byte public key bytes.
# Returns undef if the key record can't be parsed.
sub parse_dkim_pubkey {
    my ($key_txt) = @_;
    return unless $key_txt;
    my ($k) = $key_txt =~ /\bk=([^;\s]+)/;
    $k //= 'rsa';  # default per RFC 6376
    if ($k eq 'ed25519') {
        my ($p) = $key_txt =~ /\bp=([A-Za-z0-9+\/=]+)/;
        return unless $p;
        return decode_base64($p);
    }
    return Mail::DKIM::PublicKey->parse($key_txt);
}

1;

__END__

=head1 NAME

Mail::DKIM2::Common - Shared utilities for DKIM2 signing and verification

=head1 SYNOPSIS

    use Mail::DKIM2::Common qw(
        should_skip
        dkim2_canonicalize_header
        digest64
        encode_tag_json
        decode_tag_json
        build_signing_input
        extract_mi_version
        extract_domain
        relaxed_domain_match
    );

    # Check if a header should be excluded from hashing
    my $skip = should_skip('Received');  # returns 1

    # Canonicalize a header line per DKIM2 rules
    my $canon = dkim2_canonicalize_header("Subject: Hello World\r\n");

    # Extract version from a Message-Instance header value
    my $v = extract_mi_version("v=3; h=...");  # returns 3

=head1 DESCRIPTION

This module provides utility functions shared between L<Mail::DKIM2::Signer>,
L<Mail::DKIM2::Verifier>, and L<Mail::DKIM2::MessageInstance>.  It also holds
the distribution-wide C<$VERSION>.

=head1 FUNCTIONS

All functions are exportable on request.

=head2 should_skip($header_name)

Returns true if the named header should be excluded from DKIM2 hashing.
Excluded headers include C<Received>, C<Return-Path>, C<Message-Instance>,
C<DKIM2-Signature>, C<DKIM-Signature>, ARC headers, and any C<X-*> header.

=head2 dkim2_canonicalize_header($line)

Applies DKIM2 header canonicalization to a raw header line (including trailing
CRLF).  This is DKIM relaxed canonicalization plus removal of whitespace
around the colon separating the header name from its value.

=head2 digest64($sha)

Takes a L<Digest::SHA> object, calls C<b64digest>, and pads the result to
a multiple of 4 characters with C<=> signs.

=head2 encode_tag_json($data)

Encodes a Perl data structure as canonical JSON, then base64-encodes it.
Used for the JSON-in-base64 tag values in DKIM2-Signature and
Message-Instance headers.

=head2 decode_tag_json($base64)

Decodes a base64-encoded JSON string back to a Perl data structure.

=head2 extract_mi_version($header)

Extracts the version number from a Message-Instance header value string.
Accepts a plain string, a scalar ref, or an arrayref (uses first element).
Returns the version number or undef if not found.

=head2 extract_domain($address)

Extracts the domain part from an email address.  Handles both bare
C<user@domain> and angle-bracket C<< <user@domain> >> forms.

=head2 relaxed_domain_match($domain1, $domain2)

Returns true if C<$domain1> is equal to or a subdomain of C<$domain2>.
Comparison is case-insensitive.

=head2 build_signing_input(%args)

Constructs the signing input string for DKIM2 signature creation or
verification.  This is the canonicalized concatenation of Message-Instance
and DKIM2-Signature headers in the correct interleaved order.

Arguments:

=over 4

=item mi_headers

Arrayref of C<< { v => N, raw => "..." } >> hashes, sorted by version.

=item dk2_headers

Arrayref of C<< { i => N, raw => "...", sig => $sig_obj } >> hashes, sorted
by sequence number.

=item signing_i

The C<i=> value of the signature being signed or verified.

=item signature

The L<Mail::DKIM2::Signature> object for the entry being signed/verified.

=back

=head1 AUTHOR

Bron Gondwana E<lt>brong@fastmailteam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 Fastmail Pty Ltd.  This is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
