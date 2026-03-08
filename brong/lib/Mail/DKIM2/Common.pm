package Mail::DKIM2::Common;
use strict;
use warnings;

use Digest::SHA;
use MIME::Base64 qw(encode_base64 decode_base64);
use JSON::XS;
use Mail::DKIM::Canonicalization::relaxed;

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

1;
