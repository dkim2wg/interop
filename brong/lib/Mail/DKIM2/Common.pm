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

1;
