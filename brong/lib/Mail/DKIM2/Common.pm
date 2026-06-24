package Mail::DKIM2::Common;
use 5.20.0;
use strict;
use warnings;

our $VERSION = '0.01';

use MIME::Base64 qw(encode_base64 decode_base64);
use JSON::XS;
use Crypt::PK::RSA;
use Crypt::PK::Ed25519;
use Crypt::Digest::SHA256 qw(sha256 sha256_b64 sha256_hex);

use Exporter 'import';
our @EXPORT_OK = qw(
    should_skip
    dkim2_canonicalize_header
    dkim2_canonicalize_sig_header
    digest64
    encode_tag_json
    decode_tag_json
    fold_header
    fold_value
    build_signing_input
    extract_mi_version
    strip_mi_versions
    extract_domain
    relaxed_domain_match
    parse_dkim_pubkey
    load_private_key
    DKIM2_DRAFT
    DKIM2_REPO
    DKIM2_DATE
);

# Spec-version provenance, emitted in X-DKIM2-Info headers by the milter, the
# reflector, and the mailman/sympa handlers. This is the single source of truth
# for the Perl implementation; bump on a spec change (see the dkim2-spec-version
# memory for the full cross-repo list).
use constant DKIM2_DRAFT => 'ietf-dkim-dkim2-spec-03';
use constant DKIM2_REPO  => 'github.com/dkim2wg/interop';
use constant DKIM2_DATE  => '2026-06-24';

# Headers excluded from hashing per draft-ietf-dkim-dkim2-spec-03 Section 4
sub should_skip {
    my $hname = lc(shift);
    return 1 if $hname eq 'received';
    return 1 if $hname eq 'return-path';
    return 1 if $hname eq 'delivered-to';
    return 1 if $hname eq 'message-instance';
    return 1 if $hname eq 'dkim2-signature';
    return 1 if $hname =~ m/^x-/;
    return 1 if $hname eq 'dkim-signature';
    return 1 if $hname =~ m/^arc-/;
    return 1 if $hname eq 'authentication-results';
    return 0;
}

# DKIM2 header canonicalization for HEADER HASH per spec-02 Section 5.2:
# 1. Lowercase header name
# 2. Unfold continuation lines (remove CRLF before WSP)
# 3. Collapse runs of WSP to single SP
# 4. Strip trailing WSP before CRLF
# 5. Remove WSP around the colon
sub dkim2_canonicalize_header {
    my ($line) = @_;
    # Unfold: remove CRLF followed by WSP
    $line =~ s/\r?\n[ \t]/ /g;
    # Split on colon
    my ($name, $value) = split(/:/, $line, 2);
    return $line unless defined $value;
    # Lowercase name
    $name = lc($name);
    # Collapse WSP runs to single SP
    $value =~ s/[ \t]+/ /g;
    # Strip leading and trailing WSP from value
    $value =~ s/^[ \t]+//;
    $value =~ s/[ \t]*\r?\n?$//;
    return "$name:$value\r\n";
}

# DKIM2 header canonicalization for SIGNATURE INPUT per spec-02 Section 8.5:
# Same as header hash canonicalization except step 3 deletes ALL WSP
# characters rather than collapsing to single SP.
sub dkim2_canonicalize_sig_header {
    my ($line) = @_;
    # Unfold: remove CRLF followed by WSP
    $line =~ s/\r?\n[ \t]//g;
    # Split on colon
    my ($name, $value) = split(/:/, $line, 2);
    return $line unless defined $value;
    # Lowercase name
    $name = lc($name);
    # Delete ALL WSP characters
    $value =~ s/[ \t]+//g;
    # Strip trailing CRLF/LF
    $value =~ s/\r?\n?$//;
    return "$name:$value\r\n";
}

# Base64-encode a digest object (CryptX b64digest includes padding)
sub digest64 {
    my ($sha) = @_;
    return $sha->b64digest;
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

# Fold a header line at 72 characters.
# Fold a header line to $margin characters (default 72).
# Only for headers we are creating — never for headers read from elsewhere.
# First tries to fold at "; " tag boundaries, then breaks any remaining
# long segments at character positions.
# Input: a complete header line like "DKIM2-Signature: i=1; v=1; ..."
# Output: folded with "\r\n\t" continuation lines
# Tab = 8 chars visually, so continuation lines get 64 chars of content.
# First line target: 72 chars.  Continuation: 64 content + 8 tab = 72.
sub fold_header {
    my ($line, $margin) = @_;
    $margin //= 72;
    my $cont_margin = $margin - 8;  # content chars on continuation lines

    return $line if length($line) <= $margin;

    my @folded;
    my $remaining = $line;
    my $limit = $margin;

    while (length($remaining) > $limit) {
        # Find the best break point: prefer "; " boundaries, then
        # any space.  Look backwards from the limit.
        my $break = -1;

        # Try to break at "; " (tag boundary)
        my $search = substr($remaining, 0, $limit);
        my $pos = rindex($search, '; ');
        if ($pos > 0) {
            # Break after the semicolon, before the space
            $break = $pos + 1;
        }

        # If no tag boundary, try breaking at any space
        if ($break < 0) {
            $pos = rindex($search, ' ');
            $break = $pos if $pos > 0;
        }

        # If a space occurs within 2 chars before the limit, fold at
        # the space rather than leaving a 1-2 char orphan before the
        # next forced break.
        if ($break < 0 || $limit - $break <= 2) {
            # Check for a space near the limit
            for my $i (reverse ($limit - 3)..($limit - 1)) {
                next if $i < 0 || $i >= length($remaining);
                if (substr($remaining, $i, 1) eq ' ') {
                    $break = $i;
                    last;
                }
            }
        }

        # Last resort: hard break at limit
        $break = $limit if $break < 0;

        my $chunk = substr($remaining, 0, $break);
        $remaining = substr($remaining, $break);

        # Strip trailing WSP from chunk, leading WSP from remainder
        $chunk =~ s/\s+$//;
        $remaining =~ s/^\s+//;

        push @folded, $chunk;
        $limit = $cont_margin;
    }
    push @folded, $remaining if length($remaining);

    return join("\r\n\t", @folded);
}

# Fold a string at arbitrary character positions.
# Only safe for content that has NOT been signed — e.g. the s= tag value
# after signature computation but before insertion into the message.
sub fold_value {
    my ($line, $margin) = @_;
    $margin //= 64;  # 64 content + 8 tab = 72 visible

    return $line if length($line) <= $margin;

    my @parts;
    while (length($line) > 0) {
        push @parts, substr($line, 0, $margin, '');
    }
    return join("\r\n\t", @parts);
}

# Extract the revision number from a Message-Instance header value (m= tag)
sub extract_mi_version {
    my ($header) = @_;
    $header = $header->[0] if ref($header) eq 'ARRAY';
    $header = $$header if ref($header);
    return unless $header =~ m/^\s*m=(\d+)/;
    return $1;
}

# Strip Message-Instance headers with the given version numbers from a raw message string.
# The message must use CRLF line endings.  Returns the modified message string.
sub strip_mi_versions {
    my ($message, @versions) = @_;
    return $message unless @versions;
    my %to_strip = map { $_ => 1 } @versions;

    my $EOL = "\015\012";
    my $sep_pos = index($message, $EOL . $EOL);
    return $message if $sep_pos < 0;

    my $hdrs_raw = substr($message, 0, $sep_pos);
    my $rest     = substr($message, $sep_pos);   # includes blank line + body

    # Parse folded headers into whole-header strings
    my @entries;
    my $cur = '';
    for my $line (split /\015\012/, $hdrs_raw, -1) {
        if ($line =~ /^[ \t]/ && $cur ne '') {
            $cur .= $EOL . $line;
        } else {
            push @entries, $cur if $cur ne '';
            $cur = $line;
        }
    }
    push @entries, $cur if $cur ne '';

    # Keep all headers except Message-Instance ones with versions in %to_strip
    my @kept;
    for my $entry (@entries) {
        if ($entry =~ /^Message-Instance:/i) {
            my ($val) = $entry =~ /^[^:]+:\s*(.*)/s;
            if (defined $val) {
                $val =~ s/\015?\012[ \t]+/ /g;   # unfold for version extraction
                my $ver = extract_mi_version($val);
                next if defined $ver && $to_strip{$ver};
            }
        }
        push @kept, $entry;
    }

    return join($EOL, @kept) . $rest;
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
#   signing_i   => the i= value being signed/verified (gets empty s= value)
#   signature   => the Signature object for the entry being signed/verified
#   signing_header => optional folded header string (signer path)
#
# Per draft-ietf-dkim-dkim2-spec-02 Section 8.5:
#   1. All Message-Instance headers in ascending v= order
#   2. All prior DKIM2-Signature headers in ascending i= order
#   3. The incomplete DKIM2-Signature (with empty s=) being signed/verified
sub build_signing_input {
    my (%args) = @_;
    my @mi_headers  = @{$args{mi_headers}  || []};
    my @dk2_headers = @{$args{dk2_headers} || []};
    my $signing_i   = $args{signing_i};
    my $signature   = $args{signature};

    my $signing_input = '';

    # 1. All MI headers in ascending m= order
    for my $mi (@mi_headers) {
        $signing_input .= dkim2_canonicalize_sig_header($mi->{raw});
    }

    # 2. Prior DKIM2-Signature headers (i < signing_i) in ascending i= order
    for my $dk2 (@dk2_headers) {
        next if $dk2->{i} == $signing_i;
        $signing_input .= dkim2_canonicalize_sig_header($dk2->{raw});
    }

    # 3. The incomplete signature being signed/verified
    # Signer passes signing_header (folded); verifier uses default (unfolded)
    my $sig_header = $args{signing_header} // $signature->as_string_without_data();
    $sig_header .= "\r\n" unless $sig_header =~ /\r\n$/;
    $signing_input .= dkim2_canonicalize_sig_header($sig_header);

    return $signing_input;
}

# Parse a DKIM TXT record and return the appropriate key object.
# For RSA keys: returns a Crypt::PK::RSA object.
# For ed25519 keys: returns a Crypt::PK::Ed25519 object.
# Returns undef if the key record can't be parsed.
sub parse_dkim_pubkey {
    my ($key_txt) = @_;
    return unless $key_txt;
    my ($k) = $key_txt =~ /\bk=([^;\s]+)/;
    $k //= 'rsa';  # default per RFC 6376
    # h= (hash algorithm list) MUST be ignored per spec-02 Section 10.3
    my ($p) = $key_txt =~ /\bp=([A-Za-z0-9+\/=]+)/;
    return unless $p;
    if ($k eq 'ed25519') {
        # RFC 8463 publishes the raw 32-byte key in p=, but some signers
        # publish a DER SubjectPublicKeyInfo (as RSA does). Accept either, and
        # never die on a malformed/oversized key: return undef so the verifier
        # reports a clean fail/temperror instead of aborting the whole operation
        # (the RSA branch below is likewise eval-wrapped).
        my $raw = decode_base64($p);
        return eval {
            my $pk = Crypt::PK::Ed25519->new();
            if (length($raw) == 32) {
                $pk->import_key_raw($raw, 'public');
            } else {
                $pk->import_key(\$raw);   # DER SubjectPublicKeyInfo
            }
            $pk;
        };
    }
    # RSA: p= is base64-encoded SubjectPublicKeyInfo DER
    my $der = decode_base64($p);
    my $rsa = eval { Crypt::PK::RSA->new(\$der) };
    return $rsa;
}

# Load a private key from a PEM file.
# Returns a Crypt::PK::RSA or Crypt::PK::Ed25519 object depending on key type.
sub load_private_key {
    my ($file) = @_;
    # Try RSA first, then Ed25519
    my $key = eval { Crypt::PK::RSA->new($file) };
    return $key if $key;
    return Crypt::PK::Ed25519->new($file);
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

B<EXPERIMENTAL> — This module implements draft-ietf-dkim-dkim2-spec-03, an
Internet-Draft that has not yet been published as an RFC.  The API and wire
format are subject to change.  Do not use in production.

=head1 FUNCTIONS

All functions are exportable on request.

=head2 should_skip($header_name)

Returns true if the named header should be excluded from DKIM2 hashing.
Excluded headers include C<Received>, C<Return-Path>, C<Message-Instance>,
C<DKIM2-Signature>, C<DKIM-Signature>, C<Authentication-Results>, ARC
headers, and any C<X-*> header.

=head2 dkim2_canonicalize_header($line)

Applies DKIM2 header canonicalization to a raw header line (including trailing
CRLF).  This is DKIM relaxed canonicalization plus removal of whitespace
around the colon separating the header name from its value.

=head2 digest64($sha)

Takes a L<Crypt::Digest::SHA256> object and returns the base64-encoded
digest value.

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

=head2 fold_header($line, $margin)

Folds a header line at C<$margin> characters (default 72) for insertion into
a message.  First tries to break at C<; > tag boundaries, then breaks any
remaining long segments at character positions.  Extends past trailing C<=>
padding, C<;> delimiters, and single remaining characters to avoid orphaning
them on the next line.

Only for headers we are creating — never for headers read from elsewhere.

=head2 fold_value($line, $margin)

Folds a string at arbitrary character positions.  C<$margin> defaults to 71
(accounting for the leading continuation space).  Only safe for content that
has not been signed.

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

=item signing_header

Optional.  When provided, this string is used as the DKIM2-Signature header
in the signing input instead of calling C<as_string_without_data()> on the
signature object.  The Signer passes the folded form
(C<as_folded_string_without_data()>) so that fold positions are part of what
gets signed.  The Verifier omits this parameter, using the default unfolded
path.

=back

=head1 AUTHOR

Bron Gondwana E<lt>brong@fastmailteam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 Fastmail Pty Ltd.  This is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
