package Mail::DKIM2::Signature;
use strict;
use warnings;

use MIME::Base64 qw(encode_base64 decode_base64);
use Carp;

use Mail::DKIM2::Common qw(encode_tag_json decode_tag_json fold_header);

use base 'Mail::DKIM2::TagValueList';

# Indices into the 3-element signature item arrays [selector, algorithm, value]
use constant SIG_SELECTOR  => 0;
use constant SIG_ALGORITHM => 1;
use constant SIG_VALUE     => 2;

# --- Construction ---

sub new {
    my ($class, %args) = @_;

    my $self = $class->SUPER::new();
    bless $self, $class;

    $self->set_tag('i', $args{Sequence})  if defined $args{Sequence};
    $self->set_tag('v', $args{Version})   if defined $args{Version};
    $self->set_tag('t', $args{Timestamp}) if defined $args{Timestamp};
    $self->set_tag('d', $args{Domain})    if defined $args{Domain};
    $self->set_tag('n', $args{Nonce})     if defined $args{Nonce};

    if (defined $args{Flags}) {
        $self->set_tag('f', join(',', @{$args{Flags}}));
    }

    if (defined $args{SmtpParams}) {
        $self->set_tag('m', encode_tag_json($args{SmtpParams}));
    }

    if (defined $args{Signatures}) {
        $self->set_tag('s', encode_tag_json($args{Signatures}));
    }

    return $self;
}

# --- Parse from header line ---

sub parse {
    my ($class, $header_line) = @_;
    # Strip "DKIM2-Signature:" prefix if present
    $header_line =~ s/^\s*DKIM2-Signature:\s*//i;
    my $self = $class->SUPER::parse($header_line);
    bless $self, ref($class) || $class;
    return $self;
}

# --- Tag accessors ---

sub sequence {
    my $self = shift;
    if (@_) { $self->set_tag('i', shift) }
    return $self->get_tag('i');
}

sub version {
    my $self = shift;
    if (@_) { $self->set_tag('v', shift) }
    return $self->get_tag('v');
}

sub timestamp {
    my $self = shift;
    if (@_) { $self->set_tag('t', shift) }
    return $self->get_tag('t');
}

sub domain {
    my $self = shift;
    if (@_) { $self->set_tag('d', shift) }
    return $self->get_tag('d');
}

sub nonce {
    my $self = shift;
    if (@_) { $self->set_tag('n', shift) }
    return $self->get_tag('n');
}

sub flags {
    my $self = shift;
    my $f = $self->get_tag('f');
    return unless defined $f;
    return [split /,/, $f];
}

# --- JSON tag accessors ---

sub smtp_params {
    my $self = shift;
    my $m = $self->get_tag('m');
    return unless defined $m;
    return decode_tag_json($m);
}

sub signatures_data {
    my $self = shift;
    my $s = $self->get_tag('s');
    return unless defined $s;
    return decode_tag_json($s);
}

# --- Convenience methods for SMTP params ---

sub mail_from {
    my $self = shift;
    my $params = $self->smtp_params;
    return unless $params;
    return $params->{mf};
}

sub rcpt_to {
    my $self = shift;
    my $params = $self->smtp_params;
    return unless $params;
    return $params->{rt};
}

# --- Convenience methods for signature items ---

# Normalize signature items: handle both spec format (array of 3-element arrays)
# and flat array format [sel, alg, val, sel2, alg2, val2, ...]
sub _sig_items {
    my ($self) = @_;
    my $sigs = $self->signatures_data;
    return unless $sigs && @$sigs;
    # Spec format: array of 3-element arrays
    return $sigs if ref($sigs->[0]) eq 'ARRAY';
    # Flat array: group into triples
    my @items;
    for (my $i = 0; $i + 2 < @$sigs; $i += 3) {
        push @items, [$sigs->[$i], $sigs->[$i+1], $sigs->[$i+2]];
    }
    return \@items;
}

sub selector {
    my ($self, $idx) = @_;
    $idx //= 0;
    my $sigs = $self->_sig_items;
    return unless $sigs && $sigs->[$idx];
    return $sigs->[$idx][SIG_SELECTOR];
}

sub algorithm {
    my ($self, $idx) = @_;
    $idx //= 0;
    my $sigs = $self->_sig_items;
    return unless $sigs && $sigs->[$idx];
    return $sigs->[$idx][SIG_ALGORITHM];
}

sub signature_value {
    my ($self, $idx) = @_;
    $idx //= 0;
    my $sigs = $self->_sig_items;
    return unless $sigs && $sigs->[$idx];
    return $sigs->[$idx][SIG_VALUE];
}

# --- Serialization ---

# Raw unfolded header — used by the verifier to reconstruct signing input.
sub as_string {
    my ($self) = @_;
    return "DKIM2-Signature: " . $self->SUPER::as_string();
}

# Serialize with empty signature values in s= tag.
# Returns unfolded output. Used by the verifier to reconstruct the
# signing input from a header read from the message.
sub as_string_without_data {
    my ($self) = @_;
    my $raw_sigs = $self->signatures_data;
    return $self->as_string() unless $raw_sigs;

    my @empty_sigs;
    if (ref($raw_sigs->[0]) eq 'ARRAY') {
        @empty_sigs = map {
            my @copy = @$_;
            $copy[SIG_VALUE] = '';
            \@copy;
        } @$raw_sigs;
    } else {
        @empty_sigs = @$raw_sigs;
        for (my $i = SIG_VALUE; $i < @empty_sigs; $i += 3) {
            $empty_sigs[$i] = '';
        }
    }

    my $saved = $self->get_tag('s');
    $self->set_tag('s', encode_tag_json(\@empty_sigs));
    my $result = $self->as_string();
    $self->set_tag('s', $saved);
    return $result;
}

# Build the empty signature JSON for _empty_s_value().
sub _empty_sigs {
    my ($self) = @_;
    my $raw_sigs = $self->signatures_data;
    return unless $raw_sigs;

    my @empty;
    if (ref($raw_sigs->[0]) eq 'ARRAY') {
        @empty = map {
            my @copy = @$_;
            $copy[SIG_VALUE] = '';
            \@copy;
        } @$raw_sigs;
    } else {
        @empty = @$raw_sigs;
        for (my $i = SIG_VALUE; $i < @empty; $i += 3) {
            $empty[$i] = '';
        }
    }
    return encode_tag_json(\@empty);
}

# Folded header with empty s= value, ready for signing.
# Used by the Signer: fold first, then canonicalize and sign.
# The fold positions become part of what is signed.
sub as_folded_string_without_data {
    my ($self) = @_;

    # All tags except s=, then "; s=<empty>"
    my @parts;
    for my $t (@{$self->{order}}) {
        next if $t eq 's';
        push @parts, "$t=$self->{tags}{$t}";
    }
    my $empty_s = $self->_empty_sigs() // '';
    my $line = "DKIM2-Signature: " . join('; ', @parts) . "; s=$empty_s";
    return fold_header($line);
}

# Folded header with real s= value, ready for insertion into a message.
# The prefix (everything before s=) has the same fold positions as
# as_folded_string_without_data(), with s= replaced by the real value.
sub as_folded_string {
    my ($self) = @_;

    my @parts;
    for my $t (@{$self->{order}}) {
        next if $t eq 's';
        push @parts, "$t=$self->{tags}{$t}";
    }
    my $s_val = $self->{tags}{s} // '';
    my $line = "DKIM2-Signature: " . join('; ', @parts) . "; s=$s_val";
    return fold_header($line);
}

sub sig_count {
    my ($self) = @_;
    my $sigs = $self->_sig_items;
    return 0 unless $sigs;
    return scalar @$sigs;
}

# --- DNS key lookup ---

sub fetch_public_key {
    my ($self, $idx) = @_;
    $idx //= 0;
    my $sel = $self->selector($idx);
    my $dom = $self->domain;
    croak "missing selector or domain" unless $sel && $dom;

    # Fetch TXT record from DNS
    require Net::DNS::Resolver;
    my $resolver = Net::DNS::Resolver->new;
    my $fqdn = "$sel._domainkey.$dom";
    my $reply = $resolver->query($fqdn, 'TXT');
    return unless $reply;
    for my $rr ($reply->answer) {
        next unless $rr->type eq 'TXT';
        my $txt = join('', $rr->txtdata);
        require Mail::DKIM2::Common;
        return Mail::DKIM2::Common::parse_dkim_pubkey($txt);
    }
    return;
}

1;

__END__

=head1 NAME

Mail::DKIM2::Signature - Parse and construct DKIM2-Signature headers

=head1 SYNOPSIS

    use Mail::DKIM2::Signature;

    # Parse an existing header
    my $sig = Mail::DKIM2::Signature->parse($header_value);
    say $sig->sequence;    # i= tag
    say $sig->domain;      # d= tag
    say $sig->selector;    # s= from first signature item

    # Construct a new signature
    my $sig = Mail::DKIM2::Signature->new(
        Sequence   => 1,
        Domain     => 'example.com',
        Timestamp  => time(),
        SmtpParams => { mf => 'sender@example.com' },
        Signatures => [['sel1', 'rsa-sha256', '']],
    );

=head1 DESCRIPTION

Represents a DKIM2-Signature header as defined in draft-clayton-dkim2-spec-08.
Extends L<Mail::DKIM2::TagValueList> for tag-value parsing and serialization.

B<EXPERIMENTAL> — This module implements an Internet-Draft that has not yet
been published as an RFC.  The API and wire format are subject to change.
Do not use in production.

The DKIM2-Signature header uses these tags:

=over 4

=item C<i=> - Sequence number (position in the signature chain)

=item C<v=> - Message-Instance version this signature covers

=item C<t=> - Timestamp (Unix epoch)

=item C<d=> - Signing domain

=item C<n=> - Nonce

=item C<f=> - Flags (comma-separated)

=item C<m=> - SMTP parameters (base64-encoded JSON)

=item C<s=> - Signature items (base64-encoded JSON array)

=back

=head1 CONSTRUCTORS

=head2 new(%args)

Creates a new Signature object.  Accepted arguments: C<Sequence>, C<Version>,
C<Timestamp>, C<Domain>, C<Nonce>, C<Flags> (arrayref), C<SmtpParams>
(hashref), C<Signatures> (arrayref of hashrefs).

=head2 parse($header_value)

Parses a DKIM2-Signature header value string (with or without the
C<DKIM2-Signature:> prefix) into a Signature object.

=head1 TAG ACCESSORS

=head2 sequence([$value])

Get/set the C<i=> tag (sequence number).

=head2 version([$value])

Get/set the C<v=> tag (Message-Instance version).

=head2 timestamp([$value])

Get/set the C<t=> tag (Unix timestamp).

=head2 domain([$value])

Get/set the C<d=> tag (signing domain).

=head2 nonce([$value])

Get/set the C<n=> tag.

=head2 flags()

Returns the C<f=> tag as an arrayref of flag strings, or undef.

=head1 JSON TAG ACCESSORS

=head2 smtp_params()

Decodes and returns the C<m=> tag as a hashref.  Keys include C<mf>
(MAIL FROM) and C<rt> (RCPT TO).

=head2 signatures_data()

Decodes and returns the C<s=> tag as an arrayref of signature item hashrefs.
Each item has keys C<a> (algorithm), C<s> (selector), and C<b> (signature
value).

=head2 mail_from()

Convenience method: returns the C<mf> value from SMTP params.

=head2 rcpt_to()

Convenience method: returns the C<rt> value from SMTP params.

=head2 selector([$index])

Returns the selector from the signature item at C<$index> (default 0).

=head2 algorithm([$index])

Returns the algorithm from the signature item at C<$index> (default 0).

=head2 signature_value([$index])

Returns the base64 signature value from the item at C<$index> (default 0).

=head1 SERIALIZATION

=head2 as_string()

Returns the full header line: C<< DKIM2-Signature: <tags> >>.

=head2 as_string_without_data()

Returns the header with empty signature values in all C<s=> items, unfolded.
Used by the verifier to reconstruct the signing input from a header read
from the message.

=head2 as_folded_string_without_data()

Returns the header with empty signature values, folded at 72 characters.
Used by the signer as the signing input — fold positions become part of
what gets canonicalized and signed.

=head2 as_folded_string()

Returns the complete header (with real signature values) folded at 72
characters, ready for insertion into a message.

=head2 sig_count()

Returns the number of signature items in the C<s=> tag.

=head1 DNS

=head2 fetch_public_key([$index])

Fetches the public key via DNS for the signature item at C<$index>
(default 0), using the selector and domain from this signature.

=head1 AUTHOR

Bron Gondwana E<lt>brong@fastmailteam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 Fastmail Pty Ltd.  This is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
