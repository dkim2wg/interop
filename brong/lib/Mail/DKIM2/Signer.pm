package Mail::DKIM2::Signer;
use strict;
use warnings;

use base 'Mail::DKIM2::HeaderParser';
use Crypt::Digest::SHA256 qw(sha256);
use MIME::Base64 qw(encode_base64 decode_base64);
use Carp;

use Mail::DKIM2::Common qw(
    dkim2_canonicalize_header
    build_signing_input
    extract_mi_version
    load_private_key
);
use Mail::DKIM2::Signature;
use Mail::DKIM2::MessageInstance;

sub init {
    my $self = shift;
    $self->SUPER::init;
    croak "Domain required" unless $self->{Domain};
    croak "Selector required" unless $self->{Selector};
    croak "KeyFile or Key required" unless $self->{KeyFile} || $self->{Key};

    $self->{Algorithm} ||= 'rsa-sha256';

    if ($self->{KeyFile} && !$self->{Key}) {
        $self->{Key} = load_private_key($self->{KeyFile});
    }
}

sub finish_header {
    my $self = shift;

    # Extract existing MI and DKIM2-Signature headers from the parsed headers
    my @mi_headers;
    my @dk2_headers;

    for my $header (@{$self->{headers}}) {
        if ($header =~ /^Message-Instance:/i) {
            my ($val) = $header =~ /^Message-Instance:\s*(.*)/is;
            $val =~ s/\r\n$//;
            my $v = extract_mi_version($val);
            push @mi_headers, { v => $v, raw => $header } if $v;
        }
        elsif ($header =~ /^DKIM2-Signature:/i) {
            my ($val) = $header =~ /^DKIM2-Signature:\s*(.*)/is;
            $val =~ s/\r\n$//;
            my $sig = eval { Mail::DKIM2::Signature->parse($val) };
            if ($sig && $sig->sequence) {
                push @dk2_headers, { i => $sig->sequence, raw => $header, sig => $sig };
            }
        }
    }

    # Sort by index
    @mi_headers  = sort { $a->{v} <=> $b->{v} } @mi_headers;
    @dk2_headers = sort { $a->{i} <=> $b->{i} } @dk2_headers;

    # Determine next i= value
    my $next_i = @dk2_headers ? $dk2_headers[-1]{i} + 1 : 1;
    # Determine highest MI version
    my $mi_version = @mi_headers ? $mi_headers[-1]{v} : 0;

    # Build initial signature items as [selector, algorithm, value] arrays
    my @sig_items;
    push @sig_items, [
        $self->{Selector},
        $self->{Algorithm},
        '',
    ];

    # Create the signature object
    my $signature = Mail::DKIM2::Signature->new(
        Sequence   => $next_i,
        Version    => $mi_version || undef,
        Timestamp  => $self->{Timestamp} || time(),
        Domain     => $self->{Domain},
        MailFrom   => $self->{MailFrom},
        RcptTo     => $self->{RcptTo},
        Signatures => \@sig_items,
        ($self->{Nonce} ? (Nonce => $self->{Nonce}) : ()),
        ($self->{Flags} ? (Flags => $self->{Flags}) : ()),
    );

    $self->{_signature} = $signature;
    $self->{_mi_headers} = \@mi_headers;
    $self->{_dk2_headers} = \@dk2_headers;
    $self->{_next_i} = $next_i;
}

sub finish_body {
    my $self = shift;

    my $signature    = $self->{_signature};
    my @mi_headers   = @{$self->{_mi_headers}};
    my @dk2_headers  = @{$self->{_dk2_headers}};

    # Include the new signature as the signing_i entry
    my $next_i = $self->{_next_i};
    my @all_dk2 = (@dk2_headers, { i => $next_i, sig => $signature });

    # Fold before signing: the fold positions become part of what gets
    # canonicalized and signed.
    my $folded_header = $signature->as_folded_string_without_data();

    my $signing_input = build_signing_input(
        mi_headers     => \@mi_headers,
        dk2_headers    => \@all_dk2,
        signing_i      => $next_i,
        signature      => $signature,
        signing_header => $folded_header,
    );

    # Sign the signing input
    my $key = $self->{Key};
    my $alg = $self->{Algorithm} || 'rsa-sha256';
    my $sig_raw;
    if ($alg =~ /^ed25519/) {
        # Ed25519-SHA256: hash first, then sign the digest
        my $digest = sha256($signing_input);
        $sig_raw = $key->sign_message($digest);
    } else {
        # RSA-SHA256: sign_message handles hashing internally
        $sig_raw = $key->sign_message($signing_input, 'SHA256', 'v1.5');
    }
    my $signb64 = encode_base64($sig_raw, '');

    # Update the signature object with the actual signature
    # Format: sel:alg:sig
    $signature->set_tag('s', join(':', $self->{Selector}, $self->{Algorithm}, $signb64));

    $self->{result} = 'signed';
}

sub signature {
    my $self = shift;
    return $self->{_signature};
}

sub as_string {
    my $self = shift;
    return '' unless $self->{_signature};
    return $self->{_signature}->as_folded_string();
}

sub result {
    my $self = shift;
    return $self->{result} || '?';
}

1;

__END__

=head1 NAME

Mail::DKIM2::Signer - Sign email messages with DKIM2-Signature headers

=head1 SYNOPSIS

    use Mail::DKIM2::Signer;

    my $signer = Mail::DKIM2::Signer->new(
        Domain   => 'example.com',
        Selector => 'sel1',
        KeyFile  => '/path/to/private.pem',
        MailFrom => 'sender@example.com',
        RcptTo   => ['recipient@example.com'],
    );

    # Feed the message (with CRLF line endings)
    $signer->PRINT($message_text);
    $signer->CLOSE;

    # Get the generated DKIM2-Signature header
    print $signer->as_string(), "\n";
    print "Result: ", $signer->result(), "\n";

=head1 DESCRIPTION

Streaming DKIM2 message signer.  Feed an RFC 5322 message via the
C<PRINT>/C<CLOSE> interface and retrieve the generated DKIM2-Signature
header.  Automatically determines the next sequence number by examining
existing DKIM2-Signature headers on the message.

Extends L<Mail::DKIM2::HeaderParser> for the streaming message parser.

B<EXPERIMENTAL> — This module implements draft-ietf-dkim-dkim2-spec-00, an
Internet-Draft that has not yet been published as an RFC.  The API and wire
format are subject to change.  Do not use in production.

=head1 CONSTRUCTOR

=head2 new(%args)

Creates a new Signer.  Required arguments:

=over 4

=item Domain

The signing domain (C<d=> tag).

=item Selector

The DNS selector (C<s=> tag in the signature item).

=item KeyFile

Path to a PEM-encoded private key file.  Either C<KeyFile> or C<Key> is
required.

=item Key

A L<Crypt::PK::RSA> or L<Crypt::PK::Ed25519> object.  Alternative to C<KeyFile>.

=back

Optional arguments:

=over 4

=item Algorithm

Signing algorithm (default: C<rsa-sha256>).

=item MailFrom

SMTP MAIL FROM address, recorded in the C<m=> tag.

=item RcptTo

SMTP RCPT TO address(es), recorded in the C<m=> tag.

=item Nonce

A nonce value for the C<n=> tag.

=item Flags

An arrayref of flag strings for the C<f=> tag.

=back

=head1 METHODS

=head2 signature()

Returns the L<Mail::DKIM2::Signature> object (available after C<CLOSE>).

=head2 as_string()

Returns the complete C<DKIM2-Signature: ...> header line.

=head2 result()

Returns C<'signed'> on success, C<'?'> if not yet complete.

=head1 AUTHOR

Bron Gondwana E<lt>brong@fastmailteam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 Fastmail Pty Ltd.  This is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
