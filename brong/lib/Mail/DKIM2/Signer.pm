package Mail::DKIM2::Signer;
use strict;
use warnings;

use base 'Mail::DKIM::Common';
use Mail::DKIM::PrivateKey;
use Digest::SHA;
use MIME::Base64 qw(encode_base64 decode_base64);
use Carp;

use Mail::DKIM2::Common qw(
    dkim2_canonicalize_header
    encode_tag_json
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
        $self->{Key} = Mail::DKIM::PrivateKey->load(File => $self->{KeyFile});
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
            my $v = Mail::DKIM2::MessageInstance::getmi($val);
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

    # Build SMTP params
    my %smtp_params;
    $smtp_params{mf} = $self->{MailFrom} if defined $self->{MailFrom};
    $smtp_params{rt} = $self->{RcptTo} if defined $self->{RcptTo};

    # Build initial signature items (without b= yet)
    my @sig_items;
    push @sig_items, {
        a => $self->{Algorithm},
        s => $self->{Selector},
        b => '',
    };

    # Create the signature object
    my $signature = Mail::DKIM2::Signature->new(
        Sequence   => $next_i,
        Version    => $mi_version || undef,
        Timestamp  => time(),
        Domain     => $self->{Domain},
        SmtpParams => (keys %smtp_params ? \%smtp_params : undef),
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

    # Build signing input: canonicalized MI headers (v= ascending)
    # + canonicalized DKIM2-Sig headers (i= ascending)
    # + canonicalized new DKIM2-Sig (with empty s= signature values)
    # Interleaved: for each DKIM2-Sig at i=N, include all MI headers
    # with v= up to the v= value referenced by that signature

    my $signing_input = '';

    # Interleave MI and DKIM2 headers in order
    my $mi_idx = 0;
    for my $dk2 (@dk2_headers) {
        my $dk2_v = $dk2->{sig}->version || 0;
        # Add all MI headers up to this DKIM2-Sig's version
        while ($mi_idx < @mi_headers && $mi_headers[$mi_idx]{v} <= $dk2_v) {
            $signing_input .= dkim2_canonicalize_header($mi_headers[$mi_idx]{raw});
            $mi_idx++;
        }
        $signing_input .= dkim2_canonicalize_header($dk2->{raw});
    }
    # Add remaining MI headers
    while ($mi_idx < @mi_headers) {
        $signing_input .= dkim2_canonicalize_header($mi_headers[$mi_idx]{raw});
        $mi_idx++;
    }

    # Add the new signature (with empty signature values)
    my $new_sig_header = $signature->as_string_without_data();
    $signing_input .= dkim2_canonicalize_header("$new_sig_header\r\n");

    # Hash the signing input
    my $sha = Digest::SHA->new(256);
    $sha->add($signing_input);
    my $digest = $sha->digest;

    # Sign
    my $key = $self->{Key};
    my $sig_raw = $key->sign_digest('SHA-256', $digest);
    my $signb64 = encode_base64($sig_raw, '');

    # Update the signature object with the actual signature
    my @sig_items = ({
        a => $self->{Algorithm},
        s => $self->{Selector},
        b => $signb64,
    });
    $signature->set_tag('s', encode_tag_json(\@sig_items));

    $self->{result} = 'signed';
}

sub signature {
    my $self = shift;
    return $self->{_signature};
}

sub as_string {
    my $self = shift;
    return '' unless $self->{_signature};
    return $self->{_signature}->as_string();
}

sub result {
    my $self = shift;
    return $self->{result} || '?';
}

1;
