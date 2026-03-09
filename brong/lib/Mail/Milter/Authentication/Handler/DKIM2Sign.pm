package Mail::Milter::Authentication::Handler::DKIM2Sign;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for DKIM2 signing
our $VERSION = '0.01';
use base 'Mail::Milter::Authentication::Handler';

use Mail::DKIM::PrivateKey;
use Mail::DKIM::TextWrap;
use Mail::DKIM2::Common qw(extract_mi_version);
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::MessageStore;
use Mail::DKIM2::Signer;
use Email::MIME;

sub default_config {
    return {
        # Static domain config: domain => { selector, keyfile }
        'domains'              => {},
        # HTTP endpoint for dynamic key lookup: GET {url}?domain=X
        # Expected response: {"selector":"sel1","key":"base64_pem_data"}
        # or: {"selector":"sel1","keyfile":"/path/to/key.pem"}
        'key_endpoint'         => undef,
        'key_endpoint_timeout' => 5,
        # Only sign for authenticated/local senders
        'sign_authenticated'   => 1,
        'sign_local'           => 1,
        # Add Message-Instance headers
        'add_message_instance' => 1,
        # SMTP params to record in the signature
        'record_smtp_params'   => 1,
        # Directory for message snapshots (shared with DKIM2Verify)
        'snapshot_directory'   => undef,
    };
}

sub register_metrics {
    return {
        'dkim2_sign_total' => 'The number of emails signed with DKIM2',
    };
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    $self->{'failmode'}   = 0;
    $self->{'headers'}    = [];
    $self->{'body'}       = [];
    $self->{'carry'}      = q{};
    $self->{'env_from'}   = $env_from;
    $self->{'env_rcpt'}   = [];
    $self->{'sign_domain'} = undef;
}

sub envrcpt_callback {
    my ( $self, $env_to ) = @_;
    push @{$self->{'env_rcpt'}}, $env_to;
}

sub header_callback {
    my ( $self, $header, $value, $original ) = @_;
    return if $self->{'failmode'};
    my $EOL = "\015\012";
    my $chunk = $original . $EOL;
    $chunk =~ s/\015?\012/$EOL/g;
    push @{$self->{'headers'}}, $chunk;
}

sub eoh_callback {
    my ($self) = @_;
    $self->{'carry'} = q{};
}

sub body_callback {
    my ( $self, $body_chunk ) = @_;
    return if $self->{'failmode'};
    my $EOL = "\015\012";

    my $chunk;
    if ( $self->{'carry'} ne q{} ) {
        $chunk = $self->{'carry'} . $body_chunk;
        $self->{'carry'} = q{};
    }
    else {
        $chunk = $body_chunk;
    }

    if ( substr( $chunk, -1 ) eq "\015" ) {
        $self->{'carry'} = "\015";
        $chunk = substr( $chunk, 0, -1 );
    }

    $chunk =~ s/\015?\012/$EOL/g;
    push @{$self->{'body'}}, $chunk;
}

sub eom_callback {
    my ($self) = @_;
    push @{$self->{'body'}}, $self->{'carry'} if $self->{'carry'};
    # Signing happens in addheader_callback
}

sub _fmtheader {
    my $header = shift;
    my $value = $header->{value};
    $value =~ s/\015?\012/\015\012/gs;
    return "$header->{field}: $value\015\012";
}

sub addheader_callback {
    my $self = shift;
    my $handler = shift;
    return if $self->{'failmode'};

    my $config = $self->handler_config();

    # Determine if we should sign this message
    my $should_sign = 0;
    if ( $config->{'sign_authenticated'} && $self->is_authenticated() ) {
        $should_sign = 1;
    }
    if ( $config->{'sign_local'} && $self->is_local_ip_address() ) {
        $should_sign = 1;
    }
    return unless $should_sign;

    # Determine the signing domain from the envelope sender
    my $env_from = $self->{'env_from'} || '';
    $env_from =~ s/^<//;
    $env_from =~ s/>$//;
    my $sign_domain;
    if ( $env_from =~ /\@(.+)$/ ) {
        $sign_domain = lc $1;
    }
    return unless $sign_domain;

    # Look up signing config for this domain
    my $sign_config = $self->_get_sign_config($sign_domain);
    unless ($sign_config) {
        $self->dbgout( 'DKIM2Sign', "No signing config for $sign_domain", LOG_DEBUG );
        return;
    }

    eval {
        my $selector = $sign_config->{selector};
        my $key;
        if ( $sign_config->{key} ) {
            $key = Mail::DKIM::PrivateKey->load( Data => $sign_config->{key} );
        }
        elsif ( $sign_config->{keyfile} ) {
            $key = Mail::DKIM::PrivateKey->load( File => $sign_config->{keyfile} );
        }
        else {
            die "No key or keyfile in signing config for $sign_domain";
        }

        # Build the full message (pre_headers + original headers + add_headers + body)
        my $EOL = "\015\012";
        my $message_data = '';

        # pre_headers from handler (reversed as they prepend in reverse)
        foreach my $h (reverse @{$handler->{pre_headers} || []}) {
            $message_data .= _fmtheader($h);
        }

        # Original headers
        foreach my $chunk (@{$self->{'headers'} || []}) {
            $message_data .= $chunk;
        }

        # post-headers from handler
        foreach my $h (@{$handler->{add_headers} || []}) {
            $message_data .= _fmtheader($h);
        }

        # End of headers + body
        $message_data .= $EOL;
        foreach my $chunk (@{$self->{'body'}}) {
            $message_data .= $chunk;
        }

        # Compute Message-Instance if configured
        if ( $config->{'add_message_instance'} ) {
            my $mi = $self->_compute_message_instance($message_data, $config);
            if ($mi) {
                my $mi_value = $self->_format_mi($mi);
                # Prepend MI header (will be included when we re-feed the signer)
                $message_data = "Message-Instance: $mi_value$EOL" . $message_data;
                # Also add to pre_headers so it actually gets prepended to the message
                push @{$handler->{pre_headers}}, {
                    'field' => 'Message-Instance',
                    'value' => $mi_value,
                };
            }
        }

        # Build SMTP params
        my %signer_args = (
            Domain   => $sign_domain,
            Selector => $selector,
            Key      => $key,
        );

        if ( $config->{'record_smtp_params'} ) {
            $signer_args{MailFrom} = $env_from if $env_from;
            if ( @{$self->{'env_rcpt'} || []} ) {
                my @cleaned = map { my $r = $_; $r =~ s/^<//; $r =~ s/>$//; $r } @{$self->{'env_rcpt'}};
                $signer_args{RcptTo} = \@cleaned;
            }
        }

        # Create the signer and feed the message
        my $signer = Mail::DKIM2::Signer->new(%signer_args);
        $signer->PRINT($message_data);
        $signer->CLOSE();
        $self->check_timeout();

        my $sig_result = $signer->result;
        $self->dbgout( 'DKIM2SignResult', $sig_result, LOG_DEBUG );

        if ( $sig_result eq 'signed' ) {
            # Extract the DKIM2-Signature header
            my $sig_header = $signer->as_string();
            # Strip the "DKIM2-Signature: " prefix
            $sig_header =~ s/^DKIM2-Signature:\s*//;

            push @{$handler->{pre_headers}}, {
                'field' => 'DKIM2-Signature',
                'value' => $sig_header,
            };

            $self->metric_count( 'dkim2_sign_total', { 'result' => 'signed' } );
            $self->dbgout( 'DKIM2Sign', "Signed for $sign_domain ($selector)", LOG_INFO );
        }
        else {
            $self->metric_count( 'dkim2_sign_total', { 'result' => 'error' } );
            $self->log_error( "DKIM2 signing failed: $sig_result" );
        }
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( 'DKIM2 Sign Error ' . $error );
        $self->metric_count( 'dkim2_sign_total', { 'result' => 'error' } );
    }
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'failmode'};
    delete $self->{'headers'};
    delete $self->{'body'};
    delete $self->{'carry'};
    delete $self->{'env_from'};
    delete $self->{'env_rcpt'};
    delete $self->{'sign_domain'};
}

# Compute Message-Instance header for the message.
# If a snapshot directory is configured and a snapshot exists for the
# topmost MI on the current message, compute a diff MI between the
# snapshot and the current message.  Otherwise fall back to a simple
# hash-only MI.
sub _compute_message_instance {
    my ( $self, $message_data, $config ) = @_;

    my $mi = eval {
        my $msg = Email::MIME->new($message_data);

        # Skip if the message already has an MI that matches current content
        if ( Mail::DKIM2::MessageInstance->verify($msg) ) {
            $self->dbgout( 'DKIM2MI', 'Message unchanged, skipping MI', LOG_DEBUG );
            return undef;
        }

        # Try to find a stored snapshot via the topmost MI
        if ( $config->{'snapshot_directory'} ) {
            my @mi_headers = $msg->header_raw('Message-Instance');
            if ( @mi_headers ) {
                # Find the topmost (highest version) MI
                my %mi_by_v = map { (extract_mi_version($_) || 0) => $_ } @mi_headers;
                my $max_v = (sort { $b <=> $a } keys %mi_by_v)[0];
                if ( $max_v ) {
                    my $store = Mail::DKIM2::MessageStore->new(
                        directory => $config->{'snapshot_directory'},
                    );
                    my $snapshot_data = $store->fetch($mi_by_v{$max_v});
                    if ( $snapshot_data ) {
                        $self->dbgout( 'DKIM2MI', "Found snapshot for MI v=$max_v, computing diff", LOG_DEBUG );
                        my $snapshot_msg = Email::MIME->new($snapshot_data);
                        return Mail::DKIM2::MessageInstance->calculate($snapshot_msg, $msg);
                    }
                }
            }
        }

        # No snapshot available - calculate simple MI
        Mail::DKIM2::MessageInstance->calculate($msg);
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( 'DKIM2 MI Error ' . $error );
        return;
    }

    return $mi;
}

# Format MI header value with text wrapping
sub _format_mi {
    my ( $self, $mi ) = @_;
    my $output = '';
    my $tw = Mail::DKIM::TextWrap->new(
        Margin    => 72,
        Break     => qr/./,
        Separator => "\015\012\t",
        Swallow   => qr/\s+/,
        Output    => \$output,
    );
    $tw->add($mi->as_string());
    $tw->finish;
    return $output;
}

# Look up signing config for a domain (static config, then HTTP endpoint)
sub _get_sign_config {
    my ( $self, $domain ) = @_;
    my $config = $self->handler_config();

    # Check static config first
    my $domains = $config->{'domains'} || {};
    if ( my $dc = $domains->{$domain} ) {
        return $dc;
    }

    # Try parent domains (e.g., sub.example.com -> example.com)
    my $try = $domain;
    while ( $try =~ s/^[^.]+\.// ) {
        if ( my $dc = $domains->{$try} ) {
            return $dc;
        }
    }

    # Try HTTP endpoint if configured
    if ( my $endpoint = $config->{'key_endpoint'} ) {
        return $self->_fetch_sign_config($endpoint, $domain);
    }

    return;
}

# Fetch signing config from HTTP endpoint
sub _fetch_sign_config {
    my ( $self, $endpoint, $domain ) = @_;
    my $config = $self->handler_config();
    my $timeout = $config->{'key_endpoint_timeout'} || 5;

    my $result = eval {
        require HTTP::Tiny;
        my $http = HTTP::Tiny->new( timeout => $timeout );
        my $url = "$endpoint?domain=$domain";
        $self->dbgout( 'DKIM2SignKeyLookup', $url, LOG_DEBUG );
        my $response = $http->get($url);

        if ( $response->{success} ) {
            my $data = JSON::XS::decode_json( $response->{content} );
            if ( $data->{selector} && ( $data->{key} || $data->{keyfile} ) ) {
                $self->dbgout( 'DKIM2SignKeyLookup',
                    "Got config for $domain: selector=$data->{selector}", LOG_DEBUG );
                $data;
            }
            else { undef }
        }
        else {
            $self->dbgout( 'DKIM2SignKeyLookup',
                "Failed for $domain: $response->{status} $response->{reason}", LOG_DEBUG );
            undef;
        }
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( "DKIM2 key endpoint error for $domain: $error" );
    }

    return $result;
}

1;

__END__

=pod

=encoding UTF-8

=head1 NAME

Mail::Milter::Authentication::Handler::DKIM2Sign - Handler class for DKIM2 signing

=head1 DESCRIPTION

Signs outbound email with DKIM2-Signature headers and adds Message-Instance
headers for chain-of-custody tracking. Runs in the addheader_callback phase
so the signature covers all headers including those added by other handlers.

Signing keys can be configured statically per domain, or looked up dynamically
via an HTTP REST endpoint.

=head1 CONFIGURATION

    "DKIM2Sign" : {
        "domains" : {                              | Static domain configs
            "example.com" : {                      |
                "selector" : "sel1",               |   DKIM2 selector
                "keyfile"  : "/path/to/key.pem"    |   Private key file path
            },                                     |
            "other.com" : {                        |
                "selector" : "default",            |
                "key"      : "base64_pem_data"     |   Or inline key data
            }                                      |
        },                                         |
        "key_endpoint"         : null,             | HTTP endpoint for dynamic key lookup
                                                   |   GET {url}?domain=X
                                                   |   Response: {"selector":"s1","keyfile":"/path"}
                                                   |         or: {"selector":"s1","key":"base64data"}
        "key_endpoint_timeout" : 5,                | HTTP timeout in seconds
        "sign_authenticated"   : 1,                | Sign for authenticated senders
        "sign_local"           : 1,                | Sign for local IP senders
        "add_message_instance" : 1,                | Add Message-Instance headers
        "record_smtp_params"   : 1,                | Record MAIL FROM/RCPT TO in signature
        "snapshot_directory"   : null               | Snapshot dir (shared with DKIM2Verify)
    }

When C<snapshot_directory> is set, the handler looks up a stored message
snapshot (written by DKIM2Verify on inbound) using the topmost Message-Instance
header value as the key.  If found, a diff-based MI is computed capturing
header and body changes made during local processing.  Without a snapshot,
a simple hash-only MI is computed.

=head1 HTTP KEY ENDPOINT

When C<key_endpoint> is configured, the handler will make a GET request to:

    {key_endpoint}?domain={domain}

The endpoint should return a JSON object with:

    {
        "selector": "sel1",
        "keyfile": "/path/to/private.pem"
    }

or:

    {
        "selector": "sel1",
        "key": "-----BEGIN RSA PRIVATE KEY-----\n..."
    }

Return HTTP 404 or an empty response to decline signing for that domain.

=cut
