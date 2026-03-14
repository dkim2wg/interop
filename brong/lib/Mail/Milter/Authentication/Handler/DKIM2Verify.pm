package Mail::Milter::Authentication::Handler::DKIM2Verify;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for DKIM2 signature verification
our $VERSION = '0.01';
use base 'Mail::Milter::Authentication::Handler';

use Mail::DKIM2::Common qw(extract_mi_version);
use Mail::DKIM2::Verifier;
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::MessageStore;
use Mail::DKIM::PublicKey;
use Mail::DKIM::TextWrap;
use Email::MIME;

sub default_config {
    return {
        'hide_none'            => 0,
        'extra_properties'     => 0,
        'dns_overrides'        => undef,  # path to dns.json for testing
        'add_message_instance' => 1,      # compute and add MI header on inbound
        'snapshot_directory'   => undef,  # store message snapshots for egress diffing
    };
}

sub register_metrics {
    return {
        'dkim2_verify_total' => 'The number of emails processed for DKIM2 verification',
    };
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    $self->{'failmode'}    = 0;
    $self->{'headers'}     = [];
    $self->{'body'}        = [];
    $self->{'has_dkim2'}   = 0;
    $self->{'carry'}       = q{};
    $self->{'env_from'}    = $env_from;
    $self->destroy_object('dkim2_verifier');
}

sub header_callback {
    my ( $self, $header, $value, $original ) = @_;
    return if $self->{'failmode'};
    my $EOL = "\015\012";
    my $chunk = $original . $EOL;
    $chunk =~ s/\015?\012/$EOL/g;
    push @{$self->{'headers'}}, $chunk;

    if ( lc($header) eq 'dkim2-signature' ) {
        $self->{'has_dkim2'} = 1;
    }
}

sub eoh_callback {
    my ($self) = @_;
    return if $self->{'failmode'};
    my $config = $self->handler_config();

    unless ( $self->{'has_dkim2'} ) {
        $self->metric_count( 'dkim2_verify_total', { 'result' => 'none' } );
        $self->dbgout( 'DKIM2Result', 'No DKIM2-Signature headers', LOG_DEBUG );
        unless ( $config->{'hide_none'} ) {
            my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dkim2' )->safe_set_value( 'none' );
            $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'no signatures found' ) );
            $self->add_auth_header( $header );
        }
        delete $self->{'headers'};
        return;
    }

    my $verifier;
    eval {
        $verifier = Mail::DKIM2::Verifier->new();
        $self->_setup_pubkey_callback($verifier);
        $self->set_object('dkim2_verifier', $verifier, 1);
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( 'DKIM2 Setup Error ' . $error );
        $self->{'failmode'} = 1;
        $self->_check_error( $error );
        $self->metric_count( 'dkim2_verify_total', { 'result' => 'error' } );
        delete $self->{'headers'};
        return;
    }

    eval {
        $verifier->PRINT( join q{},
            @{ $self->{'headers'} },
            "\015\012",
        );
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( 'DKIM2 Headers Error ' . $error );
        $self->{'failmode'} = 1;
        $self->_check_error( $error );
        $self->metric_count( 'dkim2_verify_total', { 'result' => 'error' } );
    }

    $self->{'carry'} = q{};
}

sub body_callback {
    my ( $self, $body_chunk ) = @_;
    return if $self->{'failmode'};
    return unless $self->{'has_dkim2'};
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

    my $verifier = $self->get_object('dkim2_verifier');
    eval {
        $verifier->PRINT( $chunk );
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( 'DKIM2 Body Error ' . $error );
        $self->{'failmode'} = 1;
        $self->_check_error( $error );
        $self->metric_count( 'dkim2_verify_total', { 'result' => 'error' } );
    }
}

sub eom_callback {
    my ($self) = @_;

    return unless $self->{'has_dkim2'};
    return if $self->{'failmode'};

    my $verifier = $self->get_object('dkim2_verifier');

    eval {
        $verifier->PRINT( $self->{'carry'} );
        $verifier->CLOSE();
        $self->check_timeout();

        my $result = $verifier->result;
        my $detail = $verifier->result_detail;

        $self->metric_count( 'dkim2_verify_total', { 'result' => $result } );
        $self->dbgout( 'DKIM2Result', $detail, LOG_DEBUG );

        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dkim2' )->safe_set_value( $result );
        if ( $verifier->{details} ) {
            $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( $verifier->{details} ) );
        }

        # Add domain info from the highest-i signature
        my %dk2_map = %{$verifier->{_dk2_headers} || {}};
        if ( keys %dk2_map ) {
            my $max_i = (sort { $b <=> $a } keys %dk2_map)[0];
            my $sig = $dk2_map{$max_i}{sig};
            if ( $sig ) {
                $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.d' )->safe_set_value( $sig->domain || '' ) );
                $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.i' )->safe_set_value( $max_i ) );
            }
        }

        $self->add_auth_header( $header );

        # Compute and add Message-Instance header, then store snapshot
        if ( $result eq 'pass' && $config->{'add_message_instance'} ) {
            $self->_add_mi_and_store();
        }
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( 'DKIM2 EOM Error ' . $error );
        $self->{'failmode'} = 1;
        $self->_check_error( $error );
        $self->metric_count( 'dkim2_verify_total', { 'result' => 'error' } );
    }
}

sub _add_mi_and_store {
    my ($self) = @_;
    my $config = $self->handler_config();

    eval {
        # Reconstruct the full message
        my $EOL = "\015\012";
        my $message_data = join(q{}, @{$self->{'headers'}})
                         . $EOL
                         . join(q{}, @{$self->{'body'}});

        my $msg = Email::MIME->new($message_data);

        # Skip if the message already has an MI that matches current content
        if ( Mail::DKIM2::MessageInstance->verify($msg) ) {
            $self->dbgout( 'DKIM2MI', 'Message unchanged, skipping MI', LOG_DEBUG );
            return;
        }

        my $mi = Mail::DKIM2::MessageInstance->calculate($msg);
        my $mi_value = $self->_format_mi($mi);

        # Add MI header to the message via the milter
        $self->prepend_header( 'Message-Instance', $mi_value );
        $self->dbgout( 'DKIM2MI', "Added Message-Instance v=" . ($mi->get_tag('v') || '?'), LOG_DEBUG );

        # Store snapshot if configured
        if ( $config->{'snapshot_directory'} ) {
            my $store = Mail::DKIM2::MessageStore->new(
                directory => $config->{'snapshot_directory'},
            );
            # Store the message as-is (with MI prepended)
            my $snapshot = "Message-Instance: $mi_value$EOL" . $message_data;
            $store->store($mi_value, $snapshot);
            $self->dbgout( 'DKIM2Snapshot', "Stored snapshot for MI v=" . ($mi->get_tag('v') || '?'), LOG_DEBUG );
        }
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( 'DKIM2 MI/Snapshot Error ' . $error );
    }
}

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

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'failmode'};
    delete $self->{'headers'};
    delete $self->{'body'};
    delete $self->{'carry'};
    delete $self->{'has_dkim2'};
    delete $self->{'env_from'};
    $self->destroy_object('dkim2_verifier');
}

sub _setup_pubkey_callback {
    my ( $self, $verifier ) = @_;
    my $config = $self->handler_config();

    # If dns_overrides is set (testing), load keys from that JSON file
    if ( $config->{'dns_overrides'} ) {
        my $dns_data = JSON::XS::decode_json( File::Slurp::read_file($config->{'dns_overrides'}) );
        $verifier->set_pubkey_callback(sub {
            my ($signature, $idx) = @_;
            $idx //= 0;
            my $sel = $signature->selector($idx);
            my $dom = $signature->domain;
            my $key_txt = $dns_data->{$dom}{"$sel._domainkey"}[0][1];
            return unless $key_txt;
            return Mail::DKIM::PublicKey->parse($key_txt);
        });
    }
    else {
        # Use real DNS via the milter's resolver
        $verifier->set_pubkey_callback(sub {
            my ($signature, $idx) = @_;
            $idx //= 0;
            my $sel = $signature->selector($idx);
            my $dom = $signature->domain;
            return unless $sel && $dom;
            my $resolver = $self->get_object('resolver');
            my $lookup = "$sel._domainkey.$dom";
            $self->dbgout( 'DKIM2DNSLookup', "$lookup TXT", LOG_DEBUG );
            my $reply = $resolver->query( $lookup, 'TXT' );
            return unless $reply;
            foreach my $rr ( $reply->answer ) {
                next unless $rr->type eq 'TXT';
                my $txt = $rr->txtdata;
                return Mail::DKIM::PublicKey->parse($txt);
            }
            return;
        });
    }
}

sub _check_error {
    my ( $self, $error ) = @_;
    if ( $error =~ /^DNS error: query timed out/
            or $error =~ /^DNS query timeout/
    ){
        $self->log_error( 'Temp DKIM2 Error - ' . $error );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dkim2' )->safe_set_value( 'temperror' );
        $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'dns timeout' ) );
        $self->add_auth_header( $header );
    }
    elsif ( $error =~ /^DNS error: SERVFAIL/ ){
        $self->log_error( 'Temp DKIM2 Error - ' . $error );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dkim2' )->safe_set_value( 'temperror' );
        $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'dns servfail' ) );
        $self->add_auth_header( $header );
    }
    else {
        $self->log_error( 'DKIM2 Error - ' . $error );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dkim2' )->safe_set_value( 'temperror' );
        $self->add_auth_header( $header );
    }
}

1;

__END__

=pod

=encoding UTF-8

=head1 NAME

Mail::Milter::Authentication::Handler::DKIM2Verify - Handler class for DKIM2 signature verification

=head1 DESCRIPTION

Verifies DKIM2 signatures and chain of custody on inbound email, adding
Authentication-Results headers with the verification outcome.

=head1 CONFIGURATION

    "DKIM2Verify" : {
        "hide_none"            : 0,      | Hide auth line if result is 'none'
        "extra_properties"     : 0,      | Add extra properties to auth results
        "dns_overrides"        : null,   | Path to dns.json for testing
        "add_message_instance" : 1,      | Compute and add MI header on inbound
        "snapshot_directory"   : null     | Store message snapshots for egress diffing
    }

When C<add_message_instance> is enabled, the handler computes a Message-Instance
header after successful DKIM2 verification and prepends it to the message.

When C<snapshot_directory> is also set, the full message (with the new MI header)
is stored to disk.  The DKIM2Sign handler can later retrieve this snapshot to
compute a diff-based MI when the message leaves the system, capturing any
modifications made during local processing.

=cut
