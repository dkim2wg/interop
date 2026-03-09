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
use Mail::DKIM::PublicKey;

sub default_config {
    return {
        'hide_none'       => 0,
        'extra_properties' => 0,
        'dns_overrides'   => undef,  # path to dns.json for testing
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

    delete $self->{'headers'};
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
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( 'DKIM2 EOM Error ' . $error );
        $self->{'failmode'} = 1;
        $self->_check_error( $error );
        $self->metric_count( 'dkim2_verify_total', { 'result' => 'error' } );
    }
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'failmode'};
    delete $self->{'headers'};
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
            my $signature = shift;
            my $sel = $signature->selector(0);
            my $dom = $signature->domain;
            my $key_txt = $dns_data->{$dom}{"$sel._domainkey"}[0][1];
            return unless $key_txt;
            return Mail::DKIM::PublicKey->parse($key_txt);
        });
    }
    else {
        # Use real DNS via the milter's resolver
        $verifier->set_pubkey_callback(sub {
            my $signature = shift;
            my $sel = $signature->selector(0);
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
        "hide_none"        : 0,          | Hide auth line if result is 'none'
        "extra_properties" : 0,          | Add extra properties to auth results
        "dns_overrides"    : null         | Path to dns.json for testing
    }

=cut
