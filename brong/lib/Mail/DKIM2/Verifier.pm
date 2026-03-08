package Mail::DKIM2::Verifier;
use strict;
use warnings;

use base 'Mail::DKIM2::HeaderParser';
use Mail::DKIM::PublicKey;
use Digest::SHA;
use MIME::Base64 qw(encode_base64 decode_base64);
use Carp;

use Mail::DKIM2::Common qw(
    dkim2_canonicalize_header
    decode_tag_json
    encode_tag_json
    build_signing_input
    extract_mi_version
    extract_domain
    relaxed_domain_match
);
use Mail::DKIM2::Signature;
use Mail::DKIM2::MessageInstance;

sub init {
    my $self = shift;
    $self->SUPER::init;
    $self->{_mi_headers}  = {};
    $self->{_dk2_headers} = {};
    $self->{result}  = undef;
    $self->{details} = undef;
}

sub handle_header {
    my ($self, $field_name, $contents, $line) = @_;

    if (lc($field_name) eq 'message-instance') {
        eval {
            my $v = extract_mi_version($contents);
            if ($v) {
                $self->{_mi_headers}{$v} = $line || "$field_name:$contents";
            }
            1;
        } or do {
            $self->{_mi_parse_error} = $@;
        };
    }
    elsif (lc($field_name) eq 'dkim2-signature') {
        eval {
            my $sig = Mail::DKIM2::Signature->parse($contents);
            if ($sig && $sig->sequence) {
                $self->{_dk2_headers}{$sig->sequence + 0} = {
                    raw => $line || "$field_name:$contents",
                    sig => $sig,
                };
            }
            1;
        } or do {
            $self->{_dk2_parse_error} = $@;
        };
    }
}

sub finish_header {
    my $self = shift;
    # Nothing special needed here; verification happens in finish_body
}

sub finish_body {
    my $self = shift;

    my %mi_map  = %{$self->{_mi_headers}};
    my %dk2_map = %{$self->{_dk2_headers}};

    unless (keys %dk2_map) {
        $self->{result} = 'none';
        $self->{details} = 'no DKIM2-Signature headers found';
        return;
    }

    my $max_i = (sort { $b <=> $a } keys %dk2_map)[0];
    my $dk2_entry = $dk2_map{$max_i};
    my $signature = $dk2_entry->{sig};

    # Validate chain completeness - check for gaps
    for my $i (1..$max_i) {
        unless ($dk2_map{$i}) {
            $self->{result} = 'fail';
            $self->{details} = "missing DKIM2-Signature i=$i";
            return;
        }
    }

    # Check MI completeness if there are MI headers
    if (keys %mi_map) {
        my $max_v = (sort { $b <=> $a } keys %mi_map)[0];
        for my $v (1..$max_v) {
            unless ($mi_map{$v}) {
                $self->{result} = 'fail';
                $self->{details} = "missing Message-Instance v=$v";
                return;
            }
        }
    }

    # Verify ALL signatures in the chain, from i=1 to max_i
    for my $i (1..$max_i) {
        my $result = $self->_verify_signature($i);
        return unless $result;
    }

    # Check chain of custody between consecutive signatures
    if ($max_i > 1) {
        my $chain_result = $self->_verify_chain();
        return unless $chain_result;
    }

    $self->{result} = 'pass';
    $self->{details} = "i=1..$max_i verified";
}

sub _verify_signature {
    my ($self, $i) = @_;

    my %mi_map  = %{$self->{_mi_headers}};
    my %dk2_map = %{$self->{_dk2_headers}};
    my $dk2_entry = $dk2_map{$i};
    my $signature = $dk2_entry->{sig};

    # Only include headers that existed when signature $i was created:
    # - DKIM2-Sig headers with i <= $i
    # - MI headers with v <= the version referenced by signature $i
    my $max_v = $signature->version || 0;
    # If signature has no version (i=1 with no prior MI), include MI up to $i
    $max_v = $i if !$max_v;

    my @mi_arr  = map { { v => $_, raw => $mi_map{$_} } }
                  sort { $a <=> $b }
                  grep { $_ <= $max_v } keys %mi_map;
    my @dk2_arr = map { { i => $_, raw => $dk2_map{$_}{raw}, sig => $dk2_map{$_}{sig} } }
                  sort { $a <=> $b }
                  grep { $_ <= $i } keys %dk2_map;

    my $signing_input = build_signing_input(
        mi_headers  => \@mi_arr,
        dk2_headers => \@dk2_arr,
        signing_i   => $i,
        signature   => $signature,
    );

    # Hash the signing input
    my $sha = Digest::SHA->new(256);
    $sha->add($signing_input);
    my $digest = $sha->digest;

    # Get the public key
    my $pubkey;
    if ($self->{_pubkey_callback}) {
        $pubkey = $self->{_pubkey_callback}->($signature);
    } else {
        eval {
            $pubkey = $signature->fetch_public_key(0);
            1;
        } or do {
            $self->{result} = 'tempfail';
            $self->{details} = "public key fetch failed: $@";
            return 0;
        };
    }

    unless ($pubkey) {
        $self->{result} = 'permfail';
        $self->{details} = 'no public key available';
        return 0;
    }

    # Verify the signature
    my $sig_b64 = $signature->signature_value(0);
    unless ($sig_b64) {
        $self->{result} = 'fail';
        $self->{details} = 'no signature data in s= tag';
        return 0;
    }

    my $sig_raw = decode_base64($sig_b64);
    eval {
        my $verified = $pubkey->verify_digest('SHA-256', $digest, $sig_raw);
        unless ($verified) {
            $self->{result} = 'fail';
            $self->{details} = 'signature verification failed';
            return 0;
        }
        1;
    } or do {
        $self->{result} = 'fail';
        $self->{details} = "signature verification error: $@";
        return 0;
    };

    return 1;
}

sub _verify_chain {
    my ($self) = @_;
    my %dk2_map = %{$self->{_dk2_headers}};
    my @dk2_is = sort { $a <=> $b } keys %dk2_map;

    for my $idx (1..$#dk2_is) {
        my $cur_i = $dk2_is[$idx];
        my $prev_i = $dk2_is[$idx - 1];
        my $cur_sig = $dk2_map{$cur_i}{sig};
        my $prev_sig = $dk2_map{$prev_i}{sig};

        my $cur_mf = $cur_sig->mail_from;
        my $prev_rt = $prev_sig->rcpt_to;

        # Chain of custody: mf of N should relaxed-domain-match an rt of N-1
        if ($cur_mf && $prev_rt) {
            my $cur_mf_domain = extract_domain($cur_mf);
            my $match = 0;
            my @prev_rts = ref($prev_rt) eq 'ARRAY' ? @$prev_rt : ($prev_rt);
            for my $rt (@prev_rts) {
                my $rt_domain = extract_domain($rt);
                if (relaxed_domain_match($cur_mf_domain, $rt_domain)) {
                    $match = 1;
                    last;
                }
            }
            unless ($match) {
                $self->{result} = 'fail';
                $self->{details} = "chain of custody break at i=$cur_i";
                return 0;
            }
        }
    }

    return 1;
}

# Allow setting a callback for public key lookup (for testing with dns.json)
sub set_pubkey_callback {
    my ($self, $cb) = @_;
    $self->{_pubkey_callback} = $cb;
}

sub result {
    my $self = shift;
    return $self->{result} || 'none';
}

sub result_detail {
    my $self = shift;
    my $result = $self->result;
    if ($self->{details}) {
        return "$result ($self->{details})";
    }
    return $result;
}

1;
