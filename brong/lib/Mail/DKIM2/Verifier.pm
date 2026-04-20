package Mail::DKIM2::Verifier;
use strict;
use warnings;

use base 'Mail::DKIM2::HeaderParser';
use Crypt::Digest::SHA256 qw(sha256);
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

    # Check MI completeness and coverage if there are MI headers
    if (keys %mi_map) {
        my $max_v = (sort { $b <=> $a } keys %mi_map)[0];
        for my $v (1..$max_v) {
            unless ($mi_map{$v}) {
                $self->{result} = 'fail';
                $self->{details} = "missing Message-Instance m=$v";
                return;
            }
        }
        # Verify the top signature covers the topmost MI
        my $top_sig = $dk2_map{$max_i}{sig};
        my $top_m   = $top_sig->version || 0;
        if ($top_m != $max_v) {
            $self->{result} = 'fail';
            $self->{details} =
                "top signature i=$max_i m=$top_m does not cover topmost MI m=$max_v";
            return;
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
    # - MI headers with m <= the version referenced by signature $i
    my $max_v = $signature->version || 0;
    # If signature has no m= (i=1 with no prior MI), include MI up to $i
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

    # Validate d= matches mf= domain (skip for null sender / DSN)
    my $mf = $signature->mail_from;
    my $sig_domain = $signature->domain;
    if ($mf && $mf ne '<>') {
        my $mf_domain = extract_domain($mf);
        unless ($mf_domain && relaxed_domain_match($mf_domain, $sig_domain)) {
            $self->{result} = 'fail';
            $self->{details} = "d=$sig_domain does not match mf domain $mf_domain at i=$i";
            return 0;
        }
    }

    # Verify all signature items we support
    my $sig_count = $signature->sig_count;
    unless ($sig_count) {
        $self->{result} = 'fail';
        $self->{details} = 'no signature items in s= tag';
        return 0;
    }

    my $verified_any = 0;
    for my $idx (0 .. $sig_count - 1) {
        my $sig_b64 = $signature->signature_value($idx);
        next unless $sig_b64;

        # Get the public key for this signature item
        my $pubkey;
        if ($self->{_pubkey_callback}) {
            $pubkey = $self->{_pubkey_callback}->($signature, $idx);
        } else {
            eval {
                $pubkey = $signature->fetch_public_key($idx);
                1;
            } or do {
                $self->{result} = 'temperror';
                $self->{details} = "public key fetch failed for sig item $idx: $@";
                return 0;
            };
        }

        unless ($pubkey) {
            # Can't fetch key for this algorithm — skip it
            next;
        }

        my $sig_raw = decode_base64($sig_b64);
        my $alg = $signature->algorithm($idx) || 'unknown';
        eval {
            my $verified;
            if ($alg eq 'ed25519') {
                # Ed25519-SHA256: SHA-256 hash first, then verify with PureEdDSA
                my $digest = sha256($signing_input);
                $verified = $pubkey->verify_message($sig_raw, $digest);
            } else {
                # RSA-SHA256: verify_message handles SHA-256 internally
                $verified = $pubkey->verify_message($sig_raw, $signing_input, 'SHA256', 'v1.5');
            }
            unless ($verified) {
                $self->{result} = 'fail';
                $self->{details} = "signature verification failed for $alg at i=$i";
                return 0;
            }
            1;
        } or do {
            $self->{result} = 'fail';
            $self->{details} = "signature verification error for sig item $idx ($alg): $@";
            return 0;
        };

        $verified_any = 1;
    }

    unless ($verified_any) {
        $self->{result} = 'permerror';
        $self->{details} = "no verifiable signature items at i=$i";
        return 0;
    }

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

        # Chain of custody: mf of N must relaxed-domain-match an rt of N-1
        unless ($cur_mf) {
            $self->{result} = 'fail';
            $self->{details} = "missing MAIL FROM at i=$cur_i";
            return 0;
        }
        unless ($prev_rt) {
            $self->{result} = 'fail';
            $self->{details} = "missing RCPT TO at i=$prev_i";
            return 0;
        }

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

__END__

=head1 NAME

Mail::DKIM2::Verifier - Verify DKIM2-Signature chains on email messages

=head1 SYNOPSIS

    use Mail::DKIM2::Verifier;

    my $verifier = Mail::DKIM2::Verifier->new();

    # Optional: provide a custom public key lookup
    $verifier->set_pubkey_callback(sub {
        my ($signature) = @_;
        # return a Crypt::PK::RSA or Crypt::PK::Ed25519 object
    });

    # Feed the message
    $verifier->PRINT($message_text);
    $verifier->CLOSE;

    print $verifier->result(), "\n";         # pass, fail, none, etc.
    print $verifier->result_detail(), "\n";  # pass (i=1..3 verified)

=head1 DESCRIPTION

Streaming DKIM2 chain verifier.  Verifies B<all> DKIM2-Signature headers in
the chain (not just the outermost), checks chain completeness, validates
cryptographic signatures, and performs chain-of-custody domain matching
between consecutive hops.

Extends L<Mail::DKIM2::HeaderParser> for the streaming message parser.

B<EXPERIMENTAL> — This module implements draft-ietf-dkim-dkim2-spec-00, an
Internet-Draft that has not yet been published as an RFC.  The API and wire
format are subject to change.  Do not use in production.

=head1 CONSTRUCTOR

=head2 new(%args)

Creates a new Verifier.  No required arguments.

=head1 METHODS

=head2 set_pubkey_callback(\&callback)

Sets a callback for public key lookup.  The callback receives a
L<Mail::DKIM2::Signature> object and should return a L<Crypt::PK::RSA> or L<Crypt::PK::Ed25519>
object.  If not set, keys are fetched via DNS.

=head2 result()

Returns the verification result string:

=over 4

=item C<pass> - All signatures verified and chain is valid.

=item C<fail> - A signature failed, chain is incomplete, or custody break.

=item C<none> - No DKIM2-Signature headers found.

=item C<permerror> - Permanent failure (e.g. missing public key).

=item C<temperror> - Temporary failure (e.g. DNS lookup error).

=back

=head2 result_detail()

Returns the result with additional detail, e.g.
C<"pass (i=1..3 verified)">.

=head1 VERIFICATION PROCESS

The verifier performs these checks:

=over 4

=item 1.

B<Chain completeness>: All C<i=1> through C<i=N> signatures must be present
with no gaps.  Message-Instance headers (if any) must also be complete.

=item 2.

B<Cryptographic verification>: Each signature C<i=1..N> is independently
verified.  The signing input for signature C<i=K> includes only
Message-Instance and DKIM2-Signature headers that existed when that signature
was created.

=item 3.

B<Chain of custody>: For consecutive signatures, the MAIL FROM domain of
signature C<i=K> must relaxed-domain-match a RCPT TO domain of signature
C<i=K-1>.

=back

=head1 AUTHOR

Bron Gondwana E<lt>brong@fastmailteam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 Fastmail Pty Ltd.  This is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
