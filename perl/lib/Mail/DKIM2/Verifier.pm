package Mail::DKIM2::Verifier;
use strict;
use warnings;

use base 'Mail::DKIM2::HeaderParser';
use Crypt::Digest::SHA256 qw(sha256);
use MIME::Base64 qw(encode_base64 decode_base64);
use Carp;
use POSIX qw();

use Mail::DKIM2::Common qw(
    dkim2_canonicalize_header
    decode_tag_json
    encode_tag_json
    build_signing_input
    extract_mi_version
    extract_domain
    relaxed_domain_match
);
use Email::MIME;
use Mail::DKIM2::Signature;
use Mail::DKIM2::MessageInstance;

sub _extract_mi_hashes {
    my ($raw) = @_;
    $raw =~ s/^[^:]+://;        # strip "Message-Instance:" field name
    $raw =~ s/\r?\n[ \t]/ /g;   # unfold continuation lines
    if ($raw =~ /\bh=sha256:([A-Za-z0-9+\/=]+):([A-Za-z0-9+\/=]+)/) {
        return ($1, $2);         # (header_hash, body_hash)
    }
    return (undef, undef);
}

sub init {
    my $self = shift;
    $self->SUPER::init;
    $self->{_mi_headers}         = {};
    $self->{_dk2_headers}        = {};
    $self->{result}              = undef;
    $self->{details}             = undef;
    $self->{skip_timestamp_check} = 0;
    $self->{mid_process}         = 0;
}

sub skip_timestamp_check {
    my ($self, $val) = @_;
    $self->{skip_timestamp_check} = $val if defined $val;
    return $self->{skip_timestamp_check};
}

# mid_process: set when this Verifier is being run against a partial view of
# the chain (e.g. Validate.pm's per-level sub-verify, which strips
# higher-numbered DKIM2-Signature headers before re-verifying). In that view
# the highest remaining i= is NOT the true top of the whole chain, so the
# top-nd= rejection below (only valid for a final, whole-message verify)
# must be suppressed. Defaults to 0: a standalone/whole-message verify still
# rejects a true top nd=.
sub mid_process {
    my ($self, $val) = @_;
    $self->{mid_process} = $val if defined $val;
    return $self->{mid_process};
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

    # Local policy (stricter than spec-04 §"Check the Chain-of-Custody"): the
    # highest-numbered DKIM2-Signature MUST NOT carry nd=. The only legitimate
    # nd= producer is reflector-brand-nd, which always emits the matching
    # higher-i= signature too, so nd= never appears on top.
    #
    # Only valid for a FINAL, whole-message verification: $max_i here is the
    # top of whatever chain view this Verifier was fed. During a partial/
    # mid-chain verify (mid_process set, e.g. by Validate.pm's per-level
    # sub-verify after stripping higher signatures) that "top" is not the
    # real top of the chain, so this rejection must be suppressed.
    if (!$self->{mid_process}
        && defined $signature->next_domain && length $signature->next_domain) {
        $self->{result}  = 'permerror';
        $self->{details} = "DKIM2-Signature i=$max_i unexpected nd= tag";
        return;
    }

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

    # §10.8: Check donotmodify and donotexplode requests
    for my $i (1..$max_i) {
        my $sig   = $dk2_map{$i}{sig};
        my $flags = $sig->flags // [];

        if (grep { $_ eq 'donotmodify' } @$flags) {
            my $m = $sig->version || 0;
            if ($m >= 1 && $mi_map{$m} && $mi_map{$m + 1}) {
                my ($hh_m,  $bh_m)  = _extract_mi_hashes($mi_map{$m});
                my ($hh_m1, $bh_m1) = _extract_mi_hashes($mi_map{$m + 1});
                if (   (defined $bh_m  && defined $bh_m1  && $bh_m  ne $bh_m1)
                    || (defined $hh_m  && defined $hh_m1  && $hh_m  ne $hh_m1))
                {
                    $self->{result}  = 'fail';
                    $self->{details} = 'Message modified despite donotmodify request at i=' . $i;
                    return;
                }
            }
        }

        if (grep { $_ eq 'donotexplode' } @$flags) {
            for my $j ($i + 1 .. $max_i) {
                my $later_flags = $dk2_map{$j}{sig}->flags // [];
                if (grep { $_ eq 'exploded' } @$later_flags) {
                    $self->{result}  = 'fail';
                    $self->{details} = 'Message exploded despite donotexplode request at i=' . $i;
                    return;
                }
            }
        }
    }

    # §10.7: the cryptographic chain proves the MI headers are authentic, but
    # NOT that the current body/headers still match them. Walk the MI chain:
    # verify the top instance against the current content, then undo each
    # instance and verify the reconstructed content against the next one down,
    # until m=1 or an instance that declares the previous state unrecoverable.
    return unless $self->_verify_mi_chain();

    $self->{result} = 'pass';
    $self->{details} = "i=1..$max_i verified";
}

sub _verify_mi_chain {
    my ($self) = @_;

    my $raw = join('', @{$self->{headers}}) . "\r\n" . ($self->{_buf} // '');
    my $msg = Email::MIME->new($raw);

    while (1) {
        my @mi = $msg->header_raw('Message-Instance');
        my %by_v = map { (extract_mi_version($_) // 0) => $_ } @mi;
        my $num = %by_v ? (sort { $b <=> $a } keys %by_v)[0] : 0;
        last unless $num;

        my ($ok, $err) = Mail::DKIM2::MessageInstance->verify($msg);
        unless ($ok) {
            $self->{result}  = 'fail';
            $self->{details} = "Message-Instance m=$num does not match content"
                             . ($err ? " ($err)" : '');
            return 0;
        }

        last if $num <= 1;

        # If this instance declares the previous state non-recreatable, the
        # chain cannot (and need not) be undone further — accept what verified.
        my $mi_obj = Mail::DKIM2::MessageInstance->parse($by_v{$num});
        last if $mi_obj->unrecoverable;

        my $prev = eval { Mail::DKIM2::MessageInstance->undo($msg) };
        if ($@ || !$prev) {
            $self->{result}  = 'fail';
            $self->{details} = "Message-Instance m=$num did not undo cleanly"
                             . ($@ ? ": $@" : '');
            return 0;
        }
        $msg = $prev;
    }

    return 1;
}

sub _verify_signature {
    my ($self, $i) = @_;

    my %mi_map  = %{$self->{_mi_headers}};
    my %dk2_map = %{$self->{_dk2_headers}};
    my $dk2_entry = $dk2_map{$i};
    my $signature = $dk2_entry->{sig};

    # §8: "there MUST be only one of each kind" of tag.
    if (my $dup = $signature->duplicate_tag) {
        $self->{result}  = 'permerror';
        $self->{details} = "DKIM2-Signature i=$i duplicate tag $dup not permitted (spec 8)";
        return 0;
    }

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

    # Build signing header: use as_string_without_data() then re-add trailing
    # semicolon if the raw header from the message had one (spec ABNF requires
    # trailing ';' on every tag; new signatures have it, old ones may not).
    my $sig_hdr_for_input = $signature->as_string_without_data();
    if ($dk2_entry->{raw} =~ /;\s*(?:\r\n)?$/ && $sig_hdr_for_input !~ /;\s*$/) {
        $sig_hdr_for_input .= ';';
    }

    my $signing_input = build_signing_input(
        mi_headers     => \@mi_arr,
        dk2_headers    => \@dk2_arr,
        signing_i      => $i,
        signature      => $signature,
        signing_header => $sig_hdr_for_input,
    );

    # draft-04: every DKIM2-Signature MUST carry i=, m=, t=, d=, s=. Checked
    # via get_tag() (not the sequence/version/timestamp/domain accessors)
    # because those accessors just proxy get_tag() and would themselves
    # return undef for an absent tag anyway -- get_tag() is used directly
    # here to make explicit that "missing" means "tag truly absent", not
    # coerced to 0/''. (Verified against TagValueList::get_tag/Signature.pm:
    # none of these accessors coerce a missing tag to a false-but-defined
    # value.)
    for my $t (qw(i m t d s)) {
        my $present =
              $t eq 's' ? ($signature->sig_count ? 1 : 0)
            : $t eq 'd' ? (defined($signature->get_tag('d')) && length $signature->get_tag('d'))
            :             defined $signature->get_tag($t);
        unless ($present) {
            $self->{result}  = 'permerror';
            $self->{details} = "DKIM2-Signature i=$i tag=$t missing";
            return 0;
        }
    }

    # draft-04 §8: a signature carries either nd= or both mf= and rt=, never
    # both forms. nd= together with mf=/rt= is a PERMERROR.
    my $nd_tag = $signature->get_tag('nd');
    my $mf_tag = $signature->get_tag('mf');
    my $rt_tag = $signature->get_tag('rt');
    if (defined $nd_tag && (defined $mf_tag || defined $rt_tag)) {
        $self->{result}  = 'permerror';
        $self->{details} = "DKIM2-Signature i=$i tag=nd was unexpected";
        return 0;
    }
    if (!defined $nd_tag && !(defined $mf_tag && defined $rt_tag)) {
        $self->{result}  = 'permerror';
        $self->{details} = "DKIM2-Signature i=$i tag=mf missing";
        return 0;
    }

    # §8.3 SHOULD: n= nonce must not exceed 64 characters
    my $nonce = $signature->get_tag('n');
    if (defined $nonce && length($nonce) > 64) {
        $self->{result}  = 'fail';
        $self->{details} = "n= nonce exceeds 64 characters at i=$i";
        return 0;
    }

    # §10.3 SHOULD: reject signatures more than 14 days old or in the future
    unless ($self->{skip_timestamp_check}) {
        my $ts = $signature->timestamp;
        if (defined $ts && $ts > 0) {
            my $now = time();
            if ($ts > $now + 300) {
                $self->{result}  = 'fail';
                $self->{details} = "DKIM2-Signature i=$i timestamp is in the future";
                return 0;
            }
            if ($now > $ts + 14 * 24 * 3600) {
                $self->{result}  = 'fail';
                $self->{details} = "DKIM2-Signature i=$i has expired (age > 14 days)";
                return 0;
            }
        }
    }

    # Spec §7.5/§7.6: mf= and each rt= MUST be a bracketed RFC5321 path.
    my $mf_raw = $signature->mail_from;
    if (defined $mf_raw && length $mf_raw && $mf_raw !~ /^<.*>$/s) {
        $self->{result}  = 'fail';
        $self->{details} = "mf= is not a bracketed RFC5321 reverse-path at i=$i (spec 7.5)";
        return 0;
    }
    my $rt_raw = $signature->rcpt_to;
    if ($rt_raw) {
        for my $r (@$rt_raw) {
            next if defined $r && $r =~ /^<.*>$/s;
            $self->{result}  = 'fail';
            $self->{details} = "rt= entry is not a bracketed RFC5321 forward-path at i=$i (spec 7.6)";
            return 0;
        }
    }

    # Validate d= matches mf= domain (skip for null sender / DSN)
    my $mf = $signature->mail_from;
    my $sig_domain = $signature->domain;
    if ($mf && $mf ne '<>') {
        my $mf_domain = extract_domain($mf);
        unless ($mf_domain && relaxed_domain_match($mf_domain, $sig_domain)) {
            $self->{result} = 'fail';
            $self->{details} = "DKIM2-Signature i=$i MAIL FROM and d= do not match";
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

        # Get the public key for this signature item.  The fetch is eval'd
        # whichever way the key is sourced: every real caller (milter,
        # reflector, validator, CLIs) installs a pubkey callback, and the stock
        # callbacks end in fetch_public_key(), which dies on transient DNS.
        # Guarding only the no-callback branch let that croak escape the
        # verifier and take the caller down with it -- the reflector dropped
        # the message outright instead of reflecting it unsigned.
        my $pubkey;
        my $fetched = eval {
            $pubkey = $self->{_pubkey_callback}
                ? $self->{_pubkey_callback}->($signature, $idx)
                : $signature->fetch_public_key($idx);
            1;
        };
        unless ($fetched) {
            # A transient DNS failure is a TEMPERROR per spec-04 §10 —
            # retryable, not a permanent "no verifiable signature items", and
            # emphatically not a 'fail', which reads as a forged signature.
            my $sel = $signature->selector($idx) // '?';
            # Drop croak's " at FILE line N." tail: this reason is reported in
            # Authentication-Results on mail we send out, and our source paths
            # are nobody else's business.
            (my $why = $@) =~ s/\s+at\s+\S+\s+line\s+\d+\.?\s*\z//;
            $why =~ s/\s+\z//;
            $self->{result}  = 'temperror';
            $self->{details} = "DKIM2-Signature i=$i public key $sel could not be fetched ($why)";
            return 0;
        }

        unless ($pubkey) {
            # Can't fetch key for this algorithm — skip it
            next;
        }

        my $alg = $signature->algorithm($idx) || 'unknown';

        # §3.2: RSA keys MUST be at least 1024 bits; reject shorter keys
        # (permerror) rather than trusting a weak signature.
        if ($alg !~ /^ed25519/ && $pubkey->can('size')) {
            my $bits = $pubkey->size * 8;
            if ($bits < 1024) {
                $self->{result}  = 'permerror';
                $self->{details} = "DKIM2-Signature i=$i RSA key too short ($bits bits < 1024, spec 3.2)";
                return 0;
            }
        }

        my $sig_raw = decode_base64($sig_b64);
        my $verified = eval {
            if ($alg =~ /^ed25519/) {
                # Ed25519-SHA256: SHA-256 hash first, then verify with PureEdDSA
                my $digest = sha256($signing_input);
                $pubkey->verify_message($sig_raw, $digest);
            } else {
                # RSA-SHA256: verify_message handles SHA-256 internally
                $pubkey->verify_message($sig_raw, $signing_input, 'SHA256', 'v1.5');
            }
        };
        if ($@) {
            $self->{result} = 'fail';
            $self->{details} = "signature verification error for sig item $idx ($alg): $@";
            return 0;
        }
        unless ($verified) {
            $self->{result} = 'fail';
            $self->{details} = "signature verification failed for $alg at i=$i";
            return 0;
        }

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

        # draft-04 §11.4: an nd= hop declares the domain that signs the next
        # signature; nd= MUST exactly match that signature's d=.
        my $prev_nd = $prev_sig->next_domain;
        if (defined $prev_nd && length $prev_nd) {
            my $cur_d = $cur_sig->domain // '';
            unless (lc($prev_nd) eq lc($cur_d)) {
                $self->{result} = 'fail';
                $self->{details} = "DKIM2-Signature i=$prev_i MAIL nd= does not match";
                return 0;
            }
            next;
        }

        my $cur_mf = $cur_sig->mail_from;
        my $prev_rt = $prev_sig->rcpt_to;

        # Chain of custody: mf of N must relaxed-domain-match an rt of N-1
        unless ($cur_mf) {
            $self->{result} = 'fail';
            $self->{details} = "DKIM2-Signature i=$cur_i MAIL FROM <> did not match";
            return 0;
        }
        unless ($prev_rt) {
            $self->{result} = 'fail';
            $self->{details} = "DKIM2-Signature i=$prev_i RCPT TO <> did not match";
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
            $self->{details} = "DKIM2-Signature i=$cur_i MAIL FROM $cur_mf did not match";
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

# The bare reason for the result, with no result word wrapped around it.
# result_detail() is the display form ("temperror (...)"); callers that embed
# the reason in a report of their own -- an Authentication-Results comment, say
# -- want this one, or they end up saying the result twice.
sub details {
    my $self = shift;
    return $self->{details};
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

B<EXPERIMENTAL> — This module implements draft-ietf-dkim-dkim2-spec-04, an
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

=head2 details()

Returns just the reason, without the result wrapped around it, e.g.
C<"i=1..3 verified"> — or undef when there is no further detail.  Use this
rather than C<result_detail()> when embedding the reason in a report that
already states the result, such as an C<Authentication-Results> comment.

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
