package Mail::DKIM2::Reflector;
use strict; use warnings;
use 5.020;

use Email::MIME;
use Carp;
use Mail::DKIM2::Verifier;
use Mail::DKIM2::Signer;
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Common qw(fold_header);

our $SUBJECT_PREFIX = '[DKIM2] ';
our $FOOTER         = "-- \r\nReflected and signed by the DKIM2 reflector at dkim2.com\r\n";
our $DAMAGE_LINE    = "damage line, breaks the signature\r\n";

my %VALID = map { $_ => 1 } qw(raw subject body both redacted damage);

# reflect(%args) — verify an incoming message, transform it per mode, and
# return the message to send back to the sender (signed only if the incoming
# DKIM2 chain verified).  Works on raw text throughout (Email::MIME is used
# only to compute hashes/recipes, where body_raw/header_raw preserve the
# original bytes) so upstream signatures are never invalidated by reserialising.
sub reflect {
    my (%a) = @_;
    croak "unknown mode " . ($a{mode} // '(undef)') unless $VALID{ $a{mode} // '' };
    my $mode = $a{mode};
    $a{domain}   //= 'dkim2.com';
    $a{selector} //= 'sel1';
    $a{mailfrom} //= 'reflector-bounces@dkim2.com';

    (my $incoming = $a{message}) =~ s/\r?\n/\r\n/g;

    # 1. Verify (DKIM2-only).
    my $auth   = _verify($incoming, $a{pubkey_cb}, $a{skip_timestamp_check});
    my $passed = ($auth eq 'pass') ? 1 : 0;

    # 2. Transform (always, except damage which mutates after signing).
    my $prev_text = $incoming;
    my $cur_text  = ($mode eq 'damage') ? $incoming : _transform_text($incoming, $mode);

    my $signed = 0;
    if ($passed) {
        # 3. Message-Instance: none for raw/damage (reuse top m=); new MI otherwise.
        my $mi = _build_mi($cur_text, $prev_text, $mode);
        if ($mi) {
            my $val = fold_header("Message-Instance: " . $mi->as_string);
            $val =~ s/^Message-Instance:\s*//;
            $cur_text = "Message-Instance: $val\r\n" . $cur_text;
        }
        # 4. Sign (single sel/alg).
        my $sig = _sign($cur_text, %a);
        $cur_text = "$sig\r\n" . $cur_text;
        $signed = 1;
        # 5. Damage: append a line AFTER signing so the body hash no longer matches.
        $cur_text .= $DAMAGE_LINE if $mode eq 'damage';
    }

    # 6. Explanation headers (excluded from the DKIM2 header hash by
    #    should_skip(): ^x- and authentication-results). Safe to prepend last.
    my $verdict = ($auth eq 'pass') ? 'pass' : ($auth eq 'fail' ? 'fail' : 'none');
    my $ar = "Authentication-Results: $a{domain}; dkim2=$verdict\r\n";
    my $xr = "X-DKIM2-Reflector: mode=$mode; auth=$verdict; "
           . "signed=" . ($signed ? 'yes' : 'no') . "; note=reflected-to-sender\r\n";
    $cur_text = $ar . $xr . $cur_text;

    return { message => $cur_text, auth => $auth, signed => $signed, mode => $mode };
}

sub _verify {
    my ($text, $cb, $skip_ts) = @_;
    my $v = Mail::DKIM2::Verifier->new;
    $v->skip_timestamp_check(1) if $skip_ts;
    if ($cb) {
        $v->set_pubkey_callback($cb);
    } else {
        $v->set_pubkey_callback(sub {
            my ($sig, $idx) = @_; $idx //= 0;
            return $sig->fetch_public_key($idx);
        });
    }
    $v->PRINT($text); $v->CLOSE;
    return $v->result // 'none';
}

# Split a message into (headers-without-trailing-CRLF, body).
sub _split {
    my ($text) = @_;
    my $i = index($text, "\r\n\r\n");
    return ($text, '') if $i < 0;
    return (substr($text, 0, $i), substr($text, $i + 4));
}

sub _transform_text {
    my ($text, $mode) = @_;
    return $text if $mode eq 'raw';
    my ($head, $body) = _split($text);
    if ($mode eq 'subject' || $mode eq 'both') {
        $head =~ s/^(Subject:[ \t]*)/$1$SUBJECT_PREFIX/mi;
    }
    if ($mode eq 'body' || $mode eq 'both' || $mode eq 'redacted') {
        $body .= "\r\n" if length($body) && $body !~ /\r\n\z/;
        $body .= $FOOTER;
    }
    return "$head\r\n\r\n$body";
}

# Returns a MessageInstance object (new MI) or undef (reuse top m=).
sub _build_mi {
    my ($cur_text, $prev_text, $mode) = @_;
    return undef if $mode eq 'raw' || $mode eq 'damage';
    my $mi = Mail::DKIM2::MessageInstance->calculate(
        Email::MIME->new($cur_text), Email::MIME->new($prev_text));
    $mi->set_null_body_recipe if $mode eq 'redacted';
    return $mi;
}

sub _sign {
    my ($text, %a) = @_;
    my %sa = (
        Domain   => $a{domain},
        Selector => $a{selector},
        MailFrom => $a{mailfrom},
        RcptTo   => [ $a{sender} ],
    );
    $sa{Key}       = $a{key}       if $a{key};
    $sa{KeyFile}   = $a{keyfile}   if $a{keyfile} && !$a{key};
    $sa{Timestamp} = $a{timestamp} if $a{timestamp};
    my $signer = Mail::DKIM2::Signer->new(%sa);
    $signer->PRINT($text); $signer->CLOSE;
    croak "signing failed: " . $signer->result unless $signer->result eq 'signed';
    return $signer->as_string;   # "DKIM2-Signature: ..."
}

1;

__END__

=head1 NAME

Mail::DKIM2::Reflector - verify-and-reflect DKIM2 demonstration logic

=head1 DESCRIPTION

Core logic for the dkim2.com reflector addresses. C<reflect(%args)> verifies an
incoming message's DKIM2 chain, applies a per-mode transformation, and returns
the message to send back to the sender. A reflector DKIM2-Signature is added
only when the incoming chain verified. See
C<docs/superpowers/specs/2026-06-18-dkim2-reflector-design.md>.

B<EXPERIMENTAL> — implements draft-ietf-dkim-dkim2-spec-02.

=cut
