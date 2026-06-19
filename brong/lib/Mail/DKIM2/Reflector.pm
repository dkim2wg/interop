package Mail::DKIM2::Reflector;
use strict; use warnings;
use 5.020;

use Email::MIME;
use Carp;
use Mail::DKIM2::Verifier;
use Mail::DKIM2::Signer;
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Common qw(fold_header should_skip);

our $SUBJECT_PREFIX = '[DKIM2] ';
our $FOOTER         = "-- \r\nReflected and signed by the DKIM2 reflector at dkim2.com\r\n";
our $DAMAGE_LINE    = "damage line, breaks the signature\r\n";

# X-DKIM2-Info provenance, in the same format dkim2-milter.pl emits.
# NOTE: DKIM2_DRAFT/DKIM2_DATE also live in bin/dkim2-milter.pl and the
# mailman/sympa handlers — keep them in sync on a spec bump (see the
# dkim2-spec-version memory).
use constant DKIM2_DRAFT    => 'ietf-dkim-dkim2-spec-02';
use constant DKIM2_REPO     => 'github.com/dkim2wg/interop';
use constant DKIM2_DATE     => '2026-05-17';
use constant DKIM2_SOFTWARE => 'dkim2-reflector.pl';

sub _dkim2_info {
    my ($action, %extra) = @_;
    my $val = "draft=" . DKIM2_DRAFT
            . "; repo=" . DKIM2_REPO
            . "; date=" . DKIM2_DATE
            . "; sw=" . DKIM2_SOFTWARE
            . "; action=$action";
    for my $key (sort keys %extra) {
        next unless defined $extra{$key};
        $val .= "; $key=$extra{$key}";
    }
    return $val;
}

# (count, comma-separated-names) of the headers a Message-Instance hash covers,
# matching dkim2-milter.pl's hc=/hn= fields.
sub _header_list_for_hash {
    my ($msg) = @_;
    my @fields;
    for my $h (sort { lc($a) cmp lc($b) } $msg->header_names) {
        next if should_skip($h);
        my @vals = $msg->header_raw($h);
        push @fields, (lc $h) x scalar(@vals);
    }
    return (scalar(@fields), join(',', @fields));
}

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

    # Strip the Unix mailbox "From sender timestamp" envelope line that Postfix
    # local(8) prepends when piping a message to an alias command. It has no
    # colon, so if it survived into the reflected message it would prematurely
    # terminate the header block when the reply is re-injected (RFC 5322),
    # dumping every real header into the body. A genuine header is "From:";
    # only the mbox line is "From " followed by a space.
    $incoming =~ s/\AFrom [^\r\n]*\r\n//;

    # 1. DKIM2 verdict (computed here) + DKIM1 verdict (read from A-R).
    my $auth = _verify($incoming, $a{pubkey_cb}, $a{skip_timestamp_check});
    my $from_domain = _from_domain($incoming);
    my $dkim1_d = _dkim1_aligned($incoming, $from_domain, $a{authserv_id});
    my $dkim1   = $dkim1_d ? 'pass' : 'none';

    # 2. Three-tier signing basis: DKIM2 chain, else DKIM1 bridge (only when no
    #    chain present — a broken chain, dkim2=fail, does NOT fall back).
    my $basis = ($auth eq 'pass')                  ? 'dkim2'
              : ($auth eq 'none' && $dkim1_d)      ? 'dkim1'
              :                                       'none';
    my $will_sign = ($basis ne 'none');

    # 3. Transform (always, except damage which mutates after signing).
    my $prev_text = $incoming;
    my $cur_text  = ($mode eq 'damage') ? $incoming : _transform_text($incoming, $mode);

    # 4. Message-Instance for our change — ALWAYS for changing modes (raw/damage
    #    reuse the top m=). Emitted whether or not we sign.
    my $mi = _build_mi($cur_text, $prev_text, $mode);
    if ($mi) {
        my $val = fold_header("Message-Instance: " . $mi->as_string);
        $val =~ s/^Message-Instance:\s*//;
        $cur_text = "Message-Instance: $val\r\n" . $cur_text;
    }

    # 5. Sign when we have a basis; for damage, break the body AFTER signing.
    my $signed = 0;
    if ($will_sign) {
        my $sig = _sign($cur_text, %a);
        $cur_text = "$sig\r\n" . $cur_text;
        $signed = 1;
        $cur_text .= $DAMAGE_LINE if $mode eq 'damage';
    }

    # 6. Explanation headers (excluded from the DKIM2 header hash by
    #    should_skip(): ^x- and authentication-results). Safe to prepend last.
    my $ar = "Authentication-Results: $a{domain}; dkim2=$auth";
    $ar .= "; dkim=pass header.d=$dkim1_d" if $dkim1_d;
    $ar .= "\r\n";
    my $xr = "X-DKIM2-Reflector: mode=$mode; auth=$auth; dkim1=$dkim1; "
           . "basis=$basis; signed=" . ($signed ? 'yes' : 'no')
           . "; note=reflected-to-sender\r\n";

    # X-DKIM2-Info: provenance in dkim2-milter.pl's format. When we recorded a
    # new Message-Instance, report it as mi-m<N> with the hashed-header list,
    # exactly as the milter does; otherwise note the verify-only reflect.
    my $info;
    if ($mi) {
        my ($hc, $hn) = _header_list_for_hash(Email::MIME->new($cur_text));
        $info = _dkim2_info("mi-m" . $mi->get_tag('m'), hc => $hc, hn => $hn);
    } else {
        $info = _dkim2_info("reflect-$mode", verify => $auth);
    }
    (my $xi = fold_header("X-DKIM2-Info: $info")) =~ s/\r?\n\z//;
    $xi .= "\r\n";

    $cur_text = $ar . $xr . $xi . $cur_text;

    return {
        message => $cur_text, auth => $auth, dkim1 => $dkim1,
        basis => $basis, signed => $signed, mode => $mode,
    };
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

# Relaxed, PSL-free domain alignment: equal, or one a subdomain of the other.
sub _domains_align {
    my ($f, $d) = @_;
    return 0 unless defined $f && defined $d && length $f && length $d;
    $f = lc $f; $d = lc $d;
    return 1 if $f eq $d;
    return 1 if $f =~ /\.\Q$d\E\z/;   # f is a subdomain of d
    return 1 if $d =~ /\.\Q$f\E\z/;   # d is a subdomain of f
    return 0;
}

# Lowercased domain of the message's From: header, or undef.
sub _from_domain {
    my ($text) = @_;
    my $from = eval { Email::MIME->new($text)->header('From') };
    return undef unless defined $from && length $from;
    my $addr = ($from =~ /<([^>]+)>/) ? $1 : $from;
    my ($dom) = $addr =~ /\@([A-Za-z0-9.\-]+)/;
    return defined $dom ? lc $dom : undef;
}

# The aligned header.d of a dkim=pass result in our authserv-id's
# Authentication-Results, or undef. Only A-R bearing $authserv_id are trusted.
sub _dkim1_aligned {
    my ($text, $from_domain, $authserv_id) = @_;
    return undef unless defined $from_domain && defined $authserv_id;
    my @ar = eval { Email::MIME->new($text)->header_raw('Authentication-Results') };
    for my $ar (@ar) {
        $ar =~ s/\r?\n[ \t]+/ /g;             # unfold
        1 while $ar =~ s/\([^()]*\)//g;       # strip CFWS comments (may hold ';')
        my ($id, $rest) = split /;/, $ar, 2;
        next unless defined $rest;
        $id =~ s/^\s+|\s+$//g;
        $id =~ s/\s.*\z//;                     # drop optional version after authserv-id
        next unless lc($id) eq lc($authserv_id);
        # The first A-R bearing our authserv-id is OpenDKIM's genuine result
        # (it prepends on top of any sender-forged copy). Trust ONLY this one.
        for my $chunk (split /;/, $rest) {     # one resinfo per chunk
            next unless $chunk =~ /\bdkim\s*=\s*pass\b/i;
            next unless $chunk =~ /header\.d\s*=\s*([A-Za-z0-9.\-]+)/i;
            my $d = lc $1;
            return $d if _domains_align($from_domain, $d);
        }
        return undef;                          # ignore any lower A-R headers
    }
    return undef;
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
