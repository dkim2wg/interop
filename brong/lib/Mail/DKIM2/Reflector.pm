package Mail::DKIM2::Reflector;
use strict; use warnings;
use 5.020;

use Email::MIME;
use Carp;
use POSIX qw(strftime);
use Mail::DKIM2::Verifier;
use Mail::DKIM2::Signer;
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Common qw(fold_header should_skip DKIM2_DRAFT DKIM2_REPO DKIM2_DATE);

our $SUBJECT_PREFIX = '[DKIM2] ';
our $FOOTER         = "-- \r\nReflected and signed by the DKIM2 reflector at dkim2.com\r\n";
our $DAMAGE_LINE    = "damage line, breaks the signature\r\n";

# X-DKIM2-Info provenance, in the same format dkim2-milter.pl emits. The spec
# version constants come from Mail::DKIM2::Common (single source of truth).
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

# RFC 5322 date string (always UTC) for the given epoch.
sub _rfc2822_date {
    my ($epoch) = @_;
    return POSIX::strftime('%a, %d %b %Y %H:%M:%S +0000', gmtime($epoch));
}

# Low-level: sign $text with explicit Signer args, return the DKIM2-Signature
# header (folded, no trailing CRLF). i= is auto-assigned from existing sigs.
sub _sign_with {
    my ($text, %sa) = @_;
    my $signer = Mail::DKIM2::Signer->new(%sa);
    $signer->PRINT($text); $signer->CLOSE;
    croak "signing failed: " . $signer->result unless $signer->result eq 'signed';
    return $signer->as_string;   # "DKIM2-Signature: ..."
}

# Build a fresh message (headers + body) and prepend its m=1 Message-Instance.
# No signature. Used by generate() and generate_brand().
sub _fresh_message_text {
    my (%a) = @_;
    my $now  = $a{now} // time();
    my $mid  = $a{message_id} // sprintf('<fresh-%d-%d@%s>', $now, $$, $a{domain});
    my $date = _rfc2822_date($now);
    my $text =
        "From: $a{from}\r\n"
      . "To: $a{to}\r\n"
      . "Subject: $a{subject}\r\n"
      . "Date: $date\r\n"
      . "Message-ID: $mid\r\n"
      . "MIME-Version: 1.0\r\n"
      . "Content-Type: text/plain; charset=utf-8\r\n"
      . "\r\n"
      . $a{body};
    my $mi = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($text));
    (my $miv = fold_header("Message-Instance: " . $mi->as_string)) =~ s/^Message-Instance:\s*//;
    return "Message-Instance: $miv\r\n" . $text;
}

# Default explainer body for the fresh generator.
sub _fresh_body {
    my ($domain, $sender, $date) = @_;
    return
        "Hello,\r\n\r\n"
      . "This is a freshly-originated DKIM2 message from $domain, generated\r\n"
      . "because you sent mail to reflector-fresh\@$domain.\r\n\r\n"
      . "Unlike the other reflector addresses, this is NOT a forward of your\r\n"
      . "message: it is a brand-new message with a single Message-Instance (m=1)\r\n"
      . "and a single DKIM2-Signature (i=1), and no forwarding chain.\r\n\r\n"
      . "Paste it into https://$domain/validate/ to see it verify.\r\n\r\n"
      . "Requested by: $sender\r\n"
      . "Generated at: $date\r\n\r\n"
      . "-- \r\n"
      . "The DKIM2 reflector at $domain\r\n";
}

# generate(%args) — ORIGINATE a brand-new DKIM2 message back to the sender:
# a single Message-Instance (m=1) and a single DKIM2-Signature (i=1), no chain.
# Unlike reflect(), the incoming message is not used (the caller passes only the
# reply target as `sender`). From is a <domain> identity so DMARC aligns and the
# message lands in the inbox. An optional `body` overrides the default explainer
# (used by generate_brand()'s not-delegated path). See
# docs/superpowers/specs/2026-06-20-dkim2-reflector-fresh-design.md.
sub generate {
    my (%a) = @_;
    croak "need a sender" unless $a{sender};
    $a{domain}   //= 'dkim2.com';
    $a{selector} //= 'sel1';
    $a{mailfrom} //= "reflector-bounces\@$a{domain}";
    my $now = $a{now} // time();
    $a{timestamp} //= $now;
    my $body = $a{body} // _fresh_body($a{domain}, $a{sender}, _rfc2822_date($now));

    my $text = _fresh_message_text(
        from => "\"DKIM2 Generator\" <fresh\@$a{domain}>",
        to => $a{sender}, subject => 'Freshly generated DKIM2 message',
        body => $body, now => $now, message_id => $a{message_id}, domain => $a{domain},
    );

    # i=1 DKIM2-Signature (mf= relaxed-matches d=; rt = [sender]; no predecessor).
    my %sa = (Domain => $a{domain}, Selector => $a{selector},
              MailFrom => $a{mailfrom}, RcptTo => [ $a{sender} ], Timestamp => $a{timestamp});
    $sa{Key} = $a{key} if $a{key};
    $sa{KeyFile} = $a{keyfile} if $a{keyfile} && !$a{key};
    $text = _sign_with($text, %sa) . "\r\n" . $text;

    # X-DKIM2-Info provenance (action=generate), same format as the milter.
    my ($hc, $hn) = _header_list_for_hash(Email::MIME->new($text));
    (my $xi = fold_header("X-DKIM2-Info: " . _dkim2_info('generate', hc => $hc, hn => $hn))) =~ s/\r?\n\z//;
    return "$xi\r\n" . $text;
}

# Domain part of an email address.
sub _addr_domain { my ($a) = @_; $a =~ /\@([^>]+?)>?\s*$/ ? $1 : $a }

# True iff dkim2test._domainkey.$domain is a CNAME to dkim2test._domainkey.dkim2.com.
# Live DNS (kept out of generate_brand so the message logic is testable offline).
sub _dkim2test_cname_ok {
    my ($domain) = @_;
    require Net::DNS::Resolver;
    my $r = Net::DNS::Resolver->new;
    my $q = $r->query("dkim2test._domainkey.$domain", 'CNAME') or return 0;
    for my $rr ($q->answer) {
        next unless $rr->type eq 'CNAME';
        (my $t = $rr->cname) =~ s/\.\z//;
        return 1 if lc($t) eq 'dkim2test._domainkey.dkim2.com';
    }
    return 0;
}

# generate_brand(%args) — the reflector-brand behaviour. With delegated=1, build a
# fresh message From the brand and sign it twice (i=1 as the brand via the
# delegated key, i=2 as <domain>), on one Message-Instance. With delegated=0, fall
# back to the fresh generator carrying a CNAME-setup error body. See
# docs/superpowers/specs/2026-06-20-dkim2-reflector-brand-design.md.
sub generate_brand {
    my (%a) = @_;
    croak "need a sender" unless $a{sender};
    $a{domain}   //= 'dkim2.com';
    $a{selector} //= 'sel1';
    $a{mailfrom} //= "reflector-bounces\@$a{domain}";
    $a{brand_selector} //= 'dkim2test';
    my $now = $a{now} // time();
    my $bd  = _addr_domain($a{sender});

    unless ($a{delegated}) {
        my $err =
            "Hello,\r\n\r\n"
          . "You asked for the DKIM2 brand demo, but dkim2test._domainkey.$bd is not\r\n"
          . "a CNAME to dkim2test._domainkey.$a{domain}. Publish that CNAME and try\r\n"
          . "again to get a brand-signed (two-signature) message.\r\n\r\n"
          . "In the meantime, here is a plain freshly-generated DKIM2 message.\r\n\r\n"
          . "-- \r\n"
          . "The DKIM2 reflector at $a{domain}\r\n";
        return generate(sender => $a{sender}, domain => $a{domain}, selector => $a{selector},
                        key => $a{key}, keyfile => $a{keyfile}, mailfrom => $a{mailfrom},
                        now => $now, message_id => $a{message_id}, body => $err);
    }

    my $rcpt = "reflector-brand\@$a{domain}";
    my $body =
        "Hello,\r\n\r\n"
      . "This is a brand-signed DKIM2 message. It is freshly originated (a single\r\n"
      . "Message-Instance, m=1) but carries TWO DKIM2-Signatures:\r\n\r\n"
      . "  i=1  d=$bd  (signed with the key you delegated via the\r\n"
      . "       dkim2test._domainkey.$bd CNAME to dkim2test._domainkey.$a{domain})\r\n"
      . "  i=2  d=$a{domain}  (the platform hop out to you)\r\n\r\n"
      . "Paste it into https://$a{domain}/validate/ to see both signatures verify.\r\n\r\n"
      . "-- \r\n"
      . "The DKIM2 reflector at $a{domain}\r\n";

    my $text = _fresh_message_text(
        from => $a{sender}, to => $rcpt, subject => 'Brand-signed DKIM2 message',
        body => $body, now => $now, message_id => $a{message_id}, domain => $a{domain},
    );

    # i=1: sign AS the brand using the delegated key.
    my %b = (Domain => $bd, Selector => $a{brand_selector},
             MailFrom => $a{sender}, RcptTo => [ $rcpt ], Timestamp => $now);
    $b{Key} = $a{brand_key} if $a{brand_key};
    $b{KeyFile} = $a{brand_keyfile} if $a{brand_keyfile} && !$a{brand_key};
    $text = _sign_with($text, %b) . "\r\n" . $text;

    # i=2: the dkim2.com hop out to the sender.
    my %d = (Domain => $a{domain}, Selector => $a{selector},
             MailFrom => $a{mailfrom}, RcptTo => [ $a{sender} ], Timestamp => $now);
    $d{Key} = $a{key} if $a{key};
    $d{KeyFile} = $a{keyfile} if $a{keyfile} && !$a{key};
    $text = _sign_with($text, %d) . "\r\n" . $text;

    my ($hc, $hn) = _header_list_for_hash(Email::MIME->new($text));
    (my $xi = fold_header("X-DKIM2-Info: " . _dkim2_info('brand', hc => $hc, hn => $hn))) =~ s/\r?\n\z//;
    return "$xi\r\n" . $text;
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

    # Strip any Delivered-To: header Postfix local(8) prepends when piping the
    # message to this alias command. It is a per-hop delivery header (renamed to
    # X-Remote-Delivered-To / dropped before the reply is delivered), so it is
    # not seen by verifiers — but it is NOT an IANA trace header, so it is not in
    # should_skip(). If we left it in, _build_mi would hash it into our
    # Message-Instance and the resulting header hash could never be verified.
    # Remove it from the header block only, before we hash or sign anything.
    {
        my $hend = index($incoming, "\r\n\r\n");
        $hend = length($incoming) if $hend < 0;
        my $head = substr($incoming, 0, $hend);
        my $tail = substr($incoming, $hend);
        $head =~ s/^Delivered-To:[^\r\n]*(?:\r\n[ \t][^\r\n]*)*(?:\r\n|\z)//img;
        $incoming = $head . $tail;
    }

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
