package Mail::DKIM2::DSN;
use strict;
use warnings;

use Email::MIME;
use Carp;
use List::Util qw(max);

use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Signature;

# Mail::DKIM2::DSN - propagate a DKIM2-signed DSN upstream (draft-03 §12.1.1).
#
# When a Forwarder receives a Delivery Status Notification for a message it
# forwarded, it may propagate that DSN back towards the original sender. The
# propagated DSN is a *new* message: the Forwarder rebuilds the enclosed
# original to the state it was in when forwarded outward (undoing its own
# Message-Instance modification and removing the DKIM2-Signature and
# Message-Instance it added), then re-signs the whole DSN with MAIL FROM <>
# so that it carries exactly one Message-Instance and one DKIM2-Signature.

# Return the highest-sequence DKIM2-Signature (parsed) of an Email::MIME msg.
sub _top_sig {
    my ($msg) = @_;
    my @sigs = map { Mail::DKIM2::Signature->parse($_) } $msg->header_raw('DKIM2-Signature');
    return unless @sigs;
    my ($top) = sort { $b->sequence <=> $a->sequence } @sigs;
    return $top;
}

# Remove the single highest-sequence DKIM2-Signature header from an Email::MIME.
# (header_filter mishandles long folded values, so filter on header_raw and
# re-set the survivors.)
sub _strip_top_sig {
    my ($msg) = @_;
    my @sigs = $msg->header_raw('DKIM2-Signature');
    return unless @sigs;
    my $maxi = max(map { Mail::DKIM2::Signature->parse($_)->sequence } @sigs);
    my @keep = grep { Mail::DKIM2::Signature->parse($_)->sequence < $maxi } @sigs;
    $msg->header_raw_set('DKIM2-Signature', @keep);
    return $maxi;
}

# Extract the Email::MIME of the embedded original from a message/rfc822 (or
# text/rfc822-headers) part.
sub _embedded {
    my ($part) = @_;
    my @sub = $part->subparts;
    return $sub[0] if @sub;
    return Email::MIME->new($part->body);
}

# Re-sign a rebuilt/created DSN as a NEW message: prepend one Message-Instance
# (v=1) and one DKIM2-Signature (the supplied signer is configured with
# MailFrom => '<>'). Returns the final raw message.
sub _sign_as_new {
    my ($signer, $dsn) = @_;
    my $dsn_text = $dsn->as_string;
    $dsn_text =~ s/\r?\n/\r\n/g;
    my $mi = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($dsn_text));
    my $with_mi = "Message-Instance: " . $mi->as_string . "\r\n" . $dsn_text;
    $signer->PRINT($with_mi);
    $signer->CLOSE;
    my $sig_hdr = $signer->as_string;
    $sig_hdr =~ s/\r?\n$//;
    return $sig_hdr . "\r\n" . $with_mi;
}

# Build the multipart/report Content-Type (with report-type) by reading the
# boundary Email::MIME chose for a freshly-created multipart object.
sub _set_report_type {
    my ($msg) = @_;
    my $ct = $msg->header('Content-Type') // '';
    return if $ct =~ /report-type=/i;
    $ct =~ s{^(multipart/report)}{$1; report-type=delivery-status}i;
    $msg->header_str_set('Content-Type', $ct);
}

# Generate a fresh DKIM2-signed DSN for an inbound message, sent back to the
# original sender (draft-03 §12.1). Used by the reflector-dsn address, which
# bounces every message regardless of whether it arrived DKIM2-signed.
#
# Args: raw (inbound message), signer (MailFrom => '<>'), to (envelope sender
# to bounce to; if omitted, derived from the top DKIM2-Signature mf= or From:),
# reporting_mta, status, reason.
sub generate {
    my ($class, $args) = @_;
    my $raw    = $args->{raw}    or croak "generate: need raw message";
    my $signer = $args->{signer} or croak "generate: need signer";
    my $mta    = $args->{reporting_mta} // 'dkim2.com';
    my $status = $args->{status}        // '5.7.1';
    my $reason = $args->{reason}        // 'message rejected by reflector-dsn (demo bounce)';

    my $orig = Email::MIME->new($raw);

    # Where to send the bounce: explicit envelope sender, else top sig mf=,
    # else the From: header.
    my $to = $args->{to};
    if (!defined $to || !length $to || $to eq '<>') {
        my $top = _top_sig($orig);
        $to = $top->mail_from if $top;
    }
    if (!defined $to || !length $to || $to eq '<>') {
        $to = $orig->header('From');
    }
    croak "generate: cannot determine bounce destination" unless defined $to && length $to;

    my $final_rcpt = $args->{final_recipient} // $orig->header('To') // $to;

    # Part 1: human-readable explanation.
    my $human = Email::MIME->create(
        attributes => { content_type => 'text/plain', charset => 'UTF-8', encoding => '7bit' },
        body_str => "This is a DKIM2 demonstration Delivery Status Notification.\n\n"
                  . "Your message was received by the reflector-dsn address and a\n"
                  . "DKIM2-signed DSN has been returned to you.\n\n"
                  . "Reason: $reason\n",
    );

    # Part 2: machine-readable delivery status.
    my $ds = Email::MIME->create(
        attributes => { content_type => 'message/delivery-status', encoding => '7bit' },
        body => "Reporting-MTA: dns; $mta\r\n"
              . "\r\n"
              . "Final-Recipient: rfc822; $final_rcpt\r\n"
              . "Action: failed\r\n"
              . "Status: $status\r\n"
              . "Diagnostic-Code: smtp; $status $reason\r\n",
    );

    # Part 3: the original message.
    my $orig_part = Email::MIME->create(
        attributes => { content_type => 'message/rfc822', encoding => '7bit' },
        body => $orig->as_string,
    );

    my $dsn = Email::MIME->create(
        attributes => { content_type => 'multipart/report', encoding => '7bit' },
        header_str => [
            From    => "Mail Delivery System <postmaster\@$mta>",
            To      => $to,
            Subject => 'Delivery Status Notification (Failure)',
        ],
        parts => [ $human, $ds, $orig_part ],
    );
    _set_report_type($dsn);

    # The new DSN's envelope is MAIL FROM <> RCPT TO <bounce destination>.
    $signer->{MailFrom} = '<>';
    $signer->{RcptTo}   = [$to];
    return { raw => _sign_as_new($signer, $dsn), send_to => $to };
}

sub propagate {
    my ($class, $args) = @_;
    my $raw = $args->{raw}              or croak "propagate: need raw DSN";
    my $fwd = $args->{forwarder_domain} or croak "propagate: need forwarder_domain";
    my $signer = $args->{signer}        or croak "propagate: need signer";

    my $dsn = Email::MIME->new($raw);
    my $ct = $dsn->content_type // '';
    croak "propagate: not a multipart/report DSN" unless $ct =~ m{multipart/report}i;

    my @parts = $dsn->subparts;
    croak "propagate: DSN must have at least three parts" unless @parts >= 3;

    # Locate the embedded original (message/rfc822 or text/rfc822-headers).
    my ($orig_idx, $orig_part);
    for my $i (0 .. $#parts) {
        my $pct = $parts[$i]->content_type // '';
        if ($pct =~ m{message/rfc822}i || $pct =~ m{text/rfc822-headers}i) {
            $orig_idx = $i; $orig_part = $parts[$i]; last;
        }
    }
    croak "propagate: no embedded original message part" unless defined $orig_idx;

    my $headers_only = ($orig_part->content_type // '') =~ m{text/rfc822-headers}i;
    my $embedded = _embedded($orig_part);

    # 1. Undo the Forwarder's outward modification (reverses the highest MI and
    #    removes that Message-Instance header). If the body cannot be
    #    regenerated, fall back to headers-only.
    my $body_recoverable = 1;
    {
        my $top_mi;
        my %map = map { Mail::DKIM2::MessageInstance->parse($_) ? ($_) : () }
                  $embedded->header_raw('Message-Instance');
        # Determine whether the top MI declares an unrecoverable body.
        my @mis = $embedded->header_raw('Message-Instance');
        if (@mis) {
            my ($high) = sort { ($b =~ /m=(\d+)/)[0] <=> ($a =~ /m=(\d+)/)[0] } @mis;
            my $mi_obj = Mail::DKIM2::MessageInstance->parse($high);
            $body_recoverable = 0 if $mi_obj->unrecoverable;
        }
        my $undone = Mail::DKIM2::MessageInstance->undo($embedded);
        $embedded = $undone if $undone;   # undo() returns undef if no MI present
    }

    # 2. Remove the DKIM2-Signature the Forwarder added on the outward journey.
    _strip_top_sig($embedded);

    # 3. The propagated DSN is addressed to the MAIL FROM of the now-highest
    #    DKIM2-Signature of the rebuilt original.
    my $top = _top_sig($embedded);
    my $upstream = $top ? $top->mail_from : undef;
    croak "propagate: no remaining DKIM2-Signature to derive upstream MAIL FROM"
        unless defined $upstream;

    # 4. Rebuild the embedded part. If the body is unrecoverable, emit
    #    text/rfc822-headers (headers only); otherwise message/rfc822.
    my $rebuilt_original;
    if ($headers_only || !$body_recoverable) {
        # headers only — strip the body
        my $hdrs = $embedded->header_obj->as_string;
        $rebuilt_original = Email::MIME->create(
            attributes => { content_type => 'text/rfc822-headers',
                            encoding => '7bit' },
            body => $hdrs,
        );
    } else {
        $rebuilt_original = Email::MIME->create(
            attributes => { content_type => 'message/rfc822', encoding => '7bit' },
            body => $embedded->as_string,
        );
    }

    # 5. Replace the original part; leave the human-readable and
    #    delivery-status parts in place (a fuller implementation would rewrite
    #    the human-readable text to remove destination-specific detail).
    $parts[$orig_idx] = $rebuilt_original;
    $dsn->parts_set(\@parts);

    # 6. The propagated DSN is a NEW message: one Message-Instance (v=1) and one
    #    DKIM2-Signature, signed by the Forwarder with MAIL FROM <>.
    $signer->{MailFrom} = '<>';
    $signer->{RcptTo}   = [$upstream];
    return { raw => _sign_as_new($signer, $dsn), upstream_mailfrom => $upstream };
}

1;

__END__

=head1 NAME

Mail::DKIM2::DSN - propagate a DKIM2-signed DSN upstream (draft-03 §12.1.1)

=head1 SYNOPSIS

    my $out = Mail::DKIM2::DSN->propagate({
        raw              => $dsn_bytes,
        forwarder_domain => 'fwd.example',
        signer           => $mail_dkim2_signer,   # configured with MailFrom => '<>'
    });
    # $out->{raw}               — the propagated DSN (one MI, one DKIM2-Signature)
    # $out->{upstream_mailfrom} — address to send it to

=cut
