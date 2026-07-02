package Mail::DKIM2::BounceHandler;
use strict;
use warnings;

use Email::MIME;
use Mail::DKIM2::DSNHeader;
use Mail::DKIM2::Signature;
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Common qw(relaxed_domain_match extract_domain);

# Mail::DKIM2::BounceHandler - verify an incoming DKIM2-DSN bounce, undo the
# enclosed chain, and decide relay-to-originator vs capture.
#
# This is the dkim2-bounces@ handler's logic (kept separate from the thin
# pipe(8) CLI in bin/dkim2-bounces.pl so it is directly testable). It never
# relays a bounce unless all of the following hold:
#
#   1. rt= (the DKIM2-DSN header's recipient) decodes to the enclosed
#      message's top-hop mf= -- i.e. the DSN claims to be addressed back to
#      exactly the party the top DKIM2-Signature says originated it.
#   2. d= (the DKIM2-DSN signing domain) relaxed-domain-matches a top-hop
#      rt= domain of the enclosed message -- i.e. the domain vouching for
#      this bounce was actually a recipient of the original send.
#   3. h= (the DKIM2-DSN header hash) equals the enclosed message's top-MI
#      header-hash -- i.e. the bounce is about *this* message content, not
#      a substituted one.
#   4. The DKIM2-DSN signature itself verifies against the d=/selector
#      public key.
#
# Any failure -> capture (never relay something we can't authenticate).

# Verify a DKIM2-DSN bounce, undo the enclosed chain, and decide relay vs
# capture. Args: raw (the inbound bounce message), pubkey_cb (used to
# resolve the DKIM2-DSN's d=/selector public key, same calling convention as
# Mail::DKIM2::Verifier's pubkey callback: $cb->($signature_like_obj, $idx)).
#
# Returns { action => 'relay', relay_to => $addr, message => $reconstructed }
# or { action => 'capture' }.
sub process {
    my (%a) = @_;

    my $msg = eval { Email::MIME->new($a{raw}) };
    return { action => 'capture' } unless $msg;

    my ($dhv) = $msg->header_raw('DKIM2-DSN');
    return { action => 'capture' } unless defined $dhv;   # not a DKIM2-DSN

    my $d = eval { Mail::DKIM2::DSNHeader->parse($dhv) };
    return { action => 'capture' } unless $d;

    # Locate the embedded original (message/rfc822 or text/rfc822-headers part).
    my $emb = _embedded_headers($msg);
    return { action => 'capture' } unless defined $emb;
    my $eom = eval { Email::MIME->new($emb) };
    return { action => 'capture' } unless $eom;

    # Top (highest i=) DKIM2-Signature of the enclosed original.
    my @sigs = map { Mail::DKIM2::Signature->parse($_) } $eom->header_raw('DKIM2-Signature');
    my ($top) = sort { $b->sequence <=> $a->sequence } @sigs;
    return { action => 'capture' } unless $top;

    # (1) rt= must decode to the enclosed message's top-hop mf=.
    my $dsn_rt = $d->rcpt_to;                 # bracketed, e.g. "<sender@test1.dkim2.com>"
    my $top_mf = $top->mail_from;             # bracketed, e.g. "<sender@test1.dkim2.com>"
    return { action => 'capture' }
        unless defined $dsn_rt && defined $top_mf && $dsn_rt eq $top_mf;

    # (2) d= must relaxed-match a top-hop rt= domain of the enclosed message.
    my $rts = $top->rcpt_to || [];
    my $d_ok = grep { relaxed_domain_match(extract_domain($_), $d->domain) } @$rts;
    return { action => 'capture' } unless $d_ok;

    # (3) h= must equal the enclosed top-MI header-hash.
    my @mis = $eom->header_raw('Message-Instance');
    my ($topmi) = sort { ($b =~ /m=(\d+)/)[0] <=> ($a =~ /m=(\d+)/)[0] } @mis;
    return { action => 'capture' } unless $topmi;
    my $mi_obj = eval { Mail::DKIM2::MessageInstance->parse($topmi) };
    return { action => 'capture' } unless $mi_obj;
    my $hh = $mi_obj->header_hash;
    return { action => 'capture' }
        unless defined $hh && $d->header_hash eq "sha256:$hh";

    # (4) DKIM2-DSN signature must verify with the d=/selector public key.
    my $pub = _resolve_pubkey($d, $a{pubkey_cb});
    return { action => 'capture' } unless $pub;
    return { action => 'capture' } unless eval { $d->verify($pub) };

    # All checks pass: undo the chain to reconstruct the message as it was
    # delivered to the top hop, and relay it back to the reconstructed
    # originator (the top-hop mf=, which we've just confirmed equals rt=).
    my $reconstructed = _undo_to_origin($eom);

    (my $to = $dsn_rt) =~ s/^<(.*)>$/$1/;
    return { action => 'relay', relay_to => $to, message => $reconstructed };
}

# Return the embedded original (headers, or headers+body) as a raw string
# from the first message/rfc822 or text/rfc822-headers part found.
sub _embedded_headers {
    my ($msg) = @_;
    for my $part ($msg->parts) {
        my $ct = $part->content_type // '';
        if ($ct =~ m{message/rfc822}i) {
            my ($sub) = $part->subparts;
            return $sub ? $sub->as_string : $part->body;
        }
        return $part->body if $ct =~ m{text/rfc822-headers}i;
    }
    return;
}

# Reverse the Message-Instance chain as far as it cleanly undoes.
# Mail::DKIM2::MessageInstance->undo($email_mime) returns a (possibly
# modified in place) Email::MIME object for the previous version, or undef
# once there is nothing left to undo (no Message-Instance headers remain).
# For a single-hop message (only m=1, no diff to a prior state) there is
# nothing to undo and the loop exits immediately -- the "reconstructed
# original" is just the embedded headers/body as received.
sub _undo_to_origin {
    my ($eom) = @_;
    my $cur = $eom;
    while (1) {
        my $prev = eval { Mail::DKIM2::MessageInstance->undo($cur) };
        last unless $prev;
        $cur = $prev;
    }
    return $cur->as_string;
}

# Resolve the public key for the DKIM2-DSN's d=/selector, via the supplied
# pubkey_cb if given (test/production DNS-lookup callback, same calling
# convention as Mail::DKIM2::Verifier's: $cb->($signature_like_obj, $idx)),
# else by a real DNS fetch mirroring Signature::fetch_public_key.
sub _resolve_pubkey {
    my ($d, $pubkey_cb) = @_;

    # Build a real Signature object exposing ->domain/->selector($idx) so it
    # matches exactly what pubkey callbacks (and fetch_public_key) expect --
    # no hand-rolled shim to keep in sync with Signature's internals.
    my $sig_like = Mail::DKIM2::Signature->new(
        Domain     => $d->domain,
        Signatures => [[ $d->selector, $d->algorithm, '' ]],
    );

    if ($pubkey_cb) {
        return $pubkey_cb->($sig_like, 0);
    }
    return eval { $sig_like->fetch_public_key(0) };
}

1;

__END__

=head1 NAME

Mail::DKIM2::BounceHandler - verify a DKIM2-DSN bounce, undo the chain, decide relay vs capture

=head1 SYNOPSIS

    use Mail::DKIM2::BounceHandler;

    my $out = Mail::DKIM2::BounceHandler::process(
        raw       => $bounce_message,
        pubkey_cb => sub { my ($sig, $idx) = @_; ... },
    );
    if ($out->{action} eq 'relay') {
        # $out->{relay_to} -- address to relay to (reconstructed originator)
        # $out->{message}  -- reconstructed original message
    } else {
        # 'capture' -- could not authenticate the bounce; do not relay it
    }

=head1 DESCRIPTION

B<EXPERIMENTAL> - prototype support for the C<dkim2-bounces@> handler: an
incoming Delivery Status Notification carrying a C<DKIM2-DSN> singleton
header (see L<Mail::DKIM2::DSNHeader>) is verified, and if (and only if) it
authenticates cleanly, the enclosed original message is reconstructed (by
undoing its Message-Instance chain) and relayed back to the originator.
Anything that fails to authenticate is captured rather than relayed, so a
forged or tampered bounce can never be used to redirect mail.

=head1 FUNCTIONS

=head2 process(%args)

Args: C<raw> (the inbound bounce message, raw bytes), C<pubkey_cb> (optional;
used to resolve the DKIM2-DSN's C<d=>/selector public key -- same calling
convention as L<Mail::DKIM2::Verifier>'s pubkey callback,
C<< $cb->($signature_like_obj, $idx) >>; if omitted, a live DNS fetch is
attempted).

Returns C<< { action => 'relay', relay_to => $addr, message => $reconstructed } >>
or C<< { action => 'capture' } >>.

=head1 AUTHOR

Bron Gondwana E<lt>brong@fastmailteam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 Fastmail Pty Ltd.  This is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
