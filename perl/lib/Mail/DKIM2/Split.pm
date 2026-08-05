package Mail::DKIM2::Split;
use strict;
use warnings;

use Email::MIME;
use Exporter 'import';
our @EXPORT_OK = qw(plan_copies disclosed_addresses);

# Mail::DKIM2::Split - Bcc-safe recipient grouping for DKIM2 origination.
#
# DKIM2 records the RCPT TO of each hop in the signature's rt= tag. If a single
# submitted message with undisclosed (Bcc) recipients is signed once, all those
# recipients end up in one rt=, visible to everyone -- a Bcc leak. To avoid it,
# the message must be split into instances before signing: disclosed recipients
# (those already named in To:/Cc:) can share one copy; each Bcc recipient must
# get its own. The signing step then records only that copy's recipients in rt=.
#
# This module is the (network-free, testable) grouping logic. The LMTP daemon
# (bin/dkim2-split-lmtp.pl) uses it to fan a message out into per-copy
# re-injections. See deploy/SERVER.md "Bcc-safe origination".

# disclosed_addresses($message_bytes) -> hashref { lc-address => 1 } of every
# address named in the message's To: and Cc: header fields.
sub disclosed_addresses {
    my ($msg_bytes) = @_;
    my %seen;
    my $em = eval { Email::MIME->new($msg_bytes) } or return \%seen;
    for my $hdr (qw(To Cc)) {
        for my $val ($em->header($hdr)) {
            next unless defined $val;
            # addresses inside angle brackets: To: "Name" <a@b>, ...
            while ($val =~ /<([^>]+)>/g) { $seen{ lc $1 } = 1; }
            # bare addr-specs (comma-separated tokens with @ and no <>)
            for my $tok (split /,/, $val) {
                $tok =~ s/^\s+|\s+$//g;
                next if $tok =~ /</;
                $seen{ lc $1 } = 1 if $tok =~ /([^\s<>,]+\@[^\s<>,]+)/;
            }
        }
    }
    return \%seen;
}

# Strip optional angle brackets from an envelope path and lowercase it.
sub _addr {
    my ($r) = @_;
    $r =~ s/^<//; $r =~ s/>$//;
    return lc $r;
}

# plan_copies($message_bytes, \@envelope_rcpts) -> \@copies
#
# Returns the set of copies to generate so that no copy's rt= ever lists a Bcc
# recipient alongside anyone else. Each copy is { rcpts => [envelope rcpts] },
# preserving the original (possibly bracketed) recipient strings:
#   - all disclosed recipients (address present in To:/Cc:) share ONE copy;
#   - each undisclosed (Bcc) recipient gets its OWN copy.
# Recipients whose address is not in To:/Cc: are treated as Bcc (so a message
# with no To:/Cc: at all yields one copy per recipient -- always safe).
sub plan_copies {
    my ($msg_bytes, $envelope_rcpts) = @_;
    my $disclosed = disclosed_addresses($msg_bytes);
    my (@disc, @bcc);
    for my $r (@$envelope_rcpts) {
        if ($disclosed->{ _addr($r) }) { push @disc, $r } else { push @bcc, $r }
    }
    my @copies;
    push @copies, { rcpts => [@disc] } if @disc;
    push @copies, { rcpts => [$_] } for @bcc;
    return \@copies;
}

1;

__END__

=head1 NAME

Mail::DKIM2::Split - Bcc-safe recipient grouping for DKIM2 origination

=head1 SYNOPSIS

    use Mail::DKIM2::Split qw(plan_copies);

    my $copies = plan_copies($message_bytes, ['<a@x>', '<b@y>', '<bcc@z>']);
    # -> [ { rcpts => ['<a@x>','<b@y>'] },   # disclosed (in To:/Cc:), one copy
    #      { rcpts => ['<bcc@z>'] } ]         # Bcc, its own copy

=head1 DESCRIPTION

B<EXPERIMENTAL>. Splits the envelope recipients of a message into copies such
that, once each copy is DKIM2-signed (the signer records that copy's envelope
recipients in C<rt=>), no Bcc recipient is ever revealed to another recipient.
Disclosed recipients (named in C<To:>/C<Cc:>) share one copy; each undisclosed
recipient gets its own. This is the network-free core used by the LMTP split
content filter; see C<deploy/SERVER.md> ("Bcc-safe origination").

=head1 AUTHOR

Bron Gondwana E<lt>brong@fastmailteam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 Fastmail Pty Ltd.  This is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
