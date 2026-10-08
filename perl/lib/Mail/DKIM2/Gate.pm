package Mail::DKIM2::Gate;
use strict;
use warnings;

our $VERSION = '0.14';

use Email::MIME;
use Mail::DKIM2::Common qw(extract_mi_version);
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Verifier;

=head1 NAME

Mail::DKIM2::Gate - decide whether a front end may sign a message

=head1 SYNOPSIS

    my $g = Mail::DKIM2::Gate->check($message,
        PubkeyCallback => $cb, SkipTimestampCheck => 0,
        AllowNullBodyRecipe => 0);
    unless ($g->{ok}) { warn "not signing: $g->{message}" }

=head1 DESCRIPTION

The gate shared by C<bin/dkim2sign> and C<bin/dkim2-milter>. Mail::DKIM2::Signer
itself signs whatever it is given; a front end that extends a DKIM2 chain should
first make sure the chain is worth extending.

=head2 check

C<< Mail::DKIM2::Gate->check($message, %opts) >> takes the whole message as a
string (CRLF line endings) and returns a hashref. Options:
C<PubkeyCallback> and C<SkipTimestampCheck> are passed to the Verifier,
C<AllowNullBodyRecipe> permits a top Message-Instance whose body Recipe is null,
and C<VerifyResult> supplies an already-computed verifier result so the upstream
signatures are not verified again.

The upstream DKIM2-Signatures are verified with a Verifier that allows an
unsigned Message-Instance above the top signature (the one the caller is about
to sign), and the Message-Instance chain must match the content and undo
cleanly down to m=1, including the header history below a null body Recipe.

The result has C<ok> (true to sign), C<verify_result> (C<none> without a
DKIM2-Signature), C<has_chain>, C<top_null> and, when refusing, C<reason>
(C<upstream-chain>, C<broken-mi-chain> or C<null-body-recipe>) and a
human-readable C<message>.

=cut

sub check {
    my ($class, $message, %o) = @_;

    my $msg = Email::MIME->new($message);
    my @sigs = $msg->header_raw('DKIM2-Signature');
    my @mis  = $msg->header_raw('Message-Instance');
    my $has_dk2 = @sigs ? 1 : 0;

    my $verify_result = $o{VerifyResult};
    if (!defined $verify_result) {
        if ($has_dk2) {
            my $v = Mail::DKIM2::Verifier->new(
                SkipTimestampCheck => $o{SkipTimestampCheck} ? 1 : 0,
                ($o{PubkeyCallback} ? (PubkeyCallback => $o{PubkeyCallback}) : ()));
            $v->allow_unsigned_mi(1);
            $v->PRINT($message);
            $v->CLOSE();
            $verify_result = $v->result_detail();
        } else {
            $verify_result = 'none';
        }
    }

    my ($chain_ok, $chain_why) = Mail::DKIM2::MessageInstance->chain_verifies($message);

    my %by_v;
    for my $val (@mis) {
        (my $x = $val) =~ s/^\s+//;
        $by_v{extract_mi_version($x) // 0} = $x;
    }
    my ($top) = sort { $b <=> $a } keys %by_v;
    my $top_null = ($top
        && eval { Mail::DKIM2::MessageInstance->parse($by_v{$top})->unrecoverable }) ? 1 : 0;

    my %r = (ok => 0, verify_result => $verify_result,
             has_chain => $has_dk2, top_null => $top_null);
    if ($has_dk2 && $verify_result !~ /^pass/) {
        @r{qw(reason message)} = ('upstream-chain',
            "upstream DKIM2 chain result=$verify_result");
    } elsif (!$chain_ok) {
        @r{qw(reason message)} = ('broken-mi-chain',
            "Message-Instance chain does not undo cleanly: $chain_why");
    } elsif ($top_null && !$o{AllowNullBodyRecipe}) {
        @r{qw(reason message)} = ('null-body-recipe',
            'top Message-Instance has a null body Recipe (--allow-null-body-recipe not set)');
    } else {
        $r{ok} = 1;
    }
    return \%r;
}

1;
