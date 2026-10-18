package BodyPlanReference;
use strict;
use warnings;

# Every Message-Instance's body hash for a raw message, two ways: by the undo
# walk, rebuilding each previous body in full (MessageInstance->undo and
# b_digest), and by Mail::DKIM2::BodyPlan's one pass. Both return
#
#   { hashes => { m => { alg => base64 } }, errors => { m => text } }
#
# where an error is why instance m's body Recipe does not undo, and hashes
# stop below it, or below a null body Recipe.

use Exporter 'import';
our @EXPORT_OK = qw(reference_walk plan_walk);

use Mail::DKIM2::Common qw(parse_mime extract_mi_version);
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::BodyPlan;

my @ALGS = qw(sha256 sha512);

sub _top_mi {
    my ($msg) = @_;
    my %by_v = map { (extract_mi_version($_) // 0) => $_ } $msg->header_raw('Message-Instance');
    my ($num) = sort { $b <=> $a } keys %by_v;
    return ($num, $num && $by_v{$num});
}

sub reference_walk {
    my ($raw) = @_;
    my $msg = parse_mime($raw);
    my %out = (hashes => {}, errors => {});
    my $has_body = 1;
    while (1) {
        my ($num, $field) = _top_mi($msg);
        last unless $num;
        my $mi = Mail::DKIM2::MessageInstance->parse($field);
        if ($has_body) {
            my $hashes = $mi->get_tag('hashes') || {};
            $out{hashes}{$num}{$_} = Mail::DKIM2::MessageInstance::b_digest($msg, $_)
                for grep { $hashes->{$_} } @ALGS;
        }
        $has_body = 0 if $mi->unrecoverable;
        my $prev = eval {
            Mail::DKIM2::MessageInstance->undo($msg, HeadersOnly => !$has_body)
        };
        unless ($prev) {
            $out{errors}{$num} = $@;
            last;
        }
        $msg = $prev;
    }
    return \%out;
}

# $chunks: the raw message cut into pieces, to feed the plan the body in the
# same pieces (the cut that falls in the headers is dropped).
sub plan_walk {
    my ($raw, $chunks) = @_;
    $chunks //= [$raw];
    my $hdr_end = index($raw, "\r\n\r\n");
    $hdr_end = $hdr_end < 0 ? length $raw : $hdr_end + 4;

    my @mi;
    for my $field (_mi_fields(substr($raw, 0, $hdr_end))) {
        my $mi = eval { Mail::DKIM2::MessageInstance->parse($field) } or last;
        push @mi, $mi;
    }
    my $plan = Mail::DKIM2::BodyPlan->new(@mi);

    my $pos = 0;
    for my $c (@$chunks) {
        my $end = $pos + length $c;
        if ($end > $hdr_end) {
            my $from = $pos > $hdr_end ? $pos : $hdr_end;
            $plan->add(substr($raw, $from, $end - $from));
        }
        $pos = $end;
    }
    $plan->finish;

    my %out = (hashes => {}, errors => {});
    for my $mi (@mi) {
        my $m = $mi->get_tag('m');
        for my $alg (@ALGS) {
            my $h = $plan->body_hash($m, $alg);
            $out{hashes}{$m}{$alg} = $h if defined $h;
        }
        if (defined(my $e = $plan->recipe_error($m))) {
            $out{errors}{$m} = $e;
            last;
        }
    }
    return \%out;
}

# The Message-Instance field values in a header block, highest m= first.
sub _mi_fields {
    my ($block) = @_;
    my $msg = parse_mime("$block\r\n");
    my %by_v = map { (extract_mi_version($_) // 0) => $_ } $msg->header_raw('Message-Instance');
    return map { $by_v{$_} } sort { $b <=> $a } keys %by_v;
}

1;
