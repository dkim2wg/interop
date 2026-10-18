#!/usr/bin/perl
# Body hashing by the undo walk (rebuild each previous body, hash it) against
# Mail::DKIM2::BodyPlan (one pass, nothing rebuilt).
#
#   perl util/body-plan-bench.pl                 # both scenarios, both ways
#   perl util/body-plan-bench.pl --only plan --size 50    # one way, for
#   /usr/bin/time -l perl util/body-plan-bench.pl --only undo --size 50   # peak RSS
#
# corpus:    every captured list message (corpus/results/capture) through the
#            whole Verifier, signatures and all, without and with StreamBody.
# synthetic: a --size MB body under three instances (a MIME wrap, then a
#            footer), body hashes only.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../perl/lib", "$FindBin::Bin/../perl/t/lib";
use Getopt::Long;
use Time::HiRes qw(time);
use Path::Tiny;
use JSON qw(decode_json encode_json);
use MIME::Base64 qw(encode_base64);
use Mail::DKIM2::Verifier;
use Mail::DKIM2::Common qw(parse_dkim_pubkey);
use ChainPlanReference qw(reference_walk plan_walk);

GetOptions('only=s' => \my $only, 'size=f' => \(my $size = 10),
           'scenario=s' => \my $scenario) or die "bad options\n";
my @ways = $only ? ($only) : qw(undo plan);

sub timed {
    my ($label, $code) = @_;
    my $t = time;
    my $out = $code->();
    printf "  %-6s %8.3fs\n", $label, time - $t;
    return $out;
}

if (!$scenario || $scenario eq 'corpus') {
    my $capture = path("$FindBin::Bin/../corpus/results/capture");
    my $dns = decode_json($capture->parent->child('dns-live.json')->slurp);
    my $pubkey = sub {
        my ($sig, $idx) = @_;
        my $e = $dns->{$sig->domain}{$sig->selector($idx // 0) . '._domainkey'};
        return $e && $e->[0] ? parse_dkim_pubkey($e->[0][1]) : undef;
    };
    my @msgs = map { (my $r = $_->slurp_raw) =~ s/\r?\n/\r\n/g; $r }
               sort $capture->children(qr/\.eml\z/);
    my $bytes = 0;
    $bytes += length for @msgs;
    printf "corpus: %d messages, %.1f MB, full Verifier\n", scalar @msgs, $bytes / 1e6;
    my %verdicts;
    for my $way (@ways) {
        $verdicts{$way} = timed($way, sub {
            my %count;
            for my $raw (@msgs) {
                my $v = Mail::DKIM2::Verifier->new(SkipTimestampCheck => 1,
                    PubkeyCallback => $pubkey, StreamBody => $way eq 'plan');
                $v->PRINT($_) for unpack('(a65536)*', $raw);
                $v->CLOSE;
                $count{$v->result}++;
            }
            join ' ', map { "$_=$count{$_}" } sort keys %count;
        });
    }
    print "  verdicts: $_ $verdicts{$_}\n" for @ways;
}

if (!$scenario || $scenario eq 'synthetic') {
    my $raw = synthetic($size);
    printf "synthetic: %.1f MB body, 3 instances (wrap, footer), body hashes only\n",
        $size;
    my %out;
    my $canon = JSON->new->canonical;
    for my $way (@ways) {
        $out{$way} = timed($way, $way eq 'undo'
            ? sub { reference_walk($raw) }
            : sub { plan_walk($raw, [unpack('(a65536)*', $raw)]) });
    }
    if (@ways == 2) {
        print '  hashes ', ($canon->encode($out{undo}) eq $canon->encode($out{plan})
                            ? 'agree' : 'DIFFER'), "\n";
    }
}

# m=1 the original text, m=2 a list's MIME wrap of it, m=3 a footer added
# inside the wrap: the current body is m=3's, and each Recipe rebuilds the
# one below.
sub synthetic {
    my ($mb) = @_;
    my $line = 'The quick brown fox jumps over the lazy dog, again and again. ';
    my $n = int($mb * 1e6 / (length($line) + 2));
    my @text = map { "$line$_" } 1 .. $n;
    my @top = ('--b', 'Content-Type: text/plain', '', @text,
               '-- ', 'list footer', '--b--');
    my $r = sub { encode_base64(encode_json($_[0]), '') };
    my $h = 'h=sha256:AAAA:AAAA';
    return join("\r\n",
        "Message-Instance: m=3; $h; r=" . $r->({ b => [{ c => [1, 3 + $n] }, { c => [6 + $n, 6 + $n] }] }),
        "Message-Instance: m=2; $h; r=" . $r->({ b => [{ c => [4, 3 + $n] }] }),
        "Message-Instance: m=1; $h",
        'From: a@example.com', 'Subject: bench', '', @top, '');
}
