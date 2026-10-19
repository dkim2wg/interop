use strict; use warnings; use FindBin; use lib "$FindBin::Bin/../../perl/lib";
use Time::HiRes qw(time); use JSON::PP; use Mail::DKIM2::Verifier; use Mail::DKIM2::Common qw(parse_dkim_pubkey);
my ($list, $dnsf, $reps) = @ARGV;
my $dns = JSON::PP->new->decode(do { local (@ARGV, $/) = $dnsf; <> });
my $cb = sub { my ($s, $i) = @_; my $e = $dns->{$s->domain}{$s->selector($i // 0) . '._domainkey'}; $e ? parse_dkim_pubkey($e->[0][1]) : undef };
open my $l, '<', $list or die; chomp(my @paths = <$l>);
my @msgs = map { open my $f, '<:raw', $_ or die "$_: $!"; local $/; scalar <$f> } grep { length } @paths;
for my $walk ('plan', 'undo') {
    my ($best, %v) = (9e9);
    for (1 .. $reps) {
        %v = (); my $t = time;
        for my $raw (@msgs) {
            my $v = Mail::DKIM2::Verifier->new(SkipTimestampCheck => 1, PubkeyCallback => $cb, StreamBody => $walk eq 'plan' ? 1 : 0);
            $v->load($raw); $v{$v->result}++;
        }
        my $d = time - $t; $best = $d if $d < $best;
    }
    printf "perl %s %.3f %s\n", $walk, $best, join ',', map { "$_=$v{$_}" } sort keys %v;
}
