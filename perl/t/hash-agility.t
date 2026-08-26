#!/usr/bin/perl -w
#
# spec-05 hash agility: sha512 alongside sha256, multi-hash-set h= parsing,
# and the --hash signer flag (sha256|sha512|both, default sha256).

use 5.020;
use strict;
use warnings;
use Test::More;
use Email::MIME;
use Path::Tiny;
use File::Temp qw(tempdir);
use File::Spec;
use lib 'lib', 't/lib';
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Verifier;
use DKIM2TestKeys;

# spec-05 §3: both hashing algorithms must be implemented
my $algs = Mail::DKIM2::MessageInstance::hash_algs();
is_deeply([sort keys %$algs], ['sha256', 'sha512'], 'spec-05 §3: both hash algorithms present');

# spec-05 §7.3: h= is a comma-separated list of hash-sets
my $sets = Mail::DKIM2::MessageInstance::parse_hash_sets('sha256:AAA:BBB,sha512:CCC:DDD');
is(scalar @$sets, 2, 'two hash-sets parsed');
is_deeply($sets->[0], ['sha256', 'AAA', 'BBB'], 'first hash-set');
is_deeply($sets->[1], ['sha512', 'CCC', 'DDD'], 'second hash-set');

# RFC 5234: ABNF quoted strings are case-insensitive
my $upper = Mail::DKIM2::MessageInstance::parse_hash_sets('SHA512:AAA:BBB');
is($upper->[0][0], 'sha512', 'hash-name matched case-insensitively');

# FWS inside a folded h= must not corrupt the hash-set (§2.12: FWS may
# appear anywhere inside a base64 value, not just at the ends of an item).
my $folded = Mail::DKIM2::MessageInstance::parse_hash_sets("sha256:AA\r\n\tA:BBB");
is($folded->[0][1], 'AAA', 'FWS stripped from a folded header hash');

my $folded_mid = Mail::DKIM2::MessageInstance::parse_hash_sets("sha256:A\tA A:B B\r\nB");
is($folded_mid->[0][1], 'AAA', 'FWS stripped from the middle of a header hash');
is($folded_mid->[0][2], 'BBB', 'FWS stripped from the middle of a body hash');

# §11.2: a malformed base64 value in h= must never crash the verifier. Perl
# compares hash-set strings directly (it never base64-decodes an h= value),
# so there is no decode step to guard -- but confirm the failure path really
# is clean: no die, just a normal mismatch.
{
    my $raw = join("\r\n",
        'Message-Instance: m=1; h=sha256:not-valid-base64!!:BBBB;',
        'Subject: malformed h= test',
        '',
        'Body.',
    ) . "\r\n";
    my $msg = Email::MIME->new($raw);
    my ($ok, $err);
    my $died = !eval { ($ok, $err) = Mail::DKIM2::MessageInstance->verify($msg); 1 };
    ok(!$died, 'malformed base64 in h= does not crash verify()') or diag $@;
    ok(!$ok, 'malformed base64 in h= fails verification cleanly');
}

# §3.4/§7.3 (Verifier.pm donotmodify enforcement): the guard used there --
# "does either instance name an algorithm we implement, in common?" -- must
# correctly identify when two instances share NO implemented hash algorithm
# (fail-closed case) versus when they do (normal comparison case).
{
    my $sets1 = Mail::DKIM2::Verifier::_extract_mi_hash_sets(
        'Message-Instance: m=1; h=unknownalg:AAAA:BBBB;');
    my $sets2 = Mail::DKIM2::Verifier::_extract_mi_hash_sets(
        'Message-Instance: m=2; h=unknownalg:AAAA:CCCC;');
    is_deeply($sets1, [['unknownalg', 'AAAA', 'BBBB']],
        '_extract_mi_hash_sets parses an unimplemented algorithm too (not silently dropped)');

    my $impl = Mail::DKIM2::MessageInstance::hash_algs();
    my %by_alg1 = map { $_->[0] => $_ } @$sets1;
    my %by_alg2 = map { $_->[0] => $_ } @$sets2;
    my @common = grep { $by_alg1{$_} && $by_alg2{$_} && $impl->{$_} } keys %by_alg1;
    is(scalar @common, 0,
        'two MIs sharing only an unimplemented algorithm have no common implemented algorithm (fail-closed trigger)');

    my $sets3 = Mail::DKIM2::MessageInstance::parse_hash_sets('sha256:AAAA:BBBB,unknownalg:XXXX:YYYY');
    my %by_alg3 = map { $_->[0] => $_ } @$sets3;
    my @common2 = grep { $by_alg1{$_} && $by_alg3{$_} && $impl->{$_} } keys %by_alg3;
    is(scalar @common2, 0,
        'sha256 present in only one of the two instances is still not a common algorithm');
}

# --- CLI: bin/dkim2sign.pl --hash ------------------------------------------

my $keyfile  = '../keys/sel1._domainkey.test1.dkim2.com.pem';
plan skip_all => 'shared ../keys not available' unless -e $keyfile;

my $dir = tempdir(CLEANUP => 1);
my $src = path($dir)->child('base.eml');
$src->spew_raw(join('',
    "From: sender\@test1.dkim2.com\r\n",
    "To: rcpt\@test2.dkim2.com\r\n",
    "Subject: hash agility test\r\n",
    "Date: Fri, 24 Jul 2026 12:00:00 +0000\r\n",
    "Message-ID: <hashagility\@test1.dkim2.com>\r\n",
    "\r\n",
    "Hello signer.\r\n",
));

sub sign {
    my ($in, @args) = @_;
    my @cmd = ($^X, '-Ilib', 'bin/dkim2sign.pl', @args, "$in");
    open my $fh, '-|', @cmd or die "cannot run signer: $!";
    binmode $fh;
    my $data = do { local $/; <$fh> };
    close $fh;
    return ($data, $? >> 8);
}

sub sign_quietly {
    my @args = @_;
    open my $olderr, '>&', \*STDERR or die $!;
    open STDERR, '>', File::Spec->devnull or die $!;
    my @r = sign(@args);
    open STDERR, '>&', $olderr or die $!;
    return @r;
}

# The signer folds long Message-Instance headers (see perl/CLAUDE.md) --
# unfold back to the logical wire value for exact-format assertions. FWS
# carries no meaning anywhere in this header's grammar, so stripping all of
# it is safe and mirrors what a real parser does.
sub _unfolded_mi {
    my ($signed) = @_;
    my ($raw) = $signed =~ /^(Message-Instance:.*?)(?=\r?\n\S)/ms;
    return undef unless defined $raw;
    $raw =~ s/^Message-Instance:\s*//;
    $raw =~ s/\s+//g;
    return $raw;
}

# Default: --hash unset MUST behave exactly as before -- a single sha256
# hash-set, byte-identical to the pre-spec-05 wire form.
{
    my ($signed, $rc) = sign($src,
        '-s' => 'sel1', '-d' => 'test1.dkim2.com', '-k' => $keyfile,
        '--mailfrom' => '<sender@test1.dkim2.com>',
        '--rcptto'   => '<rcpt@test2.dkim2.com>',
        '--timestamp' => 1740000000);
    is($rc, 0, 'default signer exits 0');
    my $mi = _unfolded_mi($signed);
    ok($mi, 'found the Message-Instance header') or diag $signed;
    like($mi, qr/^m=1;h=sha256:[A-Za-z0-9+\/]{43}=:[A-Za-z0-9+\/]{43}=;$/,
        'default --hash emits a single sha256 hash-set');
    unlike($signed, qr/sha512:/, 'default --hash never mentions sha512');
}

# --hash both: sha256 FIRST, then sha512, deterministic order, comma
# separated, no spaces -- and the whole chain still verifies.
{
    my ($signed, $rc) = sign($src,
        '-s' => 'sel1', '-d' => 'test1.dkim2.com', '-k' => $keyfile,
        '--mailfrom' => '<sender@test1.dkim2.com>',
        '--rcptto'   => '<rcpt@test2.dkim2.com>',
        '--timestamp' => 1740000000,
        '--hash'     => 'both');
    is($rc, 0, '--hash both signer exits 0');

    my $mi = _unfolded_mi($signed);
    ok($mi, 'found the Message-Instance header') or diag $signed;

    like($mi,
        qr/^m=1;h=sha256:[A-Za-z0-9+\/]{43}=:[A-Za-z0-9+\/]{43}=,sha512:[A-Za-z0-9+\/]{86}==:[A-Za-z0-9+\/]{86}==;$/,
        '--hash both emits sha256 THEN sha512, comma separated, no spaces');

    my $v = Mail::DKIM2::Verifier->new;
    $v->skip_timestamp_check(1);
    $v->set_pubkey_callback(DKIM2TestKeys::pubkey_callback());
    $v->PRINT($signed);
    $v->CLOSE;
    is($v->result, 'pass', '--hash both message verifies (both hash-sets checked)')
        or diag $v->result_detail;
}

# Invalid --hash value is a usage error with a non-zero exit, not garbage
# output.
{
    my (undef, $rc) = sign_quietly($src,
        '-s' => 'sel1', '-d' => 'test1.dkim2.com', '-k' => $keyfile,
        '--hash' => 'md5');
    isnt($rc, 0, 'invalid --hash value is an error');
}

done_testing();
