use strict; use warnings;
use Test::More;
use lib 'lib';
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Common qw(parse_mime);

my $orig_body = "line one\r\nline two\r\n";
my $prev = "From: a\@example.com\r\nSubject: hi\r\n\r\n$orig_body";
my $m1 = Mail::DKIM2::MessageInstance->calculate($prev);
my $mi1 = "Message-Instance: " . $m1->as_string . "\r\n";
$prev = $mi1 . $prev;

# Wrapped body: 2 preamble lines, original at lines 3-4, 1 trailer line.
my $cur = $mi1 . "From: a\@example.com\r\nSubject: [list] hi\r\n\r\n"
        . "pre1\r\npre2\r\n$orig_body" . "post\r\n";

my $headers_only_prev = $prev; $headers_only_prev =~ s/\r\n\r\n.*\z/\r\n\r\n/s;

subtest 'array Recipe, previous body ignored' => sub {
    my $mi = Mail::DKIM2::MessageInstance->calculate($cur, $headers_only_prev,
        BodyRecipe => [[3, 4]]);
    like $mi->as_string, qr/^m=2; /, 'm=2';
    my $msg = "Message-Instance: " . $mi->as_string . "\r\n" . $cur;
    my ($ok, $err) = Mail::DKIM2::MessageInstance->chain_verifies($msg);
    ok $ok, 'chain verifies' or diag $err;

    # empty original body
    my $e1 = "From: a\@example.com\r\n\r\n";
    my $em1 = Mail::DKIM2::MessageInstance->calculate($e1);
    my $ehdr = "Message-Instance: " . $em1->as_string . "\r\n";
    my $ecur = $ehdr . "From: a\@example.com\r\n\r\nwrapped\r\n";
    my $emi = Mail::DKIM2::MessageInstance->calculate($ecur, $ehdr . $e1,
        BodyRecipe => []);
    my $p = Mail::DKIM2::MessageInstance->parse($emi->as_string);
    is_deeply $p->{bits}{rb}, [], 'empty b recipe';
    ($ok, $err) = Mail::DKIM2::MessageInstance->chain_verifies(
        "Message-Instance: " . $emi->as_string . "\r\n" . $ecur);
    ok $ok, 'empty-body chain verifies' or diag $err;
};

subtest 'null' => sub {
    my $mi = Mail::DKIM2::MessageInstance->calculate($cur, $headers_only_prev,
        BodyRecipe => 'null');
    my $p = Mail::DKIM2::MessageInstance->parse($mi->as_string);
    ok $p->unrecoverable, 'b is null';
};

subtest 'none' => sub {
    my $same = $cur; $same =~ s/\r\n\r\n.*\z/\r\n\r\n$orig_body/s;
    my $mi = Mail::DKIM2::MessageInstance->calculate($same, $headers_only_prev,
        BodyRecipe => 'none');
    ok !exists Mail::DKIM2::MessageInstance->parse($mi->as_string)->{bits}{rb},
        'no b key';
    my $msg = "Message-Instance: " . $mi->as_string . "\r\n" . $same;
    my ($ok, $err) = Mail::DKIM2::MessageInstance->chain_verifies($msg);
    ok $ok, 'chain verifies' or diag $err;
};

subtest 'malformed BodyRecipe croaks' => sub {
    for my $bad ([[0, 1]], [[3, 2]], [[3, 4], [1, 2]], {}, 'bogus') {
        eval { Mail::DKIM2::MessageInstance->calculate($cur, $headers_only_prev,
            BodyRecipe => $bad) };
        ok $@, 'croaks on ' . (ref $bad ? 'ref' : $bad);
    }
};

subtest 'body_hash and body_digest_raw' => sub {
    for my $b ("a\nb\n", "a\r\nb\r\n", "a\nb", "", "\n\n\n", "x\r\n\r\n") {
        (my $crlf = $b) =~ s/\r?\n/\r\n/g;
        my $want = Mail::DKIM2::MessageInstance::b_digest(parse_mime("H: v\r\n\r\n$crlf"));
        is(Mail::DKIM2::MessageInstance::body_digest_raw($b), $want, 'digest matches');
    }
    is(Mail::DKIM2::MessageInstance->parse($m1->as_string)->body_hash,
       Mail::DKIM2::MessageInstance::b_digest(parse_mime($prev)), 'body_hash');
};

done_testing;
