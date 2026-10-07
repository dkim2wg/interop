#!/usr/bin/perl
# A null body Recipe ("b": null) loses the previous body, not the header
# history: every lower instance's header hashes are still checked, by undoing
# header Recipes only, down to m=1.
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Mail::DKIM2::MessageInstance;

my $MI = 'Mail::DKIM2::MessageInstance';
my $EOL = "\r\n";

sub with_mi { my ($mi, $msg) = @_; "Message-Instance: " . $mi->as_string . $EOL . $msg }

my $orig = join($EOL, 'From: a@example.com', 'To: list@example.org',
    'Subject: hello', 'Message-ID: <x@example.com>', '', 'body one', 'body two', '');
my $m1 = with_mi($MI->calculate($orig), $orig);

# m=2: the list prefixed the Subject and rewrote the body; body Recipe null.
sub list_hop {
    my ($prev, $tag) = @_;
    my $cur = $prev;
    $cur =~ s/^Subject: /Subject: [$tag] /m;
    $cur .= "rewritten by $tag$EOL";
    my $mi = $MI->calculate($cur, $prev);
    $mi->set_null_body_recipe;
    return with_mi($mi, $cur);
}

{
    my $m2 = list_hop($m1, 'list');
    my ($ok, $why) = $MI->chain_verifies($m2);
    ok($ok, 'null at m=2 over m=1: header history verifies') or diag $why;
}

# A forged history: the list changed To as well as Subject, but its header
# Recipe hides the To change. The top instance matches the message; only
# undoing it shows m=1's header hash no longer matches. DKIM2-Signatures
# cover only Message-Instance and DKIM2-Signature fields (§9.6), so
# nothing else catches this.
sub forge_history {
    my ($prev) = @_;
    my $cur = $prev;
    $cur =~ s/^Subject: /Subject: [list] /m;
    $cur =~ s/^To: list\@example\.org/To: other\@example.org/m;
    $cur .= "rewritten$EOL";
    my $mi = $MI->calculate($cur, $prev);
    $mi->set_null_body_recipe;
    my $rh = $mi->{bits}{rh};
    delete $rh->{$_} for grep { lc($_) eq 'to' } keys %$rh;
    return with_mi($mi, $cur);
}

{
    my ($ok, $why) = $MI->chain_verifies(forge_history($m1));
    ok(!$ok, 'header changed below a null body Recipe is caught');
    like($why // '', qr/m=1 does not match content.*header hash/, 'reason names m=1 header hash');
}

{
    # null at m=3 over a normal m=2 over m=1
    my $cur2 = $m1; $cur2 =~ s/^Subject: /Subject: [fwd] /m;
    my $m2 = with_mi($MI->calculate($cur2, $m1), $cur2);
    my $m3 = list_hop($m2, 'list');
    my ($ok, $why) = $MI->chain_verifies($m3);
    ok($ok, 'null at m=3 over recipe m=2 over m=1 verifies') or diag $why;
}

{
    # A body Recipe below the null must not be applied (the body it would
    # apply to is gone): m=2 appends a footer with a real body Recipe, m=3
    # rewrites the body with a null one.
    my $cur2 = $m1 . "footer$EOL";
    my $m2 = with_mi($MI->calculate($cur2, $m1), $cur2);
    my $m3 = list_hop($m2, 'list');
    my ($ok, $why) = $MI->chain_verifies($m3);
    ok($ok, 'body Recipe below a null instance is skipped, headers still checked') or diag $why;
}

{
    # verify / undo HeadersOnly directly
    my $m2 = list_hop($m1, 'list');
    my $prev = $MI->undo($m2, HeadersOnly => 1);
    ok($prev, 'undo HeadersOnly returns a message');
    like($prev->body_raw, qr/rewritten by list/, 'body left as it is (not rebuilt)');
    is(scalar $MI->verify($prev, HeadersOnly => 1), 1, 'verify HeadersOnly passes m=1 on header history');
    is(scalar $MI->verify($prev), 0, 'full verify fails m=1 (body differs)');
}

use lib "$FindBin::Bin/lib";
use Mail::DKIM2::Signer;
use Mail::DKIM2::Verifier;
use DKIM2TestKeys;

sub sign_i1 {
    my ($msg) = @_;
    my $s = Mail::DKIM2::Signer->new(
        Domain => 'test1.dkim2.com', Selector => 'rsa1024',
        Key => DKIM2TestKeys::private_key('test1.dkim2.com', 'rsa1024'),
        MailFrom => 'a@test1.dkim2.com', RcptTo => ['list@test2.dkim2.com'],
        Timestamp => 1740000000);
    $s->PRINT($msg); $s->CLOSE;
    return $s->as_string . $EOL . $msg;
}

sub verifier_result {
    my ($msg) = @_;
    my $v = Mail::DKIM2::Verifier->new;
    $v->allow_unsigned_mi(1);
    $v->skip_timestamp_check(1);
    $v->set_pubkey_callback(DKIM2TestKeys::pubkey_callback());
    $v->PRINT($msg); $v->CLOSE;
    return $v->result_detail;
}

{
    my $signed = sign_i1($m1);
    my $m2 = list_hop($signed, 'list');
    like(verifier_result($m2), qr/^pass/, 'Verifier: null body over signed m=1 passes');

    my $forged = forge_history($signed);
    like(verifier_result($forged), qr/^fail.*m=1 does not match content/, 'Verifier: tampered history below null fails on m=1');
}

done_testing;
