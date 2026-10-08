#!/usr/bin/perl
# Mail::DKIM2::Gate: a null body Recipe on the top Message-Instance is refused
# (without AllowNullBodyRecipe) only when no DKIM2-Signature covers that
# instance, i.e. none has m= equal to the top m=.  That is a null THIS hop
# would introduce.  A null top that the upstream domain declared and signed
# (a list host's signed post, forwarded unchanged) is extended normally.
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/lib";
use lib "$FindBin::Bin/../lib";
use Email::MIME;
use Mail::DKIM2::Gate;
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Signer;
use DKIM2TestKeys;

my $EOL = "\015\012";
my $PLAIN = join($EOL,
    'MIME-Version: 1.0',
    'Message-Id: <post@test1.dkim2.com>',
    'Date: Thu, 10 Sep 2026 15:47:11 +1000',
    'From: Author <author@test1.dkim2.com>',
    'To: list@test2.dkim2.com',
    'Subject: a post',
    'Content-Type: text/plain',
    '',
    'hello list',
    '');

sub sign_as {
    my ($msg, $dom, $mf, $rt) = @_;
    my $s = Mail::DKIM2::Signer->new(
        Domain => $dom, Selector => 'sel1',
        Key => DKIM2TestKeys::private_key($dom, 'sel1'),
        MailFrom => $mf, RcptTo => [$rt], Timestamp => time());
    $s->PRINT($msg); $s->CLOSE;
    return $s->as_string . $EOL . $msg;
}

# i=1/m=1 by test1, then the list test2 tags the subject and rewrites the
# body, recording m=2 with a null body Recipe.  m=2 is unsigned here.
sub null_list_post {
    my (%o) = @_;
    my $mi = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($PLAIN));
    my $signed = sign_as("Message-Instance: " . $mi->as_string . $EOL . $PLAIN,
        'test1.dkim2.com', 'author@test1.dkim2.com', 'list@test2.dkim2.com');
    my $mod = $signed;
    $mod =~ s/^Subject: /Subject: [list] /m;
    $mod =~ s/^To: .*$/To: tampered\@example.net/m if $o{forge};
    $mod .= "--$EOL" . "rewritten$EOL";
    my $mi2 = Mail::DKIM2::MessageInstance->calculate(
        Email::MIME->new($mod), Email::MIME->new($signed));
    $mi2->set_null_body_recipe;
    if ($o{forge}) {
        my $rh = $mi2->{bits}{rh};
        delete $rh->{$_} for grep { lc($_) eq 'to' } keys %$rh;
    }
    return "Message-Instance: " . $mi2->as_string . $EOL . $mod;
}

# ... and the list domain signs its own m=2 (i=2, m=2) to the forwarder.
sub signed_null_list_post {
    return sign_as(null_list_post(@_), 'test2.dkim2.com',
        'list-bounces@test2.dkim2.com', 'subscriber@test3.dkim2.com');
}

my %cb = (PubkeyCallback => DKIM2TestKeys::pubkey_callback());

{
    my $msg = null_list_post();
    my $g = Mail::DKIM2::Gate->check($msg, %cb);
    ok(!$g->{ok}, 'unsigned null top: refused by default');
    is($g->{reason}, 'null-body-recipe', 'unsigned null top: reason null-body-recipe');
    like($g->{message}, qr/unsigned top Message-Instance m=2 has a null body Recipe/,
        'unsigned null top: message says the null top is unsigned');
    is($g->{top_null}, 1, 'unsigned null top: top_null');
    is($g->{top_signed}, 0, 'unsigned null top: top_signed is 0 (i=1 covers only m=1)');
    $g = Mail::DKIM2::Gate->check($msg, %cb, AllowNullBodyRecipe => 1);
    ok($g->{ok}, 'unsigned null top: signed with AllowNullBodyRecipe');
}

{
    my $msg = signed_null_list_post();
    like($msg, qr/^DKIM2-Signature: i=2; m=2;/m, 'fixture: the list signed m=2');
    my $g = Mail::DKIM2::Gate->check($msg, %cb, SigningDomain => 'test3.dkim2.com');
    ok($g->{ok}, 'signed null top: extended without the option')
        or diag($g->{message});
    is($g->{top_null}, 1, 'signed null top: top_null still reported');
    is($g->{top_signed}, 1, 'signed null top: top_signed');
    $g = Mail::DKIM2::Gate->check($msg, %cb, AllowNullBodyRecipe => 1);
    ok($g->{ok}, 'signed null top: and with the option');
}

{
    # Signed or not, the header history below the null must still check out.
    my $g = Mail::DKIM2::Gate->check(signed_null_list_post(forge => 1), %cb);
    ok(!$g->{ok}, 'signed forged null top: refused');
    isnt($g->{reason} // '', 'null-body-recipe', 'signed forged null top: for the chain, not the null');
    $g = Mail::DKIM2::Gate->check(signed_null_list_post(forge => 1), %cb,
        AllowNullBodyRecipe => 1);
    ok(!$g->{ok}, 'signed forged null top: refused even with the option');
}

done_testing;
