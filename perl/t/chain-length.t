#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/lib";
use Mail::DKIM2::Common qw(MAX_CHAIN_LENGTH);
use Mail::DKIM2::Signer;
use Mail::DKIM2::Verifier;
use Mail::DKIM2::MessageInstance;
use Email::MIME;
use DKIM2TestKeys;

# A chain of MAX_CHAIN_LENGTH hops verifies as usual. One more Message-Instance
# or DKIM2-Signature field is a PERMERROR found from the headers alone: no key
# is fetched, no signature checked, no recipe applied, and the body is not
# kept.

my $TIMESTAMP = 1740000000;
my $DOMAIN    = 'test1.dkim2.com';
my $SELECTOR  = 'sel1';
my $ADDRESS   = 'hop@test1.dkim2.com';

sub signer {
    return Mail::DKIM2::Signer->new(
        Domain    => $DOMAIN,
        Selector  => $SELECTOR,
        Key       => DKIM2TestKeys::private_key($DOMAIN, $SELECTOR),
        MailFrom  => $ADDRESS,
        RcptTo    => [$ADDRESS],
        Timestamp => $TIMESTAMP,
    );
}

sub sign_hop {
    my ($text) = @_;
    my $signer = signer();
    $signer->PRINT($text);
    $signer->CLOSE;
    (my $header = $signer->as_string) =~ s/\r?\n\z//;
    return "$header\r\n$text";
}

# $more is fed after the message, as a later chunk would be.
sub verify {
    my ($text, $more) = @_;
    my $lookups = 0;
    my $callback = DKIM2TestKeys::pubkey_callback();
    my $v = Mail::DKIM2::Verifier->new;
    $v->set_pubkey_callback(sub { $lookups++; $callback->(@_) });
    $v->skip_timestamp_check(1);
    $v->PRINT($text);
    $v->PRINT($more) if defined $more;
    $v->CLOSE;
    return ($v, $lookups);
}

# Every hop adds a body line, a Message-Instance recording how to undo it, and
# a signature.
my $text = join("\r\n",
    'From: sender@test1.dkim2.com',
    'To: hop@test1.dkim2.com',
    'Subject: a long chain',
    '',
    'original body',
    '',
);
my $mi = Mail::DKIM2::MessageInstance->calculate($text);
$text = sign_hop("Message-Instance: " . $mi->as_string . "\r\n$text");
for my $hop (2 .. MAX_CHAIN_LENGTH) {
    my $previous = Email::MIME->new($text);
    my $current  = Email::MIME->new($text);
    $current->body_set($current->body_raw . "hop $hop\r\n");
    my $next = Mail::DKIM2::MessageInstance->calculate($current, $previous);
    $current->header_raw_prepend('Message-Instance', $next->as_string);
    $text = sign_hop($current->as_string);
}

{
    my ($v) = verify($text);
    is($v->result, 'pass', MAX_CHAIN_LENGTH . ' hops verify')
        or diag($v->details);
    my ($ok, $why) = Mail::DKIM2::MessageInstance->chain_verifies($text);
    ok($ok, MAX_CHAIN_LENGTH . ' instances undo cleanly') or diag($why);
}

{
    my $signer = signer();
    ok(!eval { $signer->PRINT($text); $signer->CLOSE; 1 },
        'the signer will not add signature ' . (MAX_CHAIN_LENGTH + 1));
    like($@, qr/^cannot sign: PERMERROR more than 32 DKIM2-Signature fields/,
        '... and says why');

    my $current = Email::MIME->new($text);
    ok(!eval {
        Mail::DKIM2::MessageInstance->calculate($current, Email::MIME->new($text));
        1;
    }, 'calculate will not add instance ' . (MAX_CHAIN_LENGTH + 1));
}

# Adding a copy of the top field is enough to go over: the limit counts fields
# as they appear, whatever their i= or m=.
my ($top_sig) = $text =~ /\A(DKIM2-Signature:.*?\r\n)(?=\S)/s;
my ($top_mi)  = $text =~ /^(Message-Instance:.*?\r\n)(?=\S)/ms;

{
    my ($v, $lookups) = verify($top_sig . $text, "more body\r\n");
    is($v->result, 'permerror', 'one signature too many is a permerror');
    is($v->details, 'PERMERROR more than 32 DKIM2-Signature fields',
        '... naming the field');
    is($lookups, 0, '... with no key fetched');
    ok($v->stopped, '... and nothing more read');
    is($v->{_buf}, '', '... or kept');
}

{
    my $long = $top_mi . $text;
    my ($v, $lookups) = verify($long);
    is($v->result, 'permerror', 'one instance too many is a permerror');
    is($v->details, 'PERMERROR more than 32 Message-Instance fields',
        '... naming the field');
    is($lookups, 0, '... with no key fetched');

    my ($ok, $why) = Mail::DKIM2::MessageInstance->chain_verifies($long);
    ok(!$ok, 'chain_verifies refuses it');
    is($why, 'PERMERROR more than 32 Message-Instance fields', '... and says why');

    ok(!Mail::DKIM2::MessageInstance->verify($long), 'verify refuses it');
    ok(!eval { Mail::DKIM2::MessageInstance->undo($long); 1 },
        'undo refuses it');
    like($@, qr/^PERMERROR more than 32 Message-Instance fields/, '... and says why');
}

{
    my ($v, $lookups) = verify(join q{}, ($top_sig) x 1000, $text);
    is($v->details, 'PERMERROR more than 32 DKIM2-Signature fields',
        'a thousand signatures are refused the same way');
    is($lookups, 0, '... with no key fetched');
}

done_testing;
