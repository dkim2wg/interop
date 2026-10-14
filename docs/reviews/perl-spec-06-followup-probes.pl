use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../perl/lib", "$FindBin::Bin/../../perl/t/lib";

use Time::HiRes qw(time);
use DKIM2SignedFixture;
use DKIM2TestKeys;
use Mail::DKIM2::Common qw(parse_dkim_key_record parse_dkim_pubkey);
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Signer;
use Mail::DKIM2::Verifier;

# These probes print the current behavior; they are evidence for review,
# not assertions that the incorrect outcomes should become regression tests.
print "F1: repeated header calculation\n";
for my $n (1000, 2000, 4000, 8000, 16000) {
    my $previous = "From: a\@example.com\r\n"
                 . ("Comments: same\r\n" x $n) . "\r\nbody\r\n";
    my $mi = Mail::DKIM2::MessageInstance->calculate($previous)->as_string;
    $previous = "Message-Instance: $mi\r\n" . $previous;
    my $current = $previous;
    $current =~ s/From:/Comments: changed\r\nFrom:/;
    my $start = time;
    Mail::DKIM2::MessageInstance->calculate($current, $previous);
    printf "  %d fields: %.3fs\n", $n, time - $start;
}

print "F2: valid long signing domain\n";
my $domain = ('a' x 40) . '.' . ('b' x 40) . '.example.com';
my $message = "From: a\@$domain\r\nTo: b\@example.net\r\n\r\nbody\r\n";
my $mi = Mail::DKIM2::MessageInstance->calculate($message);
$message = 'Message-Instance: ' . $mi->as_string . "\r\n" . $message;
my $signer = Mail::DKIM2::Signer->new(
    Domain => $domain, Selector => 'sel1',
    Key => DKIM2TestKeys::private_key('test1.dkim2.com', 'sel1'),
    MailFrom => "a\@$domain", RcptTo => ['b@example.net'],
)->load($message);
my $public_key = parse_dkim_pubkey(DKIM2TestKeys::dns_txt('test1.dkim2.com', 'sel1'));
my $verifier = Mail::DKIM2::Verifier->new(
    PubkeyCallback => sub { return $public_key },
)->load($signer->as_string . "\r\n" . $message);
print '  signer: ', $signer->result_detail, "\n";
print '  verifier: ', $verifier->result_detail, "\n";

print "F3: malformed tag specifications\n";
for my $suffix ('; junk', '; 9bad=foo') {
    my $raw = DKIM2SignedFixture::signed(mi => DKIM2SignedFixture::mi_value() . $suffix);
    print "  MI $suffix: ", DKIM2SignedFixture::verify($raw)->result_detail, "\n";
}
my $raw = DKIM2SignedFixture::signed();
# Preserve the final semicolon so the only change is the junk tag fragment.
$raw =~ s/\r\nMessage-Instance:/ junk;\r\nMessage-Instance:/;
print '  signature junk fragment: ', DKIM2SignedFixture::verify($raw)->result_detail, "\n";

print "F4: internal algorithm whitespace\n";
$raw = DKIM2SignedFixture::signed(items => [['sel1', 'rsa- sha256']]);
print '  ', DKIM2SignedFixture::verify($raw)->result_detail, "\n";

print "F5: invalid extension values in DNS key records\n";
my $record = DKIM2TestKeys::dns_txt('test1.dkim2.com', 'sel1');
for my $code (0, 127) {
    my ($key, $error) = parse_dkim_key_record($record . '; x=' . chr($code));
    print "  control $code: ", ($key ? ref($key) : $error), "\n";
}

{
    package Review::HostInput;
    sub can { die bless {}, 'Review::HostTimeout' }
}
print "F6: foreign exception during load capability lookup\n";
eval { Mail::DKIM2::Verifier->new->load(bless {}, 'Review::HostInput') };
my $exception = $@;
print '  exception type: ', (ref($exception) || 'string'), "\n";
print "  $exception" unless ref($exception);
