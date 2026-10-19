# Three-hop signed chains with big bodies: originator (m=1, i=1), a list that
# tags the Subject and wraps the body in multipart/mixed with a footer part
# (m=2, i=2), and a relay that re-signs unchanged (i=3). Test keys (dns.json).
use strict; use warnings;
use FindBin; use lib "$FindBin::Bin/../../perl/lib", "$FindBin::Bin/../../perl/t/lib";
use Email::MIME; use Mail::DKIM2::Signer; use Mail::DKIM2::MessageInstance; use DKIM2TestKeys;
my ($out, @mb) = @ARGV;
sub sign {
    my ($msg, $dom, $sel, $from, $to) = @_;
    my $s = Mail::DKIM2::Signer->new(Domain => $dom, Selector => $sel,
        Key => DKIM2TestKeys::private_key($dom, $sel), MailFrom => $from, RcptTo => [$to]);
    $s->PRINT($msg); $s->CLOSE; die $s->result_detail unless $s->result eq 'signed';
    return $s->as_string . "\r\n" . $msg;
}
for my $mb (@mb) {
    my $line = 'The quick brown fox jumps over the lazy dog, again and again and again.';
    my $body = join '', map { "$line $_\r\n" } 1 .. int($mb * 1e6 / 80);
    my $orig = "From: author\@test1.dkim2.com\r\nTo: list\@test2.dkim2.com\r\nSubject: big $mb MB\r\n"
             . "Date: Sun, 18 Oct 2026 10:00:00 +0000\r\nMessage-ID: <big$mb\@test1.dkim2.com>\r\n"
             . "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n$body";
    my $mi1 = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($orig));
    my $m1 = sign("Message-Instance: " . $mi1->as_string . "\r\n$orig",
                  'test1.dkim2.com', 'sel1', 'author@test1.dkim2.com', 'list@test2.dkim2.com');
    # The list: Subject tag, multipart wrap with a footer part.
    (my $m2 = $m1) =~ s/^Subject: /Subject: [list] /m;
    my ($h, $b) = split /\r\n\r\n/, $m2, 2;
    $h =~ s/^Content-Type: .*\r\n//m;
    $h .= "\r\nContent-Type: multipart/mixed; boundary=\"LISTB\"";
    $m2 = "$h\r\n\r\n--LISTB\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n$b"
        . "--LISTB\r\nContent-Type: text/plain\r\n\r\n-- \r\nlist footer\r\n--LISTB--\r\n";
    my $mi2 = Mail::DKIM2::MessageInstance->calculate(Email::MIME->new($m2), Email::MIME->new($m1));
    $m2 = sign("Message-Instance: " . $mi2->as_string . "\r\n$m2",
               'test2.dkim2.com', 'sel2', 'list-bounces@test2.dkim2.com', 'user@test3.dkim2.com');
    my $m3 = sign($m2, 'test3.dkim2.com', 'sel3', 'relay@test3.dkim2.com', 'user@example.org');
    open my $fh, '>:raw', sprintf("%s/big-%05.1fMB.eml", $out, $mb) or die $!; print $fh $m3;
}
