#!/usr/bin/perl
# usage: off-identical.pl BUILD_LIB [FILE.eml ...]
#
# Runs each input, plus the adversarial review's inputs built in below,
# through a Sympa build (BUILD_LIB = its src/lib) with
# dkim2_message_instance off: ingress, the spool round trip, decorate with
# footer_type mime and then append, egress.  Prints one line per input:
# name, sha256 of as_string after the mime decoration, then after append.
# On stock Sympa, where Sympa::DKIM2 does not exist, the DKIM2 calls are
# skipped.  Run once per build and diff the outputs: switch-off must be
# byte-identical to stock.
use strict;
use warnings;
BEGIN {
    die "usage: $0 BUILD_LIB [FILE...]\n" unless @ARGV and -d $ARGV[0];
    unshift @INC, shift @ARGV;
}
use Digest::SHA qw(sha256_hex);
use File::Temp qw(tempdir);
use MIME::Base64 qw(encode_base64);
use Conf;
use Sympa::ConfDef;
use Sympa::Log;
use Sympa::Message;

my $dkim2 = eval { require Sympa::DKIM2; 1 };
print STDERR "Sympa::DKIM2 ", ($dkim2 ? 'present' : 'absent (stock)'), "\n";

# The same stubbed list and Conf bootstrap as Sympa's t/DKIM2.t.
Sympa::Log->instance->{log_to_stderr} = 'err';
%Conf::Conf = (domain => 'mail.example.org', listmaster => 'lm@example.org',
               tmpdir => tempdir(CLEANUP => 1));
for my $p (grep { $_->{name} and exists $_->{default} } @Sympa::ConfDef::params) {
    $Conf::Conf{$p->{name}} //= $p->{default};
}
my %FILES;
my $fdir = tempdir(CLEANUP => 1);
for ([message_header => "header text\n"],
     [message_footer => "-- \nList footer, Euro \xe2\x82\xac\n"],
     [message_global_footer => "global footer\n"]) {
    my ($n, $c) = @$_;
    open my $f, '>:raw', "$fdir/$n" or die "$fdir/$n: $!";
    print $f $c;
    close $f;
    $FILES{$n} = "$fdir/$n";
}
my $bcount;
{
    no warnings qw(redefine once);
    *Sympa::search_fullpath   = sub { $FILES{$_[1]} };
    *Sympa::List::update_stats = sub { 1 };
    # Stock boundaries hold the time and pid; make them a per-input count.
    *MIME::Entity::make_boundary = sub { sprintf '----------=_off-%d', $bcount++ };
}
sub list {
    my %a = @_;
    bless {name => 'test', domain => 'mail.example.org',
        admin => {dkim2_message_instance => 'off', %a}} => 'Sympa::List';
}

# Ingress, spool round trip, decorate, egress; sha256 of as_string.
sub run_one {
    my ($raw, $footer_type) = @_;
    $bcount = 0;
    my $l = list(footer_type => $footer_type);
    my $m = Sympa::Message->new($raw, context => $l) or return 'unparsable';
    Sympa::DKIM2::ingress($m) if $dkim2;
    my $b = Sympa::Message->new($m->to_string, context => $l)
        or return 'spool-unparsable';
    my $ctx = $dkim2 ? Sympa::DKIM2::egress_context($b) : undef;
    my $one = $b->dup;
    $one->decorate($l, undef);
    Sympa::DKIM2::egress_add($one, $ctx, body_rewritten => 0) if $dkim2;
    return sha256_hex($one->as_string);
}

# The review's inputs (scratchpad exp/ e1, e3, e4, e6, e7, e9, e10, e13, e15).
sub review_inputs {
    my $hdr = "From: Alice <a\@example.com>\nTo: test\@mail.example.org\nSubject: hello\nMessage-ID: <%s\@example.com>\nDate: Mon, 5 Oct 2026 10:00:00 +0000\nMIME-Version: 1.0\n";
    my $msg = sub { sprintf($hdr, $_[0]) . $_[1] };
    my $alt = "Content-Type: multipart/alternative; boundary=\"ALT\"\n\n--ALT\nContent-Type: text/plain; charset=us-ascii\n\nplain part\n--ALT\nContent-Type: text/html; charset=us-ascii\n\n<html><body><p>html part</p></body></html>\n--ALT--\n";
    my $mixed = "Content-Type: multipart/mixed; boundary=\"MIX\"\n\n--MIX\nContent-Type: text/plain; charset=us-ascii\n\nbody text\n--MIX\nContent-Type: application/pdf; name=\"a.pdf\"\nContent-Disposition: attachment; filename=\"a.pdf\"\nContent-Transfer-Encoding: base64\n\n" . encode_base64("PDFDATA" x 50) . "--MIX--\n";
    my $signed = "Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"SIG\"\n\n--SIG\nContent-Type: text/plain; charset=us-ascii\n\nsigned text\n--SIG\nContent-Type: application/pgp-signature\n\n-----BEGIN PGP SIGNATURE-----\nAAAA\n-----END PGP SIGNATURE-----\n--SIG--\n";
    my $txt  = join '', map { "line $_ with caf\xc3\xa9 text\n" } 1 .. 40;
    my $html = "<html><body>" . join('', map { "<p>para $_ caf&eacute;</p>\n" } 1 .. 200) . "</body></html>\n";
    my $p = "From: a\@example.com\nTo: test\@mail.example.org\nSubject: s\nMessage-ID: <s\@x>\nMIME-Version: 1.0\n";
    return (
        ['review-plain-7bit', $msg->('c1', "Content-Type: text/plain; charset=us-ascii\n\nhello\n")],
        ['review-no-final-newline', $msg->('c2', "Content-Type: text/plain; charset=us-ascii\n\nhello")],
        ['review-crlf', $msg->('c3', "Content-Type: text/plain; charset=us-ascii\n\nhello\n") =~ s/\n/\r\n/gr],
        ['review-latin1-8bit', $msg->('c4', "Content-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: 8bit\n\ncaf\xe9\n")],
        ['review-alternative', $msg->('c6', $alt)],
        ['review-mixed-pdf', $msg->('c7', $mixed)],
        ['review-pgp-mime', $msg->('c8', $signed)],
        ['review-html-only', $msg->('c9', "Content-Type: text/html; charset=us-ascii\n\n<html><body>hi</body></html>\n")],
        ['review-empty-body', $msg->('c11', "Content-Type: text/plain\n\n")],
        ['review-long-line', $msg->('c12', "Content-Type: text/plain\n\n" . ("X" x 1200) . "\n")],
        ['review-image-only', $msg->('c13', "Content-Type: image/png\nContent-Transfer-Encoding: base64\n\n" . encode_base64("\x89PNG" . ("x" x 300)))],
        ['review-odd-folding', $msg->('c14', "X-Foo: a\nReferences: <a\@b>\n\t<c\@d>\n   <e\@f>\nContent-Type: text/plain\n\nhello\n")],
        ['review-keywords-nospace', $msg->('c15', "Keywords:abc\nContent-Type: text/plain\n\nhello\n")],
        ['review-bcc', $msg->('c16', "Bcc: secret\@example.com\nContent-Type: text/plain\n\nhello\n")],
        ['review-dot-lines', $msg->('c17', "Content-Type: text/plain\n\n.\n..\nFrom me\n")],
        ['review-trailing-blanks', $msg->('c18', "Content-Type: text/plain\n\nhello\n\n\n\n")],
        ['review-bare-cr', $msg->('c19', "Content-Type: text/plain\n\nhel\rlo\n")],
        ['review-qp', "${p}Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\nCaf=C3=A9 au lait, 1+1=3D2. This is a long line that goes past the soft br=\neak boundary so QP had to wrap it.\n"],
        ['review-us-ascii', "${p}Content-Type: text/plain; charset=us-ascii\n\nplain ascii\n"],
        ['review-upstream-mi', "Message-Instance: m=1; h=sha256:x:y;\n${p}Content-Type: text/plain; charset=utf-8\n\nhello\n"],
        ['review-anonymous-shape', "From: Whistle Blower <whistle\@corp.example>\nOrganization: Corp Inc\nTo: anon\@mail.example.org\nSubject: leak\nMessage-ID: <secret-id\@corp.example>\nMIME-Version: 1.0\nContent-Type: text/plain\n\nthe documents\n"],
        ['review-big-attachment', "${p}Content-Type: multipart/mixed; boundary=B\n\n--B\nContent-Type: text/plain\n\nsee attached\n--B\nContent-Type: application/octet-stream; name=a.bin\nContent-Disposition: attachment; filename=a.bin\nContent-Transfer-Encoding: base64\n\n" . encode_base64(join '', map { chr(($_ * 7919) % 256) } 1 .. 30000) . "--B--\n"],
        ['review-alternative-b64', "${p}Content-Type: multipart/alternative; boundary=ALT\n\n--ALT\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: base64\n\n" . encode_base64($txt) . "--ALT\nContent-Type: text/html; charset=utf-8\n\n$html--ALT--\n"],
    );
}

my @inputs;
for my $f (@ARGV) {
    open my $fh, '<:raw', $f or die "$f: $!";
    (my $name = $f) =~ s{.*/}{};
    push @inputs, [$name, do { local $/; <$fh> }];
}
push @inputs, review_inputs();
for (@inputs) {
    my ($name, $raw) = @$_;
    print join("\t", $name, map { run_one($raw, $_) } qw(mime append)), "\n";
}
