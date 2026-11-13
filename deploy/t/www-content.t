#!/usr/bin/perl
# Content checks for the dkim2.com pages (deploy/www/): the things each page
# must say, so a later edit can't quietly drop the argument the site is built
# around. Structure and links are deploy/t/www-links.t's job.
use strict;
use warnings;
use utf8;
use Test::More;
use FindBin;

my $www = "$FindBin::Bin/../www";

sub slurp {
    my ($rel) = @_;
    open my $fh, '<:encoding(UTF-8)', "$www/$rel" or return undef;
    local $/;
    return scalar <$fh>;
}

# Visible text: tags stripped, common entities decoded, whitespace collapsed.
sub text {
    my ($html) = @_;
    $html =~ s/<script\b.*?<\/script>//gs;
    $html =~ s/<[^>]+>//g;
    my %ent = (amp => '&', lt => '<', gt => '>', quot => '"', nbsp => ' ',
               rsquo => "\x{2019}", lsquo => "\x{2018}", middot => "\x{b7}",
               mdash => "\x{2014}", ndash => "\x{2013}", rarr => "\x{2192}",
               darr => "\x{2193}", ouml => "\x{f6}", szlig => "\x{df}");
    $html =~ s/&(\w+);/exists $ent{$1} ? $ent{$1} : "&$1;"/ge;
    $html =~ s/\s+/ /g;
    return $html;
}

# The element whose start tag carries id="$id", up to its matching close tag.
sub section_by_id {
    my ($html, $id) = @_;
    $html =~ m{<(\w+)[^>]*\bid="\Q$id\E"[^>]*>}g or return undef;
    my ($tag, $start) = ($1, $-[0]);
    my $depth = 1;
    while ($html =~ m{<(/?)\Q$tag\E\b[^>]*>}g) {
        $depth += $1 ? -1 : 1;
        return substr($html, $start, pos($html) - $start) if $depth == 0;
    }
    return undef;
}

my $GOOD = "Good means: from who it says it\x{2019}s from, with every change "
         . "attributable to whoever made it.";

subtest home => sub {
    my $h = slurp('index.html');
    ok(defined $h, 'index.html exists') or return;
    my $t = text($h);

    like($t, qr/Shrink the grey area\./, 'tagline');

    my ($fig) = $h =~ m{(<figure class="greyarea".*?</figure>)}s;
    ok(defined $fig, 'grey-area figure') or return;
    like($fig, qr/<figcaption>/, 'grey-area figure has a caption');
    my $ft = text($fig);
    for my $s ('TODAY', 'WITH DKIM2', 'Clearly good', "Grey: can\x{2019}t tell",
               'Clearly bad',
               "forwarding \x{b7} mailing lists \x{b7} replayed signatures \x{b7} forged bounces",
               'The goal:', 'Proportions are illustrative') {
        like($ft, qr/\Q$s\E/, "grey-area figure says '$s'");
    }

    like($t, qr/\Q$GOOD\E/, 'definition of good');

    for my $d (qw(draft-ietf-dkim-replay-problem draft-ietf-dkim-dkim2-motivation
                  draft-ietf-dkim-dkim2-spec draft-ietf-dkim-dkim2-bcp
                  draft-ietf-dkim-dkim2-dns draft-gondwana-dkim2-authres
                  draft-gondwana-dkim2-debug-header draft-chuang-dkim2-sender-policy)) {
        like($h, qr{href="https://datatracker\.ietf\.org/doc/\Q$d\E/"}, "links $d");
    }

    (my $body = $h) =~ s{<nav class="site">.*?</nav>}{}s;
    like($body, qr/href="deployments\/"/, 'body links the deployments page');
    like($body, qr/href="how\/#envelope"/, 'links how/#envelope');
    like($body, qr/href="how\/#changes"/, 'links how/#changes');
    like($body, qr/href="how\/#algorithms"/, 'links how/#algorithms');

    like($h, qr{docs/dkim2-postfix-list-host-guide\.md}, 'list-host guide');
    like($h, qr{docs/dkim2-postfix-stock-mailman-guide\.md}, 'stock-Mailman guide');
};

subtest how => sub {
    my $h = slurp('how/index.html');
    ok(defined $h, 'how/index.html exists') or return;

    for my $id (qw(chain accountability changes envelope domains flags
                   algorithms keys debugging)) {
        ok(defined section_by_id($h, $id), "section #$id");
    }

    my ($chain) = $h =~ m{(<figure class="chain".*?</figure>)}s;
    ok(defined $chain, 'accountability figure') or return;
    my $ct = text($chain);
    like($ct, qr/\Q$_\E/, "chain figure says '$_'")
        for 'brand.example', 'lists.example', 'alumni.example', 'Inbox', 'exploded',
            "Every hop is on the record \x{2014} so reputation lands on whoever actually did it.";

    my ($mi) = $h =~ m{(<figure class="mi".*?</figure>)}s;
    ok(defined $mi, 'Message-Instance figure') or return;
    like(text($mi), qr/\Q$_\E/, "MI figure says '$_'") for '[EXTERNAL]', 'm=1', 'm=2', 'r=';

    my $changes = text(section_by_id($h, 'changes') // '');
    like($changes, qr/\QA hop that makes significant changes becomes the message\E\x{2019}\Qs author, and must put its own From on it.\E/,
        'From rule in #changes');
    like($changes, qr/\Q(Proposed for the next draft; not yet in the specification.)\E/,
        'From rule marked as a proposal');

    like(text(section_by_id($h, 'envelope') // ''), qr/previous hop/,
        '#envelope: control messages go back to the previous hop');
    my $alg = text(section_by_id($h, 'algorithms') // '');
    like($alg, qr/\Q$_\E/, "#algorithms names $_") for qw(RSA-SHA256 Ed25519-SHA256 ML-DSA-44);
    my $dom = text(section_by_id($h, 'domains') // '');
    unlike($dom, qr/same rule/, '#domains does not claim both matches use the same rule');
    like($dom, qr/Domain Policy Record/, '#domains: From also matches upwards unless a DPR forbids it');
    like($dom, qr/news\@example\.com\b.*d=mail\.example\.com|d=mail\.example\.com.*news\@example\.com/,
        '#domains shows the subdomain-signer case');
    like(text(section_by_id($h, 'accountability') // ''), qr/mf= sender/,
        '#accountability: mf= is the envelope sender');
    my $dbg = section_by_id($h, 'debugging') // '';
    like($dbg, qr/X-DKIM2-Info:/, '#debugging shows an X-DKIM2-Info example');
    unlike($dbg, qr/spec-06/, '#debugging example is not the stale spec-06 one');
};

subtest get_ready => sub {
    my $h = slurp('get-ready/index.html');
    ok(defined $h, 'get-ready/index.html exists') or return;
    my $t = text($h);
    like($t, qr/most of the way there/, 'reassuring headline');
    like($t, qr/SPF/, 'warns about SPF-only alignment');
    like($t, qr/f=feedback/, 'mentions f=feedback');
    my ($ol) = $h =~ m{(<ol class="steps">.*?</ol>)}s;
    ok(defined $ol, 'five steps list') or return;
    my $n = () = $ol =~ /<li>/g;
    is($n, 5, 'five steps');
};

done_testing();
