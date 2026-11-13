#!/usr/bin/perl
# deploy/bin/build-deployments.pl: builds /deployments/ from one JSON file per
# service (deployments/sites/) or software product (deployments/software/),
# and refuses -- naming the file, writing nothing -- on any bad entry.
use strict;
use warnings;
use utf8;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use File::Basename qw(dirname);
use Encode ();
use FindBin;

my $root   = "$FindBin::Bin/../..";
my $script = "$root/deploy/bin/build-deployments.pl";

my $TEMPLATE = <<'HTML';
<html><body>
<h2 id="services">Services</h2>
<!-- SITES -->
<h2 id="software">Software</h2>
<!-- SOFTWARE -->
</body></html>
HTML

# Build a data dir from { relpath => content } and run the script on it.
# Returns (exit code, stderr, output html or undef, temp file left behind?).
sub run_build {
    my (%files) = @_;
    my $dir = tempdir(CLEANUP => 1);
    make_path("$dir/data/sites", "$dir/data/software");
    for my $rel (keys %files) {
        my $p = "$dir/data/$rel";
        make_path(dirname($p));
        open my $fh, '>:raw', $p or die;
        print $fh $files{$rel};
        close $fh;
    }
    open my $t, '>', "$dir/tmpl.html" or die;
    print $t $TEMPLATE;
    close $t;
    my $out = "$dir/out/index.html";
    make_path("$dir/out");
    my $stderr = `"$^X" "$script" --data "$dir/data" --template "$dir/tmpl.html" --out "$out" 2>&1 >/dev/null`;
    my $code = $? >> 8;
    my $html = -e $out ? do { local (@ARGV, $/) = ($out); <> } : undef;
    $html = Encode::decode('UTF-8', $html) if defined $html;
    return ($code, $stderr, $html, (-e "$out.tmp" ? 1 : 0));
}

sub entry {
    my (%f) = (name => 'Example', url => 'https://example.com/',
               kind => 'mailbox provider', signs => 'true', verifies => 'false', @_);
    my @kv;
    for my $k (sort keys %f) {
        next unless defined $f{$k};
        my $v = $f{$k};
        $v = qq{"$v"} unless $v =~ /^(?:true|false|null)$/;
        push @kv, qq{"$k": $v};
    }
    return '{' . join(', ', @kv) . "}\n";
}

sub table_of {
    my ($html, $marker_id) = @_;
    my ($t) = $html =~ m{id="$marker_id".*?(<table.*?</table>)}s;
    return $t // '';
}

subtest valid_builds => sub {
    my ($code, undef, $html) = run_build(
        'sites/a.json' => entry(name => 'Alpha', since => '2026-11'),
        'sites/b.json' => entry(name => 'Bravo', since => '2026-09', verifies => 'true',
                                source => 'https://mailarchive.ietf.org/arch/msg/x'),
        'sites/c.json' => entry(name => 'Charlie', since => undef),
        'software/s.json' => entry(name => 'Serverware', kind => 'mail server'),
    );
    is($code, 0, 'exit 0') or return;
    ok(defined $html, 'page written') or return;
    my $sites = table_of($html, 'services');
    my $soft  = table_of($html, 'software');
    my @order = $sites =~ /<td class="name"><a [^>]*>(\w+)</g;
    is_deeply(\@order, [qw(Bravo Alpha Charlie)], 'dated by since, undated last');
    like($sites, qr{Charlie.*?<td class="since">\x{2014}</td>}s, 'undated shows a dash');
    like($sites, qr{Bravo.*?<td class="since"><a href="https://mailarchive\.ietf\.org/arch/msg/x">2026-09</a></td>}s,
        'since links to the source');
    like($sites, qr{Alpha.*?<td class="since">2026-11 <small>reported to us</small></td>}s,
        'no source: reported to us');
    like($sites, qr{Bravo</a></td>\s*<td[^>]*>[^<]*</td>\s*<td class="yes">\x{2713}</td>\s*<td class="yes">\x{2713}</td>}s,
        'true renders a tick');
    like($sites, qr{Alpha</a></td>\s*<td[^>]*>[^<]*</td>\s*<td class="yes">\x{2713}</td>\s*<td></td>}s,
        'false renders an empty cell');
    like($soft, qr/Serverware/, 'software entry in the software table');
    unlike($sites, qr/Serverware/, 'software entry not in the services table');
    unlike($html, qr/<!-- (?:SITES|SOFTWARE) -->/, 'markers replaced');
};

subtest escapes_html => sub {
    my ($code, undef, $html) = run_build(
        'sites/x.json' => qq({"name": "1&1 <x>", "url": "https://example.com/", "kind": "k", "signs": true, "verifies": false, "notes": "say \\"q\\""}\n),
    );
    is($code, 0, 'exit 0') or return;
    like($html, qr/1&amp;1 &lt;x&gt;/, 'name escaped');
    like($html, qr/say &quot;q&quot;/, 'notes escaped');
    unlike($html, qr/<x>/, 'no raw markup');
};

my %bad = (
    unknown_key   => ['sites/a.json', entry(foo => 'bar')],
    missing_kind  => ['sites/a.json', entry(kind => undef)],
    signs_string  => ['sites/a.json', entry(signs => 'yes')],
    since_day     => ['sites/a.json', entry(since => '2026-11-11')],
    since_month13 => ['sites/a.json', entry(since => '2026-13')],
    url_js        => ['sites/a.json', entry(url => 'javascript:alert(1)')],
    url_http      => ['sites/a.json', entry(url => 'http://x.example/')],
    source_http   => ['software/a.json', entry(source => 'http://x.example/')],
    invalid_json  => ['sites/a.json', "{ not json\n"],
    bad_filename  => ['sites/Fastmail.json', entry()],
    not_an_object => ['sites/a.json', "[1, 2]\n"],
);
for my $case (sort keys %bad) {
    subtest "rejects_$case" => sub {
        my ($rel, $content) = @{ $bad{$case} };
        my ($code, $stderr, $html, $tmp) = run_build(
            'sites/good.json' => entry(name => 'Good'),
            $rel => $content,
        );
        is($code, 1, 'exit 1');
        like($stderr, qr/\Q$rel\E/, 'error names the file');
        ok(!defined $html, 'nothing written');
        ok(!$tmp, 'no temp file left');
    };
}

subtest ignores_non_json => sub {
    my ($code, $stderr) = run_build(
        'sites/a.json'    => entry(),
        'sites/notes.txt' => "hello\n",
        'sites/a.json~'   => "{ junk\n",
        'sites/.DS_Store' => "\0\1\2",
    );
    is($code, 0, 'exit 0') or diag $stderr;
};

subtest repo_data_valid => sub {
    my $out = `"$^X" "$script" --data "$root/deploy/www/deployments" --check 2>&1`;
    is($? >> 8, 0, 'repo deployment data passes --check') or diag $out;
};

done_testing();
