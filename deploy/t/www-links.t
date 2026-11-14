#!/usr/bin/perl
# Static-site link check for dkim2.com (deploy/www/).
#
# Every page carries the shared nav; every link between the site's pages is
# relative (so the whole site works from /preview/ as well as the web root)
# and resolves, fragment included; the anchors the old single-page site
# exposed still exist on their new page and the home page redirects them.
use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use File::Spec;
use FindBin;

my $www = File::Spec->rel2abs("$FindBin::Bin/../www");

# Pages checked. Later tasks append to this list.
my @pages = (
    'index.html',
    'try/index.html',
    'implementations/index.html',
    'how/index.html',
    'get-ready/index.html',
    'deployments/index.html.in',
    'verify/index.html',
    'validate/index.html',
    'developers/index.html',
);

# Site paths (relative to the web root, as directories) not built yet: links
# to them are not resolved. Later tasks remove entries as the pages land.
my %pending = map { $_ => 1 } qw();

my @SITE_LINKS = (
    [''                 => 'DKIM2'],
    ['how/'             => 'How it works'],
    ['get-ready/'       => 'Get ready'],
    ['try/'             => 'Try it'],
    ['implementations/' => 'Implementations'],
    ['developers/'      => 'Developers'],
    ['deployments/'     => 'Deployments'],
    ['verify/'          => 'Verify'],
);

# Which nav item each page marks as current.
my %CURRENT = (
    'index.html'                 => '',
    'how/index.html'             => 'how/',
    'get-ready/index.html'       => 'get-ready/',
    'try/index.html'             => 'try/',
    'implementations/index.html' => 'implementations/',
    'deployments/index.html.in'  => 'deployments/',
    'verify/index.html'          => 'verify/',
    'validate/index.html'        => 'verify/',
    'developers/index.html'      => 'developers/',
);

my %moved = (
    'originate'             => 'try/index.html',
    'bounces'               => 'try/index.html',
    'reflector-signing'     => 'try/index.html',
    'reflector-brand'       => 'try/index.html',
    'reflector-brand-nd'    => 'try/index.html',
    'other-implementations' => 'implementations/index.html',
);

sub slurp {
    my ($rel) = @_;
    open my $fh, '<:encoding(UTF-8)', "$www/$rel" or return undef;
    local $/;
    return scalar <$fh>;
}

sub ids {
    my ($html) = @_;
    my %i;
    $i{$1}++ while $html =~ /\bid="([^"]+)"/g;
    return \%i;
}

# The nav a page at directory $dir ('' for the root) must carry, with the
# aria-current attribute stripped.
sub expected_nav {
    my ($dir) = @_;
    my $up = $dir eq '' ? '' : '../';
    my @a = map {
        my ($path, $label) = @$_;
        my $href = $up . $path;
        $href = './' if $href eq '';
        my $class = $path eq '' ? ' class="brand"' : '';
        qq{<a$class href="$href">$label</a>};
    } @SITE_LINKS;
    my $brand = shift @a;
    return qq{<nav class="site">$brand <span class="links">} . join(' ', @a) . '</span></nav>';
}

# Resolve a relative path against a page's directory (web-root relative).
# Returns the normalised directory-or-file path, e.g. 'try/' or 'style.css'.
sub resolve {
    my ($dir, $rel) = @_;
    my @parts = grep { length } split m{/}, $dir;
    my $trailing = $rel =~ m{/$} || $rel eq '.' || $rel eq '..';
    for my $seg (split m{/}, $rel) {
        next if $seg eq '' || $seg eq '.';
        if ($seg eq '..') { return undef unless @parts; pop @parts; next }
        push @parts, $seg;
    }
    my $p = join '/', @parts;
    return $trailing ? ($p eq '' ? '' : "$p/") : $p;
}

sub target_file {
    my ($path) = @_;
    return 'index.html' if $path eq '';
    return 'deployments/index.html.in' if $path eq 'deployments/';
    return "${path}index.html" if $path =~ m{/$};
    return $path;
}

my %html;
for my $p (@pages) {
    $html{$p} = slurp($p);
    ok(defined $html{$p}, "$p exists");
}

for my $p (@pages) {
    my $h = $html{$p} // next;
    my $dir = dirname($p);
    $dir = '' if $dir eq '.';

    (my $nav) = $h =~ m{(<nav class="site">.*?</nav>)}s;
    ok(defined $nav, "$p has the site nav") or next;
    my $n = () = $nav =~ /aria-current="page"/g;
    is($n, 1, "$p marks exactly one nav item current");
    (my $bare = $nav) =~ s/ aria-current="page"//g;
    is($bare, expected_nav($dir), "$p nav is the shared nav");
    my $cur = $CURRENT{$p};
    my $cur_href = ($dir eq '' ? '' : '../') . $cur;
    $cur_href = './' if $cur_href eq '';
    like($nav, qr/<a(?: class="brand")? href="\Q$cur_href\E" aria-current="page">/,
        "$p marks $cur_href current");
    my $up = $dir eq '' ? '' : '../';
    like($h, qr/<link rel="stylesheet" href="\Q${up}nav.css\E">/, "$p loads the shared nav.css");

    unlike($h, qr/canmodify/i, "$p does not mention canmodify");

    while ($h =~ /\b(href|src)="([^"]*)"/g) {
        my $url = $2;
        next if $url =~ /^(?:https?:|mailto:)/;
        next if $url eq '#';                 # script-driven link
        $url =~ s/\?[^#]*//;                 # cache-busting query string
        if ($url =~ /^#(.+)$/) {
            ok(ids($h)->{$1}, "$p: #$1 resolves on the same page");
            next;
        }
        if ($url =~ m{^/}) {
            fail("$p: absolute link $url (would escape /preview/)");
            next;
        }
        my ($path, $frag) = split /#/, $url, 2;
        my $res = resolve($dir, $path);
        ok(defined $res, "$p: $url stays inside the site") or next;
        next if $pending{$res};
        my $file = target_file($res);
        my $target = slurp($file);
        ok(defined $target, "$p: $url -> $file exists") or next;
        ok(ids($target)->{$frag}, "$p: $url fragment exists in $file")
            if defined $frag && length $frag;
    }
}

for my $id (sort keys %moved) {
    my @on = grep { defined $html{$_} && ids($html{$_})->{$id} } @pages;
    is_deeply(\@on, [$moved{$id}], "id=\"$id\" lives only on $moved{$id}");
}

my ($script) = ($html{'index.html'} // '') =~ m{<script>(.*?)</script>}s;
ok(defined $script, 'home page has the old-anchor redirect script');
for my $id (sort keys %moved) {
    (my $dest = $moved{$id}) =~ s{index\.html$}{};
    like($script // '', qr/"\Q$id\E"\s*:\s*"\Q$dest\E"/,
        "redirect maps #$id to $dest");
}

is_deeply([sort keys %pending], [], 'every page is built: nothing pending');

done_testing();
