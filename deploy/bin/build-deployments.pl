#!/usr/bin/perl
# Build dkim2.com's /deployments/ page from one JSON file per entry.
#
#   build-deployments.pl --data DIR --template FILE --out FILE
#   build-deployments.pl --data DIR --check
#
# DIR/sites/*.json     services running DKIM2       -> <!-- SITES -->
# DIR/software/*.json  software that supports DKIM2 -> <!-- SOFTWARE -->
#
# Each file is one JSON object with exactly these keys (see
# deploy/www/deployments/README.md):
#   name, url, kind, signs, verifies   required
#   since, notes, source               optional
#
# Every file is validated before anything is written. Any problem -- unknown
# key, missing or mistyped field, a date that isn't YYYY-MM, a URL that isn't
# https, a badly named file, invalid JSON -- is reported as "path: message" on
# stderr, nothing is written, and the exit status is 1. Files that don't end
# in .json are ignored. Output goes to FILE.tmp and is renamed into place, so
# a failed run never leaves a half-written page. Core Perl only.
use strict;
use warnings;
use utf8;
use Getopt::Long qw(GetOptions);
use JSON::PP ();

my ($data, $template, $out, $check);
GetOptions(
    'data=s'     => \$data,
    'template=s' => \$template,
    'out=s'      => \$out,
    'check'      => \$check,
) or usage();
usage() unless defined $data && ($check || (defined $template && defined $out));

my @SECTIONS = (['sites', 'SITES'], ['software', 'SOFTWARE']);
my %REQUIRED = map { $_ => 1 } qw(name url kind signs verifies);
my %ALLOWED  = (%REQUIRED, map { $_ => 1 } qw(since notes source));

my @errors;
my %entries;
for my $s (@SECTIONS) {
    my ($sub) = @$s;
    $entries{$sub} = [ load_dir("$data/$sub", $sub) ];
}

if (@errors) {
    print STDERR "$_\n" for @errors;
    exit 1;
}
exit 0 if $check;

my $page = read_file($template);
for my $s (@SECTIONS) {
    my ($sub, $marker) = @$s;
    my $table = render_table($entries{$sub});
    $page =~ s/<!-- \Q$marker\E -->/$table/
        or fail("$template: no <!-- $marker --> marker");
}
write_atomically($out, $page);
exit 0;

sub usage {
    print STDERR "usage: $0 --data DIR (--template FILE --out FILE | --check)\n";
    exit 2;
}

sub fail { print STDERR "$_[0]\n"; exit 1 }

sub read_file {
    my ($path) = @_;
    open my $fh, '<:raw', $path or fail("$path: $!");
    local $/;
    my $bytes = <$fh>;
    return $bytes;
}

sub write_atomically {
    my ($path, $text) = @_;
    my $tmp = "$path.tmp";
    open my $fh, '>:raw', $tmp or fail("$tmp: $!");
    print $fh $text or do { unlink $tmp; fail("$tmp: $!") };
    close $fh or do { unlink $tmp; fail("$tmp: $!") };
    rename $tmp, $path or do { unlink $tmp; fail("$path: $!") };
}

# Load and validate every *.json in $dir. Errors go to @errors, prefixed with
# "$sub/file.json" so a PR author can find the file.
sub load_dir {
    my ($dir, $sub) = @_;
    opendir my $dh, $dir or do { push @errors, "$sub/: $!"; return };
    my @files = sort grep { /\.json\z/ } readdir $dh;
    closedir $dh;

    my $json = JSON::PP->new->utf8;
    my @out;
    for my $f (@files) {
        my $rel = "$sub/$f";
        my $n = @errors;
        push @errors, "$rel: file name must be lower-case letters, digits and '-', ending .json"
            unless $f =~ /\A[a-z0-9-]+\.json\z/;
        my $obj = eval { $json->decode(read_file("$dir/$f")) };
        if (!defined $obj) {
            (my $e = $@ || 'empty file') =~ s/ at \S+ line \d+\.?\n?\z//;
            push @errors, "$rel: invalid JSON: $e";
            next;
        }
        if (ref $obj ne 'HASH') {
            push @errors, "$rel: must be a JSON object";
            next;
        }
        validate($rel, $obj);
        push @out, $obj if @errors == $n;
    }
    return sort {
        (defined $a->{since} ? 0 : 1) <=> (defined $b->{since} ? 0 : 1)
            || ($a->{since} // '') cmp ($b->{since} // '')
            || lc $a->{name} cmp lc $b->{name}
    } @out;
}

sub validate {
    my ($rel, $o) = @_;
    for my $k (sort keys %$o) {
        push @errors, "$rel: unknown key '$k'" unless $ALLOWED{$k};
    }
    for my $k (sort keys %REQUIRED) {
        push @errors, "$rel: missing '$k'" unless exists $o->{$k};
    }
    for my $k (qw(name url kind since notes source)) {
        next unless exists $o->{$k};
        if (!defined $o->{$k} || ref $o->{$k} || $o->{$k} !~ /\S/) {
            push @errors, "$rel: '$k' must be a non-empty string";
            delete $o->{$k};
        }
    }
    for my $k (qw(signs verifies)) {
        next unless exists $o->{$k};
        push @errors, "$rel: '$k' must be true or false"
            unless JSON::PP::is_bool($o->{$k});
    }
    for my $k (qw(url source)) {
        next unless defined $o->{$k};
        push @errors, "$rel: '$k' must be an https:// URL"
            unless $o->{$k} =~ m{\Ahttps://[^\s/"<>]+(?:/[^\s"<>]*)?\z};
    }
    if (defined $o->{since}) {
        push @errors, "$rel: 'since' must be YYYY-MM"
            unless $o->{since} =~ /\A(\d{4})-(\d{2})\z/ && $2 >= 1 && $2 <= 12;
    }
}

sub esc {
    my ($s) = @_;
    $s =~ s/&/&amp;/g;
    $s =~ s/</&lt;/g;
    $s =~ s/>/&gt;/g;
    $s =~ s/"/&quot;/g;
    return $s;
}

sub render_table {
    my ($list) = @_;
    my $tick = "\x{2713}";
    my @rows;
    for my $e (@$list) {
        my $since;
        if (!defined $e->{since}) {
            $since = "\x{2014}";
        } elsif (defined $e->{source}) {
            $since = sprintf '<a href="%s">%s</a>', esc($e->{source}), esc($e->{since});
        } else {
            $since = esc($e->{since}) . ' <small>reported to us</small>';
        }
        push @rows, join "\n",
            '      <tr>',
            sprintf('        <td class="name"><a href="%s">%s</a></td>', esc($e->{url}), esc($e->{name})),
            sprintf('        <td>%s</td>', esc($e->{kind})),
            ($e->{signs}    ? qq{        <td class="yes">$tick</td>} : '        <td></td>'),
            ($e->{verifies} ? qq{        <td class="yes">$tick</td>} : '        <td></td>'),
            sprintf('        <td class="since">%s</td>', $since),
            sprintf('        <td>%s</td>', esc($e->{notes} // '')),
            '      </tr>';
    }
    my $html = join "\n",
        '<table class="deployments">',
        '    <thead>',
        '      <tr><th>Name</th><th>Type</th><th>Signs</th><th>Verifies</th><th>Since</th><th>Notes</th></tr>',
        '    </thead>',
        '    <tbody>',
        @rows,
        '    </tbody>',
        '  </table>';
    utf8::encode($html);
    return $html;
}
