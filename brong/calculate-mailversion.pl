#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use Algorithm::Diff qw(traverse_balanced);
use MIME::Base64 qw(encode_base64);
use List::Util qw(max);

my $f1 = shift;
my $f2 = shift || die "need two files";

my $msg1 = Email::MIME->new(path($f1)->slurp);
my $msg2 = Email::MIME->new(path($f2)->slurp);

# message 2 is the old one; so find out which MailVersion header needs to be added
my %map = map { getv($_) => $_ } $msg2->header('MailVersion');
my $num = %map ? max(keys %map) : 0;
$num++;

# calculate the header difference

my %all = map { $_ => 1 } ($msg1->header_names, $msg2->header_names);
my @hdiff;
for my $h (sort keys %all) {
  next if should_skip($h);
  my @h1 = $msg1->header_raw($h);
  my @h2 = $msg2->header_raw($h);
  next if join("\n", @h1) eq join("\n", @h2);
  # we want the values from h2
  push @hdiff, hdiff($h, @h2);
}

# calculate the body differences

my @l1 = split /\r?\n/, $msg1->body_raw;
my @l2 = split /\r?\n/, $msg2->body_raw;

my $diff = Algorithm::Diff->new( \@l1, \@l2 );
$diff->Base(1);

my @bdiff;
my @list;
my $dirty = 0;
while ($diff->Next()) {
  if ($diff->Same()) {
    push @list, 'c:' . $diff->Min(1) . '-' . $diff->Max(1);
  } else {
    # contains things to copy back
    $dirty = 1;
    push @list, map { m/[^A-Za-z0-9_\@\.\-\ ]/ ? 'b:' . encode_base64($_, '') : "t:$_" } $diff->Items(2);
  }
}

if (@list > 1 || $dirty) {
  push @bdiff, "b=" . join(',', @list);
  # XXX - calculate mime part hashes
}

if (@hdiff or @bdiff) {
  $msg1->header_raw_prepend('MailVersion', join(";\n\t", "v=$num", @hdiff, @bdiff));
}

print $msg1->as_string();

sub getv {
  my $arg = shift;
  return 0 unless $arg =~ m/v=(\d+)/;
  return 0 + $1;
}

sub hdiff {
  my $name = shift;
  my @items = @_;
  my @res = ('d:*');
  for (@items) {
    push @res, m/[^A-Za-z0-9_\@\.\-\ ]/ ? 'b:' . encode_base64($_, '') : "t:$_";
  }
  return "h.$name=" . join(',', @res);
}

sub bval {
  my $item = shift;
  return "$item->[0]:$item->[1]-$item->[2]" if $item->[0] eq 'c';
  return "$item->[0]:$item->[1]";
}

sub should_skip {
  my $hname = lc(shift);
  # Trace Headers
  return 1 if $hname eq 'received';
  return 1 if $hname eq 'return-path';
  return 1 if $hname eq 'mailversion';
  return 1 if $hname eq 'dkim-signature';
  # X headers
  return 1 if $hname =~ m/^x-/;
}
