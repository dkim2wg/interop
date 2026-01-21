package Mail::DKIM::DKIM2::MessageInstance;
use strict;
use warnings;
use Mail::DKIM::Canonicalization::simple;
use Mail::DKIM::Canonicalization::relaxed;
use Digest::SHA;
use Email::MIME;
use MIME::Base64 qw(encode_base64 decode_base64);
use Algorithm::Diff;
use List::Util qw(max);

our $VERSION = '1.20240923'; # VERSION

# ABSTRACT: Subclass of Mail::DKIM::KeyValueList which represents a Message-Instance header

# Copyright 2017 FastMail Pty Ltd. All Rights Reserved.
# Bron Gondwana <brong@fastmailteam.com>

# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

# FILTHY PATCHING

BEGIN {
    # clone is broken for signatures with different prefixes
    *Mail::DKIM::Signature::clone = sub {
       my $self = shift;
       my $clone = ref($self)->new();
       $clone->prefix($self->prefix());
       return $clone->parse($self->as_string());
    };

    # function to replace headers from the bottom up
    *Email::Simple::Header::header_set_reverse = sub {
        my $self = shift;
        my $h = shift;
        my @vals = @_;
        my $headers = $self->{headers};
        my $max = @$headers / 2 - 1;
        for my $idx (map { $_ * 2 } reverse 0..$max) {
            next unless lc($headers->[$idx]) eq lc($h);
            if (@vals) {
                $headers->[$idx+1] = shift @vals;
            } else {
                splice(@$headers, $idx, 2);
            }
        }
        unshift @$headers, ($h, $_) for @vals;
    };

    # function to only keep headers that match an expression
    *Email::Simple::Header::header_filter = sub {
        my $self = shift;
        my $h = shift;
        my $keep = shift;
        my $headers = $self->{headers};
        my $max = @$headers / 2 - 1;
        for my $idx (map { $_ * 2 } reverse 0..$max) {
            next unless lc($headers->[$idx]) eq lc($h);
            next if $keep->($headers->[$idx+1]);
            splice(@$headers, $idx, 2);
        }
    };

}

use base 'Mail::DKIM::KeyValueList';
use Carp;

sub DEFAULT_PREFIX {
    return 'Message-Instance:';
}

sub SIMPLE {
    our $s = Mail::DKIM::Canonicalization::simple->new(Signature => 'dummy');
    return $s;
}

sub RELAXED {
    our $r = Mail::DKIM::Canonicalization::relaxed->new(Signature => 'dummy');
    return $r;
}

sub h_digest {
    my $msg = shift;

    my $relaxed = RELAXED();
    my @h;
    my $digest = Digest::SHA->new(256);
    for my $header (sort { $a cmp $b } $msg->header_names) {
        # we're going to sign everything except trace headers and DKIM-Signature and X-Headers:
        next if should_skip($header);
        for my $item (reverse $msg->header_raw($header)) {
            my $chead = $relaxed->canonicalize_header("$header: $item\r\n");
            $digest->add($chead);
            push @h, lc($header);
        }
    }

    return wantarray ? (digest64($digest), @h) : digest64($digest);
}

sub b_digest {
    my $msg = shift;

    my $simple = SIMPLE();
    my $digest = Digest::SHA->new(256);
    $digest->add($simple->canonicalize_body($msg->body_raw));
    return digest64($digest);
}

sub calculate {
    my $class = shift;
    my $msg1 = shift || die "need a message";
    my $msg2 = shift;

    my $self  = {};
    bless $self, $class;
    my $pkg = shift;

    my $relaxed = RELAXED();

    unless (ref($msg1) and $msg1->isa('Email::MIME')) {
        $msg1 = Email::MIME->new($msg1);
    }

    if ($msg2) {
        unless (ref($msg2) and $msg2->isa('Email::MIME')) {
            $msg2 = Email::MIME->new($msg2);
        }

        my $mi1 = join(',', map { $relaxed->canonicalize_header($_) } $msg1->header_raw('Message-Instance'));
        die "This message has no existing instances" unless $mi1;
        my $mi2 = join(',', map { $relaxed->canonicalize_header($_) } $msg2->header_raw('Message-Instance'));
        die "This isn't the same message" unless ($mi1 eq $mi2);

        my %map = map { getmi($_) => $_ } $msg1->header_raw('Message-Instance');
        $self->set_tag('v', max(keys %map)+1);
    }
    else {
        die "Already has Message-Instances headers" if $msg1->header_raw('Message-Instance');
        $self->set_tag('v', 1);
    }

    $self->set_tag('a1', 'sha256');
    my ($h1, @h) = h_digest($msg1);
    $self->set_tag('h', join(':', @h));
    $self->set_tag('h1', $h1);
    $self->set_tag('b1', b_digest($msg1));

    # nothing to calculate, we exit now
    return $self unless $msg2;

    # calculate the header difference
    my %all = map { lc($_) => 1 } ($msg1->header_names, $msg2->header_names);
    my @hdiff;
    for my $h (sort keys %all) {
        next if should_skip($h);
        my @h1 = reverse $msg1->header_raw($h);
        my @h2 = reverse $msg2->header_raw($h);
        next if join("\n", map { $relaxed->canonicalize_header($_) } @h1)
             eq join("\n", map { $relaxed->canonicalize_header($_) } @h2);
        # headers are indexed from 1 from the bottom up
        my %known = map { $relaxed->canonicalize_header($h1[$_]) => $_+1 } 0..$#h1;
        # we want the values from h2
        my @res = map { $known{$relaxed->canonicalize_header($_)} ? ['c', $known{$_}, $known{$_}] : ['b', encode_base64($_, '')] } @h2;
        # combine multiples
        for (1..$#res) {
            # both copies
            next unless ($res[$_][0] eq 'c' and $res[$_-1] eq 'c');
            # ranges are adjacent
            next unless ($res[$_][1] == $res[$_-1][2] + 1);
            # extend back
            $res[$_][1] = $res[$_-1][1];
            # and nuke the old one
            $res[$_-1] = undef;
        }
        my @vals = map { $_->[2] ? "$_->[0].$_->[1]-$_->[2]" : "$_->[0].$_->[1]" } grep { defined } @res;
        push @hdiff, "$h:" . join(',', @vals);
    }

    # calculate the body differences
    my $str1 = $msg1->body_raw;
    my $str2 = $msg2->body_raw;
    $str1 =~ s/[\r\n]+$//;
    $str2 =~ s/[\r\n]+$//;
    my @l1 = split /\r?\n/, $str1;
    my @l2 = split /\r?\n/, $str2;

    my $diff = Algorithm::Diff->new( \@l1, \@l2 );
    # lines are indexed from 1 from the top down
    $diff->Base(1);

    my @bdiff;
    my @list;
    my $dirty = 0;
    while ($diff->Next()) {
        if ($diff->Same()) {
            push @list, 'c.' . $diff->Min(1) . '-' . $diff->Max(1);
        } else {
            # contains things to copy back
            $dirty = 1;
            push @list, map { 'b.' . encode_base64($_, '') } $diff->Items(2);
        }
    }

    if (@list > 1 || $dirty) {
        $self->set_tag('rb', join(',', @list));
    }

    if (@hdiff) {
        $self->set_tag('rh', join('|', @hdiff));
    }

    return $self;
}

sub verify {
    my $class = shift;
    my $msg = shift || die "need a message";

    unless (ref($msg) and $msg->isa('Email::MIME')) {
        $msg = Email::MIME->new($msg);
    }

    my %map = map { getmi($_) => $_ } $msg->header_raw('Message-Instance');
    my $num = max(keys %map);
    return 0 unless $num;

    my $self = $class->parse($map{$num});
    my $h1 = $self->get_tag('h1');
    my $b1 = $self->get_tag('b1');
    my $hd = h_digest($msg);
    my $bd = b_digest($msg);
    die "($h1, $b1) => ($hd, $bd)" if ($h1 ne $hd or $b1 ne $bd);

    # we passed!
    return $num;
}

sub undo {
    my $class = shift;
    my $msg = shift || die "need a message";

    unless (ref($msg) and $msg->isa('Email::MIME')) {
        $msg = Email::MIME->new($msg);
    }

    my %map = map { getmi($_) => $_ } $msg->header_raw('Message-Instance');
    my $num = max(keys %map);
    return unless $num;

    $msg->header_obj->header_filter('Message-Instance', sub { getmi(shift) < $num });

    my $self = $class->parse($map{$num});

    my $rh = $self->get_tag('rh');
    my $rb = $self->get_tag('rb');

    # if 'z' we just don't try to undo things
    if ($rb and $rb ne 'z') {
        my @old = split /\r?\n/, $msg->body_raw;
        my @new;
        for my $cmd (split /\s*,\s*/, $rb) {
            if ($cmd =~ m/b\.(.*)/) {
                push @new, decode_base64($1);
            } elsif ($cmd =~ m/c\.(\d+)-(\d+)/) {
                my ($from, $to) = ($1-1, $2-1);
                # numbers count indexed 1 from the bottom
                push @new, @old[$from..$to];
            } elsif ($cmd eq 'z') {
                die "z which wasn't the only body recipe seen";
            } else {
                die "Unknown body recipe $cmd";
            }
        }
        $msg->body_set(join("\r\n", @new, ''));
    }

    if ($rh) {
        for my $item (split /\s*\|\s*/, $rh) {
            my ($h, $v) = split /\s*:\s*/, $item;
            # if 'z' we just don't try to undo things
            next if $v eq 'z';
            my @new;
            my @old = reverse $msg->header_raw($h);
            for my $cmd (split /\s*,\s*/, $v) {
                if ($cmd =~ m/b\.(.*)/) {
                    push @new, decode_base64($1);
                } elsif ($cmd =~ m/c\.(\d+)-(\d+)/) {
                    my ($from, $to) = ($1-1, $2-1);
                    # numbers count indexed 1 from the bottom; use ref so whitespace is kept
                    push @new, map { $_ } @old[$from..$to];
                } elsif ($cmd eq 'z') {
                    die "z which wasn't the only header recipe seen for $h";
                } else {
                    die "Unknown header recipe $cmd for $h";
                }
            }
            $msg->header_obj->header_set_reverse($h, @new);
        }
    }

    return $msg;
}

sub getmi {
    my $header = shift;
    $header = $header->[0] if ref($header) eq 'ARRAY';
    $header = $$header if ref($header);
    my $kv = Mail::DKIM::KeyValueList->parse($header);
    return $kv->get_tag('v');
}

sub digest64 {
    my $digest = shift;
    my $res = $digest->b64digest;
    while (length($res) % 4) {
        $res .= '=';
    }
    return $res;
}

sub should_skip {
    my $hname = lc(shift);
    # Stuff we handle ourselves
    return 1 if $hname eq 'message-instance';
    return 1 if $hname eq 'dkim2-signature';
    # Trace Headers
    return 1 if $hname eq 'received';
    return 1 if $hname eq 'return-path';
    # X headers
    return 1 if $hname =~ m/^x-/;
    # stuff we don't sign
    return 1 if $hname eq 'dkim-signature';
    return 1 if $hname eq 'arc-authentication-results';
    return 1 if $hname eq 'arc-message-signature';
    return 1 if $hname eq 'arc-seal';
}

1;

__END__

=pod

=encoding UTF-8

=head1 NAME

Mail::DKIM::DKIM2::MessageInstance - Subclass of Mail::DKIM::KeyValueList which represents a Message-Instance header

=head1 VERSION

version 1.20240923

=head1 CONSTRUCTORS

=head2 new() - create a new signature from parameters

  my $diff = Mail::DKIM::DKIM2::MessageInstance->new($msg1, $msg2);
  my $base = Mail::DKIM::DKIM2::MessageInstance->new($msg1);

The only differences between this module and Mail::DKIM::Signature are
the header name, and that 'instance' is an integer rather than a base64
encoded value.

=head2 instance() - get or set the signing instance (i=) field

  my $i = $signature->instance;

Instances must be integers less than 1024 according to the spec.

NOTE: the i= field is "Identity" in DKIM and is a base64 value, but in
ARC it is "Instance" and an integer.  The parsing routine does not
check that the i= value is a number.

=head1 SEE ALSO

L<Mail::DKIM::Signature> for DKIM-Signature headers

=head1 AUTHORS

=over 4

=item *

Jason Long <jason@long.name>

=item *

Marc Bradshaw <marc@marcbradshaw.net>

=item *

Bron Gondwana <brong@fastmailteam.com> (ARC)

=back

=head1 THANKS

Work on ensuring that this module passes the ARC test suite was
generously sponsored by Valimail (https://www.valimail.com/)

=head1 COPYRIGHT AND LICENSE

=over 4

=item *

Copyright (C) 2013 by Messiah College

=item *

Copyright (C) 2010 by Jason Long

=item *

Copyright (C) 2017 by Standcore LLC

=item *

Copyright (C) 2020 by FastMail Pty Ltd

=back

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut
