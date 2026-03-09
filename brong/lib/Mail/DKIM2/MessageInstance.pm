package Mail::DKIM2::MessageInstance;
use strict;
use warnings;

use Mail::DKIM::Canonicalization::simple;
use Digest::SHA;
use Email::MIME;
use MIME::Base64 qw(encode_base64 decode_base64);
use Algorithm::Diff;
use List::Util qw(max);
use Carp;

use Mail::DKIM2::Common qw(
    should_skip
    dkim2_canonicalize_header
    digest64
    encode_tag_json
    decode_tag_json
    extract_mi_version
);

our $DEBUG = 0;

# FILTHY PATCHING (needed for undo to work with Email::Simple)
BEGIN {
    # function to replace headers from the bottom up
    if (!Email::Simple::Header->can('header_set_reverse')) {
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
    }

    # function to only keep headers that match an expression
    if (!Email::Simple::Header->can('header_filter')) {
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
}

# --- Tag accessors ---

sub set_tag {
    my ($self, $k, $v) = @_;
    $self->{bits}{$k} = $v;
}

sub get_tag {
    my ($self, $k) = @_;
    return $self->{bits}{$k};
}

# --- Wire format: v=N; h=<b64json>; r=<b64json> ---

sub as_string {
    my ($self) = @_;
    my %data = %{$self->{bits}};
    my $v = delete $data{v};

    # Build h= tag JSON: {"h":["sha256","xxx"],"b":["sha256","xxx"]}
    my %hash_json;
    $hash_json{h} = ['sha256', delete $data{h1}] if exists $data{h1};
    $hash_json{b} = ['sha256', delete $data{b1}] if exists $data{b1};

    my $result = "v=$v; h=" . encode_tag_json(\%hash_json);

    # Build r= tag JSON if there are recipes
    my %recipe_json;
    if (exists $data{rb}) {
        $recipe_json{b} = _encode_recipe_list(delete $data{rb});
    }
    if (exists $data{rh}) {
        my $rh = delete $data{rh};
        my %encoded;
        for my $h (sort keys %$rh) {
            $encoded{$h} = _encode_recipe_list($rh->{$h});
        }
        $recipe_json{h} = \%encoded;
    }

    if (keys %recipe_json) {
        $result .= "; r=" . encode_tag_json(\%recipe_json);
    }

    return $result;
}

# Convert internal recipe list to -08 format
# [from,to] arrays become "(from-to)" strings; strings stay as-is
sub _encode_recipe_list {
    my ($list) = @_;
    return [map {
        ref($_) eq 'ARRAY' ? "($_->[0]-$_->[1])" : $_
    } @$list];
}

# --- Parsing ---

sub parse {
    my ($class, $header) = @_;
    my $self = bless {}, ref($class) || $class;

    # Strip leading whitespace
    $header =~ s/^\s+//;

    # Parse tag-value format: v=N; h=...; r=...
    my %tags;
    for my $part (split /\s*;\s*/, $header) {
        next unless $part =~ /^(\w+)\s*=\s*(.*)/s;
        my ($name, $val) = ($1, $2);
        $val =~ s/\s//gs;
        $tags{$name} = $val;
    }

    die "missing v= tag in Message-Instance header"
        unless exists $tags{v};
    $self->{bits}{v} = $tags{v};

    # Handle -08 format: h= and r= tags
    if (exists $tags{h}) {
        my $hash_data = decode_tag_json($tags{h});
        if ($hash_data->{h} && ref $hash_data->{h} eq 'ARRAY') {
            $self->{bits}{h1} = $hash_data->{h}[1];
        }
        if ($hash_data->{b} && ref $hash_data->{b} eq 'ARRAY') {
            $self->{bits}{b1} = $hash_data->{b}[1];
        }
    }
    # Handle legacy -06 format: j= tag
    elsif (exists $tags{j}) {
        my $data = decode_tag_json($tags{j});
        for my $k (keys %$data) {
            $self->{bits}{$k} = $data->{$k};
        }
    }

    if (exists $tags{r}) {
        my $recipe_data = decode_tag_json($tags{r});
        if ($recipe_data->{b}) {
            $self->{bits}{rb} = _decode_recipe_list($recipe_data->{b});
        }
        if ($recipe_data->{h}) {
            my %rh;
            for my $h (keys %{$recipe_data->{h}}) {
                $rh{$h} = _decode_recipe_list($recipe_data->{h}{$h});
            }
            $self->{bits}{rh} = \%rh;
        }
    }

    return $self;
}

# Convert -08 format recipe list back to internal format
# "(from-to)" strings become [from,to] arrays; strings stay as-is
sub _decode_recipe_list {
    my ($list) = @_;
    return [map {
        /^\((\d+)-(\d+)\)$/ ? [$1+0, $2+0] : $_
    } @$list];
}

# --- Digests ---

sub h_digest {
    my ($msg) = @_;

    my $digest = Digest::SHA->new(256);
    for my $header (sort { lc($a) cmp lc($b) } $msg->header_names) {
        next if should_skip($header);
        for my $item (reverse $msg->header_raw($header)) {
            my $chead = dkim2_canonicalize_header("$header: $item\r\n");
            warn "cdigest: $chead" if $DEBUG;
            $digest->add($chead);
        }
    }

    return digest64($digest);
}

sub b_digest {
    my ($msg) = @_;

    my $simple = Mail::DKIM::Canonicalization::simple->new(Signature => 'dummy');
    my $digest = Digest::SHA->new(256);
    $digest->add($simple->canonicalize_body($msg->body_raw));
    return digest64($digest);
}

# --- Calculate ---

sub calculate {
    my ($class, $msg1, $msg2) = @_;
    croak "need a message" unless $msg1;

    my $self = bless {}, $class;

    unless (ref($msg1) && $msg1->isa('Email::MIME')) {
        $msg1 = Email::MIME->new($msg1);
    }

    if ($msg2) {
        unless (ref($msg2) && $msg2->isa('Email::MIME')) {
            $msg2 = Email::MIME->new($msg2);
        }

        my @mi1 = $msg1->header_raw('Message-Instance');
        die "This message has no existing instances" unless @mi1;
        my @mi2 = $msg2->header_raw('Message-Instance');
        # Verify same message by checking MI headers match
        my $canon_mi1 = join(',', map { dkim2_canonicalize_header($_) } @mi1);
        my $canon_mi2 = join(',', map { dkim2_canonicalize_header($_) } @mi2);
        die "This isn't the same message" unless ($canon_mi1 eq $canon_mi2);

        my %map = map { extract_mi_version($_) => $_ } @mi1;
        $self->set_tag('v', max(keys %map) + 1);
    }
    else {
        die "Already has Message-Instance headers" if $msg1->header_raw('Message-Instance');
        $self->set_tag('v', 1);
    }

    $self->set_tag('h1', h_digest($msg1));
    $self->set_tag('b1', b_digest($msg1));

    # nothing to calculate, we exit now
    return $self unless $msg2;

    # calculate the header difference
    my %all = map { lc($_) => 1 } ($msg1->header_names, $msg2->header_names);
    my %hdiff;
    for my $h (sort keys %all) {
        next if should_skip($h);
        my @h1 = reverse $msg1->header_raw($h);
        my @h2 = reverse $msg2->header_raw($h);
        next if join("\n", map { dkim2_canonicalize_header($_) } @h1)
             eq join("\n", map { dkim2_canonicalize_header($_) } @h2);
        # headers are indexed from 1 from the bottom up
        my %known = map {
            dkim2_canonicalize_header($h1[$_]) => $_ + 1
        } reverse 0..$#h1;
        # we want the values from h2
        my @res = map {
            $known{dkim2_canonicalize_header($_)}
                ? [$known{dkim2_canonicalize_header($_)}, $known{dkim2_canonicalize_header($_)}]
                : $_
        } @h2;
        # combine adjacent ranges
        for (1..$#res) {
            next unless (ref $res[$_] && ref $res[$_-1]);
            next unless ($res[$_][0] == $res[$_-1][1] + 1);
            $res[$_][0] = $res[$_-1][0];
            $res[$_-1] = undef;
        }
        my @vals = grep { defined } @res;
        $hdiff{$h} = \@vals;
    }

    # calculate the body differences
    my $str1 = $msg1->body_raw;
    my $str2 = $msg2->body_raw;
    $str1 =~ s/[\r\n]+$//;
    $str2 =~ s/[\r\n]+$//;
    my @l1 = split /\r?\n/, $str1;
    my @l2 = split /\r?\n/, $str2;

    my $diff = Algorithm::Diff->new(\@l1, \@l2);
    $diff->Base(1);

    my @list;
    my $dirty = 0;
    while ($diff->Next()) {
        if ($diff->Same()) {
            push @list, [$diff->Min(1), $diff->Max(1)];
        } else {
            $dirty = 1;
            push @list, map { $_ } $diff->Items(2);
        }
    }

    if (@list > 1 || $dirty) {
        $self->set_tag('rb', \@list);
    }

    if (keys %hdiff) {
        $self->set_tag('rh', \%hdiff);
    }

    return $self;
}

# --- Verify ---

sub verify {
    my ($class, $msg) = @_;
    croak "need a message" unless $msg;

    unless (ref($msg) && $msg->isa('Email::MIME')) {
        $msg = Email::MIME->new($msg);
    }

    my %map = map { extract_mi_version($_) => $_ } $msg->header_raw('Message-Instance');
    my $num = keys %map ? max(keys %map) : 0;
    return 0 unless $num;

    my $self = $class->parse($map{$num});
    my $h1 = $self->get_tag('h1');
    my $b1 = $self->get_tag('b1');
    my $hd = h_digest($msg);
    my $bd = b_digest($msg);

    if ($h1 ne $hd) {
        return wantarray ? (0, "header hash mismatch ($h1 != $hd)") : 0;
    }
    if ($b1 ne $bd) {
        return wantarray ? (0, "body hash mismatch ($b1 != $bd)") : 0;
    }

    return $num;
}

# --- Undo ---

sub undo {
    my ($class, $msg) = @_;
    croak "need a message" unless $msg;

    unless (ref($msg) && $msg->isa('Email::MIME')) {
        $msg = Email::MIME->new($msg);
    }

    my %map = map { extract_mi_version($_) => $_ } $msg->header_raw('Message-Instance');
    my $num = keys %map ? max(keys %map) : 0;
    return unless $num;

    $msg->header_obj->header_filter('Message-Instance', sub { extract_mi_version(shift) < $num });

    my $self = $class->parse($map{$num});

    my $rb = $self->get_tag('rb');
    my $rh = $self->get_tag('rh');

    if ($rb) {
        my @old = split /\r?\n/, $msg->body_raw;
        my @new;
        for my $cmd (@$rb) {
            if (ref($cmd) eq 'ARRAY') {
                my ($from, $to) = ($cmd->[0] - 1, $cmd->[1] - 1);
                push @new, @old[$from..$to];
            } else {
                push @new, $cmd;
            }
        }
        $msg->body_set(join("\r\n", @new, ''));
    }

    if ($rh) {
        for my $h (sort keys %$rh) {
            my $v = $rh->{$h};
            next unless defined $v;
            my @old = reverse $msg->header_raw($h);
            my @new;
            for my $cmd (@$v) {
                if (ref($cmd) eq 'ARRAY') {
                    my ($from, $to) = ($cmd->[0] - 1, $cmd->[1] - 1);
                    push @new, @old[$from..$to];
                } else {
                    push @new, $cmd;
                }
            }
            $msg->header_obj->header_set_reverse($h, @new);
        }
    }

    return $msg;
}

# Backwards-compatible alias for external callers
sub getmi { return extract_mi_version(@_) }

1;

__END__

=head1 NAME

Mail::DKIM2::MessageInstance - Calculate, verify, and undo Message-Instance headers

=head1 SYNOPSIS

    use Mail::DKIM2::MessageInstance;

    # Calculate MI for the initial message (v=1)
    my $mi = Mail::DKIM2::MessageInstance->calculate($msg);
    print "Message-Instance: " . $mi->as_string . "\n";

    # Calculate MI with diff recipes between two versions
    my $mi = Mail::DKIM2::MessageInstance->calculate($msg_prev, $msg_current);

    # Verify the highest MI header matches the message
    my $version = Mail::DKIM2::MessageInstance->verify($msg);
    # or in list context:
    my ($version, $error) = Mail::DKIM2::MessageInstance->verify($msg);

    # Undo the highest MI to recover the previous message version
    my $prev_msg = Mail::DKIM2::MessageInstance->undo($msg);

=head1 DESCRIPTION

This module implements Message-Instance header computation as defined in
draft-clayton-dkim2-spec-08.  A Message-Instance header records cryptographic
hashes of the message headers and body at a point in the delivery chain, along
with optional diff recipes that allow undoing changes made at each hop.

The wire format is: C<< v=N; h=<base64json>; r=<base64json> >>

=head1 CLASS METHODS

=head2 calculate($msg)

=head2 calculate($msg_prev, $msg_current)

Creates a new MessageInstance object by computing hashes of C<$msg> (an
L<Email::MIME> object or raw message string).  If a single message is given,
it must not already have Message-Instance headers and produces a C<v=1> entry.

With two messages, computes diff recipes (header and body) between C<$msg_prev>
(the earlier version with existing MI headers) and C<$msg_current>, producing
the next version.

=head2 verify($msg)

Verifies that the highest-versioned Message-Instance header on C<$msg> matches
the current message content.  Returns the version number on success.  In list
context, returns C<(0, $error_message)> on failure; in scalar context returns
0 on failure.

=head2 undo($msg)

Applies the diff recipes from the highest Message-Instance header to reverse
the message to its previous version.  Returns the modified L<Email::MIME>
object, or undef if no MI headers exist.

=head2 parse($header_value)

Parses a Message-Instance header value string into an object.  Handles both
the current C<-08> format (C<h=> and C<r=> tags) and the legacy C<-06> format
(C<j=> tag).

=head1 INSTANCE METHODS

=head2 as_string()

Serializes the MessageInstance to its wire format string.

=head2 set_tag($key, $value)

=head2 get_tag($key)

Low-level accessors for the internal tag store.  Common tags: C<v> (version),
C<h1> (header hash), C<b1> (body hash), C<rh> (header recipes), C<rb> (body
recipes).

=head1 FUNCTIONS

=head2 h_digest($email_mime)

Computes the SHA-256 header digest of an L<Email::MIME> message, using DKIM2
canonicalization and sorted header order.  Returns a base64-encoded string.

=head2 b_digest($email_mime)

Computes the SHA-256 body digest of an L<Email::MIME> message using DKIM
simple body canonicalization.  Returns a base64-encoded string.

=head2 getmi($header)

Backwards-compatible alias for L<Mail::DKIM2::Common/extract_mi_version>.

=head1 AUTHOR

Bron Gondwana E<lt>brong@fastmailteam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 Fastmail Pty Ltd.  This is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
