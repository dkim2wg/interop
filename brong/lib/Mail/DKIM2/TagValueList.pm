package Mail::DKIM2::TagValueList;
use strict;
use warnings;

# Simple tag=value list as defined in draft-ietf-dkim-dkim2-spec-01 Sections 6 and 7.
# Preserves insertion order for serialization.

sub new {
    my ($class) = @_;
    return bless { tags => {}, order => [] }, $class;
}

sub parse {
    my ($class, $string) = @_;
    my $self = ref($class) ? $class : $class->new();
    bless $self, ref($class) || $class;

    $string =~ s/^\s+//;
    $string =~ s/\s+$//;
    my @order;
    for my $part (split /\s*;\s*/, $string) {
        next unless $part =~ /^(\w+)\s*=\s*(.*)/s;
        my ($name, $val) = ($1, $2);
        $val =~ s/\s+$//;
        $self->{tags}{$name} = $val;
        push @order, $name;
    }
    $self->{order} = \@order;
    return $self;
}

sub get_tag {
    my ($self, $name) = @_;
    return $self->{tags}{$name};
}

sub set_tag {
    my ($self, $name, $value) = @_;
    unless (exists $self->{tags}{$name}) {
        push @{$self->{order}}, $name;
    }
    $self->{tags}{$name} = $value;
}

sub as_string {
    my ($self) = @_;
    return join('; ', map { "$_=$self->{tags}{$_}" } @{$self->{order}});
}

1;

__END__

=head1 NAME

Mail::DKIM2::TagValueList - Parse and serialize DKIM2 tag=value lists

=head1 SYNOPSIS

    use Mail::DKIM2::TagValueList;

    my $tvl = Mail::DKIM2::TagValueList->parse("v=1; d=example.com");
    say $tvl->get_tag('d');   # "example.com"

    $tvl->set_tag('t', time());
    say $tvl->as_string();    # "v=1; d=example.com; t=1740000000"

=head1 DESCRIPTION

Base class for tag=value list parsing and serialization as used in
DKIM2-Signature and Message-Instance headers (draft-ietf-dkim-dkim2-spec-01
Sections 6 and 7).  Preserves insertion order for deterministic output.

B<EXPERIMENTAL> — This module implements an Internet-Draft that has not yet
been published as an RFC.  The API and wire format are subject to change.
Do not use in production.

=head1 CONSTRUCTORS

=head2 new()

Creates a new empty TagValueList.

=head2 parse($string)

Parses a semicolon-delimited tag=value string into a TagValueList object.
Whitespace around tags and values is stripped.

=head1 METHODS

=head2 get_tag($name)

Returns the value of the named tag, or undef if not present.

=head2 set_tag($name, $value)

Sets the value of the named tag.  If the tag does not already exist, it is
appended to the end of the tag order.

=head2 as_string()

Serializes the tag-value list as a semicolon-delimited string, preserving
the original insertion order.

=head1 AUTHOR

Bron Gondwana E<lt>brong@fastmailteam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 Fastmail Pty Ltd.  This is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
