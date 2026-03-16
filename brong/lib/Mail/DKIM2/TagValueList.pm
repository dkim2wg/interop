package Mail::DKIM2::TagValueList;
use strict;
use warnings;

# Simple tag=value list as defined in draft-clayton-dkim2-spec-08 Section 8.
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
