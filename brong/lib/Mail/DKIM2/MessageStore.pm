package Mail::DKIM2::MessageStore;
use 5.20.0;
use strict;
use warnings;

use Digest::SHA qw(sha256_hex);
use File::Path qw(make_path);
use Carp;

sub new {
    my ($class, %args) = @_;
    croak "directory required" unless $args{directory};
    my $self = bless \%args, $class;
    return $self;
}

# Derive a filesystem-safe key from an MI header value
sub _key_for_mi {
    my ($self, $mi_value) = @_;
    $mi_value =~ s/^\s+//;
    $mi_value =~ s/\s+$//;
    return sha256_hex($mi_value);
}

# Path with 2-char prefix subdirectory to avoid crowding
sub _path_for_key {
    my ($self, $key) = @_;
    my $prefix = substr($key, 0, 2);
    return "$self->{directory}/$prefix/$key";
}

sub store {
    my ($self, $mi_value, $message_data) = @_;
    croak "mi_value required" unless defined $mi_value;
    croak "message_data required" unless defined $message_data;

    my $key = $self->_key_for_mi($mi_value);
    my $path = $self->_path_for_key($key);

    my $dir = $path;
    $dir =~ s{/[^/]+$}{};
    make_path($dir) unless -d $dir;

    open my $fh, '>:raw', $path
        or croak "Cannot write $path: $!";
    print $fh $message_data;
    close $fh;

    return $key;
}

sub fetch {
    my ($self, $mi_value) = @_;
    croak "mi_value required" unless defined $mi_value;

    my $key = $self->_key_for_mi($mi_value);
    my $path = $self->_path_for_key($key);

    return unless -f $path;

    open my $fh, '<:raw', $path
        or croak "Cannot read $path: $!";
    local $/;
    my $data = <$fh>;
    close $fh;

    return $data;
}

sub remove {
    my ($self, $mi_value) = @_;
    croak "mi_value required" unless defined $mi_value;

    my $key = $self->_key_for_mi($mi_value);
    my $path = $self->_path_for_key($key);

    return unless -f $path;
    unlink $path or croak "Cannot remove $path: $!";
    return 1;
}

1;

__END__

=head1 NAME

Mail::DKIM2::MessageStore - Store and retrieve message snapshots by Message-Instance

=head1 SYNOPSIS

    use Mail::DKIM2::MessageStore;

    my $store = Mail::DKIM2::MessageStore->new(
        directory => '/var/spool/dkim2/snapshots',
    );

    # Store a message snapshot keyed by its MI header value
    $store->store($mi_value, $message_data);

    # Retrieve the snapshot later (e.g. on egress)
    my $snapshot = $store->fetch($mi_value);

    # Clean up
    $store->remove($mi_value);

=head1 DESCRIPTION

Provides a simple filesystem-backed store for message snapshots.  On inbound
delivery, the message is stored keyed by its topmost Message-Instance header
value.  On outbound (forwarding, mailing list redistribution), the snapshot
is retrieved so that a diff-based Message-Instance can be computed between
the stored version and the (possibly modified) current version.

Keys are derived by SHA-256 hashing the MI header value, stored under
2-character prefix subdirectories to avoid filesystem crowding.

=head1 METHODS

=head2 new(directory => $path)

Creates a new MessageStore.  The C<directory> argument is required and
specifies where snapshots are stored on disk.

=head2 store($mi_value, $message_data)

Stores C<$message_data> keyed by the given Message-Instance header value.
Creates subdirectories as needed.  Returns the hex digest key.

=head2 fetch($mi_value)

Retrieves the stored message data for the given MI header value.  Returns
the message data string, or undef if not found.

=head2 remove($mi_value)

Removes the stored snapshot for the given MI value.  Returns true on
success, undef if the file did not exist.

=head1 AUTHOR

Bron Gondwana E<lt>brong@fastmailteam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 Fastmail Pty Ltd.  This is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
