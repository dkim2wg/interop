package Mail::DKIM2::HeaderParser;
use strict;
use warnings;

# Thin base class for streaming message parsing.
# Replaces the deep Mail::DKIM::Common → Mail::DKIM::MessageParser
# inheritance chain with just what DKIM2 Signer/Verifier need.

sub new {
    my ($class, %args) = @_;
    my $self = bless \%args, $class;
    $self->init;
    return $self;
}

sub init {
    my $self = shift;
    $self->{_buf} = '';
    $self->{_in_header} = 1;
    $self->{headers} = [];
}

# Streaming interface: feed message data in chunks
sub PRINT {
    my ($self, $data) = @_;
    $self->{_buf} .= $data;

    if ($self->{_in_header}) {
        # Look for end-of-headers (blank line)
        if ($self->{_buf} =~ s/\A(.*?\r?\n)\r?\n//s) {
            my $header_block = $1;
            $self->_parse_headers($header_block);
            $self->{_in_header} = 0;
            $self->finish_header();
        }
    }
    # Body data accumulates in buffer until CLOSE
    return 1;
}

sub CLOSE {
    my $self = shift;

    # If we never saw end-of-headers, parse what we have as headers
    if ($self->{_in_header}) {
        $self->_parse_headers($self->{_buf});
        $self->{_buf} = '';
        $self->{_in_header} = 0;
        $self->finish_header();
    }

    $self->finish_body();
    return 1;
}

# Parse a block of header text into individual headers (handling continuation lines)
sub _parse_headers {
    my ($self, $block) = @_;

    # Split into lines, then recombine continuation lines
    my @lines = split /(?<=\n)/, $block;
    my $current = '';

    for my $line (@lines) {
        if ($line =~ /^\s/ && $current ne '') {
            # Continuation line: append to current header
            $current .= $line;
        } else {
            # New header — emit the previous one
            $self->_emit_header($current) if $current ne '';
            $current = $line;
        }
    }
    $self->_emit_header($current) if $current ne '';
}

sub _emit_header {
    my ($self, $raw) = @_;
    return unless $raw =~ /^([^\s:]+)\s*:\s*(.*)/s;
    my ($field_name, $contents) = ($1, $2);
    $contents =~ s/\r?\n$//s;

    push @{$self->{headers}}, $raw;
    $self->handle_header($field_name, $contents, $raw);
}

# Callbacks for subclasses to override
sub handle_header { }
sub finish_header { }
sub finish_body   { }

1;

__END__

=head1 NAME

Mail::DKIM2::HeaderParser - Thin streaming message parser base class

=head1 SYNOPSIS

    package My::Parser;
    use base 'Mail::DKIM2::HeaderParser';

    sub handle_header {
        my ($self, $field_name, $contents, $raw_line) = @_;
        # called for each header
    }

    sub finish_header {
        my $self = shift;
        # called after all headers are parsed
    }

    sub finish_body {
        my $self = shift;
        # called when CLOSE is invoked
    }

=head1 DESCRIPTION

A minimal base class that provides the streaming C<PRINT>/C<CLOSE> interface
for feeding RFC 5322 message data.  It splits input into headers and body,
handles continuation (folded) lines, and invokes callbacks for subclasses.

This replaces the deep C<Mail::DKIM::Common> inheritance chain with a focused
implementation containing only what the DKIM2 Signer and Verifier need.

B<EXPERIMENTAL> — This module implements draft-ietf-dkim-dkim2-spec-01, an
Internet-Draft that has not yet been published as an RFC.  The API and wire
format are subject to change.  Do not use in production.

=head1 METHODS

=head2 new(%args)

Constructor.  Calls C<init()> after blessing.

=head2 init()

Initialises internal state: input buffer, header-parsing flag, and the
C<< $self->{headers} >> arrayref that collects raw header lines.  Subclasses
should call C<< $self->SUPER::init >> if they override this.

=head2 PRINT($data)

Feeds message data (may be called multiple times with arbitrary chunks).
Once the blank line separating headers from body is seen, headers are parsed
and C<finish_header()> is called.

=head2 CLOSE()

Signals end of message.  If headers have not yet been finalised (e.g. a
header-only message), they are parsed now.  Then C<finish_body()> is called.

=head2 handle_header($field_name, $contents, $raw_line)

Callback invoked for each parsed header.  C<$field_name> is the header name,
C<$contents> is the value (without trailing newline), and C<$raw_line> is the
original text including any continuation lines.  Default implementation is a
no-op.

=head2 finish_header()

Callback invoked after all headers have been parsed.  Default is a no-op.

=head2 finish_body()

Callback invoked from C<CLOSE()> after all data has been received.  Default
is a no-op.

=head1 AUTHOR

Bron Gondwana E<lt>brong@fastmailteam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 Fastmail Pty Ltd.  This is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
