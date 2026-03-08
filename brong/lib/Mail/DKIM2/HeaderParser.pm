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
