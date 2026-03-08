package Mail::DKIM2::Signature;
use strict;
use warnings;

use Mail::DKIM::KeyValueList;
use Mail::DKIM::PublicKey;
use MIME::Base64 qw(encode_base64 decode_base64);
use Carp;

use Mail::DKIM2::Common qw(encode_tag_json decode_tag_json);

use base 'Mail::DKIM::KeyValueList';

# --- Construction ---

sub new {
    my ($class, %args) = @_;

    my $self = $class->SUPER::new();
    bless $self, $class;

    $self->set_tag('i', $args{Sequence})  if defined $args{Sequence};
    $self->set_tag('v', $args{Version})   if defined $args{Version};
    $self->set_tag('t', $args{Timestamp}) if defined $args{Timestamp};
    $self->set_tag('d', $args{Domain})    if defined $args{Domain};
    $self->set_tag('n', $args{Nonce})     if defined $args{Nonce};

    if (defined $args{Flags}) {
        $self->set_tag('f', join(',', @{$args{Flags}}));
    }

    if (defined $args{SmtpParams}) {
        $self->set_tag('m', encode_tag_json($args{SmtpParams}));
    }

    if (defined $args{Signatures}) {
        $self->set_tag('s', encode_tag_json($args{Signatures}));
    }

    return $self;
}

# --- Parse from header line ---

sub parse {
    my ($class, $header_line) = @_;
    # Strip "DKIM2-Signature:" prefix if present
    $header_line =~ s/^\s*DKIM2-Signature:\s*//i;
    my $self = $class->SUPER::parse($header_line);
    bless $self, ref($class) || $class;
    return $self;
}

# --- Tag accessors ---

sub sequence {
    my $self = shift;
    if (@_) { $self->set_tag('i', shift) }
    return $self->get_tag('i');
}

sub version {
    my $self = shift;
    if (@_) { $self->set_tag('v', shift) }
    return $self->get_tag('v');
}

sub timestamp {
    my $self = shift;
    if (@_) { $self->set_tag('t', shift) }
    return $self->get_tag('t');
}

sub domain {
    my $self = shift;
    if (@_) { $self->set_tag('d', shift) }
    return $self->get_tag('d');
}

sub nonce {
    my $self = shift;
    if (@_) { $self->set_tag('n', shift) }
    return $self->get_tag('n');
}

sub flags {
    my $self = shift;
    my $f = $self->get_tag('f');
    return unless defined $f;
    return [split /,/, $f];
}

# --- JSON tag accessors ---

sub smtp_params {
    my $self = shift;
    my $m = $self->get_tag('m');
    return unless defined $m;
    return decode_tag_json($m);
}

sub signatures_data {
    my $self = shift;
    my $s = $self->get_tag('s');
    return unless defined $s;
    return decode_tag_json($s);
}

# --- Convenience methods for SMTP params ---

sub mail_from {
    my $self = shift;
    my $params = $self->smtp_params;
    return unless $params;
    return $params->{mf};
}

sub rcpt_to {
    my $self = shift;
    my $params = $self->smtp_params;
    return unless $params;
    return $params->{rt};
}

# --- Convenience methods for signature items ---

sub selector {
    my ($self, $idx) = @_;
    $idx //= 0;
    my $sigs = $self->signatures_data;
    return unless $sigs && $sigs->[$idx];
    return $sigs->[$idx]{s};
}

sub algorithm {
    my ($self, $idx) = @_;
    $idx //= 0;
    my $sigs = $self->signatures_data;
    return unless $sigs && $sigs->[$idx];
    return $sigs->[$idx]{a};
}

sub signature_value {
    my ($self, $idx) = @_;
    $idx //= 0;
    my $sigs = $self->signatures_data;
    return unless $sigs && $sigs->[$idx];
    return $sigs->[$idx]{b};
}

# --- Serialization ---

sub as_string {
    my ($self) = @_;
    return "DKIM2-Signature: " . $self->SUPER::as_string();
}

# For signing: serialize with empty signature values in s= tag
sub as_string_without_data {
    my ($self) = @_;
    my $sigs = $self->signatures_data;
    return $self->as_string() unless $sigs;

    # Create a copy with empty b= values in each signature item
    my @empty_sigs = map {
        my %copy = %$_;
        $copy{b} = '';
        \%copy;
    } @$sigs;

    my $saved = $self->get_tag('s');
    $self->set_tag('s', encode_tag_json(\@empty_sigs));
    my $result = $self->as_string();
    $self->set_tag('s', $saved);
    return $result;
}

# --- DNS key lookup ---

sub fetch_public_key {
    my ($self, $idx) = @_;
    $idx //= 0;
    my $sel = $self->selector($idx);
    my $dom = $self->domain;
    croak "missing selector or domain" unless $sel && $dom;
    return Mail::DKIM::PublicKey->fetch(
        Protocol => 'dns/txt',
        Selector => $sel,
        Domain   => $dom,
    );
}

1;
