package DKIM2;

use Algorithm::Diff;
use Email::Address;
use List::Util qw(max);
use Mail::DKIM::Signer;
use Mail::DKIM::TextWrap;
use Mail::DKIM::KeyValueList;
use Mail::DKIM::Verifier;
use Mail::DKIM::PublicKey;
use MIME::Base64 qw(encode_base64 decode_base64);

sub undo {
  my ($msg, %args) = @_;
  my @mv = $msg->header_raw('MailVersion');
  my %vmap = map { getv($_) => $_ } @mv;
  my $version = %vmap ? max(keys %vmap) : 0;
  return unless $version;
  my $header = $vmap{$version};

  $msg->header_raw_set('MailVersion', grep { getv($_) < $version } @mv);

  my $data = Mail::DKIM::KeyValueList->parse($vmap{$version});

  for my $tag (@{$data->{tags}}) {
    if ($tag->{name} =~ m/^h\.(.*)/) {
      my $h = $1;
      my $old;
      my @new;
      my @program = split /,/, $tag->{value};
      for my $cmd (@program) {
        if ($cmd =~ m/b:(.*)/) {
          push @new, decode_base64($1);
        } elsif ($cmd =~ m/c:(\d+)-(\d+)/) {
          my ($from, $to) = ($1-1, $2-1);
	  # numbers count indexed 1 from the bottom
          $old ||= [ reverse $msg->header_raw($h) ];
	  push @new, @$old[$from..$to];
        }
      }
      $msg->header_raw_set($h, @new);
    } elsif ($tag->{name} eq 'b') {
      my @lines = split /\r?\n/, $msg->body_raw;
      my @outlist;
      my @program = split /,/, $tag->{value};
      for my $cmd (@program) {
        if ($cmd =~ m/b:(.*)/) {
	  push @outlist, decode_base64($1);
        } elsif ($cmd =~ m/c:(\d+)-(\d+)/) {
	  my ($from, $to) = ($1-1, $2-1);
	  push @outlist, @lines[$from..$to];
        }
      }
      $msg->body_set(join("\r\n", @outlist));
    }
  }

  return $num;
}

# return (num, header)
sub diff {
  my $msg1 = shift;
  my $msg2 = shift;
  # message 2 is the old one; so find out which MailVersion header needs to be added
  my %map = map { getv($_) => $_ } $msg2->header('MailVersion');
  my %dmap = map { getv($_) => $_ } $msg1->header('MailVersion');
  my $num = %map ? max(keys %map) : 0;  
  $num++;
  if ($dmap{$num}) {
    die "Destination message already has MailVersion header v=$num";
  }

  # calculate the header difference

  my %all = map { $_ => 1 } ($msg1->header_names, $msg2->header_names);
  my @hdiff;
  for my $h (sort keys %all) {
    next if should_skip($h);
    my @h1 = reverse $msg1->header_raw($h);
    my @h2 = reverse $msg2->header_raw($h);
    next if join("\n", @h1) eq join("\n", @h2);
    # headers are indexed from 1 from the bottom up
    my %known = map { $h1[$_] => $_+1 } 0..$#h1;
    # we want the values from h2
    my @res = map { $known{$_} ? ['c', $known{$_}, $known{$_}] : ['b', encode_base64($_, '')] } @h2;
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
    my @vals = map { $_->[2] ? "$_->[0]:$_->[1]-$_->[2]" : "$_->[0]:$_->[1]" } grep { defined } @res;
    push @hdiff, @vals ? "h.$h=" . join(',', @vals) : "h.$h";
  }

  # calculate the body differences

  my @l1 = split /\r?\n/, $msg1->body_raw;
  my @l2 = split /\r?\n/, $msg2->body_raw;

  my $diff = Algorithm::Diff->new( \@l1, \@l2 );
  # lines are indexed from 1 from the top down
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
      push @list, map { 'b:' . encode_base64($_, '') } $diff->Items(2);
    }
  }

  if (@list > 1 || $dirty) {
    push @bdiff, "b=" . join(',', @list);
    # XXX - calculate mime part hashes
  }

  return unless (@hdiff or @bdiff);
  return ($num, join("; ", "v=$num", @hdiff, @bdiff));
}

# returns ($num, $header_text)
sub sign {
  my ($msg, %args) = @_;
  my $sel = $args{selector} || 'sel1';
  my $dom = $args{domain} || 'test1.dkim2.com';
  my $key = $args{key} || "../keys/$sel._domainkey.$dom.pem";
  my $alg = $args{algorithm} || (-s $key < 500 ? 'es25519' : 'rsa-sha256');

  my %interesting;
  # we're going to sign everything except trace headers and DKIM-Signature and X-Headers:
  for my $header ($msg->header_names) {
    $interesting{lc($header)} = '+' unless should_skip($header);
  }

  my %map = map { geti($_) => $_ } $msg->header('DKIM2-Signature');
  my $num = %map ? max(keys %map) : 0;
  $num++;
  my %vmap = map { getv($_) => $_ } $msg->header('MailVersion');
  my $version = %vmap ? max(keys %vmap) : 0;

  my $signer = Mail::DKIM::Signer->new(
    Algorithm => $alg,
    Method => 'relaxed/simple',
    Domain => $dom,
    Selector => $sel,
    KeyFile => $key,
  );
  $signer->extended_headers(\%interesting);
  my $eml = $msg->as_string();
  $signer->PRINT($eml);
  $signer->CLOSE();
  my $signature = $signer->signature;
  $signature->set_tag('mv', $version) if $version;
  # remove the generated 'h=' tag 
  my $oldh = $signature->get_tag('h');
  warn $oldh;
  $signature->set_tag('h');
  my $from = $args{from} || extract_from($msg);
  $signature->set_tag('mf', $from);
  my @rt = $args{to} ? @{$args{to}} : extract_to($msg);
  $signature->set_tag('rt', join(',', @rt));
  $signature->prefix("i=$num;");
  return ($num, $signature->as_string());
} 

sub verify {
  my $msg = shift;
  my $pubkey = shift;
  my %map = map { geti($_) => $_ } $msg->header('DKIM2-Signature');
  my $num = %map ? max(keys %map) : 0;
  die "NO NUM" unless $num;
  my $signature = Mail::DKIM::Signature->parse($map{$num});
  my %res;
  $signature->set_tag('i');
  for my $key (qw(mv mf rt)) {
    $res{$key} = $signature->get_tag($key);
    $signature->set_tag($key);
  }
  my @h;
  for my $header ($msg->header_names) {
    next if should_skip($header);
    next if lc $header eq 'dkim2-signature';
    my @vals = $msg->header($header);
    warn "Setting $header " . scalar(@vals);
    push @h, (lc $header) x (1 + scalar @vals);
  }
  $signature->set_tag('h', join(':', sort @h)); # synthetic header field that will work
  # suppress lookup
  my $key = $pubkey->($signature);
  if ($key) {
    $signature->{public_key_query} = 0;
    $signature->{public} = Mail::DKIM::PublicKey->parse($key);
  }
  # set a synthetic signature
  my $dkim = Mail::DKIM::Verifier->new();
  warn "ADDING " . $signature->as_string();
  $dkim->add_signature($signature);
  # strip all DKIM signatures, we aren't verifying those
  $msg->header_raw_set('DKIM-Signature');
  $dkim->PRINT($msg->as_string());
  $dkim->CLOSE();
  $res{result} = $dkim->{result};
  use Data::Dumper;
  warn Dumper($dkim);

  return \%res;
}

sub geti {
  my $arg = shift;
  return 0 unless $arg =~ m/i=(\d+)/;
  return 0 + $1;
}

sub getv {
  my $arg = shift;
  return 0 unless $arg =~ m/v=(\d+)/;
  return 0 + $1;
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
  # stuff we don't sign
  return 1 if $hname eq 'arc-authentication-results';
  return 1 if $hname eq 'arc-message-signature';
  return 1 if $hname eq 'arc-seal';
}

sub extract_from {
  my $msg = shift;
  my @addrs = extract_addrs($msg->header('Sender'), $msg->header('From'));
  return $addrs[0];
}

sub extract_to {
  my $msg = shift;
  my @addrs = extract_addrs($msg->header('To'), $msg->header('Cc'), $msg->header('Bcc'));
  return unless @addrs;
  return join(',', @addrs);
}

sub extract_addrs {
  my %res;
  for my $item (@_) {
    next unless $item;
    my @addrs = Email::Address->parse($item);
    for my $one (@addrs) {
      next unless $one->address;
      $res{lc($one->address)} = 1;
    }
  }
  return sort keys %res;
}

sub bval {
  my $item = shift;
  return "$item->[0]:$item->[1]-$item->[2]" if $item->[0] eq 'c';
  return "$item->[0]:$item->[1]";
}


package Mail::DKIM::DKIM2::Signature;
use strict;
use warnings;
# ABSTRACT: Subclass of Mail::DKIM::Signature which represents a DKIM2-Signature header

# Copyright 2025 FastMail Pty Ltd. All Rights Reserved.
# Bron Gondwana <brong@fastmailteam.com>

# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use base 'Mail::DKIM::Signature';
use Carp;


sub new {
    my $class = shift;
    my %prms  = @_;
    my $self  = {};
    bless $self, $class;

    $self->instance( $prms{'Instance'} ) if exists $prms{'Instance'};
    $self->algorithm( $prms{'Algorithm'} || 'rsa-sha256' );
    $self->signature( $prms{'Signature'} );
    $self->canonicalization( $prms{'Method'} ) if exists $prms{'Method'};
    $self->domain( $prms{'Domain'} );
    $self->protocol( $prms{'Query'} ) if exists $prms{'Query'};
    $self->selector( $prms{'Selector'} );
    $self->timestamp( $prms{'Timestamp'} )   if defined $prms{'Timestamp'};
    $self->tags( $prms{'Tags'} ) if defined $prms{'Tags'};
    $self->key( $prms{'Key'} )               if defined $prms{'Key'};

    return $self;
}

sub DEFAULT_PREFIX {
    return 'DKIM2-Signature:';
}

sub instance {
    my $self = shift;

    # DKIM2 identities must be a number
    if (@_) {
        my $val = int(shift);
        die "INVALID instance $val" unless ( $val > 0 and $val < 1025 );
        $self->set_tag( 'i', $val );
    }

    my $i = $self->get_tag('i');
    return $i;
}

1;

