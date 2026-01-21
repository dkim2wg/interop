package DKIM2;
use strict;
use warnings;

use Algorithm::Diff;
use Email::Address;
use List::Util qw(max);
use Mail::DKIM::Signer;
use Mail::DKIM::TextWrap;
use Mail::DKIM::KeyValueList;
use Mail::DKIM::Verifier;
use Mail::DKIM::PublicKey;
use Mail::DKIM::Canonicalization::relaxed;
use Digest::SHA;
use MIME::Base64 qw(encode_base64 decode_base64);
use Carp;

# monkeypatch clone - it doesn't do the right thing
# if a prefix is set right now
BEGIN {
    *Mail::DKIM::Signature::clone = sub {
       my $self = shift;
       my $clone = ref($self)->new();
       $clone->prefix($self->prefix());
       return $clone->parse($self->as_string());
    };
}


sub undo {
  my ($msg, %args) = @_;
  my @mi = $msg->header_raw('Message-Instance');
  my %mimap = map { getmi($_) => $_ } @mi;
  my $instance = %mimap ? max(keys %mimap) : 0;
  return unless $instance;
  my $header = $mimap{$instance};

  my $data = Mail::DKIM::KeyValueList->parse($header);

  for my $tag (@{$data->{tags}}) {
    next unless $tag->{name};
    if ($tag->{name} =~ m/^r_(.*)/) {
      my $h = $1;
      my $old;
      my @new;
      my @program = split /\s*,\s*/, $tag->{value};
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
    } elsif ($tag->{name} eq 'r') {
      my @lines = split /\r?\n/, $msg->body_raw;
      my @outlist;
      my @program = split /\s*,\s*/, $tag->{value};
      for my $cmd (@program) {
        if ($cmd =~ m/b:(.*)/) {
          push @outlist, decode_base64($1);
        } elsif ($cmd =~ m/c:(\d+)-(\d+)/) {
          my ($from, $to) = ($1-1, $2-1);
          push @outlist, @lines[$from..$to];
        }
      }
      my $body = join("\r\n", @outlist,'');
      $msg->body_set($body);
    }
  }

  $msg->header_raw_set('Message-Instance', grep { getmi($_) < $instance } @mi);

  return $instance;
}

# return (num, header)
sub diff {
  my $msg1 = shift;
  my $msg2 = shift;
  # message 2 is the old one; so find out which Message-Instance header needs to be added
  my %map = map { getmi($_) => $_ } $msg2->header_raw('Message-Instance');
  my %dmap = map { getmi($_) => $_ } $msg1->header_raw('Message-Instance');
  my $num = %map ? max(keys %map) : 0;  
  $num++;
  if ($dmap{$num}) {
    warn "clearing high Message-Instances from destination message";
    my @mi = grep { getmi($_) && getmi($_) < $num } $msg1->header_raw('Message-Instance');
    $msg1->header_raw_set('Message-Instance', @mi);
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
    push @hdiff, "r_$h=" . join(',', @vals);
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
    push @bdiff, "r=" . join(',', @list);
    # XXX - calculate mime part hashes
  }

  return ($num, @hdiff, @bdiff);
}

sub validate {
  my $msg = shift;
  my %dmap = map { getmi($_) => $_ } $msg->header_raw('Message-Instance');
  my $num = %dmap ? max(keys %dmap) : 0;  
  return { valid => 0, error => "not a Message-Instance email" } unless $num;
  my $sig = Mail::DKIM::KeyValueList->parse($dmap{$num});
  my $canon = Mail::DKIM::Canonicalization::relaxed->new(Signature => 'dummy');
  my $header_digest = Digest::SHA->new(256);
  # XXX check that we used sha256
  my %have;
  for my $header (split /:/, $sig->get_tag('h')) {
    $have{$header} ||= [ reverse $msg->header_raw($header) ];
    my $item = shift @{$have{$header}};
    return { valid => 0, error => "missing $header" }
      if not defined $item;
    $header_digest->add($canon->canonicalize_header("$header: $item\r\n"));
  }
  for my $header (keys %have) {
    return { valid => 0, error => "excess copies of $header" }
      if @{$have{$header}};
  }
  return { valid => 0, error => "mismatched header hash" }
    if $sig->get_tag('hh') ne digest64($header_digest);
  my $body_digest = Digest::SHA->new(256);
  $body_digest->add($canon->canonicalize_body($msg->body_raw));
  return { valid => 0, error => "mismatched body hash" }
    if $sig->get_tag('bh') ne digest64($body_digest);

  return { valid => 1, mi => $sig->get_tag('v') };
}

sub calc {
  my $msg = shift;
  my %interesting;
  # we're going to sign everything except trace headers and DKIM-Signature and X-Headers:
  my $canon = Mail::DKIM::Canonicalization::relaxed->new(Signature => 'dummy');
  # XXX - support others?
  my @res;
  my @h;
  my $header_digest = Digest::SHA->new(256);
  for my $header ($msg->header_names) {
    next if should_skip($header);
    for my $item (reverse $msg->header_raw($header)) {
      my $chead = $canon->canonicalize_header("$header: $item\r\n");
      $header_digest->add($chead);
      push @h, lc($header);
    }
  }
  push @res, "a1=sha256";
  push @res, "h=" . join(':', @h);
  push @res, "h1=" . digest64($header_digest);
  my $body_digest = Digest::SHA->new(256);
  $body_digest->add($canon->canonicalize_body($msg->body_raw));
  push @res, "b1=" . digest64($body_digest);
  return @res;
}

sub digest64 {
  my $digest = shift;
  my $res = $digest->b64digest;
  while (length($res) % 4) {
    $res .= '=';
  }
  return $res;
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

  my %map = map { geti($_) => $_ } $msg->header_raw('DKIM2-Signature');
  my $num = %map ? max(keys %map) : 0;
  $num++;
  my %mimap = map { getmi($_) => $_ } $msg->header_raw('Message-Instance');
  my $instance = %mimap ? max(keys %mimap) : 0;

  my $mi = Mail::DKIM::KeyValueList->parse($mimap{$instance});

  my $from = $args{from} || extract_from($msg);
  my @rt = $args{to} ? @{$args{to}} : extract_to($msg);

  my $signature = Mail::DKIM::Signature->new(
    Algorithm => $alg,
    Method => 'relaxed/relaxed',
    Domain => $dom,
    Selector => $sel,
    KeyFile => $key,
  );
  $signature->prefix("DKIM2-Signature: i=$num;");
  $signature->set_tag('v', $instance) if $instance;
  $signature->set_tag('t', time());
  $signature->set_tag('mf', "<$from>");
  $signature->set_tag('rt', join('', map { "<$_>" } @rt));
  $signature->headerlist($mi->get_tag('h'));
  my $policysub = sub {
    my $self = shift;
    $self->add_signature($signature);
    return;
  };

  my $signer = Mail::DKIM::Signer->new(
    Algorithm => $alg,
    Method => 'relaxed/relaxed',
    Domain => $dom,
    Selector => $sel,
    KeyFile => $key,
    Policy => $policysub,
  );
  $signer->extended_headers(\%interesting);
  my $eml = $msg->as_string();
  $signer->PRINT($eml);

  # Add the mailversion and dkim headers in order
  {
    my $dest = $signer->{algorithms}[0]{canon};
    my $mi = 1;
    my $i = 1;
    while ($i < $num) {
      my $dk2 = $map{$i};
      my $to = getmi($dk2);
      while ($mi <= $to) {
        my $val = $mimap{$mi};
        die "NO DATA FOR v=$mi" unless $val;
        $dest->output($dest->canonicalize_header("Message-Instance: $val\r\n"));
        $mi++;
      }
      $dest->output($dest->canonicalize_header("DKIM2-Signature: $dk2\r\n"));
      $i++;
    }
    while ($mi <= $instance) {
      my $val = $mimap{$mi};
      die "NO DATA FOR v=$mi" unless $val;
      $dest->output($dest->canonicalize_header("Message-Instance: $val\r\n"));
      $mi++;
    }
  }

  $signer->CLOSE();
  return ($num, $signature->as_string());
}

sub verify {
  my $msg = shift;
  my $pubkey = shift;
  my %map = map { geti($_) => $_ } $msg->header_raw('DKIM2-Signature');
  my %mimap = map { getmi($_) => $_ } $msg->header_raw('Message-Instance');
  my $instance = %mimap ? max(keys %mimap) : 0;
  my $num = %map ? max(keys %map) : 0;
  die "NO NUM" unless $num;
  my $signature = Mail::DKIM::Signature->new();
  $signature->prefix("DKIM2-Signature: i=$num; ");
  my $val = $map{$num};
  $val =~ s/^i=\d+; //;
  $signature = $signature->parse($val);
  # suppress lookup
  my $key = $pubkey->($signature);
  if ($key) {
    $signature->{public_key_query} = 0;
    $signature->{public} = Mail::DKIM::PublicKey->parse($key);
  }
  # set a synthetic signature
  my $dkim = Mail::DKIM::Verifier->new();
  $dkim->add_signature($signature);
  $dkim->PRINT($msg->as_string());
  # Add the mailversion and dkim headers in order
  {
    my $dest = $dkim->{algorithms}[0]{canon};
    my $mi = 1;
    my $i = 1;
    while ($i < $num) {
      my $dk2 = $map{$i};
      my $to = getmi($dk2);
      while ($mi <= $to) {
        my $val = $mimap{$mi};
        die "NO DATA FOR v=$mi" unless $val;
        $dest->output($dest->canonicalize_header("Message-Instance: $val\r\n"));
        $mi++;
      }
      $dest->output($dest->canonicalize_header("DKIM2-Signature: $dk2\r\n"));
      $i++;
    }
    while ($mi <= $instance) {
      my $val = $mimap{$mi};
      die "NO DATA FOR v=$mi" unless $val;
      $dest->output($dest->canonicalize_header("Message-Instance: $val\r\n"));
      $mi++;
    }
  }
  $dkim->CLOSE();
  my %res;
  $res{result} = $dkim->{result};
  $res{s} = $signature->get_tag('s');
  $res{d} = $signature->get_tag('d');
  return \%res;
}

sub geti {
  my $arg = shift;
  return 0 unless $arg =~ m/\bi=(\d+)/;
  return 0 + $1;
}

sub getmi {
  my $arg = shift;
  return 0 unless $arg =~ m/v=(\d+)/;
  return 0 + $1;
}

sub should_skip {
  my $hname = lc(shift);
  # Trace Headers
  return 1 if $hname eq 'received';
  return 1 if $hname eq 'return-path';
  return 1 if $hname eq 'message-instance';
  return 1 if $hname eq 'dkim2-signature';
  # X headers
  return 1 if $hname =~ m/^x-/;
  # stuff we don't sign
  return 1 if $hname eq 'dkim-signature';
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

1;
