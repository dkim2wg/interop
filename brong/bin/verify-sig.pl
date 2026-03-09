#!/usr/bin/perl -w

use 5.020;
use Path::Tiny;
use Email::MIME;
use lib 'lib';
use Mail::DKIM2::Verifier;
use Mail::DKIM::PublicKey;
use JSON;

my $f1 = shift;
my $msg1 = Email::MIME->new(path($f1)->slurp);
my $dns = decode_json(path('../dns.json')->slurp);

my $verifier = Mail::DKIM2::Verifier->new();
$verifier->set_pubkey_callback(sub { find_key(@_) });
$verifier->PRINT($msg1->as_string());
$verifier->CLOSE;

say $verifier->result_detail();

sub find_key {
  my $signature = shift;
  my $sel = $signature->selector(0);
  my $dom = $signature->domain;
  my $key_txt = $dns->{$dom}{"$sel._domainkey"}[0][1];
  return unless $key_txt;
  return Mail::DKIM::PublicKey->parse($key_txt);
}
