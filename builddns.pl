#!/usr/bin/perl -w

use 5.020;
use JSON;

my %data;
for my $file (glob "keys/*.pem") {
   next unless $file =~ m{^keys/([^.]+)\._domainkey\.(.*)\.pem$};
   my ($sel, $dom) = ($1, $2);
   my $size = -s $file;
   # smaller than 500 bytes are ed25519
   my $r;
   if ($size < 500) {
      # RFC 8463: raw 32-byte public key, not SPKI-wrapped
      # SPKI DER for Ed25519 is 44 bytes: 12-byte header + 32-byte key
      my $p = `openssl pkey -in $file -pubout -outform DER 2>/dev/null | tail -c 32 | openssl base64 -A`;
      chomp $p;
      $r = "v=DKIM1; k=ed25519; p=$p";
   }
   else {
      my $p = `openssl rsa -in $file -pubout -outform DER 2>/dev/null | openssl base64 -A`;
      chomp $p;
      $r = "v=DKIM1; k=rsa; p=$p";
   }
   push @{$data{$dom}{"$sel._domainkey"}}, ['txt', $r];
}

say JSON->new->canonical->pretty->encode(\%data);
