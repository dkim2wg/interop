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
      # https://www.mailhardener.com/kb/how-to-use-dkim-with-ed25519
      my $p = `openssl asn1parse -in $file -offset 12 -noout -out /dev/stdout | openssl base64`;
      chomp $p;
      $r = "v=DKIM1; k=ed25519; p=$p";
   }
   else {
      # https://www.mailhardener.com/kb/how-to-create-a-dkim-record-with-openssl
      my $p = `openssl ec -in $file -pubout -outform der 2>/dev/null | openssl base64 -A`;
      chomp $p;
      $r = "v=DKIM1; k=rsa; p=$p";
   }
   push @{$data{$dom}{"$sel._domainkey"}}, ['txt', $r];
}

say JSON->new->canonical->pretty->encode(\%data);
