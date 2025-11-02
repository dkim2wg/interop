# DKIM2

package DKIM2crypto;

use strict;

use Digest::SHA qw(sha256_base64);
use MIME::Base64::Perl;

#============
sub DKIM2sign
#============
#
# usage
#
#  $signature = DKIM2sign ($message,
#                          $hop,
#                          $version,
#                          @headerlist,
#                          $nonce,
#                          $mf,
#                          $rt,
#                          $domain,
#                          [$algorithm1, $selector1, $privatekeyfile1],
#                          [$algorithm2, $selector1, $privatekeyfile2])
#
#
{
   my ($message, $hop, $version, $headerlist, $nonce, $mf, $rt, $domain, $signinfo1, $signinfo2) = @_;

   #-------------------------------------------------------------------------------------
   # canonicalise the message
   #-------------------------------------------------------------------------------------

   my %header;

   my $bodydigest = Digest::SHA->new(256);

   my $state = 0;
   my $headline;
   my $emptylines = 0;

   while ($message)
   {
      my $line = ($message =~ /^(.*?)\r\n(.*)$/) ? $1 : $message;

      $message = $2;

      if ($state == 0)
      {
         $headline = $line;
         $state = 1;
      }
      elsif ($state == 1)
      {
         if ($line =~ /^\s+/)
         {
            $headline .= $line;
         }
         else
         {
            $headline =~ s/\s+/ /g;

            if ($headline =~ /^(\S+)\s?:\s?(.*?)\s+$/)
            {
                my $tag = lc($1);
                my $val = $2;

                push(@{$header{$tag}}, "$tag:$val\r\n") unless ($tag eq "received")
                                                            || ($tag eq "return-path")
                                                            || ($tag eq "dkim-signature")
                                                            || ($tag =~ /^x-/);
            }

            if ($line)
            {
               $headline = $line;
            }
            else
            {
               $state = 2;
            }
         }
      }
      elsif ($state == 2)
      {
         # we are in the body, calculate the digest as we go along

         $line =~ s/\s+/ /g;
         $line =~ s/\s$//;

         if ($line)
         {
            for (my $i=0; $i<$emptylines; $i++)
            {
               $bodydigest->add("\r\n");
            }
            $bodydigest->add($line . "\r\n");

            $emptylines = 0;
         }
         else
         {
            $emptylines++;
         }
      }
   }

   my $bodyhash = $bodydigest->b64digest;

   my @DKIM2header;

   my $headdigest = Digest::SHA->new(256);

   foreach my $tag (sort keys %header)
   {
      foreach my $h (@{$header{$tag}})
      {
         if ($h =~ /^DKIM2/)
         {
            $DKIM2header[$1] = $h if ($h =~ /;\s*i=(\d+)\s*;/);
         }
         else
         {
            $headdigest->add($h);
         }
      }
   }

   for (my $i=0; $i<$#DKIM2header; $i++)
   {
      $headdigest->add($DKIM2header[$i]);
   }

   #-------------------------------------------------------------------------------------
   # generate the DKIM2 line
   #-------------------------------------------------------------------------------------

   # build the basic DKIM2 header field

   my ($s,$m,$h,$D,$M,$Y) = gmtime(time());
   my $stamp = sprintf("%04d-%02d-%02dT%02d:%02d:%02d", $Y+1900, $M+1, $D, $h, $m, $s);

   my $htag = ($#{$headerlist}) ? join(':', @$headerlist) : "";
   $htag = " h=$htag;" if ($htag);

   my $crypto = "a1=$$signinfo1[0]; s1=$$signinfo1[1]; bh1=$bodyhash;";
   $crypto  .= " a2=$$signinfo2[0]; s2=$$signinfo2[1]; bh2=$bodyhash;" if ($$signinfo2[0]);

   my $newDKIM2 = sprintf("DKIM2-Signature: i=%d; mv=%d; t=%s;%s n=%s; mf=%s; rt=%s; d=%s; %s",
                          $hop,           # i=
                          $version,       # mv=
                          $stamp,         # t=
                          $htag,          # h=
                          $nonce,         # n=
                          $mf,            # mf=
                          $rt,            # rt=
                          $domain,        # d=
                          $crypto,        # a1= s1= bh1=
                         );

   my $placeholder = "b1=;";

   $placeholder   .= ($$signinfo2[0])
                        ? " b2=;\r\n"
                        : "\r\n";

   $headdigest->add($newDKIM2 . $placeholder);

   my $hash = $headdigest->digest;

   # sign the hash of the headers

   my $sig1 = signature($$signinfo1[0], $$signinfo1[2], $hash);
   my $sig2 = signature($$signinfo2[0], $$signinfo2[2], $hash);

   # try to get sensible line lengths

   my @segments;

   while ($newDKIM2)
   {
      if ($newDKIM2 =~ /^(.{1,78}[;\s])(.*)$/s)
      {
         my $seg = $1;
         $newDKIM2 = $2;

         $seg =~ s/\s+(\r|$)//;
         push(@segments, $seg);
      }
      else
      {
         last;
      }
   }

   $newDKIM2 = join("\r\n\t", @segments) . $newDKIM2;

   # now add the signatures

   $newDKIM2 .= "\r\n\tb1=$sig1";
   $newDKIM2 .= "\r\n\tb2=$sig2" if ($$signinfo2[0]);
   $newDKIM2 .= ";\r\n";

   return $newDKIM2;
}

#============
sub signature
#============
{
   my ($algorithm, $keyfile, $hash) = @_;

   return "" unless ($algorithm);

   my $sig;

   if ($algorithm eq "rsa-sha256")
   {
       my $keystring;

       open(KEY, "<", $keyfile) or die "Failed to open 'keyfile': $!";

       while (<KEY>)
       {
          $keystring .= $_;
       }

       close KEY;

       my $pk = Crypt::OpenSSL::RSA->new_private_key($keystring);
       $sig = $pk->sign($hash);
   }
   elsif ($algorithm eq "ed55219")
   {
       my $pk = Crypt::PK::Ed25519->new($keyfile);
       $sig = $pk->sign_message($hash);
   }
   else
   {
       die "$algorithm is not supported";
   }

   my $encoded = encode_base64($sig);

   $encoded =~ s/\r//gs;
   $encoded =~ s/\n//gs;

   my $sigtext = substr($encoded, 0, 73) . "\r\n\t";
   my $rest    = substr($encoded, 73);

   while (length($rest) > 76)
   {
      $sigtext .= substr($rest, 0, 76) . "\r\n\t";
      $rest     = substr($rest, 76);
   }

   $sigtext .= $rest;

   return $sigtext;
}

1;
 
#ends
