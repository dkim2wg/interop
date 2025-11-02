#!/usr/bin/perl -I.
#
# Mail server to demo DKIM2
#
# Written March 2024 Richard Clayton <richard@highwayman.com>
#

use strict;
use Socket;
use IO::Socket;
use IO::Socket::INET;
use IO::Select;
use IO::Handle;
use Time::Local;
use Digest::SHA qw(sha256_base64);
use Mail::DKIM;
use Mail::DKIM::Signer;
use Net::DNS::Resolver;
use Net::DNS::RR::MX;

use DKIM2crypto;

our $TRUE  = 1;
our $FALSE = 0;

$| = 1, select $_ for select STDERR;      # don't buffer STDERR
$| = 1;                                   # or STDOUT

our $debug = $TRUE;

our $codechar = "";

if ($ARGV[0] && ($ARGV[0] =~ /^CODE=(\d+)$/i))
{
   $codechar = chr($1);
   shift(@ARGV);
}

# we need to know the IP address we will use (which is "me", but for clarity set it expressly)

die "usage: perl -w dkim2.pl <IP address> <hostname>\n" unless (($#ARGV == 1) && $ARGV[0] && ($ARGV[0] =~ /^(\d+\.\d+\.\d+\.\d+)$/));

our $srcIP    = $1;
our $hostname = $ARGV[1];

our $DNSserver1 = "8.8.8.8";
our $DNSserver2 = "8.8.4.4";

# shutting down

our $sigINT : shared = $FALSE;

$SIG{'INT'} = \&sigINT_handler;

#----------------------------------------------------------------------------
# globals
#----------------------------------------------------------------------------

# state of SMTP sending

our $stateWAIT   = 0;     # waiting to connect (relay only)
our $stateNONE   = 1;     # connected
our $stateHELO   = 2;     # have sent/received HELO
our $stateAUTH   = 3;
our $stateMAIL   = 4;     # have sent/received MAIL
our $stateRCPT   = 5;     # have sent/received RCPT
our $stateDATA   = 6;     # have sent/received DATA
our $stateBULK   = 7;     # doing transfer
our $stateCLOSED = 8;     # waiting to close

# SMTP relay request array

our %relayrequest;       # outgoing SMTP connections required

our $relayState     = 0;
our $relayDomain    = 1;
our $relayFrom      = 2;
our $relayTo        = 3;
our $relayMail      = 4;

# state of SMTP relay

our $relayDNS     = 100;   # waiting for DNS results
our $relayACTIVE  = 101;   # connecting and trying to send
our $relaySUCCESS = 102;   # send succeeded
our $relayFAIL    = 103;   # send failed

# DNS lookups

our $countDNS     = 0;

our @DNSaction;

our $dnsState     = 0;     # state
our $dnsIdent     = 1;     # identity (groups DNS results)
our $dnsHandle    = 2;     # handle for an active lookup
our $dnsHost      = 3;     # host being looked up
our $dnsPref      = 4;     # preference (+ve) or A order (-ve)

our $dnsMX        = 0;     # state: looking up MX
our $dnsA         = 1;     # state: looking up A 
our $dnsDONE      = 2;     # state: we have an IP address
our $dnsIGNORE    = 3;     # state: ignore this entry

our %DNSresults;

# protocol/socket information

our $sessionID  = 0;

our @serverport;         # server port number 

our @remoteIP;           # remote IP     (indexed by file number)
our @portvalue;          # dest port     (indexed by file number)
our @relayinfo;          # server/client (indexed by file number)
our @datain;             # incoming data (indexed by file number)
our @dataout;            # outgoing data (indexed by file number)
our @state;              # state machine (indexed by file number)
our @session;            # session ID    (indexed by file number)
our @sockfile;           # file          (indexed by file number)
our @timeout;            # timeout       (indexed by file number)

our @identity;           # session ident (indexed by file number)
our @mail;               # email content (indexed by file number)
our @returnpath;         # mail from     (indexed by file number)
our @recipient;          # mail to       (indexed by file number)

# logging

our $logfh;              # log file handle
our $logendtime;         # when we will next roll the log

# DNS lookups

our $DNSresolver = Net::DNS::Resolver->new(
                                            nameservers => [ $DNSserver1, $DNSserver2 ],
                                            recurse     => 1,
                                            debug       => $debug
                                          );

# off we go

our $select = IO::Select->new();

logroll($TRUE);

listener(2525);
listener(587);

action();

#=========
sub action
#=========
#
# construct and run the smtp servers
#
{
   # loop, accepting new connections and relaying mail as required

   while (!$sigINT)
   {
      my $now = time();
 
      # every 10 mins, roll the logs and read/write files

      logroll($FALSE) if ($now >= $logendtime);

      # deal with connections we can write to

      foreach my $f ($select->can_write(0))
      {
         my $fn = fileno($f);

         next if ($serverport[$fn]);

         if ($state[$fn] == $stateWAIT)
         {
            if ($f->connected())
            {
               loggera($fn, "--", "connection succeeded --");
               $timeout[$fn] = $now + 600;
               $state[$fn] = $stateNONE;
            }
            else
            {
               my $error = $f->getsockopt(SOL_SOCKET, SO_ERROR);

               next if ($error == $!{EINPROGRESS});

               sessionclose($f, "relay connection failed (error $error)");

               next;
            }
         }

         if ($dataout[$fn])
         {
            my $n = $f->send($dataout[$fn], 0);

            if ($n)
            {
               loggera($fn, ">>", substr($dataout[$fn], 0, $n));

               $dataout[$fn] = substr($dataout[$fn], $n);
            }
            else
            {
               # should we handle error here ?
            }
         }
         else
         {
            if ($state[$fn] == $stateCLOSED)
            {
               sessionclose($f, "connection closed");
            }
         }
      }

      # now find all the sockets we can read from
      # wait 2 seconds if nothing to do at the moment

      foreach my $f ($select->can_read(2))
      {
         my $fn = fileno($f);

         my $port = $serverport[$fn];

         if ($port)
         {
            # we have a new connection -- set everything up

            my $server = $sockfile[$fn]->accept();

            if ($server)
            {
               my $fn = fileno($server);

               $sockfile[$fn] = $server;

               print STDERR "New client: $fn (port $port)\n" if ($debug);

               $session[$fn] = $sessionID++;
               $relayinfo[$fn] = -1; #server

               my $stamp = timestamp(0);
               $stamp =~ s/ /_/g;
               $stamp =~ s/:/_/g;
               $identity[$fn] = sprintf("%s_%07d", $stamp, $session[$fn]);

               my $addr = $server->peeraddr();

               unless ($addr)
               {
                  $logfh->print("\n");
                  logger("--", "accept worked on port $port but client vanished");
                  $logfh->print("\n");

                  next;
               }

               $addr = inet_ntoa($addr);

               $remoteIP[$fn] = $addr;

               # report the connection event

               $logfh->print("\n");
               loggera($fn, "--", "connection opened by $addr --");

               # add new connection into select() structure 

               $server->blocking(0);
               $select->add($server);

               # arrange to send the initial banner

               $portvalue[$fn] = $port;
               $datain[$fn]    = "";

               $dataout[$fn] = "220 $hostname ESTMP server\r\n";
               $state[$fn] = $stateNONE;
            }
            else
            {
               $logfh->print("\n");
               logger("--", "accept for port $port failed --");
               $logfh->print("\n");
            }
         }
         else
         {
            # activity on one of the active sessions

            my $fn = fileno($f);

            unless ($state[$fn] == $stateWAIT)
            {
               my $receive;

               unless (defined(recv($f, $receive, 500, 0)) and $receive)
               {
                  sessionclose($f, "connection closed");
               }
               else
               {
                  loggera($fn, "<<", $receive);

                  print STDERR "client: $fn '$receive'\n" if ($debug);

                  # do protocol things

                  $datain[$fn] .= $receive;

                  if ($relayinfo[$fn] == -1)
                  {
                     serverprotocol($fn) unless ($state[$fn] == $stateCLOSED);
                  }
                  else
                  {
                     clientprotocol($fn) unless ($state[$fn] == $stateCLOSED);
                  }
               }
            }
         }
      }

      # forcibly close any connections that have gone quiet

      $now = time();

      for (my $i = 0; $i <= $#timeout; $i++)
      {
         next if ($serverport[$i]);
         next unless ($timeout[$i]);

         next unless ($now > $timeout[$i]);

         print STDERR "Inactivity timeout: $i\n" if ($debug);

         sessionclose($sockfile[$i], "inactivity timeout closes the session");
      }

      # deal with relaying

      DNSanswers();

      clientconnect();
   }

   logger("--", "Server stopping --");
   $logfh->flush();
}

#=================
sub serverprotocol
#=================
{
   my ($fn) = @_;

   while ($TRUE)
   {
      return unless ($datain[$fn] =~ /^(.*?)\r\n(.*)$/s);

      my $now = time();
      $timeout[$fn] = $now + 300;

      my $line = $1;
      $datain[$fn] = $2;

      if ($state[$fn] == $stateBULK)
      {
          $timeout[$fn] = $now + 180;

          if ($line eq ".")
          {
             $timeout[$fn] = $now + 600;
             processBULK($fn);

             $state[$fn] = $stateHELO;
             next;
          }

          $line =~ s/^\.\././;

          $mail[$fn] .= $line . "\r\n";
      }
      elsif ($line eq "")
      {
         $dataout[$fn] .= "500 blank line\r\n";
      }
      elsif ($line =~ /^noop(\s|$)/i)
      {
         $dataout[$fn] .= "250 2.0.0 nothing done\r\n";
      }
      elsif ($line =~ /^(send|soml|saml|turn)(\s|$)/i)
      {
         $dataout[$fn] .= "502 5.5.1 $1 not implemented\r\n";
      }
      elsif ($line =~ /^(expn|vrfy)(\s|$)/i)
      {
         $dataout[$fn] .= "252 2.2.0 wrong century\r\n";
      }
      elsif ($line =~ /^help(\s|$)/i)
      {
         $dataout[$fn] .= "211 2.3.0 $hostname ESMTP server\r\n";
      }
      elsif ($line =~ /^quit(\s|$)/i)
      {
         $dataout[$fn] .= "221 2.0.0 $hostname closing\r\n";
         $state[$fn] = $stateCLOSED;
      }
      elsif ($line =~ /^rset(\s|$)/i)
      {
         $state[$fn] = $stateHELO unless ($state[$fn] == $stateNONE);

         initemail($fn);

         $dataout[$fn] .= "250 2.0.0 my mind is blank\r\n";
      }
      elsif ($line =~ /^helo(\s+(.*))?$/i)
      {
         $state[$fn] = $stateHELO;

         initemail($fn);

         $dataout[$fn] .= "250 pleased to meet you\r\n";
      }
      elsif ($line =~ /^ehlo(\s+(.*))?$/i)
      {
         $state[$fn] = $stateHELO;

         initemail($fn);

         $dataout[$fn] .= "250-pleased to meet you\r\n";
         $dataout[$fn] .= "250-EXPN\r\n";
         $dataout[$fn] .= "250-HELP\r\n";
         $dataout[$fn] .= "250-8BITMIME\r\n";
         $dataout[$fn] .= "250-DSN\r\n";
         $dataout[$fn] .= "250-ENHANCEDSTATUSCODES\r\n";
         $dataout[$fn] .= "250 PIPELINING\r\n";
      }
      elsif ($line =~ /^mail\s+from:\s*(.*?)\s*$/i)
      {
         next unless (insist($fn, $stateHELO));

         next unless (parseMAIL($fn, $1));

         $state[$fn] = $stateMAIL;
      }
      elsif ($line =~ /^rcpt\s+to:\s*(.*?)\s*$/i)
      {
         if ($state[$fn] == $stateDATA)
         {
            $dataout[$fn] .= "452 5.5.3 Too many recipients: this is DKIM2!\r\n";
            next;
         }

         next unless (insist($fn, $stateMAIL));

         next unless (parseRCPT($fn, $1));

         $state[$fn] = $stateDATA;
      }
      elsif ($line =~ /^data(\s|$)/i)
      {
         next unless (insist($fn, $stateDATA));

         $dataout[$fn] .= "354 ready for data\r\n";

         $state[$fn] = $stateBULK;
      }
      else
      {
         $dataout[$fn] .= "501 5.5.1 bad command\r\n";
      }
   }
}

#=========
sub insist
#=========
#
# SMTP state machine checking
#
{
   my ($fn, $wanted) = @_;

   return $TRUE if ($state[$fn] == $wanted);

   if ($state[$fn] == $stateNONE)
   {
      $dataout[$fn] .= "503 5.5.1 you must say ehlo to me\r\n";
   }
   else
   {
      $dataout[$fn] .= "503 5.5.1 Bad sequence of commands\r\n";
   }

   return $FALSE;
}

#============
sub initemail
#============
{
   my ($fn) = @_;

   $returnpath[$fn] = "";
   $mail[$fn]       = "";
   $recipient[$fn]  = "";
}

#============
sub parseMAIL
#============
#
# parse a MAIL FROM command : reverse-path [SP mail-parameters ]
# since this is a demo program we will not handle the full range of syntax here
#
{
   my ($fn, $string) = @_;

   if ($string =~ /<(|[a-z0-9\.:;]+@[-a-z0-9\.]+)>\s*(.*)$/)
   {
      if ($2)
      {
         $dataout[$fn] .= "553 5.3.3 parameters not supported\r\n";
         return $FALSE;
      }

      $returnpath[$fn] = $1;
   }
   else
   {
      $dataout[$fn] .= "553 5.1.7 mailbox not recognised\r\n";
      return $FALSE;
   }

   $dataout[$fn] .= "250 2.1.0 OK, MAIL\r\n";
   return $TRUE;
}

#============
sub parseRCPT
#============
#
# parse a RCPT TO command : reverse-path [SP mail-parameters ]
# since this is a demo program we will not handle the full range of syntax here
#
{
   my ($fn, $string) = @_;

   if ($string =~ /<([a-z0-9\.:;]+@[-a-z0-9\.]+)>$/)
   {
      $recipient[$fn] = $1;
   }
   elsif ($string =~ /<postmaster>/i)
   {
      $recipient[$fn] = "postmaster";
   }
   else
   {
      $dataout[$fn] .= "501 5.5.1 syntax error\r\n";
      return $FALSE;
   }

   $dataout[$fn] .= "250 2.1.5 OK, RCPT\r\n";
   return $TRUE;
}

#==============
sub processBULK
#==============
#
# we have an entire email to hand
#
{
   my ($fn) = @_;

   # DKIM1 signature added iff using submission port

   my $dkim1sig = "";
   my $dkim2sig = "";

   if ($portvalue[$fn] == 587)
   {
      # submission server -- add DKIM1 signature

      my $signer = Mail::DKIM::Signer->new(
                                            Algorithm => 'rsa-sha256',
                                            Method => 'relaxed',
                                            Domain => 'dkim2.org',
                                            Selector => 'rnc1',
                                            KeyFile => 'dkim2.org.private.key',
                                            Headers => '',
                                          );

      $signer->PRINT($mail[$fn]);
      $signer->CLOSE();

      my $signature = $signer->signature;

      $signature->prettify();

      $dkim1sig = $signature->as_string() . "\r\n";

      # submission server -- add DKIM2 signature

      $dkim2sig = DKIM2crypto::DKIM2sign($mail[$fn],       # message
                                         1,                # hop 0
                                         0,                # initial version
                                         [],               # no headers added
                                         $fn,              # nonce
                                         $returnpath[$fn], # mail from 
                                         $recipient[$fn],  # rcpt to 
                                         'dkim2.org',      # signing domain
                                         ['rsa-sha256',
                                          'rnc1',
                                          'dkim2.org.private.key'],
                                         []
                                        );
   }

   # Received line always required

   my $received = "Received: ";

   if ($returnpath[$fn])
   {
      $received .= "from $returnpath[$fn] ($remoteIP[$fn]);";
   }
   else
   {
      $received .= "from $remoteIP[$fn];";
   }

   $received = addreceived($received, "by $hostname;");
   $received = addreceived($received, "with ESMTP;");
   $received = addreceived($received, "id $identity[$fn];");
   $received = addreceived($received, "for $recipient[$fn];");
   $received = addreceived($received, RFC1036_date_time());

   # add the new headers

   $mail[$fn] = $received . "\r\n" . $dkim1sig . $dkim2sig . $mail[$fn];

   # record what we have

   my $sha = sha256_base64($mail[$fn]);

   my $filename = sprintf("%s.mail.txt", $identity[$fn]);

   open(MAIL, ">", $filename) or die "Failed to open '$filename': $!"; 

   printf MAIL "FROM: $returnpath[$fn]\r\n";
   printf MAIL "TO:   $recipient[$fn]\r\n";
   printf MAIL "HASH: $sha\r\n";
   printf MAIL $mail[$fn];

   close MAIL;

   # continue with the protocol

   $dataout[$fn] .= "250 2.6.0 mail received in $filename\r\n";

   if ($recipient[$fn] =~ /@(.*+)$/)
   {
      my $todomain = $1;

      unless ($recipient[$fn] eq "dkim2.org")
      {
         DNSlookup($dnsMX, $countDNS, $todomain, 0);

         #                              0          1          2                 3                4
         @{$relayrequest{$countDNS}} = ($relayDNS, $todomain, $returnpath[$fn], $recipient[$fn], $mail[$fn]);

         $countDNS++;
      }
   }
}

#=================
sub clientprotocol
#=================
{
   my ($fn) = @_;

   while ($TRUE)
   {
      return unless ($datain[$fn] =~ /(^|\r\n)(\d)\d\d .*?\r\n(.*)$/);
      
      my $code = $2;
      $datain[$fn] = $3;

      my $now = time();
      $timeout[$fn] = $now + 180;

      if ($state[$fn] == $stateNONE)
      {
         if ($code == 2)
         {
            $dataout[$fn] .= "HELO $hostname\r\n";
            $state[$fn] = $stateHELO;
            next;
         }
      }
      elsif ($state[$fn] == $stateHELO)
      {
         if ($code == 2)
         {
            $dataout[$fn] .= "MAIL FROM:<$returnpath[$fn]>\r\n";
            $state[$fn] = $stateMAIL;
            next;
         }
      }
      elsif ($state[$fn] == $stateMAIL)
      {
         if ($code == 2)
         {
            $dataout[$fn] .= "RCPT TO:<$recipient[$fn]>\r\n";
            $state[$fn] = $stateRCPT;
            next;
         }
      }
      elsif ($state[$fn] == $stateRCPT)
      {
         if ($code == 2)
         {
            $dataout[$fn] .= "DATA\r\n";
            $state[$fn] = $stateDATA;
            next;
         }
      }
      elsif ($state[$fn] == $stateDATA)
      {
         if ($code == 3)
         {
            my $m = $mail[$fn];

            $m =~ s/^\./../;
            $m =~ s/\r\n\./\r\n../gs;

            $m =~ s/=><=/=>$codechar<=/ if ($code);

            $dataout[$fn] .= $m . ".\r\n";
            $state[$fn] = $stateBULK;
            $timeout[$fn] = $now + 600;
            next;
         }
      }
      elsif ($state[$fn] == $stateBULK)
      {
         if ($code == 2)
         {
            $dataout[$fn] .= "QUIT\r\n";
            $state[$fn] = $stateCLOSED;

            my $ident = $relayinfo[$fn];
            $relayrequest{$ident}[$relayState] = $relaySUCCESS;
            next;
         }
      }

      if ($code == 5)
      {
         $dataout[$fn] .= "QUIT\r\n";
         $state[$fn] = $stateCLOSED;

         my $ident = $relayinfo[$fn];
         $relayrequest{$ident}[$relayState] = $relayFAIL;
         next;
      }  

      if ($code == 4)
      {
         $dataout[$fn] .= "QUIT\r\n";
         $state[$fn] = $stateCLOSED;
         next;
      }
   }
}

#===========
sub listener
#===========
#
# create a listening socket on the given port
#
{
   my ($port) = @_;

   my $server = IO::Socket::INET->new(
                                        Listen    => 500,
                                        LocalAddr => $srcIP,
                                        LocalPort => $port,
                                        ReuseAddr => 1,
                                        Timeout   => 0,
                                        Proto     => 'tcp'
                                     );

   die "Could not create socket for tcp/$port: $!" unless ($server);

   $server->blocking($FALSE);

   $select->add($server);

   my $fn = fileno($server);
   $sockfile[$fn]   = $server;
   $serverport[$fn] = $port;

   print STDERR "Server for port $port running: $fn\n" if ($debug);
}

#===============
sub sessionclose
#===============
{
   my ($f, $message) = @_;

   my $fn = fileno($f);

   loggera($fn, "--", $message ." --");
   $logfh->flush();

   $select->remove($f);
   $f->close();

   print STDERR "Bye client: $fn\n" if ($debug);

   undef($timeout[$fn]);
   undef($sockfile[$fn]);

   my $ident = $relayinfo[$fn];

   if ($ident != -1)
   {
      if ($relayrequest{$ident}[$relayState] == $relaySUCCESS)
      {
         delete($relayrequest{$ident});
         delete($DNSresults{$ident});
      }
      elsif ($relayrequest{$ident}[$relayState] == $relayFAIL)
      {
         # relay has failed : we need to generate a bounce 
      }
      elsif ($DNSresults{$ident}[0])
      {
         $relayrequest{$ident}[$relayState] = $relayDNS;
      }
      else
      {
         # no more destinations to try : we need to generate a bounce

         $relayrequest{$ident}[$relayState] = $relayFAIL;
      }
   }

   $state[$fn] = $stateNONE;
}

#============
sub DNSlookup
#============
{
   my ($type, $ident, $host, $pref) = @_;

   my $typetext = ($type == $dnsMX) ? 'MX' : 'A';

   my $handle = $DNSresolver->bgsend($host, $typetext) or die $DNSresolver-errorstring();

   #           0      1       2        3      4
   my @info = ($type, $ident, $handle, $host, $pref);

   push(@DNSaction, \@info);
}

#=============
sub DNSanswers
#=============
#
# fetch the DNS answers for MX (and if needed, A) lookups
#
{
   foreach my $act (@DNSaction)
   {
      if ($$act[$dnsState] == $dnsMX)
      {
         unless ($DNSresolver->bgbusy($$act[$dnsHandle]))
         {
            # process MX results

            my $packet = $DNSresolver->bgread($$act[$dnsHandle]);

            $$act[$dnsState] = $dnsIGNORE;
            my $ident = $$act[$dnsIdent];

            if ($packet)
            {
               while (my $rr = $packet->pop('answer'))
               {
                  my $host = $rr->exchange();
                  my $pref = $rr->preference();

                  if ($host =~ /^\d+\.\d+\.\d+\.\d+$/)
                  {
                     my @info = ($dnsDONE, $ident, undef, $host, $pref);
                     push(@DNSaction, \@info); 
                  }
                  elsif ($host =~ /^[0-9:a-f]+$/)
                  {
                     # ignore IPv6                   
                  }
                  else
                  {
                     DNSlookup($dnsA, $ident, $host, $pref);
                  }
               }
            }
            else
            {
               logger("--", "Failed to resolve $$act[$dnsHost] MX");

               DNSlookup($dnsA, $ident, $$act[$dnsHost], -1);
            }
         }
      }

      if ($$act[$dnsState] == $dnsA)
      {
         unless ($DNSresolver->bgbusy($$act[$dnsHandle]))
         {
            # process A results
          
            my $packet = $DNSresolver->bgread($$act[$dnsHandle]);

            $$act[$dnsState] = $dnsIGNORE;
            my $ident = $$act[$dnsIdent];
            my $pref  = $$act[$dnsPref];

            if ($packet)
            {
               while (my $rr = $packet->pop('answer'))
               {
                  my $host = $rr->address();

                  if ($host =~ /^\d+\.\d+\.\d+\.\d+$/)
                  {
                     my @info = ($dnsDONE, $ident, undef, $host, $pref);
                     push(@DNSaction, \@info);
                  }
                  elsif ($host =~ /^[0-9:a-f]+$/)
                  {
                     # ignore IPv6                   
                  }
                  else
                  {
                     DNSlookup($dnsA, $ident, $host, -1);
                  }
               }
            }
            else
            {
               logger("--", "Failed to resolve $$act[$dnsHost] A");
            }
         }
      }

      # make a list of ids

      my %id;

      foreach my $act (@DNSaction)
      {
         $id{$$act[$dnsIdent]}++;
      }

      # for each id see if we have a full set of results

      foreach my $ident (sort {$a <=> $b} keys %id)
      {
         $id{$ident} = $TRUE;

         foreach my $act (@DNSaction)
         {
            $id{$ident} = $FALSE if (($$act[$dnsState] == $dnsA) || ($$act[$dnsState] == $dnsMX));
         }
      }

      # create a hash where we have a full set of results
      # and build a list of still to do

      my @keepaction;
      my %doneaction;

      foreach my $act (@DNSaction)
      {
         my $ident = $$act[$dnsIdent];

         if ($id{$ident})
         {
            $doneaction{$ident}{$$act[$dnsPref]}{$$act[$dnsHost]}++;
         }
         else
         {
            push(@keepaction, $act) unless ($$act[$dnsState] == $dnsIGNORE);
         }
      }

      # update the list of DNS lookups that are still active

      undef(@DNSaction);
      push(@DNSaction, @keepaction) if ($keepaction[0]);

      # construct the list of IPs we will connect to (note for MX we prefer lower values)
      # we ensure IPs are unique

      my %seenIP;

      foreach my $ident (sort {$a <=> $b} keys %doneaction)
      {
         foreach my $pref (sort {$b <=> $a} keys %{$doneaction{$ident}})
         {
            foreach my $host (sort keys %{$doneaction{$ident}{$pref}})
            {
               push(@{$DNSresults{$ident}}, $host) unless ($seenIP{$host});
               $seenIP{$host}++;
            }
         }
      }
   }
}

#================
sub clientconnect
#================
{
   foreach my $ident (sort {$a <=> $b} keys %relayrequest)
   {
       next unless ($relayrequest{$ident}[$relayState] == $relayDNS);

       my $addr = shift(@{$DNSresults{$ident}});

       next unless ($addr);

       my $now = time();

       my $port = 25;

       $relayrequest{$ident}[$relayState] = $relayACTIVE;

       my $sock = IO::Socket::INET->new(
                                          Proto      => 'tcp',
                                          Blocking   => 0,
                                          Timeout    => 0
                                       );

       die "Failed to create relay socket: $!" unless ($sock);

       my $packed_addr = pack_sockaddr_in($port, inet_aton($addr));
       my $rc = CORE::connect($sock, $packed_addr);
       
       $select->add($sock);
    
       my $fn = fileno($sock);

       # initialise

       $serverport[$fn] = 0;

       $remoteIP[$fn]   = $addr;
       $portvalue[$fn]  = $port;
       $state[$fn]      = $stateWAIT;
       $session[$fn]    = $sessionID++;
       $relayinfo[$fn]  = $ident;
       $datain[$fn]     = "";
       $dataout[$fn]    = "";
       $sockfile[$fn]   = $sock;
       $timeout[$fn]    = $now + 5;

       $identity[$fn]   = "RELAY";   # not actually used
       $mail[$fn]       = $relayrequest{$ident}[$relayMail];
       $returnpath[$fn] = $relayrequest{$ident}[$relayFrom];
       $recipient[$fn]  = $relayrequest{$ident}[$relayTo];

       print STDERR "relay requested to $addr: $fn\n" if ($debug);

       $logfh->print("\n");
       loggera($fn, "--", "relay connection opened to $addr --");
   }
}

#==========
sub logroll
#==========
#
# roll logs (or create from scratch)
#
{
   my ($ems) = @_;

   # roll the log

   my $logfilename = timestamp(0) . ".log";

   $logfilename =~ s/ /_/g;
   $logfilename =~ s/:/-/g;

   unless ($ems)
   {
      logger("--", "Rolling into the new log: $logfilename --");

      $logfh->close();
   }       

   open($logfh, ">", $logfilename) or die "Failed to open '$logfilename': $!";

   logger("--", ($ems)
                   ? "Server started --"
                   : "Log has been rolled --");

   $logfh->flush();

   print STDERR "Now logging to $logfilename\n";

   $logendtime = time() + 600;
   $logendtime -= $logendtime % 600;
   $logendtime += 300;
}

#==========
sub loggera
#==========
{
   my ($fn, $intro, $text) = @_;

   logger($intro, sprintf("%5d %06d %s", $portvalue[$fn], $session[$fn], $text));
}

#=========
sub logger
#=========
{
   my ($intro, $text) = @_;

   $text =~ s/(.)/((ord($1) >= 0x20) && (ord($1) <= 0x7E)) ? $1 : sprintf("0x%02x", ord($1))/esg;

   $text =~ s/0x09/\\t/g;
   $text =~ s/0x0a/\\n/g;
   $text =~ s/0x0d/\\r/g;
   $text =~ s/0x00/\\0/g;

   my $ttext = timestamp(0);

   print $logfh "$ttext $intro $text\n";

   print STDERR "Log: '$ttext $intro $text'\n" if ($debug);
}

#==============
sub addreceived
#==============
{
   my ($received, $text) = @_;

   my $last = $received;
   $last =~ s/^.*\r\n//s;

   if (length($last . " " . $text) >= 78)
   {
       return $received . "\r\n\t" . $text;
   }
   else
   {
       return $received . " " . $text;
   }
}

#====================
sub RFC1036_date_time
#====================
{
   my ($s, $m, $h, $D, $M, $Y, $w) = gmtime(time());

   my @days = ("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat");
   my @months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec");

   return sprintf("%s, %d %s %d %02d:%02d:%02d +0000", $days[$w], $D, $months[$M], $Y+1900, $h, $m, $s);
}

#============
sub timestamp
#============
{
   my ($adjust) = @_;

   my ($s, $m, $h, $D, $M, $Y, $w, $y, $i) = gmtime(time() - ($adjust * 60 * 60));

   return sprintf("%04d-%02d-%02d %02d:%02d:%02d", $Y+1900, $M+1, $D, $h, $m, $s);
}

#=================
sub sigINT_handler
#=================
#
# want to stop
#
{
   $sigINT = $TRUE;
}

# end of file
