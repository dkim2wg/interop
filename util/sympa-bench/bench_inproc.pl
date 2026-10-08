#!/usr/bin/perl
# Drive one Sympa build over the benchmark corpus in-process.
#
#   bench_inproc.pl BUILD LIBDIR [--dkim2lib DIR] [--switch on|off]
#       [--corpus DIR] [--out DIR] [--tmp DIR] [--verifier-lib DIR]
#       [--repeat 5] [--timeout 300] [--budget 240]
#       [--configs a,b] [--ids a,b] [--limit N] [--signed signed|unsigned]
#       [--heavy-max-size BYTES] [--resume]
#
# Loads LIBDIR (a copy of the build's src/lib plus Constants.pm) with a
# throwaway %Conf::Conf and a stub list, as t/DKIM2.t does: no database, no
# daemons, no MTA.  Which pipeline runs is read off the libraries, not BUILD
# (BUILD is only the label):
#   wrap  Sympa::DKIM2 exists: ingress(), then egress_context() per packet
#         and egress_add() inside __twist_one;
#   cte   Message.pm has add_message_instance_ingress: the old series' hooks
#         (ProcessIncoming's ingress, the .mi_orig spool file, the egress
#         call inside __twist_one);
#   up    neither: stock 6.2.78, decorate only.
# Without --dkim2lib, Mail::DKIM2 is hidden from @INC (the box has 0.14
# installed system-wide), so cte without it is `cte-nomod`.
#
# Per message, per list configuration, one forked child runs the case:
#   ingress  Sympa::Message->new from the received text + the ingress hook
#   tolist   dup, a TransformIncoming stand-in (subject tag, List-* fields),
#            prepare_message_according_to_mode, ToList's shelving
#   spool    the outgoing spool round trip: to_string to a file (+ .mi_orig
#            for cte), then new_from_file once per packet, as bulk does
#   decorate time inside Message::decorate and Message::personalize
#   egress   egress_context + egress_add (wrap), add_message_instance_* (cte)
#   total    all of it, less the capturing mailer stub
# The real Sympa::Spindle::ProcessOutgoing::__twist_one runs per packet (or
# per recipient when VERP, merge or tracking needs it), with Sympa::Mailer's
# store() replaced by a capture.  CPU is CLOCK_PROCESS_CPUTIME_ID; stage
# values are the median of up to --repeat runs (fewer when the runs would
# pass --budget seconds).  peak_rss_kb is the child's VmHWM.  The child has
# alarm(--timeout); a timeout, death or OOM kill is recorded and the run
# moves on.  The first wire copy is checked afterwards in a second child
# with Mail::DKIM2 from --verifier-lib: chain_verifies on the CRLF text.
#
# Writes OUT/inproc-BUILD.jsonl (one record per message x config x signed).
use strict;
use warnings;
no warnings qw(once);
use Getopt::Long qw(GetOptionsFromArray);
use IPC::Open2 ();
use JSON::PP;
use POSIX qw(WNOHANG);
use Time::HiRes qw(clock_gettime CLOCK_PROCESS_CPUTIME_ID);
use File::Path qw(make_path remove_tree);

my ($BUILD, $LIBDIR) = splice @ARGV, 0, 2;
die "usage: $0 BUILD LIBDIR [options]\n" unless $BUILD and $LIBDIR;
my %o = (
    switch         => 'on',
    corpus         => '/opt/sympa-bench/corpus',
    out            => '/opt/sympa-bench/results',
    tmp            => '/opt/sympa-bench/tmp',
    'verifier-lib' => '/opt/sympa-bench/dkim2lib',
    repeat         => 5,
    timeout        => 300,
    budget         => 240,
);
GetOptionsFromArray(\@ARGV, \%o, 'dkim2lib=s', 'switch=s', 'corpus=s',
    'out=s', 'tmp=s', 'verifier-lib=s', 'repeat=i', 'timeout=i', 'budget=i',
    'configs=s', 'ids=s', 'limit=i', 'signed=s', 'resume', 'verify-server',
    'heavy-max-size=i')
    or die "bad options\n";
die "--switch on|off\n" unless $o{switch} =~ /\A(on|off)\z/;

our $EXPECT_MI;

# Verifier mode (internal): bench_inproc.pl - - --verify-server reads wire
# file names on stdin and answers each with one JSON line, checking each in
# a forked child (modules loaded once, memory returned after each).
if ($o{'verify-server'}) {
    unshift @INC, $o{'verifier-lib'};
    require Mail::DKIM2::MessageInstance;
    require Mail::DKIM2::Common;
    $| = 1;
    while (my $line = <STDIN>) {
        chomp $line;
        (my $file, $EXPECT_MI) = split /\t/, $line;
        my ($res, $fail) = in_child(sub {
            my $wfh = shift;
            alarm $o{timeout};
            verify_file($file, $wfh);
        });
        my %r = %{$res || {}};
        $r{verify_fail} = join ',', map {"$_=$fail->{$_}"} sort keys %$fail
            if %$fail;
        print encode_json(\%r), "\n";
    }
    exit 0;
}

unshift @INC, $LIBDIR;
if ($o{dkim2lib}) {
    unshift @INC, $o{dkim2lib};
} else {
    # Hide every Mail::DKIM2 (the system-wide CPAN copy included).
    unshift @INC, sub { die "Mail::DKIM2 hidden (no --dkim2lib)\n"
        if $_[1] =~ m{\AMail/DKIM2(?:/|\.pm)}; return };
}

# Sympa::Process has an INIT block; loaded at run time it warns.
local $SIG{__WARN__} = sub { warn @_ unless $_[0] =~ /Too late to run INIT/ };
require Conf;
require Sympa::ConfDef;
require Sympa::Log;
require Sympa::Message;
require Sympa::List;
require Sympa::Mailer;
require Sympa::Spool::Outgoing;
require Sympa::Spindle::ProcessOutgoing;
make_path($o{tmp}, $o{out});

my $VARIANT =
      eval { require Sympa::DKIM2; 1 } ? 'wrap'
    : Sympa::Message->can('add_message_instance_ingress') ? 'cte'
    : 'up';
die "$BUILD: Sympa libs not from $LIBDIR ($INC{'Sympa/Message.pm'})\n"
    unless index($INC{'Sympa/Message.pm'}, $LIBDIR) == 0;
my $DKIM2_VERSION = eval {
    require Mail::DKIM2::MessageInstance;
    Mail::DKIM2::MessageInstance->VERSION;
};

%Conf::Conf = (
    domain          => 'bench.example.org',
    listmaster      => 'listmaster@bench.example.org',
    tmpdir          => $o{tmp},
    nrcpt_by_domain => {},
);
for my $p (grep { $_->{name} and exists $_->{default} } @Sympa::ConfDef::params) {
    $Conf::Conf{$p->{name}} //= $p->{default};
}

# Errors and notices are kept per case (the first one goes in the record);
# nothing reaches syslog.
my @LOG;
{
    no warnings 'redefine';
    *Sympa::Log::syslog = sub {
        my (undef, $level, $fmt, @args) = @_;
        return unless $level eq 'err' or $level eq 'notice'
            or $level eq 'warning';
        my $msg = eval { sprintf $fmt =~ s/%m/%%m/gr, map { "$_" } @args }
            // $fmt;
        push @LOG, "$level: $msg";
    };
}

our %FILES;
{
    no warnings 'redefine';
    *Sympa::search_fullpath = sub { $FILES{$_[1]} };
    *Sympa::List::get_list_member = sub {
        my ($self, $email) = @_;
        return {email => $email, gecos => 'Bench Member', date => 1759881600,
            reception => 'mail', visibility => 'noconceal'};
    };
}

# List configurations: spec section "List configurations", one factor at a
# time from the first.  heavy: 1000 members, run on the synthetics and every
# 10th charset sample only (and m1000-verp100 below 2 MB).
my @CONFIGS = (
    {name => 'f-mime'},
    {name => 'hf-mime',     header => 1},
    {name => 'f-append',    type   => 'append'},
    {name => 'hf-append',   header => 1, type => 'append'},
    {name => 'pers-footer', pers   => 'footer'},
    {name => 'pers-all',    pers   => 'all'},
    {name => 'verp100',     verp   => 100},
    {name => 'txt',         mode   => 'txt'},
    {name => 'notice',      mode   => 'notice'},
    {name => 'm1000',         members => 1000, heavy => 1},
    {name => 'm1000-manydom', members => 1000, manydom => 1, heavy => 1},
    {name => 'm1000-verp100', members => 1000, verp => 100, heavy => 2},
);
for (@CONFIGS) {
    $_->{header}  //= 0;
    $_->{type}    //= 'mime';
    $_->{pers}    //= 'off';
    $_->{verp}    //= 0;
    $_->{mode}    //= 'mail';
    $_->{members} //= 25;
}

my $fseq = 0;
my $fdir = "$o{tmp}/files-$$";
make_path($fdir);
sub set_file {
    my ($n, $c) = @_;
    my $p = "$fdir/" . ++$fseq . "-$n";
    open my $f, '>:raw', $p or die "$p: $!";
    print $f $c;
    close $f;
    $FILES{$n} = $p;
}

# A UTF-8 footer (non-ASCII), so latin1 and ISO-2022-JP bodies meet one.
sub setup_list {
    my $cfg = shift;
    %FILES = ();
    my $footer = "-- \nbench list footer \xe2\x80\x94 d\xc3\xa9sabonnement: "
        . "https://bench.example.org/unsub\n";
    $footer .= "You are subscribed as [% user.email %]\n"
        unless $cfg->{pers} eq 'off';
    set_file('message_footer', $footer);
    set_file('message_header', "bench list header\n") if $cfg->{header};
    return bless {
        name   => 'bench',
        domain => 'bench.example.org',
        admin  => {
            footer_type             => $cfg->{type},
            dkim2_message_instance  => $o{switch},
            anonymous_sender        => '',
            personalization_feature => ($cfg->{pers} eq 'off' ? 'off' : 'on'),
            personalization         => {mail_apply_on => $cfg->{pers},
                web_apply_on => 'none'},
            verp_rate             => "$cfg->{verp}%",
            priority              => 5,
            rfc2369_header_fields => [],
        },
    } => 'Sympa::List';
}

# Few domains: every member is under example.net, so the packet rule that
# splits on a change of the last two domain labels ("avg") never fires and
# packets fill to nrcpt (25).  Many domains (manydom): 200 distinct
# registrable domains (dN.example), so a packet also ends once it holds
# more than avg (10) recipients and the next one is in another domain.
sub members {
    my ($n, $manydom) = @_;
    return map { sprintf 'member%d@d%d.example', $_, $_ % 200 } 0 .. $n - 1
        if $manydom;
    return map { sprintf 'member%d@d%d.example.net', $_, $_ % 50 } 0 .. $n - 1;
}

sub cpu { clock_gettime(CLOCK_PROCESS_CPUTIME_ID) }

# Stage accounting for the functions __twist_one calls.
my %ACC;
my $IN_TWIST = 0;
sub instrument {
    my ($name, $bucket) = @_;
    no strict 'refs';
    no warnings 'redefine';
    return unless defined &{$name};
    my $orig = \&{$name};
    *{$name} = sub {
        return $orig->(@_) unless $IN_TWIST;
        my $t0 = cpu();
        my @r = wantarray ? $orig->(@_) : scalar $orig->(@_);
        $ACC{$bucket} += cpu() - $t0;
        return wantarray ? @r : $r[0];
    };
}
instrument('Sympa::Message::decorate',                    'decorate');
instrument('Sympa::Message::personalize',                 'decorate');
instrument('Sympa::DKIM2::egress_add',                    'egress');
instrument('Sympa::Message::add_message_instance_egress',  'egress');
instrument('Sympa::Message::add_message_instance_ingress', 'egress');

# The capturing mailer.  Wire text as Sympa::Mailer::store sends it
# (Return-Path pseudo-header stripped), with CRLF line ends.
my ($CAPTURE, @WIRE);
{
    no warnings 'redefine';
    *Sympa::Mailer::store = sub {
        my ($self, $message, $rcpt) = @_;
        my $t0 = cpu();
        if ($CAPTURE) {
            my $s = $message->as_string;
            $s =~ s/\AReturn-Path: (.*?)\n(?![ \t])//s;
            $s =~ s/\r?\n/\r\n/g;
            my $n = ref $rcpt ? scalar @$rcpt : 1;
            push @WIRE, [length $s, $n, mi_len_max($s),
                (@WIRE ? undef : $s)];
        }
        $ACC{store} += cpu() - $t0;
        return 1;
    };
}

sub mi_len_max {
    my ($head) = split /\r\n\r\n/, $_[0], 2;
    my $max = 0;
    for (split /\r\n(?![ \t])/, $head) {
        $max = length if /\AMessage-Instance:/i and length > $max;
    }
    return $max;
}

my $STAGEFILE;
sub stage { return unless $STAGEFILE; open my $f, '>', $STAGEFILE; print $f $_[0] }

# One run of one case.  Returns {stage => cpu...} plus run facts.
sub run_once {
    my ($raw, $cfg, $dir, $capture) = @_;
    my $list = setup_list($cfg);
    my @rcpts = members($cfg->{members}, $cfg->{manydom});
    %ACC = ();
    @WIRE = ();
    $CAPTURE = $capture;
    my %r;
    my $all0 = cpu();

    stage('ingress');
    my $t0 = cpu();
    my $msg = Sympa::Message->new($raw, context => $list)
        or die "Sympa::Message->new failed\n";
    if ($VARIANT eq 'wrap') {
        Sympa::DKIM2::ingress($msg);
    } elsif ($VARIANT eq 'cte') {
        # The old series' ProcessIncoming hook.
        if ($msg->{_head}->count('Message-Instance')) {
            $msg->{mi_original} = $msg->as_rfc822_string;
        } else {
            $msg->add_message_instance_ingress;
        }
    }
    $r{ingress} = cpu() - $t0;

    stage('tolist');
    $t0 = cpu();
    # TransformIncoming stand-in: the header changes every list makes.
    my $subject = $msg->get_header('Subject') // '';
    $msg->delete_header('Subject');
    $msg->add_header('Subject', "[bench] $subject");
    $msg->add_header('List-Id', '<bench.bench.example.org>');
    $msg->add_header('List-Unsubscribe',
        '<mailto:sympa@bench.example.org?subject=unsubscribe%20bench>');
    $msg->add_header('Precedence', 'list');
    # ToList::_send_msg / _mail_message for one reception mode.
    my $new = $msg->dup;
    $new->prepare_message_according_to_mode($cfg->{mode}, $list)
        or die "prepare_message_according_to_mode failed\n";
    $new->shelve_personalization(type => 'mail')
        unless $new->{shelved}{merge};
    $new->{envelope_sender} = Sympa::get_address($list, 'return_path');
    # verp 100%: every member is a VERP recipient; ToList sets tracking
    # before storing them.
    $new->{shelved}{tracking} ||= 'verp' if $cfg->{verp};
    $r{tolist} = cpu() - $t0;

    stage('spool');
    $t0 = cpu();
    my $file = "$dir/msg";
    {
        open my $fh, '>', $file or die "$file: $!";
        print $fh $new->dup->to_string;
        close $fh;
    }
    if ($VARIANT eq 'cte' and defined $new->{mi_original}) {
        open my $fh, '>', "$file.mi_orig" or die "$file.mi_orig: $!";
        print $fh $new->{mi_original};
        close $fh;
    }
    $r{spool_bytes} = (-s $file) + (-s "$file.mi_orig" // 0);
    $r{spool} = cpu() - $t0;
    undef $new;
    undef $msg;

    my @packets = Sympa::Spool::Outgoing::_get_recipient_tabs_by_domain(
        $list->{domain}, @rcpts);
    $r{packets} = scalar @packets;
    $r{twists}  = 0;
    for my $packet (@packets) {
        # bulk: one spool read per packet.
        stage('spool');
        $t0 = cpu();
        my $m = Sympa::Message->new_from_file($file, context => $list)
            or die "new_from_file failed\n";
        if (-e "$file.mi_orig") {
            open my $fh, '<', "$file.mi_orig" or die;
            local $/;
            $m->{mi_original} = <$fh>;
        }
        $r{spool} += cpu() - $t0;

        stage('egress');
        $IN_TWIST = 1;
        my $dkim2;
        if ($VARIANT eq 'wrap') {
            $t0 = cpu();
            $dkim2 = Sympa::DKIM2::egress_context($m);
            $ACC{egress} += cpu() - $t0;
        }
        stage('twist');
        if (   $m->{shelved}{merge}
            or $m->{shelved}{smime_encrypt}
            or $m->{shelved}{tracking}) {
            for my $rcpt (@$packet) {
                Sympa::Spindle::ProcessOutgoing::__twist_one($m, $rcpt, {},
                    {}, 0, $dkim2);
                $r{twists}++;
            }
        } else {
            Sympa::Spindle::ProcessOutgoing::__twist_one($m, [@$packet], {},
                {}, 0, $dkim2);
            $r{twists}++;
        }
        $IN_TWIST = 0;
    }
    $r{total} = cpu() - $all0 - ($ACC{store} // 0);
    $r{decorate} = $ACC{decorate} // 0;
    $r{egress}   = $ACC{egress}   // 0;
    unlink $file, "$file.mi_orig";

    if ($capture) {
        my ($bytes, $n, $mi) = (0, 0, 0);
        for (@WIRE) {
            $bytes += $_->[0] * $_->[1];
            $n     += $_->[1];
            $mi = $_->[2] if $_->[2] > $mi;
        }
        $r{n_wire}              = scalar @WIRE;
        $r{wire_bytes_per_rcpt} = $n ? int($bytes / $n + 0.5) : 0;
        $r{mi_len_max}          = $mi;
        if (@WIRE) {
            open my $fh, '>', "$dir/wire.eml" or die;
            print $fh $WIRE[0][3];
            close $fh;
        }
    }
    @WIRE = ();
    return \%r;
}

sub vm {
    my $key = shift;
    open my $fh, '<', '/proc/self/status' or return undef;
    while (<$fh>) { return $1 + 0 if /^\Q$key\E:\s+(\d+)/ }
    return undef;
}

sub median {
    my @v = sort { $a <=> $b } @_;
    return undef unless @v;
    return @v % 2 ? $v[$#v / 2] : ($v[@v / 2 - 1] + $v[@v / 2]) / 2;
}

# The case child: up to --repeat runs inside --budget, one JSON line out.
sub case_child {
    my ($signed, $id, $cfg, $dir, $wfh) = @_;
    alarm $o{timeout};
    my $rss_base = vm('VmRSS');
    # Read here, not in the parent: the parent's heap is inherited by every
    # child (and counted in its VmHWM), so it must not grow with the corpus.
    my $raw = read_raw($signed, $id);
    my (@runs, $facts);
    my $w0 = Time::HiRes::time();
    for my $i (1 .. $o{repeat}) {
        my $r0 = Time::HiRes::time();
        my $r = run_once($raw, $cfg, $dir, $i == 1);
        $facts //= $r;
        push @runs, $r;
        my $took = Time::HiRes::time() - $r0;
        last if Time::HiRes::time() - $w0 + $took > $o{budget};
    }
    my %out = (
        stage_cpu => {map { my $k = $_; ($k => median(map { $_->{$k} } @runs)) }
                qw(ingress tolist spool decorate egress total)},
        runs        => scalar @runs,
        wall_s      => (Time::HiRes::time() - $w0) / @runs,
        peak_rss_kb => vm('VmHWM'),
        rss_base_kb => $rss_base,
        map { $_ => $facts->{$_} }
            qw(spool_bytes wire_bytes_per_rcpt mi_len_max n_wire packets twists),
    );
    $out{log} = $LOG[0] if @LOG;
    print $wfh encode_json(\%out), "\n";
    close $wfh;
}

# Parse a child's exit for timeout / OOM / death.
sub oom_kills {
    my $cg = '';
    if (open my $fh, '<', '/proc/self/cgroup') {
        while (<$fh>) { $cg = $1 if /^0::(.*)$/ }
    }
    open my $fh, '<', "/sys/fs/cgroup$cg/memory.events" or return 0;
    while (<$fh>) { return $1 if /^oom_kill (\d+)/ }
    return 0;
}

# Fork, run CODE in the child (it writes one JSON line to the pipe), and
# return (decoded result or undef, failure facts).
sub in_child {
    my ($code) = @_;
    pipe my $rfh, my $wfh or die "pipe: $!";
    my $ooms = oom_kills();
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        close $rfh;
        $code->($wfh);
        POSIX::_exit(0);
    }
    close $wfh;
    my $line = do { local $/; <$rfh> };
    close $rfh;
    waitpid $pid, 0;
    my $st = $?;
    my %fail;
    if ($st & 127) {
        my $sig = $st & 127;
        if ($sig == 14) {
            $fail{timeout} = 1;
        } elsif ($sig == 9 and oom_kills() > $ooms) {
            $fail{oom} = 1;
        } else {
            $fail{error} = "killed by signal $sig";
        }
    } elsif ($st >> 8) {
        $fail{error} = "exit " . ($st >> 8);
    }
    my $res = eval { decode_json($line // '') };
    if (!$res and !%fail) {
        $fail{error} = 'no result' . (length($line // '') ? ": $line" : '');
    }
    return ($res, \%fail);
}

sub verify_file {
    my ($file, $wfh) = @_;
    my $s = do { local $/; open my $fh, '<', $file or die; <$fh> };
    my ($head) = split /\r\n\r\n/, $s, 2;
    my @mi = grep {/\AMessage-Instance:/i} split /\r\n(?![ \t])/, $head;
    my %r = (mi_count => scalar @mi,
        # The Sympa spool pseudo-header must never reach the wire.
        pseudo_leak => ($head =~ /^X-Sympa-DKIM2-Headers:/mi
            ? JSON::PP::true : JSON::PP::false));
    if (@mi) {
        my ($ok, $err) =
            eval { Mail::DKIM2::MessageInstance->chain_verifies($s) };
        $err //= $@ unless $ok;
        my ($top) = sort {
            Mail::DKIM2::Common::extract_mi_version($b)
                <=> Mail::DKIM2::Common::extract_mi_version($a)
        } map { s/\AMessage-Instance:\s*//ir } @mi;
        my $mi = eval { Mail::DKIM2::MessageInstance->parse($top) };
        my $null = grep {
            my $p = eval { Mail::DKIM2::MessageInstance->parse(s/\AMessage-Instance:\s*//ir) };
            $p && $p->unrecoverable
        } @mi;
        $r{verifies}  = $ok ? JSON::PP::true : JSON::PP::false;
        $r{top_m}     = $mi ? $mi->get_tag('m') + 0 : undef;
        $r{null_body} = $null ? JSON::PP::true : JSON::PP::false;
        # The body as received is recoverable: the chain undoes, the top
        # instance is this hop's, and no Recipe on the way is null.
        $r{undo_ok} = ($ok and $mi and $r{top_m} >= 2 and !$null)
            ? JSON::PP::true : JSON::PP::false;
        ($r{verify_err} = "$err") =~ s/\s+\z// if !$ok and defined $err;
    } elsif ($EXPECT_MI) {
        # A DKIM2 build with DKIM2 on must always leave an instance.
        $r{verifies}   = $r{undo_ok} = JSON::PP::false;
        $r{verify_err} = 'no instance';
    } else {
        $r{verifies} = $r{undo_ok} = undef;
    }
    print $wfh encode_json(\%r), "\n";
    close $wfh;
}

# --- main ---

# DKIM2 is on for this build: wrap with the switch on, or cte with
# Mail::DKIM2 loadable.  Its output must carry a Message-Instance.
my $expect_mi = (($VARIANT eq 'wrap' and $o{switch} eq 'on')
    or ($VARIANT eq 'cte' and defined $DKIM2_VERSION)) ? 1 : 0;

my @index = do {
    open my $fh, '<', "$o{corpus}/index.tsv" or die "$o{corpus}/index.tsv: $!";
    <$fh>;    # header
    map { chomp; my @f = split /\t/; {id => $f[0], size => $f[1], cls => $f[2]} } <$fh>;
};
# Heavy configurations: the synthetics and every 10th charset sample;
# m1000-verp100 (1000 __twist_one per run) only below 2 MB.
my $nth = 0;
my %sampled = map { $_->{id} => ($_->{id} =~ /^syn-/ || $nth++ % 10 == 0) } @index;
if ($o{ids}) {
    my %want = map { $_ => 1 } split /,/, $o{ids};
    @index = grep { $want{$_->{id}} } @index;
}
splice @index, $o{limit} if $o{limit} and $o{limit} < @index;
my @configs = @CONFIGS;
if ($o{configs}) {
    my %want = map { $_ => 1 } split /,/, $o{configs};
    @configs = grep { $want{$_->{name}} } @configs;
    die "no such configs: $o{configs}\n" unless @configs;
}
my @signed = $o{signed} ? ($o{signed}) : qw(unsigned signed);

sub wanted {
    my ($cfg, $row) = @_;
    return 1 unless $cfg->{heavy};
    return 0 unless $sampled{$row->{id}};
    return 0 if $cfg->{heavy} == 2 and $row->{size} >= 2_000_000;
    return 0 if $o{'heavy-max-size'} and $row->{size} >= $o{'heavy-max-size'};
    return 1;
}

my $out_file = "$o{out}/inproc-$BUILD.jsonl";
my %done;
if ($o{resume} and open my $fh, '<', $out_file) {
    while (<$fh>) {
        my $r = eval { decode_json($_) } or next;
        my $signed = $r->{signed} ? 'signed' : 'unsigned';
        $done{"$r->{msg_id}\t$signed\t$r->{config}"} = 1;
    }
}
open my $OUT, ($o{resume} ? '>>' : '>'), $out_file or die "$out_file: $!";
$OUT->autoflush(1);

# The verifier: Mail::DKIM2 from --verifier-lib whatever the build loads.
my $VPID = IPC::Open2::open2(my $VOUT, my $VIN, $^X, $0, '-', '-',
    '--verifier-lib', $o{'verifier-lib'}, '--timeout', $o{timeout},
    '--verify-server');
$VIN->autoflush(1);

my $casedir = "$o{tmp}/case-$$";
make_path($casedir);
$STAGEFILE = "$casedir/stage";

sub read_raw {
    my ($signed, $id) = @_;
    my $p = "$o{corpus}/$signed/$id.eml";
    open my $fh, '<:raw', $p or die "$p: $!";
    local $/;
    my $raw = <$fh>;
    $raw =~ s/\r\n/\n/g;    # as Postfix hands it to the queue program
    return $raw;
}

# Warm-up in the parent (module loading, template compilation), not
# recorded, so the first case is not charged for it.
{
    my ($w) = grep { $_->{size} < 100_000 } @index;
    if ($w) {
        local $SIG{__WARN__} = sub { };
        eval { run_once(read_raw('signed', $w->{id}), $configs[0], $casedir, 0) };
    }
    @LOG = ();
}

printf STDERR "%s: %s pipeline, Mail::DKIM2 %s, switch %s, %d messages x %d configs\n",
    $BUILD, $VARIANT, $DKIM2_VERSION // 'none', $o{switch}, scalar @index,
    scalar @configs;
for my $row (@index) {
    for my $signed (@signed) {
        for my $cfg (@configs) {
            next unless wanted($cfg, $row);
            next if $done{"$row->{id}\t$signed\t$cfg->{name}"};
            unlink "$casedir/wire.eml", $STAGEFILE;
            my %rec = (
                expect_mi     => ($expect_mi ? JSON::PP::true : JSON::PP::false),
                build         => $BUILD,
                variant       => $VARIANT,
                switch        => ($VARIANT eq 'up' ? undef : $o{switch}),
                dkim2_version => $DKIM2_VERSION,
                msg_id        => $row->{id},
                size          => $row->{size} + 0,
                class         => $row->{cls},
                signed        => ($signed eq 'signed' ? JSON::PP::true : JSON::PP::false),
                config        => $cfg->{name},
                members       => $cfg->{members},
            );
            my ($res, $fail) = in_child(sub {
                my $wfh = shift;
                local $SIG{__WARN__} = sub { };
                eval { case_child($signed, $row->{id}, $cfg, $casedir, $wfh); 1 } or do {
                    (my $e = $@) =~ s/\s+\z//;
                    print $wfh encode_json({died => substr($e, 0, 500)}), "\n";
                };
            });
            %rec = (%rec, %{$res || {}});
            $rec{error} = delete $rec{died} if $rec{died};
            $rec{error} //= $fail->{error} if $fail->{error};
            $rec{timeout} = $fail->{timeout} ? JSON::PP::true : JSON::PP::false;
            $rec{oom}     = $fail->{oom}     ? JSON::PP::true : JSON::PP::false;
            if ($fail->{timeout} or $fail->{oom}) {
                $rec{timeout_s} = $o{timeout} if $fail->{timeout};
                if (open my $fh, '<', $STAGEFILE) { $rec{stage} = <$fh> }
            }
            if (-s "$casedir/wire.eml") {
                print $VIN "$casedir/wire.eml\t$expect_mi\n";
                my $v = eval { decode_json(scalar <$VOUT> // '') }
                    // {verify_fail => 'verifier gave no answer'};
                %rec = (%rec, %$v);
                # Keep the first config's wire copy of each message.
                if ($cfg eq $configs[0]) {
                    make_path("$o{out}/eml");
                    rename "$casedir/wire.eml",
                        "$o{out}/eml/$BUILD-$signed-$row->{id}.eml";
                }
            }
            $rec{verifies} //= undef;
            $rec{undo_ok}  //= undef;
            print $OUT JSON::PP->new->canonical->encode(\%rec), "\n";
        }
    }
}
close $OUT;
close $VIN;
waitpid $VPID, 0;
remove_tree($casedir, $fdir);
printf STDERR "%s: done\n", $BUILD;
