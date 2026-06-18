package Mail::DKIM2::Validate;
use strict; use warnings; use 5.020;

use Email::MIME;
use List::Util qw(max);
use Mail::DKIM2::Common qw(extract_mi_version extract_domain relaxed_domain_match parse_dkim_pubkey);
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Verifier;
use Mail::DKIM2::Signature;

sub _i { my $h = shift // ''; $h =~ /\bi=(\d+)/ ? 0 + $1 : 0 }
sub _m { my $h = shift // ''; $h =~ /\bm=(\d+)/ ? 0 + $1 : 0 }

# Default live-DNS pubkey callback (dns.json override if $dns_path readable).
sub _default_cb {
    my ($dns_path) = @_;
    my $dns;
    if ($dns_path && -r $dns_path) {
        require JSON;
        if (open my $fh, '<', $dns_path) {
            $dns = eval { JSON::decode_json(do { local $/; <$fh> }) };
            close $fh;
        }
    }
    return sub {
        my ($sig, $idx) = @_; $idx //= 0;
        my $sel = $sig->selector($idx); my $dom = $sig->domain;
        if ($dns && $dom && $sel) {
            my $t = $dns->{$dom}{"$sel._domainkey"}[0][1];
            return parse_dkim_pubkey($t) if $t;
        }
        return eval { $sig->fetch_public_key($idx) };
    };
}

sub report {
    my ($text, %opts) = @_;
    $text //= '';
    $text =~ s/\r?\n/\r\n/g;
    my $cb = $opts{pubkey_cb} || _default_cb($opts{dns_path});
    my $skip_ts = $opts{skip_timestamp_check} ? 1 : 0;

    my %res = (overall => 'none', summary => '',
               counts => { signatures => 0, instances => 0 }, levels => []);

    my $msg = eval { Email::MIME->new($text) };
    return { %res, overall => 'fail', summary => "could not parse message: $@" }
        if $@ || !$msg;

    my @sig_hdrs = $msg->header('DKIM2-Signature');
    my @mi_hdrs  = $msg->header('Message-Instance');
    $res{counts} = { signatures => scalar @sig_hdrs, instances => scalar @mi_hdrs };
    return { %res, overall => 'none', summary => 'no DKIM2-Signature headers found' }
        unless @sig_hdrs;

    # Overall verdict from the full verifier (includes the §10.7 deep MI walk).
    # Timestamp age is graded per-signature as a soft 'warn' below, so it must
    # not hard-fail the crypto verdict here.
    my $v = Mail::DKIM2::Verifier->new;
    $v->skip_timestamp_check(1);
    $v->set_pubkey_callback($cb);
    eval { $v->PRINT($text); $v->CLOSE; 1 };
    my $ov = $v->result // 'fail';
    $res{summary} = $v->result_detail // '';
    $res{overall} = $ov eq 'pass' ? 'pass' : ($ov eq 'none' ? 'none' : 'fail');

    my %sig_by_i = map { _i($_) => $_ } @sig_hdrs;

    # Descend the chain top-down. At each step: verify every signature whose
    # m= equals the current top Message-Instance (content is at the right level
    # for them), then record that MI level and undo one step. Records a level
    # for every signature and every MI, in chain order (top hop first).
    my @levels;
    my $work = Email::MIME->new($text);
    my $stopped;

    while (1) {
        my %sigmap = map { _i($_) => $_ } $work->header('DKIM2-Signature');
        my %mimap  = map { extract_mi_version($_) => $_ } $work->header('Message-Instance');
        my $num  = %sigmap ? max(keys %sigmap) : 0;
        my $inst = %mimap  ? max(keys %mimap)  : 0;
        last if !$num && !$inst;

        # Signatures covering the current top MI (highest i first).
        while ($num > 0 && _m($sigmap{$num}) == $inst) {
            push @levels, _sig_level($work, $num, \%sig_by_i, $cb, $skip_ts);
            $work->header_raw_set('DKIM2-Signature',
                grep { _i($_) < $num } $work->header('DKIM2-Signature'));
            %sigmap = map { _i($_) => $_ } $work->header('DKIM2-Signature');
            $num = %sigmap ? max(keys %sigmap) : 0;
        }

        last unless $inst;   # no more MIs to record

        my $lvl = _mi_level($work, $inst, $mimap{$inst});
        push @levels, $lvl;

        last if $inst <= 1;                 # base instance recorded; done
        if ($lvl->{undo} eq 'clean') {
            Mail::DKIM2::MessageInstance->undo($work);
            $work = Email::MIME->new($work->as_string);   # reset Email::MIME caches
        } else {
            $stopped = "stopped below m=$inst ($lvl->{undo})";
            last;
        }
    }

    $res{summary} = ($res{summary} ? "$res{summary}; " : '') . $stopped if $stopped;

    # An old/future timestamp is a soft warning, not a hard fail: if the chain
    # otherwise verified, surface it as an amber 'warn' overall.
    if ($res{overall} eq 'pass'
        && grep { ($_->{result} // '') eq 'warn' } @levels) {
        $res{overall} = 'warn';
    }

    $res{levels} = \@levels;
    return \%res;
}

# Level hashref for the top Message-Instance m=$inst of $msg.
sub _mi_level {
    my ($msg, $inst, $mi_raw) = @_;
    my %lvl = (kind => 'mi', m => $inst, result => 'fail',
               header_hash => 'mismatch', body_hash => 'mismatch',
               recipe => 'none', undo => 'n/a', detail => '');
    my $mi = eval { Mail::DKIM2::MessageInstance->parse($mi_raw) };
    unless ($mi) { $lvl{detail} = 'unparseable Message-Instance'; return \%lvl; }

    my $h1 = $mi->get_tag('h1'); my $b1 = $mi->get_tag('b1');
    my $hd = Mail::DKIM2::MessageInstance::h_digest($msg);
    my $bd = Mail::DKIM2::MessageInstance::b_digest($msg);
    $lvl{header_hash} = (defined $h1 && $h1 eq $hd) ? 'match' : 'mismatch';
    $lvl{body_hash}   = (defined $b1 && $b1 eq $bd) ? 'match' : 'mismatch';
    $lvl{recipe} = $mi->unrecoverable ? 'null'
                 : ($mi->get_tag('rb') || $mi->get_tag('rh')) ? 'diff' : 'none';

    if ($inst <= 1) {
        $lvl{undo} = 'n/a';
    } elsif ($mi->unrecoverable) {
        $lvl{undo} = 'unrecoverable';
    } else {
        my $clone = Email::MIME->new($msg->as_string);
        my $ok = eval { Mail::DKIM2::MessageInstance->undo($clone) };
        $lvl{undo} = ($ok && !$@) ? 'clean' : 'failed';
    }

    $lvl{result} = ($lvl{header_hash} eq 'match' && $lvl{body_hash} eq 'match')
                 ? 'pass' : 'fail';
    return \%lvl;
}

# Signature-level hashref for i=$num, verifying the chain prefix on $work.
sub _sig_level {
    my ($work, $num, $sig_by_i, $cb, $skip_ts) = @_;
    # $sig_by_i values come from Email::MIME->header() — already bare values.
    my $sig = eval { Mail::DKIM2::Signature->parse($sig_by_i->{$num}) };
    my %lvl = (kind => 'signature', i => $num, m => _m($sig_by_i->{$num}),
               domain => ($sig ? ($sig->domain // '') : ''),
               items => [], timestamp => { ok => 1, detail => '' },
               custody => { ok => 1, detail => '' }, result => 'fail', detail => '');

    if ($sig) {
        my $n = $sig->sig_count || 0;
        for my $idx (0 .. $n - 1) {
            push @{$lvl{items}}, {
                selector  => ($sig->selector($idx)  // ''),
                algorithm => ($sig->algorithm($idx) // ''),
            };
        }
        unless ($skip_ts) {
            my $ts = $sig->timestamp;
            if (defined $ts && $ts > 0) {
                my $now = time();
                if    ($ts > $now + 300)        { $lvl{timestamp} = { ok => 0, status => 'future', detail => 'timestamp in the future' }; }
                elsif ($now > $ts + 14*24*3600) { $lvl{timestamp} = { ok => 0, status => 'old',    detail => 'older than 14 days' }; }
            }
        }
        if ($num > 1 && $sig_by_i->{$num - 1}) {
            my $prev = eval { Mail::DKIM2::Signature->parse($sig_by_i->{$num-1}) };
            my $mf = $sig->mail_from;
            if ($prev && $mf && $mf ne '<>') {
                my $mfd = extract_domain($mf);
                my @rts = do { my $rt = $prev->rcpt_to; ref $rt eq 'ARRAY' ? @$rt : ($rt // ()) };
                my $ok = grep { relaxed_domain_match($mfd // '', extract_domain($_) // '') } @rts;
                $lvl{custody} = $ok ? { ok => 1, detail => '' }
                                    : { ok => 0, detail => "mf domain " . ($mfd // '?') . " not in previous rt domains" };
            }
        }
    } else {
        $lvl{detail} = 'unparseable DKIM2-Signature';
    }

    # Timestamp age never hard-fails here; it is graded as a soft warn above.
    my $vv = Mail::DKIM2::Verifier->new;
    $vv->skip_timestamp_check(1);
    $vv->set_pubkey_callback($cb);
    eval { $vv->PRINT($work->as_string); $vv->CLOSE; 1 };
    my $r = $vv->result // 'fail';
    my $crypto = ($r eq 'pass') ? 'pass' : 'fail';
    $lvl{result} = $crypto;
    $lvl{detail} = ($vv->result_detail // $lvl{detail}) unless $crypto eq 'pass';
    # Crypto verified but timestamp old/future -> soft amber warning.
    $lvl{result} = 'warn' if $crypto eq 'pass' && !$lvl{timestamp}{ok};
    $_->{result} = $crypto for @{$lvl{items}};
    return \%lvl;
}

1;

__END__

=head1 NAME

Mail::DKIM2::Validate - structured per-level DKIM2 + Message-Instance report

=head1 DESCRIPTION

C<report($message_text, %opts)> walks a DKIM2 message top-down and returns a
structured breakdown of each DKIM2-Signature and Message-Instance level
(including MI undo), for display by the web validator. Never dies. See
C<docs/superpowers/specs/2026-06-18-dkim2-web-validator-design.md>.

B<EXPERIMENTAL> - implements draft-ietf-dkim-dkim2-spec-02.

=cut
