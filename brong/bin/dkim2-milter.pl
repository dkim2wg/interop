#!/usr/bin/perl
use 5.20.0;
use strict;
use warnings;
use Getopt::Long;
use Pod::Usage;
use Sendmail::PMilter ':all';

use constant DKIM2_DRAFT   => 'ietf-dkim-dkim2-spec-01';
use constant DKIM2_REPO    => 'github.com/dkim2wg/interop';
use constant DKIM2_DATE    => '2026-04-20';
use constant DKIM2_SOFTWARE => 'dkim2-milter.pl';

sub _dkim2_info {
    my ($action, %extra) = @_;
    # Fold at semicolons using LF+tab for milter protocol
    my $val = "draft=" . DKIM2_DRAFT
            . ";\n\trepo=" . DKIM2_REPO
            . ";\n\tdate=" . DKIM2_DATE
            . "; sw=" . DKIM2_SOFTWARE
            . ";\n\taction=$action";
    for my $key (sort keys %extra) {
        next unless defined $extra{$key};
        $val .= "; $key=$extra{$key}";
    }
    return $val;
}

# Return (count, comma-separated-names) of headers that would be included
# in the header hash for the given Email::MIME message object.
sub _header_list_for_hash {
    my ($msg) = @_;
    my @fields;
    for my $header (sort { lc($a) cmp lc($b) } $msg->header_names) {
        next if should_skip($header);
        my @vals = $msg->header_raw($header);
        push @fields, (lc($header)) x scalar(@vals);
    }
    return (scalar(@fields), join(',', @fields));
}

use Mail::DKIM2::Common qw(
    parse_dkim_pubkey load_private_key fold_header extract_mi_version should_skip
);
use Mail::DKIM2::Signer;
use Mail::DKIM2::Verifier;
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::MessageStore;
use Email::MIME;

# --- Command-line options ---

my %opts;
GetOptions(\%opts,
    'socket|s=s',
    'mode|m=s',
    'domain|d=s',
    'selector=s',
    'keyfile|k=s',
    'keydir=s',
    'algorithm|a=s',
    'snapshot-dir=s',
    'dns-json=s',
    'use-epilogue',
    'epilogue-threshold=i',
    'help|h',
) or pod2usage(2);

pod2usage(-exitval => 0, -verbose => 2) if $opts{help};

if ($opts{'use-epilogue'} && defined $opts{'epilogue-threshold'}) {
    die "--use-epilogue and --epilogue-threshold are mutually exclusive\n";
}

$opts{socket}    //= 'unix:/var/run/dkim2-milter.sock';
$opts{algorithm} //= 'rsa-sha256';
$opts{mode}      //= 'both';

unless ($opts{mode} =~ /^(inbound|outbound|both)$/) {
    die "Invalid --mode: must be inbound, outbound, or both\n";
}

my $do_verify = $opts{mode} eq 'inbound' || $opts{mode} eq 'both';
my $do_sign   = $opts{mode} eq 'outbound' || $opts{mode} eq 'both';

# Determine if signing is possible
my $can_sign_single = $opts{domain} && $opts{selector} && $opts{keyfile};
my $can_sign_keydir = $opts{keydir} && -d $opts{keydir};
my $can_sign = $can_sign_single || $can_sign_keydir;

if ($do_sign && !$can_sign) {
    die "Signing (--mode $opts{mode}) requires --keydir OR (--domain, --selector, and --keyfile)\n";
}

if ($can_sign_single && $can_sign_keydir) {
    die "Cannot use both --keydir and --domain/--selector/--keyfile\n";
}

# Preload single-domain signing key
my $sign_key;
if ($can_sign_single) {
    $sign_key = load_private_key($opts{keyfile});
    warn "dkim2-milter: signing enabled for $opts{domain} "
       . "(selector=$opts{selector}, algorithm=$opts{algorithm})\n";
}

# Key cache for keydir mode: { domain => { selector, key, algorithm } }
my %keydir_cache;

if ($can_sign_keydir) {
    warn "dkim2-milter: signing enabled via keydir $opts{keydir}\n";
}
warn "dkim2-milter: mode=$opts{mode}\n";

# Preload DNS overrides if specified
my $dns_data;
if ($opts{'dns-json'}) {
    require JSON::XS;
    open my $fh, '<', $opts{'dns-json'}
        or die "Cannot read $opts{'dns-json'}: $!\n";
    local $/;
    $dns_data = JSON::XS::decode_json(<$fh>);
    close $fh;
    warn "dkim2-milter: using DNS overrides from $opts{'dns-json'}\n";
}

# Snapshot store
my $snapshot_store;
if ($opts{'snapshot-dir'}) {
    $snapshot_store = Mail::DKIM2::MessageStore->new(
        directory => $opts{'snapshot-dir'},
    );
    warn "dkim2-milter: snapshots in $opts{'snapshot-dir'}\n";
}

# Options passed to MessageInstance->calculate() for diff-based MI
my %mi_opts;
if ($opts{'use-epilogue'}) {
    $mi_opts{UseEpilogue} = 1;
    warn "dkim2-milter: MI strategy: UseEpilogue (always store body in MIME epilogue)\n";
}
elsif (defined $opts{'epilogue-threshold'}) {
    $mi_opts{EpilogueThreshold} = $opts{'epilogue-threshold'};
    warn "dkim2-milter: MI strategy: EpilogueThreshold=$opts{'epilogue-threshold'}\n";
}

# --- Key directory lookup ---

# Look up signing config for a domain from the keydir.
# Tries exact domain first, then walks up parent domains.
# Returns { domain, selector, key, algorithm } or undef.
sub _keydir_lookup {
    my ($domain) = @_;
    $domain = lc($domain);

    # Check cache
    return $keydir_cache{$domain} if exists $keydir_cache{$domain};

    my $try = $domain;
    while ($try) {
        my $dir = "$opts{keydir}/$try";
        if (-d $dir) {
            # Find the newest .key file (by ctime)
            opendir my $dh, $dir or next;
            my @keys = map { $_->[0] }
                       sort { $b->[1] <=> $a->[1] }
                       map { [$_, (stat("$dir/$_"))[10] || 0] }
                       grep { /\.key$/ } readdir $dh;
            closedir $dh;

            if (@keys) {
                my $file = $keys[0];
                (my $selector = $file) =~ s/\.key$//;
                my $key = eval { load_private_key("$dir/$file") };
                if ($key) {
                    # Detect algorithm from key type
                    my $alg = ref($key) =~ /Ed25519/
                        ? 'ed25519-sha256' : 'rsa-sha256';
                    my $config = {
                        domain    => $try,
                        selector  => $selector,
                        key       => $key,
                        algorithm => $alg,
                    };
                    # Cache for both the looked-up domain and the matched domain
                    $keydir_cache{$domain} = $config;
                    $keydir_cache{$try} = $config if $try ne $domain;
                    return $config;
                }
            }
        }
        # Walk up: sub.example.com -> example.com -> (stop)
        $try =~ s/^[^.]+\.// or last;
    }

    # Cache the miss too
    $keydir_cache{$domain} = undef;
    return undef;
}

# --- Milter setup ---

my $milter = Sendmail::PMilter->new();
$milter->setconn($opts{socket});

# We need to add/insert headers
$milter->register('dkim2-milter', {
    envfrom => \&cb_envfrom,
    envrcpt => \&cb_envrcpt,
    header  => \&cb_header,
    eoh     => \&cb_eoh,
    body    => \&cb_body,
    eom     => \&cb_eom,
    close   => \&cb_close,
}, SMFIF_ADDHDRS);

warn "dkim2-milter: listening on $opts{socket}\n";
$milter->main();

# --- Milter callbacks ---

sub cb_envfrom {
    my ($ctx, $from) = @_;
    $from =~ s/^<//;
    $from =~ s/>$//;
    $ctx->setpriv({
        env_from  => $from,
        env_rcpt  => [],
        headers   => [],
        raw_hdrs  => [],
        body      => '',
    });
    return SMFIS_CONTINUE;
}

sub cb_envrcpt {
    my ($ctx, $rcpt) = @_;
    $rcpt =~ s/^<//;
    $rcpt =~ s/>$//;
    push @{$ctx->getpriv->{env_rcpt}}, $rcpt;
    return SMFIS_CONTINUE;
}

sub cb_header {
    my ($ctx, $field, $value) = @_;
    my $priv = $ctx->getpriv;
    my $EOL = "\015\012";
    # Postfix delivers folded header values with LF continuations;
    # normalize to CRLF so the reconstructed message is RFC 5322 compliant.
    $value =~ s/\r?\n/$EOL/g;
    # Store parsed form and raw form
    push @{$priv->{headers}}, [$field, $value];
    push @{$priv->{raw_hdrs}}, "$field: $value$EOL";
    return SMFIS_CONTINUE;
}

sub cb_eoh {
    my ($ctx) = @_;
    return SMFIS_CONTINUE;
}

sub cb_body {
    my ($ctx, $chunk) = @_;
    my $priv = $ctx->getpriv;
    my $EOL = "\015\012";
    $chunk =~ s/\015?\012/$EOL/g;
    $priv->{body} .= $chunk;
    return SMFIS_CONTINUE;
}

sub cb_eom {
    my ($ctx) = @_;
    my $priv = $ctx->getpriv;
    my $EOL = "\015\012";

    # Reconstruct the full message
    my $message = join('', @{$priv->{raw_hdrs}}) . $EOL . $priv->{body};

    # Extract message-id for logging
    my $msgid = '';
    for my $hdr (@{$priv->{headers}}) {
        if (lc($hdr->[0]) eq 'message-id') {
            $msgid = $hdr->[1];
            $msgid =~ s/^\s+//;
            last;
        }
    }

    warn "dkim2-milter: processing $msgid from=$priv->{env_from} mode=$opts{mode}\n";

    # --- Inbound: verify and cache snapshot ---
    if ($do_verify) {
        my $result = _do_verify($message);
        warn "dkim2-milter: verify $msgid result=$result\n";

        # Build the A-R and X-DKIM2-Info headers we're about to add.
        # Authentication-Results is not in the spec exclusion list so it
        # is included in the header hash.  The MI must be computed over
        # a synthetic message that already contains these headers.
        my $ar_value = "localhost; dkim2=$result";
        my $info_value = _dkim2_info("verify=$result");
        my $ar_raw = "Authentication-Results: $ar_value$EOL";
        my $info_raw = "X-DKIM2-Info: $info_value$EOL";
        my $message_with_ar = $info_raw . $ar_raw . $message;

        # Insert the headers into the milter output
        $ctx->insheader('Authentication-Results', $ar_value, 0);
        $ctx->insheader('X-DKIM2-Info', _milter_value($info_value), 0);

        # Compute MI from the message that includes A-R
        my $mi_header;
        my %mi_info;
        if ($snapshot_store) {
            $mi_header = _compute_mi($message_with_ar, \%mi_info);
            if ($mi_header) {
                warn "dkim2-milter: computed MI for $msgid\n";
            }
        }

        if ($mi_header) {
            $ctx->insheader('Message-Instance', _milter_value($mi_header), 0);
            my ($mi_ver) = $mi_header =~ /m=(\d+)/;
            $ctx->insheader('X-DKIM2-Info', _dkim2_info("mi-m$mi_ver",
                hc => $mi_info{hc}, hn => $mi_info{hn},
                snaps => $mi_info{snaps}), 0);
            warn "dkim2-milter: added MI header for $msgid\n";
        }
    }

    # --- Outbound: compute MI diff if needed, then sign ---
    if ($do_sign) {
        # Check if upstream already handled MI (more MI headers than cached)
        my $mi_header;
        my %mi_info;
        if ($snapshot_store) {
            $mi_header = _compute_mi($message, \%mi_info);
            if ($mi_header) {
                warn "dkim2-milter: computed MI for $msgid\n";
                $ctx->insheader('Message-Instance', _milter_value($mi_header), 0);
                my ($mi_ver) = $mi_header =~ /m=(\d+)/;
                $ctx->insheader('X-DKIM2-Info', _dkim2_info("mi-m$mi_ver",
                    hc => $mi_info{hc}, hn => $mi_info{hn},
                    snapf => $mi_info{snapf}, snaps => $mi_info{snaps}), 0);
                warn "dkim2-milter: added MI header for $msgid\n";
            }
        }

        my $sign_config = _get_sign_config($priv->{env_from});
        if ($sign_config) {
            # If we computed an MI, prepend it to the message for the signer
            my $sign_msg = $message;
            if ($mi_header) {
                $sign_msg = "Message-Instance: $mi_header$EOL" . $sign_msg;
            }

            my $sig_header = _do_sign($sign_msg, $priv, $sign_config);
            if ($sig_header) {
                $ctx->insheader('DKIM2-Signature', _milter_value($sig_header), 0);
                $ctx->insheader('X-DKIM2-Info',
                    _dkim2_info("sign d=$sign_config->{domain} a=$sign_config->{algorithm}"), 0);
                warn "dkim2-milter: signed $msgid d=$sign_config->{domain} "
                   . "a=$sign_config->{algorithm} sel=$sign_config->{selector}\n";
            }
        } else {
            warn "dkim2-milter: no signing key for $msgid from=$priv->{env_from}\n";
        }
    }

    return SMFIS_CONTINUE;
}

sub cb_close {
    my ($ctx) = @_;
    $ctx->setpriv(undef);
    return SMFIS_CONTINUE;
}

# --- Signing config lookup ---

# Returns { domain, selector, key, algorithm } or undef.
sub _get_sign_config {
    my ($env_from) = @_;
    my ($from_domain) = ($env_from || '') =~ /\@(.+)$/;
    return unless $from_domain;
    $from_domain = lc($from_domain);

    # Single-domain mode
    if ($can_sign_single) {
        return unless $from_domain eq lc($opts{domain});
        return {
            domain    => $opts{domain},
            selector  => $opts{selector},
            key       => $sign_key,
            algorithm => $opts{algorithm},
        };
    }

    # Keydir mode
    if ($can_sign_keydir) {
        return _keydir_lookup($from_domain);
    }

    return;
}

# --- Verification ---

sub _do_verify {
    my ($message) = @_;

    my $verifier = Mail::DKIM2::Verifier->new();

    if ($dns_data) {
        $verifier->set_pubkey_callback(sub {
            my ($sig, $idx) = @_;
            $idx //= 0;
            my $sel = $sig->selector($idx);
            my $dom = $sig->domain;
            my $key_txt = $dns_data->{$dom}{"$sel._domainkey"}[0][1]
                if $dns_data->{$dom} && $dns_data->{$dom}{"$sel._domainkey"};
            return parse_dkim_pubkey($key_txt) if $key_txt;
            return $sig->fetch_public_key($idx);  # fall back to real DNS
        });
    }

    $verifier->PRINT($message);
    $verifier->CLOSE();

    return $verifier->result_detail();
}

# --- Message-Instance ---

sub _compute_mi {
    my ($message, $info) = @_;
    $info //= {};

    my $msg = eval { Email::MIME->new($message) };
    return unless $msg;

    # Record which headers will be included in any hash we compute.
    my ($hcount, $hnames) = _header_list_for_hash($msg);
    $info->{hc} = $hcount;
    $info->{hn} = $hnames;

    # Check if topmost MI already matches
    if (Mail::DKIM2::MessageInstance->verify($msg)) {
        # Store snapshot keyed by the matching MI
        my @mi_hdrs = $msg->header_raw('Message-Instance');
        if (@mi_hdrs && $snapshot_store) {
            my %by_v = map { (extract_mi_version($_) || 0) => $_ } @mi_hdrs;
            my $max_v = (sort { $b <=> $a } keys %by_v)[0];
            $snapshot_store->store($by_v{$max_v}, $message);
            $info->{snaps} = $snapshot_store->rel_path_for_mi($by_v{$max_v});
        }
        return undef;  # no new MI needed
    }

    my @mi_hdrs = $msg->header_raw('Message-Instance');

    if (@mi_hdrs && $snapshot_store) {
        my %by_v = map { (extract_mi_version($_) || 0) => $_ } @mi_hdrs;
        my $max_v = (sort { $b <=> $a } keys %by_v)[0];

        # Try to find a snapshot for diff computation
        for my $v (sort { $b <=> $a } keys %by_v) {
            my $snap = $snapshot_store->fetch($by_v{$v});
            if ($snap) {
                $info->{snapf} = $snapshot_store->rel_path_for_mi($by_v{$v});
                my $snap_msg = Email::MIME->new($snap);
                my @snap_mi = $snap_msg->header_raw('Message-Instance');

                # If the current message has more MI headers than the
                # snapshot, upstream (e.g. Mailman) already computed the
                # diff.  Just cache the current state and move on.
                if (@mi_hdrs > @snap_mi) {
                    $snapshot_store->store($by_v{$max_v}, $message);
                    $info->{snaps} = $snapshot_store->rel_path_for_mi($by_v{$max_v});
                    return undef;
                }

                my $mi = eval {
                    Mail::DKIM2::MessageInstance->calculate($msg, $snap_msg, %mi_opts);
                };
                if ($mi) {
                    my $mi_val = _format_mi($mi);
                    # Store new snapshot
                    my $EOL = "\015\012";
                    $snapshot_store->store($mi_val,
                        "Message-Instance: $mi_val$EOL" . $message);
                    $info->{snaps} = $snapshot_store->rel_path_for_mi($mi_val);
                    return $mi_val;
                }
                # calculate failed — upstream may have added MI already
                $snapshot_store->store($by_v{$max_v}, $message);
                $info->{snaps} = $snapshot_store->rel_path_for_mi($by_v{$max_v});
                return undef;
            }
        }
        # Modified but no snapshot available
        return undef;
    }

    if (!@mi_hdrs) {
        # First-time: compute MI v=1
        my $mi = Mail::DKIM2::MessageInstance->calculate($msg);
        my $mi_val = _format_mi($mi);
        # Store snapshot
        if ($snapshot_store) {
            my $EOL = "\015\012";
            $snapshot_store->store($mi_val,
                "Message-Instance: $mi_val$EOL" . $message);
            $info->{snaps} = $snapshot_store->rel_path_for_mi($mi_val);
        }
        return $mi_val;
    }

    return undef;
}

sub _format_mi {
    my ($mi) = @_;
    my $folded = fold_header("Message-Instance: " . $mi->as_string());
    $folded =~ s/^Message-Instance: //;
    return $folded;
}

# Convert CRLF folding to LF for milter insheader (CRLF = end of value)
sub _milter_value {
    my ($val) = @_;
    $val =~ s/\r\n/\n/g;
    return $val;
}

# --- Signing ---

sub _do_sign {
    my ($message, $priv, $config) = @_;

    my $signer = Mail::DKIM2::Signer->new(
        Domain    => $config->{domain},
        Selector  => $config->{selector},
        Key       => $config->{key},
        Algorithm => $config->{algorithm},
        MailFrom  => $priv->{env_from},
        RcptTo    => $priv->{env_rcpt},
    );

    $signer->PRINT($message);
    $signer->CLOSE();

    return unless $signer->result eq 'signed';

    my $header = $signer->as_string();
    # Strip "DKIM2-Signature: " prefix for insheader
    $header =~ s/^DKIM2-Signature:\s*//;
    # Convert CRLF folding to LF folding for milter protocol
    $header =~ s/\r\n/\n/g;
    return $header;
}

__END__

=head1 NAME

dkim2-milter.pl - Standalone DKIM2 milter for Postfix

=head1 SYNOPSIS

    # Verify only (no signing)
    dkim2-milter.pl --socket unix:/var/run/dkim2.sock

    # Sign for a single domain
    dkim2-milter.pl --socket unix:/var/run/dkim2.sock \
        --domain example.com \
        --selector sel1 \
        --keyfile /etc/dkim2/sel1.pem

    # Sign for any domain with keys in a directory
    dkim2-milter.pl --socket unix:/var/run/dkim2.sock \
        --keydir /etc/dkim2/keys

    # With message snapshots for diff-based Message-Instance
    dkim2-milter.pl --socket unix:/var/run/dkim2.sock \
        --keydir /etc/dkim2/keys \
        --snapshot-dir /var/spool/dkim2/snapshots

    # Epilogue-based MI (body in MIME epilogue, compact header)
    dkim2-milter.pl --socket unix:/var/run/dkim2.sock \
        --keydir /etc/dkim2/keys \
        --snapshot-dir /var/spool/dkim2/snapshots \
        --use-epilogue

    # Auto-switch to epilogue when diff exceeds 5 literal lines
    dkim2-milter.pl --socket unix:/var/run/dkim2.sock \
        --keydir /etc/dkim2/keys \
        --snapshot-dir /var/spool/dkim2/snapshots \
        --epilogue-threshold 5

    # Testing with dns.json instead of real DNS
    dkim2-milter.pl --socket inet:8891@localhost \
        --keydir keys \
        --dns-json dns.json

=head1 DESCRIPTION

A standalone milter daemon that provides DKIM2 signature verification and
signing for Postfix (or any milter-compatible MTA).  Uses L<Sendmail::PMilter>
for the milter protocol.

Verification is enabled by default for all inbound messages.

Signing can be configured in two ways:

=over 4

=item B<Single domain>: C<--domain>, C<--selector>, and C<--keyfile>.
Signs only when the envelope sender matches the configured domain.

=item B<Key directory>: C<--keydir PATH>.  The directory contains
subdirectories named by domain, each containing key files named
C<selector.key>.  The milter looks up the sender domain (with parent
domain fallback) and uses the first key found.  The algorithm is
auto-detected from the key type (RSA or Ed25519).

=back

B<EXPERIMENTAL> — This tool implements draft-ietf-dkim-dkim2-spec-01, an
Internet-Draft that has not yet been published as an RFC.  Do not use in
production.

=head1 KEY DIRECTORY LAYOUT

The C<--keydir> option points to a directory tree where each subdirectory
is named after a domain and contains one or more PEM key files with a
C<.key> extension.  The filename (minus the extension) becomes the DKIM
selector.

    /etc/dkim2/keys/
        example.com/
            sel1.key              # RSA key, selector "sel1"
            sel2.key              # another key (used if newer)
        sub.example.com/
            default.key           # selector "default"
        other.org/
            ed25519.key           # Ed25519 key, auto-detected

=head2 Domain lookup

When a message arrives from C<user@sub.example.com>, the milter:

=over 4

=item 1.

Looks for a directory named C<sub.example.com/> under the keydir.

=item 2.

If not found, strips the leftmost label and tries C<example.com/>.

=item 3.

Continues stripping labels until a match is found or no labels remain.

=back

The signing domain (C<d=> tag) is set to the directory name that matched,
not necessarily the full sender domain.

=head2 Key selection

If a domain directory contains multiple C<.key> files, the newest file
by ctime is used.  This makes key rotation straightforward:

    # Generate a new key and publish its DNS record
    openssl genrsa -out /etc/dkim2/keys/example.com/sel2.key 2048

    # The milter will start using sel2 for new signatures immediately
    # (after the domain lookup cache is refreshed on next restart).
    # Keep sel1.key around until its DNS record has propagated.

=head2 Algorithm detection

The signing algorithm is auto-detected from each key file:

=over 4

=item *

Ed25519 keys (32-byte raw or PEM-wrapped) use the C<ed25519> algorithm.

=item *

All other keys (RSA) use C<rsa-sha256>.

=back

No C<--algorithm> flag is needed in keydir mode.

=head2 Caching

Domain-to-key mappings are cached in memory for the lifetime of the milter
process.  After adding or removing key files, restart the milter to pick up
the changes.

=head1 OPTIONS

=over 4

=item B<--socket>, B<-s> I<SPEC>

Milter socket specification.  Default: C<unix:/var/run/dkim2-milter.sock>.
Examples: C<unix:/path/to/sock>, C<inet:8891@localhost>.

=item B<--domain>, B<-d> I<DOMAIN>

Signing domain (single-domain mode).  Requires C<--selector> and C<--keyfile>.

=item B<--selector> I<SELECTOR>

DKIM selector (single-domain mode).  Requires C<--domain> and C<--keyfile>.

=item B<--keyfile>, B<-k> I<PATH>

Path to a PEM-encoded private key (single-domain mode).

=item B<--keydir> I<PATH>

Directory of per-domain key subdirectories (multi-domain mode).
Cannot be combined with C<--domain>/C<--selector>/C<--keyfile>.

=item B<--algorithm>, B<-a> I<ALG>

Signing algorithm for single-domain mode.  Default: C<rsa-sha256>.
In keydir mode, the algorithm is auto-detected from each key file.

=item B<--snapshot-dir> I<PATH>

Directory for message snapshots.  Enables diff-based Message-Instance
computation: on inbound, a snapshot is stored keyed by the MI header value;
on outbound, the snapshot is used to compute recipes describing changes.

=item B<--use-epilogue>

When computing a diff-based MI, always store the previous message body in
the MIME epilogue rather than as inline diff lines.  This keeps MI headers
small regardless of how much the body changed, at the cost of increasing
the transmitted message size.  Cannot be combined with C<--epilogue-threshold>.

=item B<--epilogue-threshold> I<N>

When computing a diff-based MI, switch to epilogue storage only when the
diff recipe would contain more than I<N> literal (non-range) lines.  Small
changes (C<< <= N >> lines) stay as a compact inline diff; large changes
fall back to epilogue.  C<5> is a reasonable starting value.
Cannot be combined with C<--use-epilogue>.

=item B<--dns-json> I<PATH>

Path to a JSON file with DNS key records (for testing without real DNS).
Format: C<< { "domain": { "selector._domainkey": [["txt", "v=DKIM1; ..."]] } } >>.

=item B<--verify>, B<--no-verify>

Enable or disable verification.  Default: enabled.

=item B<--sign>, B<--no-sign>

Enable or disable signing.  Default: enabled if signing config is available.

=item B<--help>, B<-h>

Show this help message.

=back

=head1 POSTFIX CONFIGURATION

Add to C<main.cf>:

    # For inbound verification
    smtpd_milters = unix:/var/run/dkim2-milter.sock

    # For outbound signing (locally-generated mail)
    non_smtpd_milters = unix:/var/run/dkim2-milter.sock

    # Milter default action if the milter is unavailable
    milter_default_action = accept

=head1 DEPENDENCIES

Requires L<Sendmail::PMilter> (not included in this distribution).
Install via CPAN:

    cpanm Sendmail::PMilter

=head1 AUTHOR

Bron Gondwana E<lt>brong@fastmailteam.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2025 Fastmail Pty Ltd.  This is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
