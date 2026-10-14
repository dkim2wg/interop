# DKIM2 for stock Mailman (milters + Postfix only) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a Postfix host running unpatched Mailman 3 give chosen lists full DKIM2 chain-of-custody, with `dkim2-milter` wrapping single-part posts at ingress and Postfix routing only chosen list traffic through the milters.

**Architecture:** A new pure library function `Mail::DKIM2::Wrap::wrap_single_part` turns a single-part message into a one-part `multipart/mixed`. `dkim2-milter --wrap-single-part` (inbound mode) applies it after its usual verify/stamp/snapshot, records it as its own unsigned `Message-Instance` (`m=k+1`) and snapshots the wrapped form. Stock Mailman then adds its footer as an extra part, and the outbound milter diffs against that snapshot (`m=k+2`) and signs. Postfix `transport_maps` (per recipient, inbound) and `check_sender_access` `FILTER` (per envelope sender, outbound on a loopback listener) keep every other message away from the milters. The outbound milter also stops adding anything when it has no key.

**Tech Stack:** Perl 5.20+, Sendmail::PMilter 1.28+, CryptX (`Crypt::PRNG`), Postfix 3.x, stock Mailman 3.3.x.

**Spec:** `docs/superpowers/specs/2026-10-13-stock-mailman-milter-only-design.md`

## Global Constraints

- Spec: draft-ietf-dkim-dkim2-spec-06. No change to signing, verifying or Recipe formats.
- Mailman stays stock: only `[mta] smtp_port: 10025` and `max_recipients: 1` change in `mailman.cfg`. No patch, no plugin.
- `dkim2-milter` only; authentication_milter handlers are not touched.
- Library conventions (read `perl/lib/Mail/DKIM2.pm` first): CamelCase options, snake_case functions, string-only exceptions, every public function documented in POD (`t/pod-coverage.t`).
- Release: Mail::DKIM2 **0.20** (every `$VERSION` in `perl/lib`); tarball built, not uploaded (Bron uploads to CPAN).
- No wall-clock timing assertions in tests.
- Without `--wrap-single-part`, inbound behaviour is unchanged. Without a key, outbound adds nothing (this changes behaviour for everyone, deliberately).
- Postfix sender map lives only on a loopback listener, never on port 25 (signing oracle otherwise).
- All work on branch `stock-mailman`; finish by merging locally into `master`.

## Review Focus

1. A single-part post whose body does not end in CRLF, or is empty: the wrapped part must still contain exactly the original body, and `m=k+1`'s undo must rebuild the arrival message byte for byte (Task 1 tests both; Task 3 tests the undo end to end).
2. A post with several `Content-*` fields (duplicated `Content-Type`, folded `Content-Type`, `Content-Disposition`): order and folding kept in the inner part, every outer one removed, Postfix index semantics respected (Task 1 + Task 3 apply the edits the way Postfix does).
3. A post whose upstream top `Message-Instance` does not verify (no arrival snapshot): must be delivered unwrapped with no `m=k+1`, never wrapped with an instance that cannot be undone (Task 3).
4. A body larger than 65535 bytes: replace-body must go out in several packets and reassemble exactly (Task 3).
5. Mail from a sender with no key through the outbound milter: no `Message-Instance`, no `X-DKIM2-Info`, no `DKIM2-Signature`, verdict continue (Task 2).

---

### Task 1: `Mail::DKIM2::Wrap`

**Files:**
- Create: `perl/lib/Mail/DKIM2/Wrap.pm`
- Create: `perl/t/wrap.t`
- Modify: `perl/MANIFEST` (add both, keep sorted)

**Interfaces:**
- Produces: `Mail::DKIM2::Wrap::wrap_single_part($message, %opt)` (exportable). `$message` is a whole message with CRLF line ends. `%opt`: `Boundary => sub { ... }` returning a candidate boundary string (tests only; default random). Returns `undef` when the message is `multipart/*` or has no header/body separator; otherwise a hashref:
  - `message` — the wrapped message (headers in original order, first `Content-Type` replaced in place, other `Content-*` removed, `Content-Type` appended if there was none, `MIME-Version: 1.0` appended if absent; then CRLF; then `body`)
  - `body` — the new body
  - `boundary` — the boundary used
  - `edits` — arrayref of `{ op => 'delete', name, index }`, then at most one `{ op => 'change', name => 'Content-Type', index => 1, value }`, then `{ op => 'add', name, value }`. `index` is 1-based among fields of that name (case-insensitive) in the input; deletes come last-first so each index still names the same field when applied in order.

- [ ] **Step 1: Write the failing test** — `perl/t/wrap.t`:

```perl
#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use lib 'lib';
use Mail::DKIM2::Wrap qw(wrap_single_part);

my $EOL = "\015\012";
sub msg { join($EOL, @_) }
my $B = 'BOUNDARY';
my @fixed = (Boundary => sub { $B });

# 1. Plain text/plain post: inner part keeps the Content-* fields verbatim,
#    in order, with their folding; body copied byte for byte.
{
    my $in = msg('From: a@example.org', 'Content-Type: text/plain;', "\tcharset=utf-8",
                 'Subject: hi', 'Content-Transfer-Encoding: 8bit', '', "h\xc3\xa9llo", '');
    my $w = wrap_single_part($in, @fixed);
    ok($w, 'single part is wrapped');
    is($w->{boundary}, $B, 'uses the boundary given');
    is($w->{body},
       "--$B$EOL" . "Content-Type: text/plain;$EOL\tcharset=utf-8$EOL"
       . "Content-Transfer-Encoding: 8bit$EOL$EOL" . "h\xc3\xa9llo$EOL" . "$EOL--$B--$EOL",
       'inner part: Content-* verbatim and in order, then the body, then the close');
    is($w->{message},
       msg('From: a@example.org', qq{Content-Type: multipart/mixed; boundary="$B"},
           'Subject: hi', 'MIME-Version: 1.0', '', '') . $w->{body},
       'outer: Content-Type changed in place, CTE removed, MIME-Version appended');
    is_deeply($w->{edits}, [
        { op => 'delete', name => 'Content-Transfer-Encoding', index => 1 },
        { op => 'change', name => 'Content-Type', index => 1, value => qq{multipart/mixed; boundary="$B"} },
        { op => 'add', name => 'MIME-Version', value => '1.0' },
    ], 'edits for the milter');
}

# 2. Body without a trailing CRLF, and an empty body: the part content is
#    exactly the original body (the CRLF before the close delimiter belongs
#    to the delimiter).
{
    my $w = wrap_single_part(msg('MIME-Version: 1.0', 'Content-Type: text/plain', '', 'no newline'), @fixed);
    like($w->{body}, qr/\r\n\r\nno newline\r\n--$B--\r\n\z/, 'no trailing CRLF: none invented in the content');
    my $e = wrap_single_part(msg('Content-Type: text/plain', '', ''), @fixed);
    is($e->{body}, "--$B$EOL" . "Content-Type: text/plain$EOL$EOL$EOL--$B--$EOL", 'empty body');
}

# 3. No Content-* fields at all: an inner part with no headers (MIME's
#    default text/plain), Content-Type and MIME-Version appended outside.
{
    my $w = wrap_single_part(msg('From: a@example.org', '', 'x', ''), @fixed);
    is($w->{body}, "--$B$EOL$EOL" . "x$EOL$EOL--$B--$EOL", 'inner part with no headers');
    is_deeply($w->{edits}, [
        { op => 'add', name => 'Content-Type', value => qq{multipart/mixed; boundary="$B"} },
        { op => 'add', name => 'MIME-Version', value => '1.0' },
    ], 'both added, nothing changed or deleted');
}

# 4. Duplicate Content-Type, plus Content-Disposition: second one deleted
#    before the first is changed; deletes last-first.
{
    my $w = wrap_single_part(msg('Content-Type: text/plain', 'Content-Disposition: inline',
        'Content-Type: text/html', 'MIME-Version: 1.0', '', 'x', ''), @fixed);
    is_deeply($w->{edits}, [
        { op => 'delete', name => 'Content-Type', index => 2 },
        { op => 'delete', name => 'Content-Disposition', index => 1 },
        { op => 'change', name => 'Content-Type', index => 1, value => qq{multipart/mixed; boundary="$B"} },
    ], 'duplicate Content-Type deleted, first changed, MIME-Version kept');
    like($w->{body}, qr/^--$B\r\nContent-Type: text\/plain\r\nContent-Disposition: inline\r\nContent-Type: text\/html\r\n\r\n/,
         'all three Content-* fields carried into the part, in order');
}

# 5. Multipart is left alone, however it is spelled; so is a message with no
#    blank line between header and body.
is(wrap_single_part(msg('Content-Type: Multipart/Alternative; boundary=x', '', '--x--', '')), undef,
   'multipart/alternative left alone');
is(wrap_single_part(msg('Content-Type: multipart/mixed', '', 'x', '')), undef,
   'multipart without a boundary parameter left alone');
is(wrap_single_part("From: a\@example.org$EOL"), undef, 'no header/body separator: left alone');

# 6. A boundary that occurs in the body is not used.
{
    my @c = ('clash', 'clean');
    my $w = wrap_single_part(msg('Content-Type: text/plain', '', '--clash in the body', ''),
                             Boundary => sub { shift @c });
    is($w->{boundary}, 'clean', 'a boundary found in the body is skipped');
}

# 7. Default boundaries are random and distinct.
{
    my $m = msg('Content-Type: text/plain', '', 'x', '');
    isnt(wrap_single_part($m)->{boundary}, wrap_single_part($m)->{boundary}, 'random boundaries differ');
}

done_testing;
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd perl && prove -l t/wrap.t`
Expected: FAIL, `Can't locate Mail/DKIM2/Wrap.pm`.

- [ ] **Step 3: Implement** — `perl/lib/Mail/DKIM2/Wrap.pm`:

```perl
package Mail::DKIM2::Wrap;
use 5.20.0;
use strict;
use warnings;

our $VERSION = '0.19';

use Exporter 'import';
use Crypt::PRNG qw(random_bytes);

our @EXPORT_OK = qw(wrap_single_part);

my $EOL = "\015\012";

sub _random_boundary { '=_dkim2_' . unpack('H*', random_bytes(12)) }

sub wrap_single_part {
    my ($message, %opt) = @_;
    my $gen = $opt{Boundary} // \&_random_boundary;

    my $sep = index($message, "$EOL$EOL");
    return undef if $sep < 0;
    my $head = substr($message, 0, $sep + 2);
    my $body = substr($message, $sep + 4);

    my @fields = $head =~ /\G([^\r\n]*\r\n(?:[ \t][^\r\n]*\r\n)*)/g;
    return undef unless join('', @fields) eq $head;
    my @parsed;
    for my $f (@fields) {
        my ($name) = $f =~ /^([^:\s]+)[ \t]*:/ or return undef;
        push @parsed, [$name, $f];
    }

    my ($ct) = grep { lc $_->[0] eq 'content-type' } @parsed;
    return undef if $ct && $ct->[1] =~ /^[^:]+:\s*multipart\//i;

    my $boundary;
    for (1 .. 10) {
        my $c = $gen->();
        if (index($body, "--$c") < 0) { $boundary = $c; last }
    }
    return undef unless defined $boundary;

    my @content = grep { $_->[0] =~ /^content-/i } @parsed;
    my $new_body = "--$boundary$EOL" . join('', map { $_->[1] } @content)
                 . $EOL . $body . "$EOL--$boundary--$EOL";
    my $ct_value = qq{multipart/mixed; boundary="$boundary"};

    my (%count, @deletes, @out, $changed);
    for my $p (@parsed) {
        my $lc = lc $p->[0];
        my $i = ++$count{$lc};
        if ($lc eq 'content-type' && $i == 1) {
            push @out, "$p->[0]: $ct_value$EOL";
            $changed = 1;
        } elsif ($lc =~ /^content-/) {
            push @deletes, { op => 'delete', name => $p->[0], index => $i };
        } else {
            push @out, $p->[1];
        }
    }
    my @edits = reverse @deletes;
    push @edits, { op => 'change', name => 'Content-Type', index => 1, value => $ct_value }
        if $changed;
    my @adds;
    push @adds, ['Content-Type', $ct_value] unless $changed;
    push @adds, ['MIME-Version', '1.0'] unless $count{'mime-version'};
    for my $a (@adds) {
        push @out, "$a->[0]: $a->[1]$EOL";
        push @edits, { op => 'add', name => $a->[0], value => $a->[1] };
    }

    return {
        message  => join('', @out) . $EOL . $new_body,
        body     => $new_body,
        boundary => $boundary,
        edits    => \@edits,
    };
}

1;

__END__

=head1 NAME

Mail::DKIM2::Wrap - wrap a single-part message in a one-part multipart/mixed

=head1 SYNOPSIS

    use Mail::DKIM2::Wrap qw(wrap_single_part);
    my $w = wrap_single_part($message) or return;   # undef: already multipart
    # $w->{message}, $w->{body}, $w->{boundary}, $w->{edits}

=head1 DESCRIPTION

A list manager that adds a footer to a single-part C<text/plain> post
re-encodes the whole body, and the change can then only be described by a
null body Recipe. Wrapping the post first -- its C<Content-*> fields and its
body, byte for byte, become the only part of a C<multipart/mixed> -- makes
the footer an extra part instead. C<dkim2-milter --wrap-single-part> applies
this at ingress for stock Mailman.

=head1 FUNCTIONS

=head2 wrap_single_part($message, %options)

C<$message> is a whole message with CRLF line ends. Returns C<undef> for a
C<multipart/*> message (or one with no blank line after the header), else a
hash reference: C<message> (the wrapped message), C<body> (its new body),
C<boundary>, and C<edits>, the header changes as milter operations: deletes
(C<name>, 1-based C<index> among fields of that name, last first), then the
change of the first C<Content-Type>, then additions (C<Content-Type> if there
was none, C<MIME-Version: 1.0> if absent). Option C<Boundary> is a code
reference returning a candidate boundary; the default is random. A
candidate that occurs in the body is skipped.

=cut
```

(`$VERSION` stays `0.19` here; Task 5 bumps every module together.)

- [ ] **Step 4: Run the tests**

Run: `cd perl && prove -l t/wrap.t t/pod.t t/pod-coverage.t`
Expected: PASS.

- [ ] **Step 5: Add both files to `perl/MANIFEST`** (alphabetical position: `lib/Mail/DKIM2/Wrap.pm` after `lib/Mail/DKIM2/Verifier.pm`; `t/wrap.t` after the last `t/v*` entry), then commit:

```bash
git add perl/lib/Mail/DKIM2/Wrap.pm perl/t/wrap.t perl/MANIFEST
git commit -m "perl: Mail::DKIM2::Wrap, a single-part message as a one-part multipart/mixed"
```

---

### Task 2: dkim2-milter: header/body capabilities and no-key passthrough

**Files:**
- Modify: `perl/bin/dkim2-milter` (the `register` call near "We need to add/insert headers"; the outbound block in `cb_eom` starting `if ($do_sign) {`)
- Test: `perl/t/milter-script.t`

**Interfaces:**
- Produces (in `t/milter-script.t`, used by Task 3): `spawn_milter(mode => 'inbound'|'outbound', extra => [...])`; `read_verdict` records `{ op => 'body', value }` for `SMFIR_REPLBODY` (`'b'`); `apply_mods($message, $mods)` returns the message as Postfix would leave it (inserts, changes/deletes by per-name index, adds, replaced body).

- [ ] **Step 1: Extend the harness.** In `spawn_milter`, replace `'--mode', 'outbound',` with `'--mode', ($o{mode} // 'outbound'),`. In `read_verdict`, before the `'p'` branch add:

```perl
        } elsif ($code eq 'b') {           # SMFIR_REPLBODY: one chunk of the new body
            push @$mods, { op => 'body', value => $data };
```

After `sub assemble`, add:

```perl
# The message as Postfix leaves it: insert at idx, change/delete the idx-th
# field of that name (case-insensitive, 1-based), add at the end, and the
# replace-body chunks concatenated.
sub apply_mods {
    my ($message, $mods) = @_;
    my ($hdr, $body) = split /$EOL$EOL/, $message, 2;
    my @h = map { [ (/^([^:\s]+):/)[0], "$_$EOL" ] } split /$EOL(?!\s)/, $hdr;
    my $new_body;
    for my $m (@$mods) {
        my $v = $m->{value} // '';
        $v =~ s/\r?\n/$EOL/g;
        if ($m->{op} eq 'insert') {
            splice @h, $m->{idx}, 0, [$m->{name}, "$m->{name}: $v$EOL"];
        } elsif ($m->{op} eq 'add') {
            push @h, [$m->{name}, "$m->{name}: $v$EOL"];
        } elsif ($m->{op} eq 'change') {
            my ($n, $pos) = (0);
            for my $i (0 .. $#h) {
                next unless lc $h[$i][0] eq lc $m->{name};
                if (++$n == $m->{idx}) { $pos = $i; last }
            }
            next unless defined $pos;
            if ($v eq '') { splice @h, $pos, 1 }
            else          { $h[$pos] = [$h[$pos][0], "$h[$pos][0]: $v$EOL"] }
        } elsif ($m->{op} eq 'body') {
            $new_body .= $m->{value};
        }
    }
    return join('', map { $_->[1] } @h) . $EOL . ($new_body // $body);
}
```

- [ ] **Step 2: Write the failing no-key test.** Append before `done_testing;`:

```perl
# --- Outbound with no key for the sender: add nothing at all ---
# A list host's single outbound listener carries every list; a list whose
# domain has no key must leave exactly as it came, not with an unsigned
# Message-Instance a receiver reports as permerror.
{
    my $signed = originator_signed();
    my ($verdict, $mods) = run_milter(
        from => 'list-bounces@nokey.example', rcpt => ['subscriber@example.org'],
        message => list_modified($signed));
    is($verdict, 'c', 'no key: milter continues');
    is_deeply($mods, [], 'no key: no header added, changed or removed')
        or diag(explain($mods));
    like(milter_log(), qr/no signing key for .* from=list-bounces\@nokey\.example/, 'no key: logged');
}
```

- [ ] **Step 3: Run it to make sure it fails**

Run: `cd perl && prove -l t/milter-script.t`
Expected: FAIL at `no key: no header added, changed or removed` (today a `Message-Instance` and `X-DKIM2-Info` are inserted).

- [ ] **Step 4: Implement.** In `cb_eom`'s outbound block, the first statement inside `if ($do_sign) {` becomes a key lookup that returns early; reuse the result later instead of the second `_get_sign_config` call:

```perl
    if ($do_sign) {
        # No key for this sender: this message is not ours to sign, so it
        # leaves exactly as it came -- no Message-Instance (unsigned, a
        # receiver reports it as permerror), no X-DKIM2-Info, no snapshot.
        my $from_hdr_domain = '';
        for my $hdr (@{$priv->{headers}}) {
            if (lc($hdr->[0]) eq 'from') {
                ($from_hdr_domain) = $hdr->[1] =~ /\@([\w.-]+)/;
                $from_hdr_domain = lc($from_hdr_domain // '');
                last;
            }
        }
        my $sign_config = _get_sign_config($priv->{env_from}, $from_hdr_domain);
        unless ($sign_config) {
            warn "dkim2-milter: no signing key for $msgid from=$priv->{env_from}\n";
            return SMFIS_CONTINUE;
        }
```

Then delete the now-duplicate code: the `my $gate_sd; { ... }` block (use `my $gate_sd = $sign_config->{domain};`), the later `my $from_hdr_domain = ''; for ... { ... }` block, and change `my $sign_config = $mi_failed ? undef : _get_sign_config(...)` to `$sign_config = undef if $mi_failed;`. Remove the final `else { warn "...no signing key..." }` branch (unreachable). Keep the `$mi_failed` log path.

In `--mode both`, the inbound half has already run before this point, so its headers are unaffected.

- [ ] **Step 5: Register the capabilities the program uses.** It already calls `chgheader` (stripping broken intermediate instances), which Sendmail::PMilter refuses without `SMFIF_CHGHDRS`; Task 3 adds `replacebody`. Change the registration to:

```perl
}, SMFIF_ADDHDRS | SMFIF_CHGHDRS | SMFIF_CHGBODY);
```

and the comment above it to `# Insert, change and delete headers; replace the body (--wrap-single-part).`

- [ ] **Step 6: Run the milter tests**

Run: `cd perl && prove -l t/milter-script.t t/milter-sign-gate.t t/milter.t`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add perl/bin/dkim2-milter perl/t/milter-script.t
git commit -m "dkim2-milter: add nothing to mail it has no key for; register CHGHDRS/CHGBODY"
```

---

### Task 3: `dkim2-milter --wrap-single-part`

**Files:**
- Modify: `perl/bin/dkim2-milter` (options, startup checks, inbound block of `cb_eom`, POD)
- Test: `perl/t/milter-script.t`

**Interfaces:**
- Consumes: `wrap_single_part` (Task 1); `spawn_milter(mode =>)`, `apply_mods`, `{op=>'body'}` (Task 2); existing `_compute_mi($message, \%info)` which, when the top instance does not match, diffs against the newest stored snapshot, returns the new instance value and stores `"Message-Instance: <value>\r\n" . $message` keyed by it.
- Produces: option `--wrap-single-part`; `X-DKIM2-Info` action `wrap-single-part`; log line `dkim2-milter: wrapped <msgid> as m=<N>`.

- [ ] **Step 1: Write the failing tests.** Append before `done_testing;` in `t/milter-script.t`:

```perl
# --- Inbound --wrap-single-part (stock Mailman) ---
my ($in_pid, $in_sock) = spawn_milter(mode => 'inbound', extra => ['--wrap-single-part']);
ok(-S $in_sock, 'wrapping inbound milter is listening');

sub verify_unsigned_top {
    my ($raw) = @_;
    my $v = Mail::DKIM2::Verifier->new;
    $v->set_pubkey_callback(DKIM2TestKeys::pubkey_callback());
    $v->allow_unsigned_mi(1);
    $v->PRINT($raw); $v->CLOSE;
    return $v;
}
sub mi_numbers { my ($raw) = @_; sort { $a <=> $b } $raw =~ /^Message-Instance:.*?\bm=(\d+)/msig }

# What stock Mailman's decorator does to a multipart/mixed: the footer as an
# extra text/plain part before the close delimiter, plus list headers.
sub stock_decorate {
    my ($raw) = @_;
    my ($b) = $raw =~ /boundary="([^"]+)"/ or die 'no boundary';
    $raw =~ s/^Subject: /Subject: [list] /m;
    $raw =~ s/^(From: )/List-Id: <list.test2.dkim2.com>$EOL$1/m;
    $raw =~ s/--\Q$b\E--$EOL\z/--$b$EOL"
        . "Content-Type: text\/plain; charset=\"us-ascii\"$EOL" . "MIME-Version: 1.0$EOL"
        . "Content-Transfer-Encoding: 7bit$EOL" . "Content-Disposition: inline$EOL$EOL"
        . "list footer$EOL" . "--$b--$EOL"/e;
    return $raw;
}

# 1. Signed single-part post: m=2 records the wrap and undoes to the signed m=1.
{
    my $signed = originator_signed();
    my ($verdict, $mods) = run_milter(sock => $in_sock,
        from => 'author@test1.dkim2.com', rcpt => ['list@test2.dkim2.com'], message => $signed);
    is($verdict, 'c', 'wrap: milter continues');
    my $wire = apply_mods($signed, $mods);
    like($wire, qr/^Content-Type: multipart\/mixed; boundary="=_dkim2_[0-9a-f]+"$/m, 'wrap: outer is multipart/mixed');
    is_deeply([mi_numbers($wire)], [1, 2], 'wrap: m=1 (sender) and m=2 (the wrap)');
    like(join(' ', map { $_->{value} } inserted($mods, 'X-DKIM2-Info')), qr/action=wrap-single-part;/,
         'wrap: X-DKIM2-Info records it');
    my $v = verify_unsigned_top($wire);
    is($v->result, 'pass', 'wrap: m=2 undoes to the signed m=1') or diag($v->result_detail);

    # The snapshot for m=2 is the wrapped message itself.
    my ($m2) = grep { /\bm=2\b/ } map { $_->{value} } inserted($mods, 'Message-Instance');
    my $snap = Mail::DKIM2::MessageStore->new(directory => "$dir/snap")->fetch($m2);
    ok($snap, 'wrap: snapshot stored for m=2');
    my ($snap_body) = $snap =~ /\r\n\r\n(.*)\z/s;
    my ($wire_body) = $wire =~ /\r\n\r\n(.*)\z/s;
    is($snap_body, $wire_body, 'wrap: snapshot body is the wrapped body');

    # Stock decoration, then the outbound milter: m=3 and i=2 over the whole chain.
    my $decorated = stock_decorate($wire);
    my ($v2, $omods) = run_milter(
        from => 'list-bounces@test2.dkim2.com', rcpt => ['subscriber@example.org'], message => $decorated);
    my $out = assemble($decorated, $omods);
    is_deeply([mi_numbers($out)], [1, 2, 3], 'wrap: list changes are m=3');
    my $rv = verify($out);
    is($rv->result, 'pass', 'wrap: full chain verifies at a receiver') or diag($rv->result_detail);
    like($rv->result_detail, qr/i=1\.\.2/, 'wrap: both signatures verified');
}

# 2. Unsigned single-part post: m=1 stamped, m=2 wrap; the outbound milter
#    signs the unchanged message as i=1 over both.
{
    my ($verdict, $mods) = run_milter(sock => $in_sock,
        from => 'author@test1.dkim2.com', rcpt => ['list@test2.dkim2.com'], message => $PLAIN);
    my $wire = apply_mods($PLAIN, $mods);
    is_deeply([mi_numbers($wire)], [1, 2], 'unsigned wrap: m=1 and m=2');
    my ($v2, $omods) = run_milter(
        from => 'list-bounces@test2.dkim2.com', rcpt => ['subscriber@example.org'], message => $wire);
    my $rv = verify(assemble($wire, $omods));
    is($rv->result, 'pass', 'unsigned wrap: signed copy verifies') or diag($rv->result_detail);
}

# 3. Multipart is left alone: no body, no header change, only the arrival headers.
{
    my $mp = join($EOL, 'MIME-Version: 1.0', 'Message-Id: <mp@test1.dkim2.com>',
        'From: Author <author@test1.dkim2.com>', 'To: list@test2.dkim2.com', 'Subject: mp',
        'Content-Type: multipart/alternative; boundary="x"', '', '--x',
        'Content-Type: text/plain', '', 'plain', '--x', 'Content-Type: text/html', '', '<p>html</p>', '--x--', '');
    my ($verdict, $mods) = run_milter(sock => $in_sock,
        from => 'author@test1.dkim2.com', rcpt => ['list@test2.dkim2.com'], message => $mp);
    is_deeply([grep { $_->{op} ne 'insert' } @$mods], [], 'multipart: nothing changed, only inserts');
    is_deeply([mi_numbers(assemble($mp, $mods))], [1], 'multipart: only the arrival m=1');
}

# 4. Upstream top instance that does not match (no arrival snapshot): not wrapped.
#    Its own Message-Id: snapshots are keyed by the instance value, and test 1
#    already stored one for originator_signed()'s m=1 -- the tampered copy
#    would find it and look like a local change.
{
    (my $other = $PLAIN) =~ s/<post\@test1/<tampered\@test1/;
    my $broken = originator_signed($other);
    $broken =~ s/Here's a test user!/Here's a tampered user!/;
    my ($verdict, $mods) = run_milter(sock => $in_sock,
        from => 'author@test1.dkim2.com', rcpt => ['list@test2.dkim2.com'], message => $broken);
    is($verdict, 'c', 'broken upstream: milter continues');
    ok(!grep({ $_->{op} eq 'body' || $_->{op} eq 'change' || $_->{op} eq 'add' } @$mods),
       'broken upstream: not wrapped');
    like(milter_log(), qr/not wrapping .*no arrival snapshot/, 'broken upstream: logged');
}

# 5. A body over one milter packet (65535 bytes) is replaced in several
#    chunks and reassembles exactly.
{
    my $big = $PLAIN;
    $big =~ s/Here's a test user!/join($EOL, map { "line $_ " . ('x' x 70) } 1 .. 2000)/e;
    my ($verdict, $mods) = run_milter(sock => $in_sock,
        from => 'author@test1.dkim2.com', rcpt => ['list@test2.dkim2.com'], message => $big);
    cmp_ok(scalar(grep { $_->{op} eq 'body' } @$mods), '>', 1, 'big body: several replace-body packets');
    my $wire = apply_mods($big, $mods);
    my ($orig_body) = $big =~ /\r\n\r\n(.*)\z/s;
    ok(index($wire, $orig_body) > 0, 'big body: original body carried whole');
    my ($v2, $omods) = run_milter(
        from => 'list-bounces@test2.dkim2.com', rcpt => ['subscriber@example.org'], message => $wire);
    is(verify(assemble($wire, $omods))->result, 'pass', 'big body: signed copy verifies');
}

# 6. Startup checks.
like(`$^X -I$LIB $SCRIPT --mode outbound --keydir $dir/keys --snapshot-dir $dir/snap --wrap-single-part 2>&1`,
     qr/--wrap-single-part needs --mode inbound/, 'wrap refused in outbound mode');
like(`$^X -I$LIB $SCRIPT --mode inbound --wrap-single-part 2>&1`,
     qr/--wrap-single-part needs --snapshot-dir/, 'wrap refused without a snapshot directory');
```

Add `use Mail::DKIM2::MessageStore;` to the `use` lines at the top of the file, and let the existing `originator_signed` take an optional message: change its first line to `my $plain = shift // $PLAIN;` and use `$plain` in place of `$PLAIN` in its body (existing callers pass nothing and are unaffected).

- [ ] **Step 2: Run them to make sure they fail**

Run: `cd perl && prove -l t/milter-script.t`
Expected: FAIL: the inbound milter ignores/rejects `--wrap-single-part` (`Unknown option`), so it never listens.

- [ ] **Step 3: Implement the option.** In `GetOptions` add `'wrap-single-part',`. After the existing option checks add:

```perl
if ($opts{'wrap-single-part'}) {
    die "--wrap-single-part needs --mode inbound\n" unless $opts{mode} eq 'inbound';
    die "--wrap-single-part needs --snapshot-dir\n" unless $opts{'snapshot-dir'};
}
```

(The mode default is applied before these checks: place them after `$opts{mode} //= 'both';`.) Add `use Mail::DKIM2::Wrap qw(wrap_single_part);` next to the other `use Mail::DKIM2::...` lines, and log `warn "dkim2-milter: wrapping single-part posts\n" if $opts{'wrap-single-part'};` after the mode log line.

- [ ] **Step 4: Implement the wrap in `cb_eom`.** At the end of the inbound block (after the `if ($mi_header) { ... }` that inserts the arrival instance), add:

```perl
        # --wrap-single-part: stock Mailman pastes a footer into a single-part
        # body (re-encoding it); a multipart/mixed gets the footer as an extra
        # part instead. Wrap here, record the wrap as its own unsigned
        # instance, and snapshot the wrapped message for the outbound diff.
        # Everything is computed before anything is sent, so any failure
        # leaves the message unwrapped with only its arrival headers.
        if ($opts{'wrap-single-part'}) {
            my $current = ($mi_header ? "Message-Instance: $mi_header$EOL" : '') . $message_with_ar;
            my ($wrap, $wrap_mi, %wrap_info);
            if (!$mi_info{snaps}) {
                warn "dkim2-milter: not wrapping $msgid: no arrival snapshot\n";
            } else {
                my $ok = eval {
                    $wrap = wrap_single_part($current);
                    $wrap_mi = _compute_mi($wrap->{message}, \%wrap_info) if $wrap;
                    1;
                };
                if (!$ok) {
                    warn "dkim2-milter: not wrapping $msgid: internal error: " . _error_text($@) . "\n";
                    $wrap = undef;
                } elsif ($wrap && !$wrap_mi) {
                    warn "dkim2-milter: not wrapping $msgid: no Message-Instance for the wrap\n";
                    $wrap = undef;
                }
            }
            if ($wrap) {
                for my $e (@{$wrap->{edits}}) {
                    if    ($e->{op} eq 'delete') { $ctx->chgheader($e->{name}, $e->{index}, '') }
                    elsif ($e->{op} eq 'change') { $ctx->chgheader($e->{name}, $e->{index}, $e->{value}) }
                    else                         { $ctx->addheader($e->{name}, $e->{value}) }
                }
                my $body = $wrap->{body};
                for (my $o = 0; $o < length $body; $o += 65535) {
                    $ctx->replacebody(substr($body, $o, 65535));
                }
                $ctx->insheader('Message-Instance', _milter_value($wrap_mi), 0);
                my ($wrap_ver) = $wrap_mi =~ /m=(\d+)/;
                $ctx->insheader('X-DKIM2-Info', _milter_value(_dkim2_info("wrap-single-part")), 0);
                $ctx->insheader('X-DKIM2-Info', _dkim2_info("mi-m=$wrap_ver",
                    hc => $wrap_info{hc}, hn => $wrap_info{hn},
                    snapf => $wrap_info{snapf}, snaps => $wrap_info{snaps}), 0);
                warn "dkim2-milter: wrapped $msgid as m=$wrap_ver\n";
            }
        }
```

Notes for the implementer: `$mi_info{snaps}` is set by `_compute_mi` whenever it stored the arrival snapshot (both when it stamped `m=1` and when the upstream top instance already matched). `_compute_mi` on the wrapped message finds the arrival snapshot (keyed by the top instance), returns `m=k+1`, and stores the wrapped message under it, which is the snapshot the outbound milter will find. If `_compute_mi` ever returns a `strip_mi_versions` entry here, treat it as a failure (set `$wrap = undef` with a log line): the inbound side never strips.

- [ ] **Step 5: Document the option in the POD** (`=head1 OPTIONS`, after `--allow-null-body-recipe`):

```pod
=item B<--wrap-single-part>

Inbound mode only, and needs C<--snapshot-dir>. After verifying, stamping and
keeping the arrival snapshot, wrap a message that is not C<multipart/*> into a
one-part C<multipart/mixed> (its C<Content-*> fields and body unchanged, see
L<Mail::DKIM2::Wrap>), record the wrap as a new unsigned Message-Instance, and
keep the wrapped message as the snapshot the outbound milter diffs against.
For stock Mailman, whose footer then becomes an extra MIME part instead of
re-encoding the body. A message whose arrival snapshot could not be kept (an
upstream instance that does not match) is not wrapped. Adds
C<X-DKIM2-Info: action=wrap-single-part;>.
```

- [ ] **Step 6: Run the tests**

Run: `cd perl && prove -l t/milter-script.t t/wrap.t t/pod.t`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add perl/bin/dkim2-milter perl/t/milter-script.t
git commit -m "dkim2-milter: --wrap-single-part wraps posts for stock Mailman as their own Message-Instance"
```

---

### Task 4: Postfix + unit examples and the mailop guide

**Files:**
- Create: `deploy/examples/postfix-stock-mailman-main.cf.fragment`
- Create: `deploy/examples/postfix-stock-mailman-master.cf.fragment`
- Create: `deploy/examples/postfix-dkim2-lists` (transport map template)
- Create: `deploy/examples/postfix-dkim2-list-senders` (PCRE map template)
- Create: `deploy/examples/dkim2-milter-wrap.service`
- Create: `docs/dkim2-postfix-stock-mailman-guide.md`
- Modify: `docs/dkim2-postfix-list-host-guide.md` (pointer near the top and in section 7), `docs/dkim2-operator-guide.md` (pointer where it links the list-host guide), `deploy/www/index.html` (link next to the list-host guide link)
- Test: `perl/t/examples.t`, `perl/t/guide-links.t`

- [ ] **Step 1: Write the failing tests.** In `t/examples.t`, add the new files to the `ok(-f ...)` list, include `dkim2-milter-wrap` in the `for my $u (...)` unit loop, and add:

```perl
my $wrap = slurp("$ex/dkim2-milter-wrap.service");
like($wrap, qr/--mode inbound/, 'wrap unit is an inbound milter');
like($wrap, qr/--wrap-single-part/, '  ... that wraps');
like($wrap, qr{dkim2-milter-wrap\.sock}, '  ... on its own socket');
my $smaster = slurp("$ex/postfix-stock-mailman-master.cf.fragment");
for my $port (qw(10025 10026 10587)) {
    like($smaster, qr/^127\.0\.0\.1:$port inet/m, "stock master fragment defines 127.0.0.1:$port");
}
like($smaster, qr/content_filter=lmtp:\[127\.0\.0\.1\]:8024/, 'the wrap listener hands every message to Mailman');
like($smaster, qr/dkim2-list-senders/, 'the Mailman submission listener routes by sender');
like($smaster, qr/myhostname=/, 'loopback hops use a distinct myhostname');
my $smain = slurp("$ex/postfix-stock-mailman-main.cf.fragment");
like($smain, qr/^transport_maps = hash:\/etc\/postfix\/dkim2-lists,/m, 'the DKIM2 list map comes before Mailman\'s');
unlike($smain, qr/^smtpd_milters\s*=\s*\S/m, 'port 25 runs no DKIM2 milter');
like(slurp("$ex/postfix-dkim2-list-senders"), qr/FILTER smtp:\[127\.0\.0\.1\]:10587/, 'sender map filters to the signer');
like(slurp("$ex/postfix-dkim2-lists"), qr/smtp:\[127\.0\.0\.1\]:10026/, 'transport map sends to the wrap listener');
```

In `t/guide-links.t`, extend it to also check the new guide: loop the existing path-exists checks over both `docs/dkim2-postfix-list-host-guide.md` and `docs/dkim2-postfix-stock-mailman-guide.md`, and add:

```perl
like($index, qr{docs/dkim2-postfix-stock-mailman-guide\.md}, 'dkim2.com links to the stock-Mailman guide');
like($text, qr{dkim2-postfix-stock-mailman-guide\.md}, 'the list-host guide points to it');
```

Run: `cd perl && prove -l t/examples.t t/guide-links.t` — Expected: FAIL (files missing).

- [ ] **Step 2: Write the examples.**

`deploy/examples/postfix-stock-mailman-main.cf.fragment`:

```
# DKIM2 for stock Mailman: main.cf settings. See
# docs/dkim2-postfix-stock-mailman-guide.md.
#
# Only the DKIM2 lists' traffic reaches a DKIM2 milter; it is routed there by
# the two maps below. Port 25 (smtpd_milters) gets no DKIM2 milter.
#
# transport_maps: the DKIM2 list map FIRST, then whatever you have now
# (Mailman's postfix_lmtp map, as Mailman's postfix config generates it; it
# may be regexp: rather than hash: on your host -- keep its type).
transport_maps = hash:/etc/postfix/dkim2-lists, hash:/var/lib/mailman3/data/postfix_lmtp

# Never rewrite a signed body on the way out (8bit -> 7bit would change
# Content-Transfer-Encoding after signing).
disable_mime_output_conversion = yes
```

`deploy/examples/postfix-dkim2-lists`:

```
# DKIM2 lists: the posting address of each list that gets DKIM2, routed to
# the wrapping inbound milter's listener (postfix-stock-mailman-master.cf.fragment).
# One line per list; then: postmap /etc/postfix/dkim2-lists && postfix reload
dkim2-test@lists.example.org    smtp:[127.0.0.1]:10026
```

`deploy/examples/postfix-dkim2-list-senders`:

```
# DKIM2 lists, outbound: the envelope senders Mailman uses for each DKIM2 list
# (the list itself, its -bounces address, VERP'd -bounces+...), sent to the
# signing listener. One line per list; then: postfix reload (pcre maps need no
# postmap). Only on the loopback listener Mailman submits to -- never port 25.
/^dkim2-test(-bounces(\+.*)?)?@lists\.example\.org$/    FILTER smtp:[127.0.0.1]:10587
```

`deploy/examples/postfix-stock-mailman-master.cf.fragment`:

```
# DKIM2 for stock Mailman: master.cf listeners. See
# docs/dkim2-postfix-stock-mailman-guide.md.
#
# cleanup-dkim2 keeps Bcc/Resent-Bcc/Content-Length on mail that is, or will
# be, signed (the list-host guide, "Keep Bcc, Resent-Bcc and Content-Length").
cleanup-dkim2 unix n     -       y       -       0       cleanup
  -o message_drop_headers=return-path
#
# 1. Inbound for DKIM2 lists (transport_maps sends their posts here): verify,
#    stamp, snapshot, wrap single-part posts, then hand every message to
#    Mailman's LMTP. A distinct myhostname, or Postfix's SMTP client refuses
#    the hop as "loops back to myself".
127.0.0.1:10026 inet n  -       y       -       -       smtpd
  -o syslog_name=postfix/dkim2-wrap
  -o myhostname=dkim2-wrap.localhost
  -o cleanup_service_name=cleanup-dkim2
  -o smtpd_milters=unix:var/run/dkim2-milter-wrap.sock
  -o content_filter=lmtp:[127.0.0.1]:8024
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o smtpd_relay_restrictions=permit_mynetworks,reject
  -o receive_override_options=no_address_mappings,no_unknown_recipient_checks,no_header_body_checks
#
# 2. Mailman's submission listener (mailman.cfg smtp_port: 10025). No milter;
#    a DKIM2 list's mail is FILTERed to the signer, everything else is
#    delivered as it is today.
127.0.0.1:10025 inet n  -       y       -       -       smtpd
  -o syslog_name=postfix/mailman-out
  -o smtpd_milters=
  -o local_header_rewrite_clients=
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o smtpd_sender_restrictions=check_sender_access,pcre:/etc/postfix/dkim2-list-senders
  -o smtpd_relay_restrictions=permit_mynetworks,reject
#
# 3. The signer: DKIM2 list copies only (from listener 2's FILTER).
127.0.0.1:10587 inet n  -       y       -       -       smtpd
  -o syslog_name=postfix/dkim2-sign
  -o myhostname=dkim2-sign.localhost
  -o cleanup_service_name=cleanup-dkim2
  -o local_header_rewrite_clients=
  -o smtpd_milters=unix:var/run/dkim2-milter-out.sock
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o smtpd_relay_restrictions=permit_mynetworks,reject
  -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks
```

(Task 6 proves this on the box; if the restriction syntax or the loop check needs a different spelling there, fix the fragment and the guide to match what worked, in that task.)

`deploy/examples/dkim2-milter-wrap.service`: copy `deploy/examples/dkim2-milter-inbound.service` and change Description to `DKIM2 Milter Daemon (inbound for DKIM2 lists: verify, stamp, wrap)`, the `--socket` to `unix:/var/spool/postfix/var/run/dkim2-milter-wrap.sock`, and add `--wrap-single-part \` before `--snapshot-dir`. The outbound unit is the existing `dkim2-milter-outbound.service` unchanged (it already shares `/var/spool/dkim2/snapshots`).

- [ ] **Step 3: Write `docs/dkim2-postfix-stock-mailman-guide.md`.** Same voice and structure as `docs/dkim2-postfix-list-host-guide.md` (header block with Spec/Audience/Status, numbered steps each ending with a Check). Sections:

1. **What you get** — DKIM2 on chosen lists of a stock Mailman 3 (3.3.8/3.3.10), Mailman unpatched; everything else untouched. Diagram:

```
  Internet ─▶ :25 (no DKIM2 milter) ─┬─ DKIM2 list post ─▶ 10026 wrap milter ─▶ Mailman LMTP
                                     └─ everything else ─▶ as today
  Mailman ─▶ 10025 ─┬─ DKIM2 list sender ─▶ FILTER ─▶ 10587 outbound milter (sign) ─▶ out
                    └─ everything else ───────────────────────────────────────────▶ out
```

2. **Why the wrap** — stock decorate pastes a footer into single-part text/plain and re-encodes it (often base64), which only a null body Recipe can describe; a `multipart/mixed` gets the footer as an extra part, as Mailman already does for text+html posts. Subscribers see the footer as its own part. The wrap is recorded as its own `Message-Instance` (`m=k+1`, `X-DKIM2-Info: action=wrap-single-part;`), Mailman's changes as the next (`m=k+2`), so `https://dkim2.com/validate/` shows each step.
3. **Keys, DNS, Mail::DKIM2** — "as in the list-host guide, steps 2–4" (link `dkim2-postfix-list-host-guide.md#3-keys-and-dns`); Mail::DKIM2 0.20 or later.
4. **The milters** — install `dkim2-milter-wrap.service` and `dkim2-milter-outbound.service` (no `dkim2-milter-inbound`), `install -d` lines as in the list-host guide; check `journalctl -u dkim2-milter-wrap -n 5` shows `wrapping single-part posts`.
5. **Postfix** — main.cf fragment, master.cf fragment, the two maps with one example list, `postmap /etc/postfix/dkim2-lists`, `postfix reload`; explain each listener; why the sender map is only on 10025 (signing oracle); `max_recipients: 1` makes per-message FILTER exact; Check: `postconf -M | grep -E '1002[56]|10587'`.
6. **Mailman** — `mailman.cfg` `[mta]`: `smtp_port: 10025`, `max_recipients: 1` (with the "comments on their own lines" note); restart.
7. **Adding and removing a list** — one line in each map; `postmap`; `postfix reload`. Nothing in Mailman.
8. **Check it works** — post to the list; subscriber copy shows `Message-Instance` m=1 (or the sender's), the wrap instance, the list's instance, one `DKIM2-Signature` with your `d=`; `dkim2verify copy.eml` passes; a list not in the maps shows no DKIM2 headers; reflectors as in the list-host guide.
9. **Limits** — Postfix-generated bounces for the list domain are not signed; a list that content-filters rewrites the body (null Recipe; the outbound unit's `--allow-null-body-recipe` signs it); a list with no header or footer still gets the wrap (harmless; don't route it); posts with several recipients at once on this host are wrapped only for the DKIM2 list (transport is per recipient). Troubleshooting table: `loops back to myself` → distinct `myhostname`; list copies unsigned + `no signing key` in the log → key directory/sender domain; `not wrapping ... no arrival snapshot` → upstream instance broken, mail still delivered.

In `docs/dkim2-postfix-list-host-guide.md`: after the intro paragraph add "Running stock Mailman, without the patches, and only some lists? See [DKIM2 for stock Mailman](dkim2-postfix-stock-mailman-guide.md)." and the same pointer at the start of section 7. Add the equivalent one-line pointer in `docs/dkim2-operator-guide.md` and a link in `deploy/www/index.html` next to the list-host guide link (match its markup).

- [ ] **Step 4: Run the tests**

Run: `cd perl && prove -l t/examples.t t/guide-links.t`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/examples docs/dkim2-postfix-stock-mailman-guide.md docs/dkim2-postfix-list-host-guide.md docs/dkim2-operator-guide.md deploy/www/index.html perl/t/examples.t perl/t/guide-links.t
git commit -m "docs+examples: DKIM2 for stock Mailman with milters and Postfix routing only"
```

---

### Task 5: Mail::DKIM2 0.20

**Files:**
- Modify: every `our $VERSION = '0.19';` under `perl/lib` (including the new `Wrap.pm`), `perl/Changes`

- [ ] **Step 1: Bump**

```bash
cd perl && grep -rl "our \$VERSION = '0.19';" lib | xargs sed -i '' "s/our \$VERSION = '0.19';/our \$VERSION = '0.20';/"
grep -rn "VERSION = '0.19'" lib   # expect no output
```

- [ ] **Step 2: Changes entry** at the top of `perl/Changes`, in the existing style:

```
0.20    2026-10-14
        DKIM2 for stock Mailman, with dkim2-milter and Postfix routing only.
        - New: dkim2-milter --wrap-single-part (inbound mode, needs
          --snapshot-dir). A single-part post is wrapped as a one-part
          multipart/mixed (its Content-* fields and body unchanged), the
          wrap recorded as its own unsigned Message-Instance, and the
          wrapped message kept as the snapshot the outbound milter diffs
          against. Stock Mailman then adds its footer as an extra part
          rather than re-encoding the body. See
          docs/dkim2-postfix-stock-mailman-guide.md in the interop repository.
        - New: Mail::DKIM2::Wrap (wrap_single_part).
        - Behaviour change: dkim2-milter in outbound mode adds nothing --
          no Message-Instance, no X-DKIM2-Info -- to mail from a sender it
          has no key for. It used to add an unsigned Message-Instance,
          which receivers report as permerror.
        - Fix: dkim2-milter registers SMFIF_CHGHDRS, so removing a broken
          intermediate Message-Instance (which calls chgheader) no longer
          dies in Sendmail::PMilter.
```

- [ ] **Step 3: Full suite and tarball**

Run: `cd perl && perl Makefile.PL >/dev/null && make >/dev/null && make test 2>&1 | tail -5 && make manifest 2>&1 | tail -3 && make dist`
Expected: `Result: PASS`; `make manifest` adds nothing unexpected (if it adds files, inspect, then fix `MANIFEST`/`MANIFEST.SKIP`); `Mail-DKIM2-0.20.tar.gz` built (ignored by git).

- [ ] **Step 4: Commit**

```bash
git add perl/lib perl/Changes perl/MANIFEST
git commit -m "perl: Mail::DKIM2 0.20"
```

---

### Task 6: Deploy and acceptance on dkim2.com

The box is reached as `ssh dkim2` (see `deploy/SERVER.md`); the repo checkout there is `/root/interop`. Mailman on the box is the patched build, and a list with `dkim2_message_instance: false` behaves exactly as stock: that is the test list.

**Files:**
- Modify: `deploy/deploy.sh` (install `dkim2-milter-wrap.service` with the other units; restart it with the others; install `/etc/postfix/dkim2-lists` + `postmap`, and `/etc/postfix/dkim2-list-senders`, from new box-specific files `deploy/postfix-dkim2-lists` and `deploy/postfix-dkim2-list-senders`)
- Create: `deploy/postfix-dkim2-lists`, `deploy/postfix-dkim2-list-senders` (the box's real entries, below)
- Modify: `deploy/dkim2-corpus-inject.sh` (third list), `util/charset-corpus.sh` (third list in `lists` stage reporting if it names lists explicitly)
- Modify: `deploy/SERVER.md` (Postfix section: the three listeners and two maps; Mailman section: `smtp_port: 10025`; new subsection "Stock-Mailman test list `dkim2stock@mailman.dkim2.com`"), `deploy/config/` (refresh with `deploy/capture-server-config.sh`)

- [ ] **Step 1: Box entries.** `deploy/postfix-dkim2-lists`:

```
# dkim2.com: lists run the stock-Mailman way (docs/dkim2-postfix-stock-mailman-guide.md)
dkim2stock@mailman.dkim2.com        smtp:[127.0.0.1]:10026
dkim2stockcorpus@mailman.dkim2.com  smtp:[127.0.0.1]:10026
```

`deploy/postfix-dkim2-list-senders` — every Mailman list on the box keeps signing, so all `@mailman.dkim2.com` senders go to the signer (exercising the new 10025 → 10587 hop for every list):

```
/@mailman\.dkim2\.com$/    FILTER smtp:[127.0.0.1]:10587
```

- [ ] **Step 2: Deploy the code** — push the branch, then on the box check it out and run the deploy script:

```bash
git push origin stock-mailman
ssh dkim2 'cd /root/interop && git fetch && git checkout stock-mailman && git pull && bash deploy/deploy.sh'
```

Expected: tests pass, milters restart, null-sender smoke test passes.

- [ ] **Step 3: Postfix wiring on the box.** Append listeners 1 and 2 of the stock master fragment to `/etc/postfix/master.cf` (the box already has `cleanup-dkim2` and a `10587` signer: add `-o myhostname=dkim2-sign.localhost` to the existing 10587 entry instead of adding a second one). Put `hash:/etc/postfix/dkim2-lists` FIRST in the box's `transport_maps` (`postconf transport_maps`, then `postconf -e "transport_maps = hash:/etc/postfix/dkim2-lists <existing value>"`). `postfix check && postfix reload`. Port 25 keeps its existing inbound milter on the box (the demo needs it for every other address); the stock lists' posts therefore pass two inbound milters, which is expected: the second finds `m=1` already matching and wraps.

- [ ] **Step 4: Mailman on the box** — `smtp_port: 10025` in `/etc/mailman3/mailman.cfg`, restart `mailman3`. Create the two lists via REST (`curl -u restadmin:dkim2demo`, see SERVER.md "REST API" and how `dkim2corpus` was created in "DKIM2 charset corpus lists"): `dkim2stock@mailman.dkim2.com` and `dkim2stockcorpus@mailman.dkim2.com`, both with `dkim2_message_instance: false`, a non-empty footer (the default), the corpus list configured like `dkim2corpus` (open posting, no holds, no archive, closed subscription, only the `dkim2capture@` member), `dkim2stock` with the `dkim2capture@` member as well.

- [ ] **Step 5: Acceptance checks** (all on the box):
  - Existing lists still sign through the new hop: `bash deploy/dkim2-list-smoke.sh` passes as before.
  - Plain post to `dkim2stock@`: capture shows `m=1` (port 25 milter), the wrap `m=2` with `action=wrap-single-part`, the list's `m=3`, `DKIM2-Signature i=1 d=mailman.dkim2.com`; `dkim2verify` → `pass (i=1..1 verified)`; footer is a separate MIME part.
  - DKIM2-signed post (send from a `reflector-*` round trip or sign with `dkim2sign` as `dkim2.com`, as `dkim2-corpus-inject.sh` does): `pass (i=1..2 verified)`.
  - Loop check: `grep 'loops back' /var/log/mail.log` is empty for the test window.
  - Unrouted list: a post to an existing Mailman list not in `dkim2-lists` shows no `action=wrap-single-part`.
  - Paste one capture into `https://dkim2.com/validate/`: three hops, each undo shown.

- [ ] **Step 6: Corpus replay.** Add `dkim2stockcorpus@mailman.dkim2.com` as a third list in `deploy/dkim2-corpus-inject.sh` (same roster safety check), then run `./util/charset-corpus.sh --stage lists` from the laptop. Bar: every sample that passes on `dkim2corpus@mailman` also passes on `dkim2stockcorpus@mailman` with all five verifiers, with a non-null body Recipe on the list's instance. Report any difference with its sample id; investigate before calling it done.

- [ ] **Step 7: Record the server state** — update `deploy/SERVER.md` as listed above; `bash deploy/capture-server-config.sh` and review the diff under `deploy/config/`; commit:

```bash
git add deploy/ util/charset-corpus.sh
git commit -m "deploy: stock-Mailman routing on dkim2.com; dkim2stock test lists; corpus replays them"
```

- [ ] **Step 8: Finish** — merge `stock-mailman` into `master` locally (`git checkout master && git merge --no-ff stock-mailman`), point the box back at `master` (`ssh dkim2 'cd /root/interop && git checkout master && git pull'`), and tell Bron the 0.20 tarball is at `perl/Mail-DKIM2-0.20.tar.gz` for CPAN.
