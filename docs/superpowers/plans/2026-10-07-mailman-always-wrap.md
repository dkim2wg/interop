# Mailman Always-Wrap, Null Body Recipe and Performance Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Mailman's CTE-preserving decoration with a raw-splice MIME wrap on DKIM2 lists, emit a null body Recipe when Mailman has rewritten the body, teach Mail::DKIM2 and dkim2-milter to check the full header history past a null body Recipe, and measure the resource cost of each variant against upstream.

**Architecture:** Three repos. `~/src/interop` (Perl `Mail::DKIM2` library, `perl/bin/dkim2-milter`, deploy files, the new `util/mailman-bench/` harness). `~/src/mailman` (fork `brong/mailman`, branches `dkim2-3.3.10` = production, `dkim2-3.3.8`, `dkim2` = master), exported as patch series into interop `mailman/patches-*`. The box `dkim2` (ssh alias; 2 vCPU, 2 GB RAM, runs production) runs Mailman's test suite, the deploy, and the benchmark.

**Tech Stack:** Perl 5 (Test::More, Email::MIME), Python 3.13 / 3.12 (Mailman 3, nose2, `email` package), Postfix milter, bash, systemd-run.

**Spec:** `docs/superpowers/specs/2026-10-07-mailman-always-wrap-design.md`

## Global Constraints

- Mailman change is active only when `[mta] message_instance: yes` AND the list's `dkim2_message_instance` is true (`_mi_enabled(mlist)` in `handlers/message_instance.py`). With either off, `decorate.py` must behave byte-for-byte like upstream v3.3.10.
- Every DKIM2-list decoration with a header or footer wraps; there is no "only signed mail" gate.
- Null header Recipes are forbidden (draft-06 §5.1); only `"b": null` may be null.
- Recipe body lines exclude trailing empty lines (existing `_get_body_lines` / `_body_lines_raw` rule).
- `--allow-null-body-recipe` defaults to OFF in `bin/dkim2-milter`; the example unit `deploy/examples/dkim2-milter-outbound.service` turns it ON.
- Historical branches `dkim2-cte-preserve-3.3.10`, `dkim2-cte-preserve-3.3.8`, `dkim2-cte-preserve` are created from the current heads BEFORE any rewrite and pushed to the `brong` remote; never deleted.
- Mailman DKIM2 series stays 3 commits per branch (keep-bytes, MI ingress/egress, per-list flag), plus the two py3.13 upstream fixes underneath on 3.3.10. Work is amended into those commits (fixup + autosquash), then cherry-picked to the other two branches, then `util/export-list-patches.sh` and `util/export-list-patches.sh --check`.
- Mailman branch pushes to `brong` are force-pushes of rewritten history; Bron has approved rewrites of these branches. Never push hm. Interop work happens on a local branch `mailman-always-wrap` and is merged locally into `master` at the end (no PR).
- Benchmark processes on the box always run under `systemd-run --scope -p MemoryMax=700M` and one build at a time. Production Mailman (`/opt/mailman/venv`, `mailman3.service`) and Postfix are never touched by the benchmark.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

**Box test command** (used by several tasks; `<checkout>` is the local `~/src/mailman` worktree being tested, `<clone>`/`<venv>` are `/opt/mailman/src-test` + `/opt/mailman/test-venv` for 3.3.10 and master, `/opt/mailman/src-test-3.3.8` + `/opt/mailman/test-venv-3.12` for 3.3.8):

```bash
rsync -a --delete ~/src/mailman/src/ dkim2:<clone>/src/
ssh dkim2 'cd <clone> && <venv>/bin/python -m nose2 \
  mailman.handlers.tests.test_message_instance mailman.handlers.tests.test_mi_roundtrip \
  mailman.handlers.tests.test_mi_null_recipe mailman.handlers.tests.test_decorate \
  mailman.handlers.tests.test_mimedel mailman.handlers.tests.test_dmarc \
  mailman.rest.tests.test_listconf mailman.runners.tests.test_lmtp'
ssh dkim2 'cd <clone> && <venv>/bin/python -m nose2 -s src mailman.handlers.docs' # doctests incl. decorate.rst
```
Before the first rsync of a task, `ssh dkim2 'cd <clone> && git status --short | head'` — the clone is scratch; anything there is disposable.

## Review Focus

1. **Body containing the chosen boundary string** — a splice must never emit a boundary that occurs in the original body; expected: a different boundary is picked. Test in Task 8.
2. **Original with no `Content-Type` or with Content-* headers folded over several lines** — the inner part must carry them byte-for-byte (folding intact) and the Recipe must still undo to m=1. Test in Task 8.
3. **8-bit / non-UTF-8 body octets (Latin-1, ISO-2022-JP, raw 8bit)** — the splice must put the exact octets on the wire (surrogateescape round trip through `BytesGenerator`/`smtplib.send_message`). Test in Task 8.
4. **A null body Recipe whose lower history has been tampered** (header changed below the null instance) — expected: Mail::DKIM2 and the milter refuse. Tests in Tasks 1, 2, 3.
5. **Message reaching decorate without `original_bytes`** (old queue entry from before the upgrade, internally generated mail through the virgin pipeline) — expected: no crash; ingress sets `original_bytes` from the serialized message, and a message that never went through ingress decorates the upstream way. Tests in Tasks 6 and 8.

---

## Part A — Mail::DKIM2 and dkim2-milter (interop repo)

Start: `cd ~/src/interop && git switch -c mailman-always-wrap`.

### Task 1: Header-history walk past a null body Recipe in `MessageInstance`

**Files:**
- Modify: `perl/lib/Mail/DKIM2/MessageInstance.pm` (`verify` ~l.872, `undo` ~l.993, `chain_verifies` ~l.1041, POD for all three)
- Test: `perl/t/mi-null-header-history.t` (new)

**Interfaces:**
- Produces: `Mail::DKIM2::MessageInstance->verify($msg, HeadersOnly => 1, %opts)` → checks header hashes only; same return contract as today. `->undo($msg, HeadersOnly => 1)` → applies header Recipes only, body untouched. `->chain_verifies($msg, %opts)` → `(1, undef)` or `(0, $why)`; now walks header-only to m=1 past a null body Recipe.

- [ ] **Step 1: Write the failing test**

Create `perl/t/mi-null-header-history.t`:

```perl
#!/usr/bin/perl
# A null body Recipe ("b": null) loses the previous body, not the header
# history: every lower instance's header hashes are still checked, by undoing
# header Recipes only, down to m=1.
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Mail::DKIM2::MessageInstance;

my $MI = 'Mail::DKIM2::MessageInstance';
my $EOL = "\r\n";

sub with_mi { my ($mi, $msg) = @_; "Message-Instance: " . $mi->as_string . $EOL . $msg }

my $orig = join($EOL, 'From: a@example.com', 'To: list@example.org',
    'Subject: hello', 'Message-ID: <x@example.com>', '', 'body one', 'body two', '');
my $m1 = with_mi($MI->calculate($orig), $orig);

# m=2: the list prefixed the Subject and rewrote the body; body Recipe null.
sub list_hop {
    my ($prev, $tag) = @_;
    my $cur = $prev;
    $cur =~ s/^Subject: /Subject: [$tag] /m;
    $cur .= "rewritten by $tag$EOL";
    my $mi = $MI->calculate($cur, $prev);
    $mi->set_null_body_recipe;
    return with_mi($mi, $cur);
}

{
    my $m2 = list_hop($m1, 'list');
    my ($ok, $why) = $MI->chain_verifies($m2);
    ok($ok, 'null at m=2 over m=1: header history verifies') or diag $why;
}

# A forged history: the list changed To as well as Subject, but its header
# Recipe hides the To change. The top instance matches the message; only
# undoing it shows m=1's header hash no longer matches. DKIM2-Signatures
# cover only Message-Instance and DKIM2-Signature fields (§9.6), so
# nothing else catches this.
sub forge_history {
    my ($prev) = @_;
    my $cur = $prev;
    $cur =~ s/^Subject: /Subject: [list] /m;
    $cur =~ s/^To: list\@example\.org/To: other\@example.org/m;
    $cur .= "rewritten$EOL";
    my $mi = $MI->calculate($cur, $prev);
    $mi->set_null_body_recipe;
    my $rh = $mi->{bits}{rh};
    delete $rh->{$_} for grep { lc($_) eq 'to' } keys %$rh;
    return with_mi($mi, $cur);
}

{
    my ($ok, $why) = $MI->chain_verifies(forge_history($m1));
    ok(!$ok, 'header changed below a null body Recipe is caught');
    like($why // '', qr/m=1 does not match content.*header hash/, 'reason names m=1 header hash');
}

{
    # null at m=3 over a normal m=2 over m=1
    my $cur2 = $m1; $cur2 =~ s/^Subject: /Subject: [fwd] /m;
    my $m2 = with_mi($MI->calculate($cur2, $m1), $cur2);
    my $m3 = list_hop($m2, 'list');
    my ($ok, $why) = $MI->chain_verifies($m3);
    ok($ok, 'null at m=3 over recipe m=2 over m=1 verifies') or diag $why;
}

{
    # A body Recipe below the null must not be applied (the body it would
    # apply to is gone): m=2 appends a footer with a real body Recipe, m=3
    # rewrites the body with a null one.
    my $cur2 = $m1 . "footer$EOL";
    my $m2 = with_mi($MI->calculate($cur2, $m1), $cur2);
    my $m3 = list_hop($m2, 'list');
    my ($ok, $why) = $MI->chain_verifies($m3);
    ok($ok, 'body Recipe below a null instance is skipped, headers still checked') or diag $why;
}

{
    # verify / undo HeadersOnly directly
    my $m2 = list_hop($m1, 'list');
    my $prev = $MI->undo($m2, HeadersOnly => 1);
    ok($prev, 'undo HeadersOnly returns a message');
    unlike($prev->body_raw, qr/^body one\r\nbody two\r\n\z/, 'body left as it is (not rebuilt)');
    is(scalar $MI->verify($prev, HeadersOnly => 1), 1, 'verify HeadersOnly passes m=1 on header history');
    is(scalar $MI->verify($prev), 0, 'full verify fails m=1 (body differs)');
}

done_testing;
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/src/interop/perl && prove -l t/mi-null-header-history.t`
Expected: FAIL — the tamper case passes `chain_verifies` (it stops at the null instance today), and `verify(... HeadersOnly => 1)` on `$prev` returns 0.

- [ ] **Step 3: Implement**

In `verify` (the hash loop near l.912), skip the body hash when asked:

```perl
    for my $alg (@usable) {
        my ($h1, $b1) = @{ $hashes->{$alg} };
        my $hd = h_digest($msg, $alg, $opts{IgnorePrefixes});
        if ($h1 ne $hd) {
            return wantarray ? (0, "$alg header hash mismatch ($h1 != $hd)") : 0;
        }
        # HeadersOnly: below a null body Recipe the body this instance
        # hashed is gone; its header hashes are still checkable.
        next if $opts{HeadersOnly};
        my $bd = b_digest($msg, $alg);
        if ($b1 ne $bd) {
            return wantarray ? (0, "$alg body hash mismatch ($b1 != $bd)") : 0;
        }
    }
```

In `undo`, take options and skip the body Recipe when asked:

```perl
sub undo {
    my ($class, $msg, %opts) = @_;
    ...
    if ($rb && !$opts{HeadersOnly}) {
```

Replace the loop body of `chain_verifies` from the `verify` call down:

```perl
    my $headers_only = 0;
    while (1) {
        my @mi = $msg->header_raw('Message-Instance');
        my %by_v = map { (extract_mi_version($_) // 0) => $_ } @mi;
        my $num = %by_v ? (sort { $b <=> $a } keys %by_v)[0] : 0;
        last unless $num;

        my ($ok, $err) = $class->verify($msg, %opts, HeadersOnly => $headers_only);
        return (0, "Message-Instance m=$num does not match content"
                 . ($err ? " ($err)" : '')) unless $ok;

        last if $num <= 1;
        # A null body Recipe loses the previous body, not the header
        # history: from here down, undo header Recipes only and check each
        # instance's header hashes, down to m=1.
        $headers_only = 1 if $class->parse($by_v{$num})->unrecoverable;

        my $prev = eval { $class->undo($msg, HeadersOnly => $headers_only) };
        die $@ if ref $@;
        return (0, "Message-Instance m=$num did not undo cleanly"
                 . ($@ ? ": $@" : '')) if $@ || !$prev;
        $msg = $prev;
    }
    return (1, undef);
```

Update the comment above `chain_verifies` ("until m=1 or an instance that declares the previous state unrecoverable" → "until m=1; past an instance with a null body Recipe, header-only") and the POD for `verify`, `undo`, `chain_verifies` (add a `HeadersOnly` paragraph to each; `chain_verifies` returns `(1, undef)` only when the whole header history checks out).

- [ ] **Step 4: Run tests**

Run: `cd ~/src/interop/perl && prove -l t/mi-null-header-history.t t/mi-null-recipe.t t/mi-chain.t t/full-chain.t t/pod.t t/pod-coverage.t`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/src/interop && git add perl/lib/Mail/DKIM2/MessageInstance.pm perl/t/mi-null-header-history.t
git commit -m "Mail::DKIM2: check the header history past a null body Recipe

chain_verifies stopped at an instance whose body Recipe is null and
passed, checking nothing below it. A null body Recipe loses the body,
not the header Recipes: walk on header-only (verify/undo HeadersOnly)
and check every lower instance's header hashes down to m=1.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2: Same walk in the Verifier

**Files:**
- Modify: `perl/lib/Mail/DKIM2/Verifier.pm` (`_verify_mi_chain` ~l.405-457; POD near l.895 and l.1089)
- Test: `perl/t/mi-null-header-history.t` (extend)

**Interfaces:**
- Consumes: `verify(..., HeadersOnly => 1)`, `undo(..., HeadersOnly => 1)` from Task 1.
- Produces: `Mail::DKIM2::Verifier` result `pass` only when the header history below a null body Recipe checks out; `fail` with details `Message-Instance m=N does not match content (...)` otherwise.

- [ ] **Step 1: Write the failing test** — append to `perl/t/mi-null-header-history.t` before `done_testing`:

```perl
use lib "$FindBin::Bin/lib";
use Mail::DKIM2::Signer;
use Mail::DKIM2::Verifier;
use DKIM2TestKeys;

sub sign_i1 {
    my ($msg) = @_;
    my $s = Mail::DKIM2::Signer->new(
        Domain => 'test1.dkim2.com', Selector => 'rsa1024',
        Key => DKIM2TestKeys::private_key('test1.dkim2.com', 'rsa1024'),
        MailFrom => 'a@test1.dkim2.com', RcptTo => ['list@test2.dkim2.com'],
        Timestamp => 1740000000);
    $s->PRINT($msg); $s->CLOSE;
    return $s->as_string . $EOL . $msg;
}

sub verifier_result {
    my ($msg) = @_;
    my $v = Mail::DKIM2::Verifier->new;
    $v->allow_unsigned_mi(1);
    $v->set_pubkey_callback(DKIM2TestKeys::pubkey_callback());
    $v->PRINT($msg); $v->CLOSE;
    return $v->result_detail;
}

{
    my $signed = sign_i1($m1);
    my $m2 = list_hop($signed, 'list');
    like(verifier_result($m2), qr/^pass/, 'Verifier: null body over signed m=1 passes');

    my $forged = forge_history($signed);
    like(verifier_result($forged), qr/^fail.*m=1 does not match content/, 'Verifier: tampered history below null fails on m=1');
}
```

(`$mi->{bits}{rh}` is where `calculate` keeps the header Recipe, keyed by field name; `as_string` lower-cases the names on output.)

- [ ] **Step 2: Run to verify it fails**

Run: `cd ~/src/interop/perl && prove -l t/mi-null-header-history.t`
Expected: the forged-history Verifier case FAILS (result is `pass`).

- [ ] **Step 3: Implement** — in `Verifier::_verify_mi_chain`, mirror Task 1:

```perl
    my $headers_only = 0;
    while (1) {
        ...
        my ($ok, $err) = Mail::DKIM2::MessageInstance->verify($msg,
            IgnorePrefixes => $self->{IgnorePrefixes},
            HeadersOnly    => $headers_only);
        ... (unchanged failure handling) ...
        last if $num <= 1;

        # A null body Recipe loses the previous body, not the header
        # history: from here down, undo header Recipes only and check each
        # instance's header hashes, down to m=1.
        my $mi_obj = Mail::DKIM2::MessageInstance->parse($by_v{$num});
        $headers_only = 1 if $mi_obj->unrecoverable;

        my $prev = eval { Mail::DKIM2::MessageInstance->undo($msg, HeadersOnly => $headers_only) };
        ... (unchanged) ...
    }
```

Update the comment block above the `eval` in `finish_body` (~l.348) and the POD paragraphs at ~l.895 and ~l.1089 to say the walk continues header-only past a null body Recipe.

- [ ] **Step 4: Run tests**

Run: `cd ~/src/interop/perl && prove -lr t/`
Expected: all PASS (the whole suite: the Verifier change touches every verify).

- [ ] **Step 5: Commit**

```bash
cd ~/src/interop && git add perl/lib/Mail/DKIM2/Verifier.pm perl/t/mi-null-header-history.t
git commit -m "Mail::DKIM2::Verifier: check the header history past a null body Recipe

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 3: `--allow-null-body-recipe` in dkim2-milter, release bump

**Files:**
- Modify: `perl/bin/dkim2-milter` (GetOptions ~l.65; eom chain gate ~l.371-388; POD options section ~l.893)
- Modify: `deploy/examples/dkim2-milter-outbound.service`
- Modify: `perl/Changes`, `perl/lib/Mail/DKIM2.pm` and every `our $VERSION` in `perl/lib/Mail/DKIM2/*.pm`
- Modify: `docs/dkim2-postfix-list-host-guide.md` (milter section)
- Test: `perl/t/milter-script.t`

**Interfaces:**
- Consumes: `chain_verifies` from Task 1 (now checks header history), `Mail::DKIM2::MessageInstance->parse($v)->unrecoverable`.
- Produces: milter option `--allow-null-body-recipe`; X-DKIM2-Info actions `not-signed=null-body-recipe` and `null-body-recipe`.

- [ ] **Step 1: Write the failing test.** In `t/milter-script.t`, the spawn block is a single fork/exec. Refactor it into `sub spawn_milter { my (%o) = @_; ... return ($pid, $sock, $log) }` taking `extra => [ ... ]` args appended to the exec list (keep the existing call as `spawn_milter()` so current tests are untouched; the END block kills every spawned pid). Then add, after the existing cases:

```perl
# --- A list's unsigned m=2 with a null body Recipe -------------------------
# Built like the existing list case in this file (signed i=1 m=1 from
# test1, list rewrites Subject + body), but the m=2 body Recipe is null.
sub null_body_list_post {
    my $orig = make_signed_i1();          # the helper the existing list case uses
    (my $cur = $orig) =~ s/^Subject: /Subject: [list] /m;
    $cur .= "-- \r\nrewritten\r\n";
    my $mi = Mail::DKIM2::MessageInstance->calculate($cur, $orig);
    $mi->set_null_body_recipe;
    return "Message-Instance: " . $mi->as_string . "\r\n" . $cur;
}

{
    my $mods = send_message($sock, null_body_list_post());   # default milter: option off
    my @info = map { $_->{value} } grep { $_->{name} eq 'X-DKIM2-Info' } @$mods;
    ok((grep { /not-signed=null-body-recipe/ } @info), 'option off: null body Recipe not signed');
    ok(!(grep { $_->{name} eq 'DKIM2-Signature' } @$mods), 'option off: no signature');
}

{
    my ($pid2, $sock2) = spawn_milter(extra => ['--allow-null-body-recipe']);
    my $mods = send_message($sock2, null_body_list_post());
    ok((grep { $_->{name} eq 'DKIM2-Signature' } @$mods), 'option on: signed');
    ok((grep { $_->{name} eq 'X-DKIM2-Info' && $_->{value} =~ /null-body-recipe/ } @$mods),
       'option on: X-DKIM2-Info records null-body-recipe');

    # Forged history below the null: the list changed To too, and its
    # header Recipe hides that. Still refused with the option on.
    my $orig = make_signed_i1();
    (my $cur = $orig) =~ s/^Subject: /Subject: [list] /m;
    $cur =~ s/^To: .*$/To: tampered\@example.net/m;
    $cur .= "-- \r\nrewritten\r\n";
    my $mi = Mail::DKIM2::MessageInstance->calculate($cur, $orig);
    $mi->set_null_body_recipe;
    my $rh = $mi->{bits}{rh};
    delete $rh->{$_} for grep { lc($_) eq 'to' } keys %$rh;
    my $mods2 = send_message($sock2, "Message-Instance: " . $mi->as_string . "\r\n" . $cur);
    ok(!(grep { $_->{name} eq 'DKIM2-Signature' } @$mods2), 'option on: forged header history not signed');
}
```

`make_signed_i1` and `send_message` are the names to use for the helpers this file already has for the list case and for driving one message through the socket — read the file first and use its actual helper names (rename these calls to match; do not add duplicates). The forged-history case passes today's milter (the walk stops at the null instance); only Task 1's header-history walk refuses it.

- [ ] **Step 2: Run to verify it fails**

Run: `cd ~/src/interop/perl && prove -l t/milter-script.t`
Expected: "option off: null body Recipe not signed" FAILS (today it signs); "option on" spawn fails on the unknown option.

- [ ] **Step 3: Implement.** Add `'allow-null-body-recipe',` to `GetOptions`. In `cb_eom`, after `my ($mi_chain_ok, $mi_chain_why) = ...chain_verifies(...)`, compute whether the top instance is a null body Recipe:

```perl
        # A top instance with a null body Recipe ("b": null): the list
        # rewrote the body (content filtering, DMARC wrap) and says so.
        # chain_verifies has already checked the header history below it.
        # Signing it is the host's choice: --allow-null-body-recipe.
        my $top_null = 0;
        {
            my %by_v = map { (Mail::DKIM2::Common::extract_mi_version($_) // 0) => $_ }
                       map { $_->[1] } grep { lc($_->[0]) eq 'message-instance' } @{$priv->{headers}};
            my ($top) = sort { $b <=> $a } keys %by_v;
            $top_null = 1 if $top && eval { Mail::DKIM2::MessageInstance->parse($by_v{$top})->unrecoverable };
        }
```

(Use the same header-tuple shape `@{$priv->{headers}}` the `$has_dk2` line above uses; if the value element needs unfolding before `parse`, unfold the same way `_compute_mi` does.) Then extend the decision chain:

```perl
        if ($has_dk2 && $verify_result !~ /^pass/) {
            ... unchanged ...
        } elsif (!$mi_chain_ok) {
            ... unchanged ...
        } elsif ($top_null && !$opts{'allow-null-body-recipe'}) {
            warn "dkim2-milter: not signing $msgid: top Message-Instance has a "
               . "null body Recipe (--allow-null-body-recipe not set)\n";
            $ctx->insheader('X-DKIM2-Info',
                _milter_value(_dkim2_info("not-signed=null-body-recipe")), 0);
        } else {
            ... unchanged signing path; after a successful sign, when $top_null:
            $ctx->insheader('X-DKIM2-Info', _milter_value(_dkim2_info("null-body-recipe")), 0) if $top_null;
        }
```

POD: add `=item B<--allow-null-body-recipe>` under OPTIONS: default off; when set, a message whose top Message-Instance has a null body Recipe is signed provided the upstream signatures verify and the header history below it checks out; for list hosts whose list manager rewrites bodies (content filtering, DMARC wrap).

Example unit: append ` \` + `    --allow-null-body-recipe` to `ExecStart` with a comment above `ExecStart`:

```
# --allow-null-body-recipe: this unit is for list hosts. A list that rewrites
# a body (content filtering, DMARC wrap) records a null body Recipe; sign it.
```

List-host guide: one paragraph in the milter section saying the same, and that it is off by default in the program.

Version: check CPAN — `curl -s https://fastapi.metacpan.org/v1/release/Mail-DKIM2 | grep -o '"version" *: *"[^"]*"'`. If it reports `0.13`, bump every `$VERSION` to `0.14` and add a `0.14    <date>` entry to `perl/Changes`; if it reports `0.12`, add the entries under the existing unreleased `0.13` instead. Changes text: header-history walk past null body Recipes (t/mi-null-header-history.t); dkim2-milter `--allow-null-body-recipe` (default off; a null body Recipe is no longer signed silently).

- [ ] **Step 4: Run tests**

Run: `cd ~/src/interop/perl && prove -lr t/`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/src/interop && git add perl deploy/examples/dkim2-milter-outbound.service docs/dkim2-postfix-list-host-guide.md
git commit -m "dkim2-milter: --allow-null-body-recipe (off by default; on in the list-host unit)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Part B — Mailman (`~/src/mailman`)

All of Tasks 5-8 are developed on `dkim2-3.3.10` as fixup commits onto the MI commit (`git commit --fixup=<MI-commit>`), tested on the box, and squashed in Task 9.

### Task 4: Preserve the CTE-preserving series

**Files:** none (git refs only)

- [ ] **Step 1:** Record the heads.

```bash
cd ~/src/mailman && git fetch brong
for b in dkim2-3.3.10 dkim2-3.3.8 dkim2; do git rev-parse --short brong/$b; git log --oneline -1 $b; done
```
Expected: each local branch equals `brong/<branch>`. If not, stop and ask Bron.

- [ ] **Step 2:** Create and push the history branches.

```bash
git branch dkim2-cte-preserve-3.3.10 dkim2-3.3.10
git branch dkim2-cte-preserve-3.3.8  dkim2-3.3.8
git branch dkim2-cte-preserve        dkim2
git push brong dkim2-cte-preserve-3.3.10 dkim2-cte-preserve-3.3.8 dkim2-cte-preserve
```

- [ ] **Step 3:** Add to `~/src/interop/mailman/README.md`, after the branch list, a paragraph:

```markdown
The previous approach, which preserved the body's Content-Transfer-Encoding
when appending a footer instead of MIME-wrapping, is kept on the branches
`dkim2-cte-preserve-3.3.10`, `dkim2-cte-preserve-3.3.8` and
`dkim2-cte-preserve` (October 2026) in case it is wanted again.
```
Commit in interop: `git commit -am "mailman/README: name the cte-preserve history branches"` (with the Co-Authored-By line).

### Task 5: Drop the CTE-preserving decoration

**Files:**
- Remove commit: "Preserve the original Content-Transfer-Encoding when decorating" (`86d1cba95` on dkim2-3.3.10)
- Modify: `src/mailman/handlers/tests/test_message_instance.py` (remove `TestDecorateCTEPreservation`; rewrite the CTE-specific flow tests)

- [ ] **Step 1:** Rebase it out.

```bash
cd ~/src/mailman && git switch dkim2-3.3.10
git rebase --onto 86d1cba95~1 86d1cba95
```
Resolve conflicts by taking upstream `src/mailman/handlers/decorate.py` and `src/mailman/handlers/docs/decorate.rst` exactly: `git checkout v3.3.10 -- src/mailman/handlers/decorate.py src/mailman/handlers/docs/decorate.rst` (then `git add` and `git rebase --continue`). Verify: `git diff v3.3.10 -- src/mailman/handlers/decorate.py src/mailman/handlers/docs/decorate.rst` prints nothing.

- [ ] **Step 2:** In `test_message_instance.py`, delete class `TestDecorateCTEPreservation` entirely, and delete `test_qp_recipe_has_no_literals`, `test_base64_recipe_has_one_literal_for_last_line`, `test_7bit_body_recipe_is_compact` (they assert CTE-preserving Recipe shapes; Task 8 replaces them with wrap-shape tests). Keep every `test_undo_*` test: they must keep passing under upstream decoration and later under the wrap.

- [ ] **Step 3:** Run the box test command (3.3.10 clone).
Expected: PASS except possibly `test_recipe_rebuilds_the_received_octets` and undo tests for base64/QP if upstream decoration re-encodes in a way the Recipe cannot express — if any fail, note the names in the fixup commit message; Task 8 makes them pass again. Nothing else may fail.

- [ ] **Step 4:** Commit the test edits as a fixup of the MI commit.

```bash
git add -A src/mailman/handlers/tests && git commit --fixup=$(git log --format=%h --grep='Add DKIM2 Message-Instance headers' -1)
```

### Task 6: `original_bytes` is the snapshot; remove the mi-cache

**Files:**
- Modify: `src/mailman/handlers/message_instance.py` (ingress ~l.1122-1210, egress ~l.1212-1290; delete `_mi_cache_dir`, `save_mi_original`, `load_mi_original`, `_cleanup_mi_original`; drop now-unused imports `makedirs`, `safe_remove` if unused)
- Test: `src/mailman/handlers/tests/test_message_instance.py`

**Interfaces:**
- Produces: after `MessageInstanceIngress.process`, `msg.original_bytes` is always the CRLF-normalized snapshot bytes; `msgdata['mi_snapshot'] == {'version': int, 'header_hash': bytes, 'body_hash': bytes}` (no `mi_file`). Egress reads `msg.original_bytes`.

- [ ] **Step 1: Write the failing tests** (in `TestMessageInstanceFlow`):

```python
    def test_ingress_sets_original_bytes_without_received_octets(self):
        msg = self._make_7bit_msg()
        self.assertIsNone(getattr(msg, 'original_bytes', None))
        msgdata = {}
        self._ingress.process(self._mlist, msg, msgdata)
        self.assertIsInstance(msg.original_bytes, bytes)
        self.assertIn(b'\r\nHello world.\r\n', msg.original_bytes)
        self.assertNotIn('mi_file', msgdata['mi_snapshot'])

    def test_no_mi_cache_directory(self):
        msg = self._make_received_msg()
        msgdata = {}
        self._ingress.process(self._mlist, msg, msgdata)
        decorate.process(self._mlist, msg, msgdata)
        self._egress.process(self._mlist, msg, msgdata)
        self.assertEqual(get_max_mi_version(msg), 2)
        self.assertFalse(os.path.exists(os.path.join(config.VAR_DIR, 'mi-cache')))

    def test_snapshot_survives_a_queue_pickle(self):
        msg = self._make_received_msg()
        msgdata = {}
        self._ingress.process(self._mlist, msg, msgdata)
        msg, msgdata = pickle.loads(pickle.dumps((msg, msgdata)))
        decorate.process(self._mlist, msg, msgdata)
        self._egress.process(self._mlist, msg, msgdata)
        v, err = verify_message_instance(msg)
        self.assertEqual(v, 2, err)
```

Update `test_ingress_hashes_the_received_octets`: replace the `with open(msgdata['mi_snapshot']['mi_file'] ...)` block with `self.assertEqual(msg.original_bytes, self.RECEIVED)`. Add `import pickle` to the imports. Remove any other test that references `mi_file`, `save_mi_original`, `load_mi_original` or `mi-cache` (grep the file; each such test is about the cache and has no replacement).

- [ ] **Step 2:** Run the box test command. Expected: the three new tests FAIL.

- [ ] **Step 3: Implement.** In ingress, everywhere a snapshot is decided, set it on the message instead of writing a file:

```python
            snap_raw = ...            # unchanged logic choosing the bytes
            msg.original_bytes = snap_raw
            msgdata['mi_snapshot'] = {
                'version': existing_version,
                'header_hash': compute_header_hash_raw(snap_raw),
                'body_hash': compute_body_hash_raw(snap_raw),
            }
```
and in the no-MI branch:

```python
        snap_raw = received if received is not None else _serialize_msg(msg)
        ...
        _prepend_header(msg, 'Message-Instance', value)
        msg.original_bytes = snap_raw
        _prepend_header(msg, 'X-DKIM2-Info', _dkim2_info(
            'mi-m=1', hc=hcount, hn=hnames))
        msgdata['mi_snapshot'] = {
            'version': 1, 'header_hash': h_hash, 'body_hash': b_hash}
```

(Note: in the existing-MI baseline case, `snap_raw` is `_serialize_msg(baseline)`; setting `original_bytes` to it is intended — it is the state the m=N instance describes.)

In egress, replace the cache load and the two `_cleanup_mi_original` calls:

```python
        if (h_hash == snapshot['header_hash']
                and b_hash == snapshot['body_hash']):
            return
        snap_raw = getattr(msg, 'original_bytes', None)
        if snap_raw is None:
            log.warning('Message-Instance snapshot missing (no original_bytes)'
                        ' -- skipping MI egress')
            return
        snap_raw = _normalize_crlf(snap_raw)
        prev_body_lines = _body_lines_raw(snap_raw)
        prev_headers = _hashed_pairs(_raw_header_pairs(snap_raw))
```
and drop `snapf=` from the egress `_dkim2_info(...)` call. Delete the four cache functions and the "Pipeline handlers" comment block's references to the cache. Update the module docstring / `DKIM2-MESSAGE-INSTANCE.md` sentences that describe `mi-cache` (grep `mi-cache` and `mi_file` across the repo; every hit is removed or reworded to "msg.original_bytes").

- [ ] **Step 4:** Run the box test command. Expected: PASS (same pre-existing exceptions as Task 5, if any).

- [ ] **Step 5:** Commit: `git commit -a --fixup=<MI commit>`.

### Task 7: `body-modified` and the null body Recipe

**Files:**
- Modify: `src/mailman/handlers/mime_delete.py` (`process` ~l.96-220)
- Modify: `src/mailman/handlers/dmarc.py` (`wrap_message` ~l.159-194)
- Modify: `src/mailman/handlers/message_instance.py` (`build_mi_header_value` ~l.687; egress)
- Test: `src/mailman/handlers/tests/test_message_instance.py`

**Interfaces:**
- Produces: `msgdata['body-modified'] = True` set by `mime-delete` and `dmarc` when they change the body. `message_instance.NULL_BODY_RECIPE` sentinel; `build_mi_header_value(..., body_recipe=NULL_BODY_RECIPE)` emits `"b": null`.

- [ ] **Step 1: Write the failing tests**

```python
class TestNullBodyRecipe(unittest.TestCase):
    """A body Mailman rewrote before decoration gets "b": null."""

    layer = ConfigLayer

    def setUp(self):
        self._mlist = create_list('ant@example.com')
        config.push('test_mi_null', """\
        [mta]
        message_instance: yes
        """)
        self.addCleanup(config.pop, 'test_mi_null')
        self._ingress = config.handlers['message-instance-ingress']
        self._egress = config.handlers['message-instance-egress']

    RAW = (b'To: ant@example.com\r\nFrom: aperson@example.com\r\n'
           b'Message-ID: <alpha>\r\nMIME-Version: 1.0\r\n'
           b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
           b'--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n'
           b'--b\r\nContent-Type: application/x-kitten\r\n'
           b'Content-Transfer-Encoding: base64\r\n\r\nAAAA\r\n--b--\r\n')

    def _msg(self):
        msg = _msg_from_bytes(self.RAW)
        msg.original_bytes = self.RAW
        return msg

    def test_mime_delete_sets_body_modified(self):
        self._mlist.filter_content = True
        self._mlist.filter_types = ['application/x-kitten']
        msg, msgdata = self._msg(), {}
        config.handlers['mime-delete'].process(self._mlist, msg, msgdata)
        self.assertTrue(msgdata.get('body-modified'))

    def test_mime_delete_unchanged_leaves_flag_unset(self):
        self._mlist.filter_content = True
        self._mlist.filter_types = ['image/gif']
        msg, msgdata = self._msg(), {}
        config.handlers['mime-delete'].process(self._mlist, msg, msgdata)
        self.assertNotIn('body-modified', msgdata)

    def test_egress_emits_null_body_recipe(self):
        msg, msgdata = self._msg(), {}
        self._ingress.process(self._mlist, msg, msgdata)
        self._mlist.filter_content = True
        self._mlist.filter_types = ['application/x-kitten']
        config.handlers['mime-delete'].process(self._mlist, msg, msgdata)
        msg['Subject'] = '[ant] hi'
        self._egress.process(self._mlist, msg, msgdata)
        recipe = _recipe_at(msg, 2)
        self.assertIn('b', recipe)
        self.assertIsNone(recipe['b'])
        self.assertIn('h', recipe)
        self.assertIsNotNone(recipe['h'])
        v, err = verify_message_instance(msg)
        self.assertEqual(v, 2, err)
        # The kitten is not in the Recipe.
        self.assertNotIn('AAAA', msg['message-instance'])

    def test_dmarc_wrap_sets_body_modified(self):
        from mailman.handlers.dmarc import wrap_message
        msg, msgdata = self._msg(), {}
        wrap_message(self._mlist, msg, msgdata)
        self.assertTrue(msgdata.get('body-modified'))
```

Note `mime-delete` only runs when the list's `filter_content` is true — the handler checks this in its `IHandler.process` wrapper; call the registered handler as above so that wrapper is exercised. Check `_recipe_at` returns the decoded Recipe dict (it is the existing helper the flow tests use); if it returns `recipe.get('b', [])`-style already, use the dict-returning helper `_parse_mi(...)[2]` directly.

- [ ] **Step 2:** Run the box test command. Expected: the four tests FAIL.

- [ ] **Step 3: Implement.**

`mime_delete.py` — set the flag at each place the body changes. After the outer-`multipart/alternative` `reset_payload(msg, firstalt)`, inside `if changedp:`, and in the `if attach_report and ...:` block, add `msgdata['body-modified'] = True`. Concretely:

```python
        if ctype == 'multipart/alternative':
            firstalt = msg.get_payload(0)
            reset_payload(msg, firstalt)
            msgdata['body-modified'] = True
    ...
    if changedp:
        msg['X-Content-Filtered-By'] = 'Mailman/MimeDel {}'.format(VERSION)
        msgdata['body-modified'] = True
    if attach_report and as_boolean(config.mailman.filter_report):
        msgdata['body-modified'] = True
        ...
```

`dmarc.py` — at the end of `wrap_message`, `msgdata['body-modified'] = True`.

`message_instance.py`:

```python
# The body Recipe of an instance whose previous body cannot be rebuilt:
# Mailman rewrote it (content filtering, DMARC wrap) before decoration.
# Emitted as "b": null (spec-06 §4.2).
NULL_BODY_RECIPE = object()
```
In `build_mi_header_value`: `r['b'] = None if body_recipe is NULL_BODY_RECIPE else body_recipe` (inside the existing `if body_recipe is not None:`). In egress, where the body Recipe is computed:

```python
        if b_hash != snapshot['body_hash']:
            if msgdata.get('body-modified'):
                body_recipe = NULL_BODY_RECIPE
            else:
                current_lines = _get_body_lines(msg)
                body_recipe = compute_body_recipe(current_lines, prev_body_lines)
```
Add `NULL_BODY_RECIPE` to `__all__` via `public(NULL_BODY_RECIPE=...)` only if the module's style requires; otherwise a module constant is fine.

Check `undo_message_instance` / `_plan_undo` handle `"b": null` (body left as is, headers undone). If `_compile_recipe` raises on `None`, make `_plan_undo` return `body_lines=None` for a null body step, and add to `TestNullBodyRecipe`:

```python
    def test_undo_null_body_restores_headers_only(self):
        msg, msgdata = self._msg(), {}
        self._ingress.process(self._mlist, msg, msgdata)
        self._mlist.filter_content = True
        self._mlist.filter_types = ['application/x-kitten']
        config.handlers['mime-delete'].process(self._mlist, msg, msgdata)
        msg['Subject'] = '[ant] hi'
        self._egress.process(self._mlist, msg, msgdata)
        self.assertEqual(undo_message_instance(msg), 2)
        self.assertIsNone(msg['subject'])
```

- [ ] **Step 4:** Run the box test command (adds `test_mimedel`, `test_dmarc`). Expected: PASS.

- [ ] **Step 5:** Commit: `git commit -a --fixup=<MI commit>`.

### Task 8: Raw-splice MIME wrap in `decorate.py`

**Files:**
- Modify: `src/mailman/handlers/decorate.py` (`process`, just after the empty-header/footer escape hatch ~l.95)
- Test: `src/mailman/handlers/tests/test_message_instance.py` (new class `TestDKIM2Wrap`)

**Interfaces:**
- Consumes: `msg.original_bytes` (Task 6), `msgdata['body-modified']` (Task 7), `_mi_enabled`, `_split_raw`, `_normalize_crlf` from `mailman.handlers.message_instance`.
- Produces: `decorate._dkim2_wrap(mlist, msg, header, footer)` → `True` when it wrapped, `False` when the caller must decorate the upstream way.

- [ ] **Step 1: Write the failing tests.** New class (same setUp as `TestMessageInstanceFlow`, header AND footer templates both set — add a `myheader.txt` with `'List Header\n'` registered as `'list:member:regular:header'`):

```python
def _wrap_round_trip(test, raw):
    """Ingress, decorate, egress, then undo m=2: m=1 must verify and the
    rebuilt body must be the original octets."""
    msg = _msg_from_bytes(raw)
    msg.original_bytes = raw
    msgdata = {}
    test._ingress.process(test._mlist, msg, msgdata)
    decorate.process(test._mlist, msg, msgdata)
    test._egress.process(test._mlist, msg, msgdata)
    wire = msg.as_bytes(policy=msg.policy.clone(linesep='\r\n'))
    test.assertEqual(msg.get_content_type(), 'multipart/mixed')
    v, err = verify_message_instance(msg)
    test.assertEqual(v, 2, err)
    recipe = _recipe_at(msg, 2)
    test.assertEqual(len(_copy_steps(recipe['b'])), 1, recipe['b'])
    test.assertEqual(undo_message_instance(msg), 2)
    v, err = verify_message_instance(msg)
    test.assertEqual(v, 1, err)
    return wire


class TestDKIM2Wrap(unittest.TestCase):
    layer = ConfigLayer
    # setUp: as TestMessageInstanceFlow.setUp, plus a header template.

    HDRS = (b'To: ant@example.com\r\nFrom: aperson@example.com\r\n'
            b'Message-ID: <alpha>\r\nMIME-Version: 1.0\r\n')

    def test_7bit(self):
        raw = self.HDRS + (b'Content-Type: text/plain; charset=us-ascii\r\n'
                           b'Content-Transfer-Encoding: 7bit\r\n\r\nHello.\r\n')
        wire = _wrap_round_trip(self, raw)
        self.assertIn(b'MIME-wrapped because the list adds DKIM2', wire)

    def test_qp_bytes_untouched(self):
        body = b'=48=65=6C=6C=6F=\r\n world\r\n'
        raw = self.HDRS + (b'Content-Type: text/plain; charset=utf-8\r\n'
                           b'Content-Transfer-Encoding: quoted-printable\r\n\r\n') + body
        wire = _wrap_round_trip(self, raw)
        self.assertIn(body, wire)

    def test_base64_bytes_untouched(self):
        body = b'SGVs\r\nbG8u\r\n'
        raw = self.HDRS + (b'Content-Type: text/plain; charset=utf-8\r\n'
                           b'Content-Transfer-Encoding: base64\r\n\r\n') + body
        self.assertIn(body, _wrap_round_trip(self, raw))

    def test_8bit_latin1_bytes_untouched(self):
        body = b'Gr\xfc\xdfe aus K\xf6ln\r\n'
        raw = self.HDRS + (b'Content-Type: text/plain; charset=iso-8859-1\r\n'
                           b'Content-Transfer-Encoding: 8bit\r\n\r\n') + body
        self.assertIn(body, _wrap_round_trip(self, raw))

    def test_multipart_alternative_with_bare_final_boundary(self):
        raw = self.HDRS + (
            b'Content-Type: multipart/alternative;\r\n boundary="b"\r\n\r\n'
            b'--b\r\nContent-Type: text/plain; charset="us-ascii" \r\n\r\nHi\r\n'
            b'--b\r\nContent-Type: text/html\r\n\r\n<p>Hi</p>\r\n--b--')
        wire = _wrap_round_trip(self, raw)
        # Folded Content-Type carried as received.
        self.assertIn(b'Content-Type: multipart/alternative;\r\n boundary="b"\r\n', wire)

    def test_no_content_type(self):
        raw = (b'To: ant@example.com\r\nFrom: aperson@example.com\r\n'
               b'Message-ID: <alpha>\r\n\r\nplain old mail\r\n')
        _wrap_round_trip(self, raw)

    def test_boundary_collision(self):
        with patch('mailman.handlers.decorate._new_boundary',
                   side_effect=['COLLIDE', 'COLLIDE', 'fresh-boundary']):
            raw = self.HDRS + (b'Content-Type: text/plain\r\n\r\n'
                               b'--COLLIDE\r\nnot a part\r\n')
            wire = _wrap_round_trip(self, raw)
        self.assertIn(b'boundary="fresh-boundary"', wire)

    def test_body_modified_uses_upstream_decoration(self):
        raw = self.HDRS + b'Content-Type: text/plain\r\n\r\nHello.\r\n'
        msg = _msg_from_bytes(raw)
        msg.original_bytes = raw
        msgdata = {}
        self._ingress.process(self._mlist, msg, msgdata)
        msgdata['body-modified'] = True
        decorate.process(self._mlist, msg, msgdata)
        self.assertEqual(msg.get_content_type(), 'text/plain')   # upstream concatenation

    def test_list_flag_off_uses_upstream_decoration(self):
        self._mlist.dkim2_message_instance = False
        raw = self.HDRS + b'Content-Type: text/plain\r\n\r\nHello.\r\n'
        msg = _msg_from_bytes(raw)
        msg.original_bytes = raw
        decorate.process(self._mlist, msg, {})
        self.assertEqual(msg.get_content_type(), 'text/plain')

    def test_no_original_bytes_uses_upstream_decoration(self):
        # Never went through ingress (e.g. the virgin pipeline).
        raw = self.HDRS + b'Content-Type: text/plain\r\n\r\nHello.\r\n'
        msg = _msg_from_bytes(raw)
        decorate.process(self._mlist, msg, {})
        self.assertEqual(msg.get_content_type(), 'text/plain')

    def test_smtplib_wire_matches_hashed_body(self):
        # What smtplib.send_message puts on the wire must be what egress
        # hashed: check m=2's body hash against the CRLF wire body.
        raw = self.HDRS + (b'Content-Type: text/plain; charset=iso-8859-1\r\n'
                           b'Content-Transfer-Encoding: 8bit\r\n\r\nK\xf6ln\r\n')
        msg = _msg_from_bytes(raw)
        msg.original_bytes = raw
        msgdata = {}
        self._ingress.process(self._mlist, msg, msgdata)
        decorate.process(self._mlist, msg, msgdata)
        self._egress.process(self._mlist, msg, msgdata)
        buf = BytesIO()
        BytesGenerator(buf, mangle_from_=False,
                       policy=msg.policy.clone(linesep='\r\n')).flatten(msg)
        wire = buf.getvalue()
        self.assertEqual(verify_mi_raw(wire)[0], 2, verify_mi_raw(wire)[1])
```

Imports to add at the top of the test module if absent: `from io import BytesIO`, `from email.generator import BytesGenerator`, `from unittest.mock import patch`, `verify_mi_raw` from `mailman.handlers.message_instance`. Also re-add the compactness assertion the deleted Task 5 tests made, in wrap form: `_wrap_round_trip` already asserts exactly one copy step.

- [ ] **Step 2:** Run the box test command. Expected: the new tests FAIL (upstream decoration concatenates text/plain).

- [ ] **Step 3: Implement** in `decorate.py`:

```python
import uuid
from io import BytesIO
from email.generator import BytesGenerator
from mailman.handlers.message_instance import (
    _mi_enabled, _normalize_crlf, _split_raw)

DKIM2_PREAMBLE = (
    'This message was MIME-wrapped because the list adds DKIM2 change\n'
    'records; a MIME-capable mail reader shows it as the sender intended.\n')


def _new_boundary():
    return '===============DKIM2{}=='.format(uuid.uuid4().hex)


def _part_text(text, charset):
    """A decoration part (header or footer), serialized."""
    part = MIMEText(text.encode(charset, errors='replace'), 'plain', charset)
    part['Content-Disposition'] = 'inline'
    buf = BytesIO()
    BytesGenerator(buf, mangle_from_=False, policy=part.policy.clone(
        linesep='\n')).flatten(part)
    return buf.getvalue().decode('ascii', 'surrogateescape')


def _dkim2_wrap(mlist, msg, header, footer):
    """On a DKIM2 list, wrap the body exactly as it arrived.

    The original top-level Content-* fields and body octets become the
    middle part of a multipart/mixed, so a Message-Instance Recipe for
    this hop is literal lines, one copy range, literal lines -- whatever
    the body's encoding or structure.  The payload is a string, which the
    generator writes out verbatim.  Returns False when the message must be
    decorated the usual way: DKIM2 is off for this list, the message did
    not come through ingress, or Mailman already rewrote the body (it then
    gets a null body Recipe instead).
    """
    raw = getattr(msg, 'original_bytes', None)
    if raw is None or not _mi_enabled(mlist):
        return False
    head, body = _split_raw(_normalize_crlf(raw))
    content_fields = []
    for field in re.split(rb'\r\n(?![ \t])', head):
        if field.split(b':', 1)[0].strip().lower().startswith(b'content-'):
            content_fields.append(field.replace(b'\r\n', b'\n'))
    body = body.replace(b'\r\n', b'\n')
    while True:
        boundary = _new_boundary()
        if boundary.encode('ascii') not in body:
            break
    lcset = mlist.preferred_language.charset
    out = [DKIM2_PREAMBLE]
    if header:
        out.append('--{}\n{}\n'.format(boundary, _part_text(header, lcset)))
    inner = b''.join(f + b'\n' for f in content_fields) + b'\n' + body
    if not inner.endswith(b'\n'):
        inner += b'\n'
    out.append('--{}\n'.format(boundary))
    out.append(inner.decode('ascii', 'surrogateescape'))
    if footer:
        out.append('--{}\n{}\n'.format(boundary, _part_text(footer, lcset)))
    out.append('--{}--\n'.format(boundary))
    for name in ('content-type', 'content-transfer-encoding',
                 'content-disposition'):
        del msg[name]
    msg['Content-Type'] = 'multipart/mixed; boundary="{}"'.format(boundary)
    if msg['MIME-Version'] is None:
        msg['MIME-Version'] = '1.0'
    msg.set_payload(''.join(out))
    return True
```

In `process`, right after the empty-decoration escape hatch:

```python
    if not msgdata.get('body-modified') and _dkim2_wrap(
            mlist, msg, header, footer):
        return
```

Add `import re` if not already imported. Check `_part_text` output ends with `\n` (BytesGenerator ends the part body with the footer's own trailing newline); if the footer text lacks a final newline, the `'--{}\n{}\n'` format supplies one — adjust so there is exactly one line break before the next `--boundary` (RFC 2046: the CRLF before a boundary belongs to the boundary). If `test_7bit` shows the copy range is split into two because of a blank-line mismatch, the fix is in how `inner` ends, not in the Recipe code.

- [ ] **Step 4:** Run the box test command. Expected: PASS, including every `test_undo_*` and `test_recipe_rebuilds_the_received_octets`, and the upstream `decorate.rst` doctest (DKIM2 is off there).

- [ ] **Step 5:** Commit: `git commit -a --fixup=<MI commit>`.

### Task 9: Squash, docs, port to 3.3.8 and master, export

**Files:**
- Modify (mailman): `DKIM2-MESSAGE-INSTANCE.md`
- Modify (interop): `mailman/README.md`, `mailman/patches-*` (regenerated), `docs/dkim2-postfix-list-host-guide.md` (Mailman section), `deploy/www/` (any page describing CTE preservation — `grep -rln -i "transfer-encoding\|CTE" deploy/www docs`)

- [ ] **Step 1:** Docs. In `DKIM2-MESSAGE-INSTANCE.md`, replace the CTE-preservation description with: on a DKIM2 list every decorated message is wrapped by splicing the received octets into a multipart/mixed (Recipe = literal / one copy range / literal); a body rewritten by content filtering or the DMARC wrap gets `"b": null`; the snapshot is `msg.original_bytes`, no on-disk cache. In interop `mailman/README.md`, rewrite "The patches" list: three DKIM2 patches (keep the bytes; MI ingress/egress incl. the DKIM2 wrap and null body Recipe; per-list flag) — remove the CTE patch item; note `mi-cache` is gone. Commit the mailman doc change as a fixup of the MI commit.

- [ ] **Step 2:** Squash.

```bash
cd ~/src/mailman && git rebase -i --autosquash v3.3.10   # non-interactive: GIT_SEQUENCE_EDITOR=: git rebase -i --autosquash v3.3.10
git log --oneline v3.3.10..   # expect 5: two py3.13 fixes + keep-bytes + MI + flag
```

- [ ] **Step 3:** Port. For each of `dkim2-3.3.8` (base tag `3.3.8`) and `dkim2` (base `687b9e4dc`): drop its CTE commit with `git rebase --onto <cte>~1 <cte>` (taking that base's upstream `decorate.py`/`decorate.rst` on conflict), then make its MI commit's tree match 3.3.10's for the DKIM2 files:

```bash
git switch dkim2-3.3.8
git rebase --onto $(git log --format=%h --grep='Preserve the original Content-Transfer' -1)~1 $(git log --format=%h --grep='Preserve the original Content-Transfer' -1)
git checkout dkim2-3.3.10 -- src/mailman/handlers/message_instance.py src/mailman/handlers/decorate.py \
  src/mailman/handlers/mime_delete.py src/mailman/handlers/dmarc.py \
  src/mailman/handlers/tests/test_message_instance.py src/mailman/handlers/tests/test_mi_roundtrip.py \
  src/mailman/handlers/tests/test_mi_null_recipe.py DKIM2-MESSAGE-INSTANCE.md
git diff 3.3.8 -- src/mailman/handlers/decorate.py src/mailman/handlers/mime_delete.py src/mailman/handlers/dmarc.py
```
Review that last diff: it must contain ONLY the DKIM2 additions (the `_dkim2_wrap` block and imports; the `body-modified` lines). If 3.3.8's `decorate.py`/`mime_delete.py`/`dmarc.py` differ from v3.3.10's outside those additions, re-apply the additions by hand onto the 3.3.8 file instead of checking out 3.3.10's. Commit as fixup of the MI commit, autosquash. Repeat for `dkim2` (master).

- [ ] **Step 4:** Box tests on all three (3.3.10 and master use `/opt/mailman/src-test` + `test-venv` in turn; 3.3.8 uses `src-test-3.3.8` + `test-venv-3.12`). Expected: PASS on each.

- [ ] **Step 5:** Push and export.

```bash
cd ~/src/mailman && git push --force-with-lease brong dkim2-3.3.10 dkim2-3.3.8 dkim2
cd ~/src/interop && util/export-list-patches.sh && util/export-list-patches.sh --check
ls mailman/patches-3.3.10 mailman/patches-3.3.8 mailman/patches-master
```
Expected: 5 / 3 / 3 patches; `--check` reports every series applies. Remove stale old-numbered patch files if the export script does not (`git status mailman/`).

- [ ] **Step 6:** Commit interop: `git add -A mailman docs deploy/www && git commit -m "Mailman: always MIME-wrap on DKIM2 lists; null body Recipe; series re-exported"` (with Co-Authored-By).

---

## Part C — Deploy and acceptance

### Task 10: Deploy and acceptance test on the box

**Files:**
- Modify (interop): `deploy/SERVER.md` (Mailman section: no `mi-cache`; outbound milter runs with `--allow-null-body-recipe`; a `dkim2filter` test list)

- [ ] **Step 1:** Deploy the Perl library and milter: `ssh dkim2 'cd /root/interop && git fetch && git checkout mailman-always-wrap && git pull && deploy/deploy.sh'` (use the repo path and invocation `deploy/README.md` gives if different). Verify: `ssh dkim2 'systemctl cat dkim2-milter-outbound | grep allow-null; systemctl is-active dkim2-milter-outbound'` → the flag line, `active`.

- [ ] **Step 2:** Deploy Mailman per SERVER.md:

```bash
ssh dkim2 "/opt/mailman/venv/bin/pip install --force-reinstall --no-deps 'git+https://github.com/brong/mailman@dkim2-3.3.10' \
  && systemctl stop mailman3 && sudo -u mailman /opt/mailman/venv/bin/mailman -C /etc/mailman3/mailman.cfg info \
  && systemctl start mailman3 && systemctl restart mailman-web"
```
Then `ssh dkim2 'rm -rf /var/lib/mailman3/var/mi-cache'` only after confirming `ls /var/lib/mailman3/var/queue/*/ | wc -l` is 0 (no in-flight entry references a cache file; adjust var path to the one in `/etc/mailman3/mailman.cfg`).

- [ ] **Step 3:** Smoke: `ssh dkim2 deploy/dkim2-list-smoke.sh` (from the repo dir). Expected: PASS for both lists.

- [ ] **Step 4:** Corpus replay: `util/charset-corpus.sh lists` (the replay stage; see the header of `util/charset-corpus.sh` for the exact stage name). Expected: 317/317 through dkim2corpus@mailman.dkim2.com with all five verifiers; Sympa 317/317 unchanged. Inspect two Mailman captures by hand: outer `multipart/mixed`, the preamble note, the original part byte-identical.

- [ ] **Step 5:** Null-body acceptance. Create a local-only list `dkim2filter@mailman.dkim2.com` the same way the corpus list was made (SERVER.md "DKIM2 charset corpus lists": members = the dkim2capture addresses, no archive, closed subscription), with `filter_content` on and `filter_types = ['application/zip']`. Post a signed message with a small zip attachment via the corpus listener (127.0.0.1:10591). Expected capture: `Message-Instance: m=2` whose Recipe JSON has `"b":null`, a `DKIM2-Signature` i=2, `X-DKIM2-Info: ... null-body-recipe`, and the Fastmail-style verifiers in `util/` report pass for the chain (header history verified). Record the commands in SERVER.md next to the corpus lists.

- [ ] **Step 6:** Commit SERVER.md; merge interop `mailman-always-wrap` into `master` locally (`git switch master && git merge --no-ff mailman-always-wrap`), push master. Update memory `project_mailman_always_wrap.md` with the deployed state.

---

## Part D — Performance harness (`util/mailman-bench/`)

### Task 11: Bench builds on the box

**Files:**
- Create: `util/mailman-bench/setup-builds.sh`
- Create: `util/mailman-bench/README.md`

**Interfaces:**
- Produces: `/opt/mailman/bench/<id>/venv` for `id` in `up cte wrap`; each venv has Mailman installed from its ref plus `nose2`-free runtime deps. (`cte-off`/`wrap-off` reuse the `cte`/`wrap` venvs with the list flag off.)

- [ ] **Step 1:** Write `setup-builds.sh` (runs ON the box, idempotent):

```bash
#!/bin/bash
# Build one venv per Mailman variant for the benchmark. Runs on the box.
set -euo pipefail
ROOT=/opt/mailman/bench
PY=/opt/mailman/venv/bin/python3       # the production interpreter (3.13)
declare -A REF=(
  [up]=up-3.3.10-py313        # v3.3.10 + the two py3.13 fixes; see below
  [cte]=dkim2-cte-preserve-3.3.10
  [wrap]=dkim2-3.3.10
)
SRC=$ROOT/src
[ -d $SRC ] || git clone https://github.com/brong/mailman $SRC
git -C $SRC fetch --all --tags
# "up": upstream 3.3.10 cannot run on 3.13 without the two fixes, so build it
# as v3.3.10 + those two commits (the first two of dkim2-3.3.10).
git -C $SRC branch -f up-3.3.10-py313 $(git -C $SRC rev-parse 'origin/dkim2-3.3.10~3')
for id in "${!REF[@]}"; do
  d=$ROOT/$id
  want=$(git -C $SRC rev-parse --verify -q origin/${REF[$id]} || git -C $SRC rev-parse ${REF[$id]})
  [ -x $d/venv/bin/mailman ] && [ "$(cat $d/ref 2>/dev/null)" = "$want" ] && continue
  ref=$(git -C $SRC rev-parse --verify -q origin/${REF[$id]} || git -C $SRC rev-parse ${REF[$id]})
  rm -rf $d && git -C $SRC worktree prune && mkdir -p $d
  $PY -m venv $d/venv
  $d/venv/bin/pip -q install -r <(/opt/mailman/venv/bin/pip freeze | grep -viE '^mailman( @|==)|^-e ')
  git -C $SRC worktree add -f --detach $d/src $ref
  $d/venv/bin/pip -q install --no-deps $d/src
  echo $ref > $d/ref
done
```

Check `git log --oneline origin/dkim2-3.3.10 -5` on the box and confirm `~3` lands on the second py3.13 fix (3 DKIM2 commits above it); adjust if the series count changed.

- [ ] **Step 2:** Run: `scp util/mailman-bench/setup-builds.sh dkim2:/opt/mailman/bench/ && ssh dkim2 'bash /opt/mailman/bench/setup-builds.sh && for i in up cte wrap; do /opt/mailman/bench/$i/venv/bin/mailman --version; done'`
Expected: three `GNU Mailman 3.3.10 ...` lines.

- [ ] **Step 3:** README: what the harness measures, the five builds table from the spec, how to run each script, the memory cap, and that it never touches production. Commit both files.

### Task 12: Benchmark corpus

**Files:**
- Create: `util/mailman-bench/make-corpus.py`

**Interfaces:**
- Produces: `bench/corpus/{unsigned,signed}/<id>.eml` (CRLF) and `bench/corpus/index.tsv` with columns `id  size  class  filter` where `class ∈ {small, medium, large, huge}` (<20KB, <1MB, <20MB, ≥20MB) and `filter ∈ {0,1}` (1 = post to the filter list).

- [ ] **Step 1:** Write `make-corpus.py` (runs locally; stdlib only):

```python
#!/usr/bin/env python3
"""Build the Mailman benchmark corpus: the charset-corpus samples plus
synthetic messages, each unsigned and DKIM2-signed (perl/bin/dkim2sign)."""
import base64, os, random, subprocess, sys
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'bench' / 'corpus'
KEY = ROOT / 'perl/t/data/keys/sel1._domainkey.test1.dkim2.com.pem'
rng = random.Random(20261007)

def base(subject):
    m = EmailMessage(policy=SMTP)
    m['From'] = 'bench@test1.dkim2.com'
    m['To'] = 'bench@lists.example.com'
    m['Subject'] = subject
    m['Message-ID'] = '<{}@bench.dkim2.com>'.format(subject.replace(' ', '-'))
    m['Date'] = 'Wed, 07 Oct 2026 00:00:00 +0000'
    return m

def text(n):
    words = 'the list adds a footer and the message is wrapped once more'.split()
    lines, line = [], []
    while sum(len(l) + 1 for l in lines) < n:
        line.append(rng.choice(words))
        if len(' '.join(line)) > 66:
            lines.append(' '.join(line)); line = []
    return '\n'.join(lines) + '\n'

def synthetic():
    m = base('plain 2k'); m.set_content(text(2_000)); yield 'syn-plain-2k', m, 0
    m = base('outlook'); m.set_content(text(4_000))
    m.add_alternative('<html><body>' + '<p>' * 4000 + text(4_000) + '</body></html>', subtype='html')
    yield 'syn-outlook', m, 0
    for mb in (1, 10, 50):
        m = base(f'attach {mb}MB'); m.set_content(text(1_000))
        m.add_attachment(rng.randbytes(mb * 1_000_000), maintype='application',
                         subtype='octet-stream', filename=f'blob{mb}.bin')
        yield f'syn-attach-{mb}mb', m, 0
    m = base('qp 5MB'); m.set_content(text(5_000_000).replace('the', 'thé'), cte='quoted-printable')
    yield 'syn-qp-5mb', m, 0
    m = base('filtered 10MB'); m.set_content(text(1_000))
    m.add_attachment(rng.randbytes(10_000_000), maintype='application',
                     subtype='zip', filename='kitten.zip')
    yield 'syn-filter-10mb', m, 1

def size_class(n):
    return 'small' if n < 20_000 else 'medium' if n < 1_000_000 else 'large' if n < 20_000_000 else 'huge'

def sign(raw):
    return subprocess.run(
        ['perl', '-I', str(ROOT / 'perl/lib'), str(ROOT / 'perl/bin/dkim2sign'),
         '-d', 'test1.dkim2.com', '-s', 'sel1', '-k', str(KEY),
         '--mailfrom', 'bench@test1.dkim2.com', '--rcptto', 'bench@lists.example.com'],
        input=raw, capture_output=True, check=True).stdout

def main():
    for sub in ('unsigned', 'signed'):
        (OUT / sub).mkdir(parents=True, exist_ok=True)
    rows = []
    items = [(p.stem, p.read_bytes(), 0) for p in sorted((ROOT / 'corpus/sample').glob('*.eml'))]
    items += [(i, m.as_bytes(policy=SMTP), f) for i, m, f in synthetic()]
    for ident, raw, filt in items:
        raw = raw.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
        (OUT / 'unsigned' / f'{ident}.eml').write_bytes(raw)
        signed = sign(raw)
        assert b'Message-Instance:' in signed and b'DKIM2-Signature:' in signed, ident
        (OUT / 'signed' / f'{ident}.eml').write_bytes(signed)
        rows.append(f'{ident}\t{len(raw)}\t{size_class(len(raw))}\t{filt}')
    (OUT / 'index.tsv').write_text('id\tsize\tclass\tfilter\n' + '\n'.join(rows) + '\n')
    print(f'{len(rows)} messages -> {OUT}')

if __name__ == '__main__':
    sys.exit(main())
```

- [ ] **Step 2:** Run: `python3 util/mailman-bench/make-corpus.py && head -3 bench/corpus/index.tsv && du -sh bench/corpus`
Expected: ~324 messages; ~140 MB (the large synthetics twice). If `dkim2sign` writes only the header block rather than the whole message, prepend its output to `raw` instead (check one output by hand).

- [ ] **Step 3:** Commit `make-corpus.py`.

### Task 13: In-process driver

**Files:**
- Create: `util/mailman-bench/bench_inproc.py`
- Create: `util/mailman-bench/run-inproc.sh`

**Interfaces:**
- Consumes: `bench/corpus/` (copied to `/opt/mailman/bench/corpus` on the box), the venvs from Task 11.
- Produces: `/opt/mailman/bench/results/inproc-<build>-<signed|unsigned>.jsonl`, one JSON object per message: `{"build","signed","id","class","filter","cpu_in","cpu_pipeline","cpu_out","peak_in","peak_pipeline","peak_out","pck_in","pck_pipeline","pck_out","pck_archive","mi_cache","wire_bytes","mi_header_len","oom":false}`; plus `out/<build>/<signed>/<id>.eml` (first recipient's wire bytes) for verification.

- [ ] **Step 1:** Write `bench_inproc.py`:

```python
"""Drive one Mailman build over the benchmark corpus in-process.

Run with that build's venv python:
  bench_inproc.py --build wrap --dkim2 on --corpus DIR --signed signed --out DIR --members 25
Mirrors what the runners do -- LMTP parse, in queue, posting pipeline,
out queue, delivery -- without runner processes or an MTA, so each
message's CPU, peak memory and queue footprint can be measured alone.
"""
import argparse, email, json, os, shutil, statistics, tempfile, time, tracemalloc
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument('--build', required=True)
ap.add_argument('--dkim2', choices=['on', 'off', 'na'], required=True)
ap.add_argument('--corpus', required=True)
ap.add_argument('--signed', choices=['signed', 'unsigned'], required=True)
ap.add_argument('--out', required=True)
ap.add_argument('--members', type=int, default=25)
ap.add_argument('--repeat', type=int, default=5)
ap.add_argument('--resume', action='store_true',
                help='skip ids already in the output file (after an OOM kill)')
args = ap.parse_args()

var = Path(tempfile.mkdtemp(prefix='mmbench-'))
cfg = var / 'mailman.cfg'
cfg.write_text(f"""\
[mailman]
site_owner: bench@example.com
layout: bench
[paths.bench]
var_dir: {var}
template_dir: {var}/templates
[database]
url: sqlite:///{var}/mailman.db
[mta]
smtp_host: 127.0.0.1
smtp_port: 9
{"message_instance: yes" if args.dkim2 == 'on' else ""}
[archiver.prototype]
enable: yes
""")
from mailman.core.initialize import initialize
initialize(str(cfg))
from mailman.config import config
from mailman.app.lifecycle import create_list
from mailman.core.pipelines import process as run_pipeline
from mailman.email.message import Message
from mailman.interfaces.usermanager import IUserManager
from mailman.mta import connection as mta_connection
from mailman.mta.deliver import deliver
from zope.component import getUtility
from mailman.interfaces.action import Action
from mailman.interfaces.template import ITemplateManager
from mailman.runners import lmtp as lmtp_runner
from mailman.utilities.datetime import now
from email.generator import BytesGenerator
from io import BytesIO
import inspect, re

# Only builds whose LMTP runner keeps the received octets carry them in
# their queue pickles; setting the attribute on the others would charge
# upstream for our patch.
KEEPS_BYTES = 'original_bytes' in inspect.getsource(lmtp_runner)

WIRE = []

class FakeSMTP:
    def send_message(self, msg, from_addr, to_addrs):
        buf = BytesIO()
        BytesGenerator(buf, mangle_from_=False,
                       policy=msg.policy.clone(linesep='\r\n')).flatten(msg)
        WIRE.append(buf.getvalue())
        return {}
    def sendmail(self, from_addr, to_addrs, msg):
        WIRE.append(msg); return {}
    def quit(self): pass

mta_connection.Connection._connect = lambda self: setattr(self, '_connection', FakeSMTP())
mta_connection.Connection._login = lambda self: None

def make_list(name, filt):
    mlist = create_list(f'{name}@lists.example.com')
    if hasattr(mlist, 'dkim2_message_instance'):
        mlist.dkim2_message_instance = (args.dkim2 == 'on')
    mlist.filter_content = bool(filt)
    mlist.filter_types = ['application/zip'] if filt else []
    mlist.default_nonmember_action = Action.accept   # the corpus sender is not a member
    um = getUtility(IUserManager)
    for i in range(args.members):
        addr = um.create_address(f'member{i}@example.net')
        addr.verified_on = now()
        mlist.subscribe(addr)
    # A header and a footer, as on a typical list.
    tdir = var / 'templates' / 'site' / 'en'; tdir.mkdir(parents=True, exist_ok=True)
    (tdir / 'bench-footer.txt').write_text('-- \nbench list footer\nhttps://example.com/unsub\n')
    (tdir / 'bench-header.txt').write_text('bench list header\n')
    tm = getUtility(ITemplateManager)
    tm.set('list:member:regular:footer', mlist.list_id, 'mailman:///bench-footer.txt')
    tm.set('list:member:regular:header', mlist.list_id, 'mailman:///bench-header.txt')
    config.db.commit()
    return mlist

LISTS = {0: make_list('bench', 0), 1: make_list('benchfilter', 1)}

def measure(fn):
    tracemalloc.start(); tracemalloc.reset_peak()
    t0 = time.process_time()
    result = fn()
    cpu = time.process_time() - t0
    _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    return result, cpu, peak

def pck_size(sb, filebase):
    return os.path.getsize(os.path.join(sb.queue_directory, filebase + '.pck'))

def mi_cache_bytes():
    d = var / 'mi-cache'
    return sum(p.stat().st_size for p in d.glob('*')) if d.exists() else 0

def mi_len(wire):
    head = wire.split(b'\r\n\r\n', 1)[0]
    return sum(len(f) for f in re.split(rb'\r\n(?![ \t])', head)
               if f.split(b':', 1)[0].strip().lower() == b'message-instance')

def one(raw, mlist):
    WIRE.clear()
    sb_in, sb_pipe, sb_out, sb_arch = (config.switchboards[n] for n in ('in', 'pipeline', 'out', 'archive'))
    def lmtp():
        msg = email.message_from_bytes(raw, Message)
        if KEEPS_BYTES:
            msg.original_bytes = raw
        msg.original_size = len(raw)
        return sb_in.enqueue(msg, {}, listid=mlist.list_id, original_size=len(raw), to_list=True)
    fb, cpu_in, peak_in = measure(lmtp)
    r = {'pck_in': pck_size(sb_in, fb), 'cpu_in': cpu_in, 'peak_in': peak_in}
    # The incoming runner's posting chain accepts the post (non-members are
    # accepted on these lists) and moves it to the pipeline queue unchanged.
    msg, data = sb_in.dequeue(fb); sb_in.finish(fb)
    fb = sb_pipe.enqueue(msg, data, listid=mlist.list_id)
    r['pck_pipeline'] = pck_size(sb_pipe, fb)
    def pipeline():
        msg, data = sb_pipe.dequeue(fb); sb_pipe.finish(fb)
        run_pipeline(mlist, msg, data, mlist.posting_pipeline)
        return msg, data
    (msg, data), r['cpu_pipeline'], r['peak_pipeline'] = measure(pipeline)
    # to-outgoing and to-archive enqueued copies; measure and dequeue them.
    for name, sb in (('pck_out', sb_out), ('pck_archive', sb_arch)):
        files = sb.files
        r[name] = sum(pck_size(sb, f) for f in files)
    out_files = sb_out.files
    r['mi_cache'] = mi_cache_bytes()
    def outgoing():
        for f in out_files:
            m, d = sb_out.dequeue(f); sb_out.finish(f)
            deliver(mlist, m, d)
    _, r['cpu_out'], r['peak_out'] = measure(outgoing)
    for f in sb_arch.files:
        sb_arch.dequeue(f); sb_arch.finish(f)
    first = WIRE[0] if WIRE else b''
    r['wire_bytes'] = len(first)
    r['mi_header_len'] = mi_len(first)
    return r, first

index = [l.split('\t') for l in Path(args.corpus, 'index.tsv').read_text().splitlines()[1:]]
out_dir = Path(args.out); (out_dir / 'eml').mkdir(parents=True, exist_ok=True)
out_file = out_dir / f'inproc-{args.build}-{args.signed}.jsonl'
current = out_dir / f'inproc-{args.build}-{args.signed}.current'
done = set()
if args.resume and out_file.exists():
    done = {json.loads(l)['id'] for l in out_file.open()}
# A cgroup OOM kill ends this process outright (no MemoryError), so the id
# being worked on is written to .current first; run-inproc.sh records it as
# an OOM row and resumes after it.
with open(out_file, 'a' if args.resume else 'w') as fp:
    for ident, size, cls, filt in index:
        if ident in done:
            continue
        current.write_text(f'{ident}\t{size}\t{cls}\t{filt}\n')
        raw = Path(args.corpus, args.signed, ident + '.eml').read_bytes()
        runs = []
        for _ in range(args.repeat):
            r, first = one(raw, LISTS[int(filt)])
            runs.append(r)
        row = {k: statistics.median(run[k] for run in runs) for k in runs[0]}
        row['oom'] = False
        (out_dir / 'eml' / f'{args.build}-{args.signed}-{ident}.eml').write_bytes(first)
        row.update(build=args.build, dkim2=args.dkim2, signed=args.signed,
                   id=ident, size=int(size), cls=cls, filter=int(filt))
        fp.write(json.dumps(row) + '\n'); fp.flush()
current.unlink(missing_ok=True)
shutil.rmtree(var)
```

Note: tracemalloc slows the measured code; every build pays the same overhead, so comparisons hold, but absolute CPU numbers are inflated — say so in the report. Also: confirm the queue names on 3.3.10 (`config.switchboards` keys) and that `deliver` is the function `[mta] outgoing` points to (`config.mta.outgoing`); if a post still does not reach `out`, check `var/logs/vette.log` in the temp var dir for the hold reason.

- [ ] **Step 2:** Write `run-inproc.sh` (on the box):

```bash
#!/bin/bash
# Run the in-process benchmark for every build, one at a time, memory-capped.
set -euo pipefail
B=/opt/mailman/bench; OUT=$B/results; mkdir -p $OUT
run() { # build venv dkim2
  for s in unsigned signed; do
    resume=
    while ! systemd-run --scope -q -p MemoryMax=700M -p MemorySwapMax=0 \
        $B/$2/venv/bin/python $B/bench_inproc.py --build $1 --dkim2 $3 \
          --corpus $B/corpus --signed $s --out $OUT $resume; do
      cur=$OUT/inproc-$1-$s.current
      [ -s $cur ] || { echo "$1 $s: failed, not an OOM" >> $OUT/failures.txt; break; }
      IFS=$'\t' read -r id size cls filt < $cur
      printf '{"build":"%s","dkim2":"%s","signed":"%s","id":"%s","size":%s,"cls":"%s","filter":%s,"oom":true}\n' \
        "$1" "$3" "$s" "$id" "$size" "$cls" "$filt" >> $OUT/inproc-$1-$s.jsonl
      echo "$1 $s: OOM on $id" >> $OUT/failures.txt
      resume=--resume
    done
  done
}
run up       up   na
run cte      cte  on
run cte-off  cte  off
run wrap     wrap on
run wrap-off wrap off
```

- [ ] **Step 3:** Smoke run on 5 messages: copy corpus + scripts (`rsync -a bench/corpus util/mailman-bench/ dkim2:/opt/mailman/bench/`), then temporarily run one build by hand with a 5-line `index.tsv`. Expected: a JSONL file with 5 rows, nonzero `cpu_pipeline`, `wire_bytes`; `wrap` rows have outer `multipart/mixed` in `eml/`; `up` rows have no `Message-Instance`.

- [ ] **Step 4:** Verify the outputs' Message-Instance chains: `ssh dkim2 'cd /opt/mailman/bench/results/eml && for f in cte-* wrap-*; do perl -MMail::DKIM2::MessageInstance -0777 -ne "my (\$ok,\$why)=Mail::DKIM2::MessageInstance->chain_verifies(\$_); print qq{\$ARGV \$ok \$why\n} unless \$ok" $f; done'`
Expected: no lines printed (every chain undoes; with the 0.14 header-history walk).

- [ ] **Step 5:** Full run: `ssh dkim2 'bash /opt/mailman/bench/run-inproc.sh'` (run in background; it is long). Expected: 10 JSONL files; `failures.txt` lists any OOM (that is a result, not a failure of the harness).

- [ ] **Step 6:** Commit both files.

### Task 14: Soak run on real runners

**Files:**
- Create: `util/mailman-bench/soak.sh`
- Create: `util/mailman-bench/sink.py`

**Interfaces:**
- Produces: `/opt/mailman/bench/results/soak-<build>.tsv` columns `t  runner  pid  rss_kb  hwm_kb  cpu_ticks` (one row per runner per second) and `soak-<build>-du.tsv` columns `t  queue_kb  archives_kb  micache_kb`, plus `soak-<build>-summary.json` `{build, drain_seconds, injected, delivered}`.

- [ ] **Step 1:** `sink.py` — an SMTP sink that discards and counts:

```python
"""Discard-all SMTP sink for the soak run. Usage: sink.py PORT COUNTFILE"""
import asyncio, sys
from aiosmtpd.controller import Controller

class Sink:
    n = 0
    async def handle_DATA(self, server, session, envelope):
        Sink.n += len(envelope.rcpt_tos)
        open(sys.argv[2], 'w').write(str(Sink.n))
        return '250 OK'

Controller(Sink(), hostname='127.0.0.1', port=int(sys.argv[1])).start()
asyncio.get_event_loop().run_forever()
```
(`aiosmtpd` is a Mailman dependency, so every bench venv has it.)

- [ ] **Step 2:** `soak.sh BUILD VENV DKIM2(on|off|na)`:

```bash
#!/bin/bash
# One real Mailman instance for BUILD: LMTP in on 127.0.0.1:18024, delivery to
# a discard sink on 127.0.0.1:18025, prototype archiver on, 100 members.
# Injects the whole corpus 3x, samples runner RSS/CPU and disk every second,
# stops when the queues drain. Never touches production.
set -euo pipefail
BUILD=$1 VENV=$2 DK=$3
B=/opt/mailman/bench; OUT=$B/results; V=$B/soak-$BUILD
rm -rf $V && mkdir -p $V
cat > $V/mailman.cfg <<EOF
[mailman]
site_owner: bench@example.com
layout: soak
[paths.soak]
var_dir: $V/var
template_dir: $V/var/templates
[database]
url: sqlite:///$V/var/mailman.db
[mta]
lmtp_host: 127.0.0.1
lmtp_port: 18024
smtp_host: 127.0.0.1
smtp_port: 18025
$( [ "$DK" = on ] && echo "message_instance: yes" )
[archiver.prototype]
enable: yes
[webservice]
port: 18001
EOF
M="$VENV/bin/mailman -C $V/mailman.cfg"
$VENV/bin/python $B/sink.py 18025 $V/delivered & SINK=$!
$M create soak@lists.example.com >/dev/null
for i in $(seq 0 99); do echo "member$i@example.net"; done > $V/members
$M addmembers $V/members soak@lists.example.com
$VENV/bin/python - $V/mailman.cfg $DK <<'EOF'
import sys
from mailman.core.initialize import initialize
initialize(sys.argv[1])
from mailman.config import config
from mailman.interfaces.listmanager import IListManager
from mailman.interfaces.action import Action
from zope.component import getUtility
from mailman.interfaces.template import ITemplateManager
import os
ml = getUtility(IListManager).get('soak@lists.example.com')
ml.default_nonmember_action = Action.accept
tdir = os.path.join(config.TEMPLATE_DIR, 'site', 'en')
os.makedirs(tdir, exist_ok=True)
open(os.path.join(tdir, 'bench-footer.txt'), 'w').write('-- \nbench list footer\nhttps://example.com/unsub\n')
open(os.path.join(tdir, 'bench-header.txt'), 'w').write('bench list header\n')
tm = getUtility(ITemplateManager)
tm.set('list:member:regular:footer', ml.list_id, 'mailman:///bench-footer.txt')
tm.set('list:member:regular:header', ml.list_id, 'mailman:///bench-header.txt')
if hasattr(ml, 'dkim2_message_instance'):
    ml.dkim2_message_instance = (sys.argv[2] == 'on')
config.db.commit()
EOF
systemd-run --scope -q -p MemoryMax=700M --unit=mmsoak-$BUILD $M start --force &
sleep 15
( while sleep 1; do
    t=$(date +%s)
    for p in $(pgrep -f "mailman -C $V/mailman.cfg|runner.*$V/mailman.cfg"); do
      r=$(tr '\0' ' ' </proc/$p/cmdline | grep -o -- '--runner=[a-z:0-9]*' || echo master)
      awk -v t=$t -v r="$r" -v p=$p '/^VmRSS/{rss=$2} /^VmHWM/{hwm=$2} END{printf "%s\t%s\t%s\t%s\t%s\t", t,r,p,rss,hwm}' /proc/$p/status
      awk '{print $14+$15}' /proc/$p/stat
    done >> $OUT/soak-$BUILD.tsv
    printf "%s\t%s\t%s\t%s\n" $t $(du -sk $V/var/queue | cut -f1) $(du -sk $V/var/archives 2>/dev/null | cut -f1 || echo 0) \
      $(du -sk $V/var/mi-cache 2>/dev/null | cut -f1 || echo 0) >> $OUT/soak-$BUILD-du.tsv
  done ) & SAMPLER=$!
START=$(date +%s); N=0
for pass in 1 2 3; do
  for f in $B/corpus/signed/*.eml $B/corpus/unsigned/*.eml; do
    $VENV/bin/python - "$f" <<'EOF'
import smtplib, sys
raw = open(sys.argv[1], 'rb').read()
with smtplib.LMTP('127.0.0.1', 18024) as s:
    s.sendmail('bench@test1.dkim2.com', ['soak@lists.example.com'], raw)
EOF
    N=$((N+1))
  done
done
# Drain: every queue empty for 10 consecutive seconds.
quiet=0; while [ $quiet -lt 10 ]; do
  sleep 1; [ -z "$(find $V/var/queue -name '*.pck' -print -quit)" ] && quiet=$((quiet+1)) || quiet=0
done
END=$(date +%s)
kill $SAMPLER; $M stop || true; kill $SINK || true
printf '{"build":"%s","drain_seconds":%d,"injected":%d,"delivered":%s}\n' \
  $BUILD $((END-START)) $N "$(cat $V/delivered)" > $OUT/soak-$BUILD-summary.json
```

Note: the runner processes are children of `mailman start` (master), so they inherit the scope's memory cap; an OOM kill shows as a runner restart in `$V/var/logs/mailman.log` — record it in the summary by grepping that log for `died` / `signal 9` and adding `"oom_kills": N`.

- [ ] **Step 3:** Smoke: run `soak.sh wrap /opt/mailman/bench/wrap/venv on` with a 10-message corpus copy. Expected: summary `delivered` = 10 × 100 × 3 = 3000 (minus any filtered/discarded), TSVs populated, production `systemctl is-active mailman3` still `active` and its log untouched.

- [ ] **Step 4:** Full runs, one at a time: `for b in "up up na" "cte cte on" "cte-off cte off" "wrap wrap on" "wrap-off wrap off"; do bash soak.sh $b; done` (background). Commit both files.

### Task 15: Report and publication

**Files:**
- Create: `util/mailman-bench/bench_report.py`
- Create: `docs/mailman-dkim2-performance.md` (generated, then annotated)
- Create (scratchpad): the HTML report, published as an Artifact

**Interfaces:**
- Consumes: `results/inproc-*.jsonl`, `results/soak-*`.
- Produces: `bench/report.md` and `bench/report.json` (all aggregates).

- [ ] **Step 1:** `bench_report.py` (stdlib only; run locally after `rsync -a dkim2:/opt/mailman/bench/results/ bench/results/`):

```python
#!/usr/bin/env python3
"""Aggregate benchmark results into bench/report.{md,json}."""
import json, statistics, sys
from collections import defaultdict
from pathlib import Path

R = Path(__file__).resolve().parents[2] / 'bench'
METRICS = ['cpu_in', 'cpu_pipeline', 'cpu_out', 'peak_in', 'peak_pipeline', 'peak_out',
           'pck_in', 'pck_out', 'pck_archive', 'mi_cache', 'wire_bytes', 'mi_header_len']
BUILDS = ['up', 'cte', 'cte-off', 'wrap', 'wrap-off']

def p95(xs):
    xs = sorted(xs); return xs[min(len(xs) - 1, int(0.95 * len(xs)))]

rows = [json.loads(l) for f in sorted((R / 'results').glob('inproc-*.jsonl')) for l in f.open()]
agg = defaultdict(dict)
for b in BUILDS:
    for signed in ('unsigned', 'signed'):
        for cls in ('small', 'medium', 'large', 'huge', 'all'):
            sel = [r for r in rows if r['build'] == b and r['signed'] == signed
                   and (cls == 'all' or r['cls'] == cls) and not r.get('oom')]
            if not sel:
                continue
            agg[f'{b}/{signed}/{cls}'] = {m: {'median': statistics.median(r[m] for r in sel),
                                                'p95': p95([r[m] for r in sel]),
                                                'max': max(r[m] for r in sel)} for m in METRICS}
            agg[f'{b}/{signed}/{cls}']['n'] = len(sel)
            agg[f'{b}/{signed}/{cls}']['oom'] = sum(1 for r in rows if r['build'] == b and r.get('oom'))

soak = {}
for f in (R / 'results').glob('soak-*-summary.json'):
    s = json.loads(f.read_text()); b = s['build']
    tsv = [l.split('\t') for l in (R / 'results' / f'soak-{b}.tsv').read_text().splitlines()]
    by_runner = defaultdict(list)
    for t, runner, pid, rss, hwm, cpu in tsv:
        by_runner[runner].append((int(rss), int(hwm), int(cpu)))
    du = [l.split('\t') for l in (R / 'results' / f'soak-{b}-du.tsv').read_text().splitlines()]
    s['runners'] = {r: {'peak_rss_kb': max(x[1] for x in v), 'mean_rss_kb': statistics.mean(x[0] for x in v)}
                    for r, v in by_runner.items()}
    s['peak_queue_kb'] = max(int(x[1]) for x in du)
    s['peak_micache_kb'] = max(int(x[3]) for x in du)
    soak[b] = s

(R / 'report.json').write_text(json.dumps({'inproc': agg, 'soak': soak}, indent=1))

def fmt(m, v):
    if m.startswith('cpu'): return f'{v * 1000:.1f} ms'
    return f'{v / 1024:.0f} KiB' if v >= 10240 else f'{v:.0f} B'

out = ['# Mailman DKIM2 benchmark', '']
for signed in ('unsigned', 'signed'):
    for cls in ('all', 'small', 'medium', 'large', 'huge'):
        keys = [f'{b}/{signed}/{cls}' for b in BUILDS if f'{b}/{signed}/{cls}' in agg]
        if not keys:
            continue
        out += [f'## {signed}, {cls} (median; vs up)', '',
                '| metric | ' + ' | '.join(k.split('/')[0] for k in keys) + ' |',
                '|---|' + '---|' * len(keys)]
        base = agg.get(f'up/{signed}/{cls}')
        for m in METRICS:
            cells = []
            for k in keys:
                v = agg[k][m]['median']
                rel = '' if not base or not base[m]['median'] else f' ({v / base[m]["median"]:.2f}×)'
                cells.append(fmt(m, v) + rel)
            out.append(f'| {m} | ' + ' | '.join(cells) + ' |')
        out.append('')
out += ['## Soak (real runners)', '', '| build | drain s | delivered | peak queue | peak mi-cache | peak runner RSS (max over runners) |',
        '|---|---|---|---|---|---|']
for b in BUILDS:
    if b in soak:
        s = soak[b]
        out.append(f"| {b} | {s['drain_seconds']} | {s['delivered']} | {s['peak_queue_kb']} KiB | "
                   f"{s['peak_micache_kb']} KiB | {max(r['peak_rss_kb'] for r in s['runners'].values())} KiB |")
(R / 'report.md').write_text('\n'.join(out) + '\n')
print(R / 'report.md')
```

- [ ] **Step 2:** Run it; sanity-check: `wrap-off` ≈ `up` on every metric within noise (if not, find why before publishing — a disabled feature must cost nothing); `wrap` `mi_cache` = 0; `cte` `mi_cache` > 0.

- [ ] **Step 3:** Write `docs/mailman-dkim2-performance.md`: method (builds, corpus, box spec 2 vCPU / 2 GB, memory cap), the generated tables, and a short findings section answering Steve's questions directly — queue bytes per message vs upstream, runner RSS under backlog, CPU per message, wire bytes per recipient (wrap adds the preamble + MIME framing), whether the 50 MB case fits in 700 MB per build. Facts only; no claims not in the tables.

- [ ] **Step 4:** Load the `artifact-design` skill, build the HTML report page from `bench/report.json` (tables plus one chart per headline metric — load `dataviz` for charts), publish it with the Artifact tool (`icon: "chart"`), and add its link to the doc.

- [ ] **Step 5:** Commit `bench_report.py` and the doc in interop; merge locally to master (Task 10 step 6 pattern).

---

## Execution notes

- Tasks 1-3 (interop Perl) are independent of Tasks 4-9 (Mailman) and can run in parallel; Task 10 needs both. Tasks 11-12 can start any time; Task 13 needs Task 9 (the `wrap` build); Tasks 14-15 follow 13.
- Next stage (NOT this plan; tracked in the spec): Sympa always-wrap + harness; header-history walk and null-body signer option in the Python, C, Go, JS and browser verifiers.
