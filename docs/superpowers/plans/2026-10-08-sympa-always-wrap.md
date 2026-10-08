# Sympa DKIM2 always-wrap rebuild: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild Sympa's DKIM2 series on 6.2.78 so that DKIM2 lists
MIME-wrap decorated posts with a layout-built Recipe and use a null body
Recipe when the body changed. The original headers travel in a spool
pseudo-header, and the cost against stock and the old series is measured
with a benchmark harness.

**Architecture:**
- A new module `Sympa::DKIM2` holds all the DKIM2 logic: switch, ingress,
  wrap, egress and chain strip.
- `Sympa::Message` gets three thin hooks: the pseudo-header in
  `to_string`/`new`, `as_rfc822_string`, and a branch at the top of
  `decorate`.
- The spindles call `Sympa::DKIM2` at ingress (`ProcessIncoming`, before
  S/MIME decryption) and egress (`ProcessOutgoing`, last step before
  DKIM/ARC).
- `Mail::DKIM2::MessageInstance->calculate` gains a `BodyRecipe` option, so
  no body diff ever runs.

**Tech stack:**
- Perl 5, Sympa 6.2.78.
- Mail::DKIM2 from interop `perl/`: 0.14 is on CPAN, so this change ships
  as 0.15.
- Email::MIME, MIME::Tools, Test::More, prove.
- The benchmark uses bash plus Perl drivers and runs on dkim2-dev.

**Spec:** `docs/superpowers/specs/2026-10-08-sympa-always-wrap-design.md`
(read it first).

## Global constraints

- **Base:** Sympa 6.2.78 (`09ea5c972`). Work branch: `dkim2-wrap` in
  `~/src/sympa`, from tag `6.2.78`.
- **Keep the old series:** tag `dkim2-cte-preserve-6.2.78` (`bc6d4413b`).
  Never delete it, and never rewrite `dkim2` until Task 10.
- **Switch:** list parameter `dkim2_message_instance`, format `on`/`off`,
  context list/domain/site, default `off`. Off means byte-identical to stock
  6.2.78.
- **Pseudo-header name:** `X-Sympa-DKIM2-Headers`, value is base64 with no
  line breaks of the header block after ingress.
- **No Algorithm::Diff, `.mi_orig` or TextWrap** anywhere in the new series.
  Do not change commit 1's encoding code: it is not carried over.
- **Sympa never originates an instance.** No m=1 for digests,
  notifications, ToMailer or ResendArchive.
- **Never block mail:** every DKIM2 call site is inside `eval`. On failure,
  log with a valid Sympa level (`err`, `info`, `notice`, `debug`; there is
  no `warning`) and deliver without the new instance.
- **Mail::DKIM2:** 0.14 is released on CPAN. The `BodyRecipe` work is 0.15:
  bump `$VERSION` in all 16 modules that say `'0.14'` and add a new Changes
  entry `0.15`. Sympa's dependency is Mail::DKIM2 >= 0.15.
- **Interop repo rules:**
  - never commit `perl/Capital One.pdf`;
  - commit trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`;
  - merging a dev branch means merging locally;
  - never `git stash` in shared checkouts.
- **Sympa fork rules:**
  - never push without Bron's yes; a force-move of `brong/dkim2` needs
    explicit approval;
  - deploy to the box with a git bundle, because the box can't pull.
- **Box rules:**
  - run test suites one at a time;
  - production Sympa, spools and DB are read-only for the benchmark;
  - rebuild the C and Go CLIs before running the interop matrices.

## Review focus

1. **No pseudo-header:** a message that reaches egress without
   `X-Sympa-DKIM2-Headers` (switch turned on mid-spool, or an old spool
   file) must go out with no new instance and no error. Test in Task 6.
2. **Original body without a final newline,** or an empty body: the wrap
   must still give a Recipe that undoes to a body with the same body hash.
   Tests in Task 5.
3. **A boundary-like line inside the original body** (`--=_dkim2_...`):
   wrap must pick a boundary that occurs nowhere in the body. Test in
   Task 5.
4. **8bit or binary original part:** the outer `Content-Transfer-Encoding`
   must not claim 7bit. Test in Task 5.
5. **Per-recipient footer personalisation** across several recipients:
   every copy verifies, and the copies differ only in the footer. Test in
   Task 9.

---

## File structure

| File | Responsibility |
|---|---|
| `interop/perl/lib/Mail/DKIM2/MessageInstance.pm` (+ version bump to 0.15 in every module) | `calculate(..., BodyRecipe => ...)`, `body_hash`, `body_digest_raw` |
| `interop/perl/t/mi-body-recipe-option.t` | tests for the above |
| `sympa/src/lib/Sympa/Config/Schema.pm` | `dkim2_message_instance` parameter |
| `sympa/src/lib/Sympa/DKIM2.pm` (new) | `enabled`, `ingress`, `wrap`, `egress_context`, `egress_add`, folding, X-DKIM2-Info |
| `sympa/src/lib/Sympa/Message.pm` | pseudo-header in `to_string` and the constructor, `as_rfc822_string`, `decorate` branch |
| `sympa/src/lib/Sympa/Spindle/ProcessIncoming.pm` | call `Sympa::DKIM2::ingress` before `smime_decrypt` |
| `sympa/src/lib/Sympa/Spindle/ProcessOutgoing.pm` | `egress_context` once per `_twist`; reorder the tracking and rm_sig blocks; `egress_add` before signing |
| `sympa/src/lib/Sympa/Spindle/ResendArchive.pm` | `shelved{dkim2_strip}` |
| `sympa/src/lib/Sympa/DKIM2.pod` or inline POD | module docs |
| `sympa/t/DKIM2.t` (new) | real-code tests (replaces `t/Message_DKIM2.t`) |
| `sympa/Makefile.am`, `sympa/src/lib/Makefile.am` | register the test and the module |
| `sympa/DKIM2-MESSAGE-INSTANCE.md` | rewritten design and resource doc |
| `interop/util/sympa-bench/` (new) | builds, in-process driver, soak, report, off-identical check |
| `interop/sympa/README.md`, `interop/sympa/patches-6.2.78/` | exported series and docs |
| `interop/docs/sympa-dkim2-performance.md` (new) | benchmark summary |

---

### Task 1: Mail::DKIM2 0.15: a `BodyRecipe` option for `calculate`, `body_hash`, `body_digest_raw`

**Files:**
- Modify: `perl/lib/Mail/DKIM2/MessageInstance.pm` (in `calculate`, near
  `header_hash` at about line 126, and the POD at about line 1190)
- Modify: `perl/Changes` (new 0.15 entry), `$VERSION` in every module
- Test: `perl/t/mi-body-recipe-option.t` (new)

**Interfaces:**
- **Produces:**
  - `Mail::DKIM2::MessageInstance->calculate($cur, $prev, BodyRecipe => $br)`
    where `$br` is one of:
    - `'none'`: no `"b"` key;
    - `'null'`: `"b": null`;
    - an ARRAY ref in the internal form: `[from,to]` arrays for copy ranges
      (1-based body lines of `$cur`), plain strings for literal lines.
    With `BodyRecipe` present, no body diff runs and `$prev`'s body is
    ignored (it may be empty). Croaks on a malformed `$br`: a range with
    `from < 1`, `to < from`, or not ascending; any other ref.
  - `$mi->body_hash` returns the sha256 body hash (`b1`).
  - `Mail::DKIM2::MessageInstance::body_digest_raw($body, [$alg])` returns
    the same value as `b_digest(parse_mime($hdr . "\r\n" . $body))` for a
    body string with LF or CRLF line ends.

- [ ] **Step 1: Write the failing test** `perl/t/mi-body-recipe-option.t`:

```perl
use strict; use warnings;
use Test::More;
use lib 'lib';
use Mail::DKIM2::MessageInstance;
use Mail::DKIM2::Common qw(parse_mime);

my $orig_body = "line one\r\nline two\r\n";
my $prev = "From: a\@example.com\r\nSubject: hi\r\n\r\n$orig_body";
my $m1 = Mail::DKIM2::MessageInstance->calculate($prev);
my $mi1 = "Message-Instance: " . $m1->as_string . "\r\n";
$prev = $mi1 . $prev;

# Wrapped body: 2 preamble lines, original at lines 3-4, 1 trailer line.
my $cur = $mi1 . "From: a\@example.com\r\nSubject: [list] hi\r\n\r\n"
        . "pre1\r\npre2\r\n$orig_body" . "post\r\n";

my $headers_only_prev = $prev; $headers_only_prev =~ s/\r\n\r\n.*\z/\r\n\r\n/s;

subtest 'array Recipe, previous body ignored' => sub {
    my $mi = Mail::DKIM2::MessageInstance->calculate($cur, $headers_only_prev,
        BodyRecipe => [[3, 4]]);
    like $mi->as_string, qr/^m=2; /, 'm=2';
    my $msg = "Message-Instance: " . $mi->as_string . "\r\n" . $cur;
    my ($ok, $err) = Mail::DKIM2::MessageInstance->chain_verifies($msg);
    ok $ok, 'chain verifies' or diag $err;
};

subtest 'null' => sub {
    my $mi = Mail::DKIM2::MessageInstance->calculate($cur, $headers_only_prev,
        BodyRecipe => 'null');
    my $p = Mail::DKIM2::MessageInstance->parse($mi->as_string);
    ok $p->unrecoverable, 'b is null';
};

subtest 'none' => sub {
    my $same = $cur; $same =~ s/\r\n\r\n.*\z/\r\n\r\n$orig_body/s;
    my $mi = Mail::DKIM2::MessageInstance->calculate($same, $headers_only_prev,
        BodyRecipe => 'none');
    ok !exists Mail::DKIM2::MessageInstance->parse($mi->as_string)->{bits}{rb},
        'no b key';
    my $msg = "Message-Instance: " . $mi->as_string . "\r\n" . $same;
    my ($ok, $err) = Mail::DKIM2::MessageInstance->chain_verifies($msg);
    ok $ok, 'chain verifies' or diag $err;
};

subtest 'malformed BodyRecipe croaks' => sub {
    for my $bad ([[0, 1]], [[3, 2]], [[3, 4], [1, 2]], {}, 'bogus') {
        eval { Mail::DKIM2::MessageInstance->calculate($cur, $headers_only_prev,
            BodyRecipe => $bad) };
        ok $@, 'croaks on ' . (ref $bad ? 'ref' : $bad);
    }
};

subtest 'body_hash and body_digest_raw' => sub {
    for my $b ("a\nb\n", "a\r\nb\r\n", "a\nb", "", "\n\n\n", "x\r\n\r\n") {
        (my $crlf = $b) =~ s/\r?\n/\r\n/g;
        my $want = Mail::DKIM2::MessageInstance::b_digest(parse_mime("H: v\r\n\r\n$crlf"));
        is Mail::DKIM2::MessageInstance::body_digest_raw($b), $want, 'digest matches';
    }
    is Mail::DKIM2::MessageInstance->parse($m1->as_string)->body_hash,
       Mail::DKIM2::MessageInstance::b_digest(parse_mime($prev)), 'body_hash';
};

done_testing;
```

  `parse` stores the decoded body Recipe in `{bits}{rb}` (check
  `MessageInstance.pm` `parse`, about line 241, for the key name and adjust
  if it differs).

  Add one more case to the 'array Recipe' subtest: an empty original body
  (`BodyRecipe => []`) must emit `"b": []` and pass `chain_verifies`.

- [ ] **Step 2: Run it and check it fails**

  Run: `cd ~/src/interop/perl && prove -l t/mi-body-recipe-option.t`
  Expected: FAIL (unknown option ignored or `body_hash` undefined).

- [ ] **Step 3: Implement.** In `calculate`, inside `if ($previous) {`,
  before `if ($opts{UseEpilogue})`:

```perl
        if (exists $opts{BodyRecipe}) {
            my $br = $opts{BodyRecipe};
            if (!ref $br && $br eq 'none') {
                $rb_recipe = undef;
            } elsif (!ref $br && $br eq 'null') {
                $self->set_null_body_recipe;
            } elsif (ref $br eq 'ARRAY') {
                my $last = 0;
                for my $step (@$br) {
                    next unless ref $step;
                    croak "BodyRecipe step must be [from,to] or a string"
                        unless ref $step eq 'ARRAY' && @$step == 2;
                    my ($f, $t) = @$step;
                    croak "BodyRecipe range [$f,$t] invalid"
                        unless $f =~ /^\d+\z/ && $t =~ /^\d+\z/
                            && $f >= 1 && $t >= $f && $f > $last;
                    $last = $t;
                }
                $rb_recipe = [ map { ref $_ ? [ @$_ ] : $_ } @$br ];
            } else {
                croak "BodyRecipe must be 'none', 'null' or an ARRAY ref";
            }
        }
        elsif ($opts{UseEpilogue}) {
```

  Then change the `if ($opts{UseEpilogue})` that follows to be part of this
  `elsif` chain (the existing `elsif (defined $opts{EpilogueThreshold})` and
  `else` stay).

  An empty array (empty original body) emits `"b": []`. The later
  `if ($rb_recipe) { set_tag('rb', ...) }` accepts it, because an array ref
  is true.

  Make sure `set_null_body_recipe` isn't overwritten later: `rb` is set only
  `if ($rb_recipe)`.

  Add near `header_hash`:

```perl
sub body_hash { return $_[0]->{bits}{b1} }

# The body hash (spec-06 §6.3) of a raw body string with LF or CRLF line
# ends: no Email::MIME parse, for callers that hold the body alone.
sub body_digest_raw {
    my ($body, $alg) = @_;
    $alg = lc($alg // 'sha256');
    (my $b = $body // '') =~ s/\r?\n/\r\n/g;
    $b =~ s/(\r\n)+\z//;
    $b .= "\r\n";
    return _hash_data_b64($alg, $b);
}
```

  POD: document `BodyRecipe`, `body_hash` and `body_digest_raw` under
  `calculate` and the accessors (`t/pod-coverage.t` must pass).

  Bump `$VERSION` from `'0.14'` to `'0.15'` everywhere it appears
  (`grep -rln "VERSION = '0.14'" lib bin`; 16 files). Then add a new top
  Changes entry `0.15    <today>` with: `- MessageInstance->calculate takes BodyRecipe
  ('none', 'null' or a Recipe) and then skips the body diff; body_hash
  accessor; body_digest_raw(). For list managers that build the Recipe from
  their own layout (Sympa always-wrap).`

- [ ] **Step 4: Run the tests and check they pass**

  Run: `cd ~/src/interop/perl && prove -l t/mi-body-recipe-option.t && prove -lr t`
  Expected: all PASS (1588+ tests).

- [ ] **Step 5: Commit**

```bash
cd ~/src/interop && git add perl/lib perl/bin perl/Changes perl/t/mi-body-recipe-option.t
git commit -m "Mail::DKIM2 0.15: calculate(BodyRecipe => ...), body_hash, body_digest_raw

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Sympa work branch, local dev environment, and the `dkim2_message_instance` switch

**Files:**
- Modify: `~/src/sympa/src/lib/Sympa/Config/Schema.pm` (next to
  `remove_dkim_headers`, about line 4892)
- Create: `~/src/sympa/t/DKIM2.t`

**Interfaces:**
- **Produces:**
  - `$list->{admin}{dkim2_message_instance}` is `'on'` or `'off'`;
  - `Conf::get_robot_conf($robot, 'dkim2_message_instance')`;
  - the test bootstrap in `t/DKIM2.t`, which later tasks extend.

- [ ] **Step 1: Branch and environment**

```bash
cd ~/src/sympa && git status --short   # must be clean; do not stash
git switch -c dkim2-wrap 6.2.78
```

  Dependencies: the correctness review installed Sympa's Perl dependencies
  under
  `/private/tmp/claude-501/-Users-brong-src-interop/38405230-d3eb-4167-a6e1-d7dd2402999f/scratchpad/sympa-review-correctness/local`.
  Copy that tree to `~/src/sympa-dev-deps/` so it outlives the scratchpad.
  Copy its generated `src/src/lib/Sympa/Constants.pm` into
  `~/src/sympa/src/lib/Sympa/` (it is gitignored: `git check-ignore`
  confirms).

  Test command for every later task:

```bash
cd ~/src/sympa && PERL5LIB=$HOME/src/sympa-dev-deps/lib/perl5:$HOME/src/interop/perl/lib prove -Isrc/lib t/DKIM2.t
```

- [ ] **Step 2: Write the failing test** `t/DKIM2.t`. Its bootstrap
  (adapted from the review harness `exp/H.pm`):

```perl
# -*- indent-tabs-mode: nil; -*-
# DKIM2 Message-Instance support. Needs Mail::DKIM2 (interop perl/lib or
# CPAN) on PERL5LIB; without it the test fails rather than skipping.
use strict; use warnings;
use English qw(-no_match_vars);
use File::Temp qw(tempdir);
use Test::More;
use Conf; use Sympa::ConfDef; use Sympa::Log; use Sympa::Message;
use Sympa::Config::Schema;
use Mail::DKIM2::MessageInstance; use Mail::DKIM2::Common;

Sympa::Log->instance->{log_to_stderr} = 'err';
%Conf::Conf = (domain => 'mail.example.org', listmaster => 'lm@example.org',
               tmpdir => tempdir(CLEANUP => 1));
for my $p (grep { $_->{name} and exists $_->{default} } @Sympa::ConfDef::params) {
    $Conf::Conf{$p->{name}} //= $p->{default};
}
our %FILES; my $fdir = tempdir(CLEANUP => 1);
sub set_file { my ($n, $c) = @_; open my $f, '>:raw', "$fdir/$n" or die;
               print $f $c; close $f; $FILES{$n} = "$fdir/$n" }
{ no warnings 'redefine';
  *Sympa::search_fullpath = sub { $FILES{$_[1]} };
  *Sympa::List::update_stats = sub { 1 };
}
sub list { my %a = @_; bless { name => 'test', domain => 'mail.example.org',
    admin => { footer_type => 'mime', dkim2_message_instance => 'on', %a } }
    => 'Sympa::List' }

subtest 'switch parameter' => sub {
    my %p = %{ $Sympa::Config::Schema::pinfo{dkim2_message_instance} || {} };
    ok %p, 'defined';
    is_deeply $p{format}, ['on', 'off'], 'on/off';
    is $p{default}, 'off', 'default off';
    is_deeply $p{context}, [qw(list domain site)], 'list/domain/site';
};

done_testing;
```

  Before writing the assertion, check how `Schema.pm` exposes its table:
  `%pinfo` or another name, via `grep -n "^our\|^my %" src/lib/Sympa/Config/Schema.pm`.
  Use the real name.

- [ ] **Step 3: Run it.** Expected: FAIL (`defined` not ok).

- [ ] **Step 4: Add the parameter** after `remove_dkim_headers`:

```perl
    dkim2_message_instance => {
        context    => [qw(list domain site)],
        order      => 70.09,
        group      => 'dkim',
        gettext_id => 'Add DKIM2 Message-Instance header fields',
        gettext_comment =>
            'If set to "on", Sympa records what it changed in each message in a DKIM2 Message-Instance header field (draft-ietf-dkim-dkim2-spec), wraps decorated messages in a MIME container so the original body is carried unchanged, and marks the body unrecoverable when it rewrites it. Requires the Mail::DKIM2 Perl module; the DKIM2-Signature itself is added by the MTA.',
        format     => ['on', 'off'],
        occurrence => '1',
        default    => 'off',
        not_before => '6.2.78',
    },
```

  Grep for other places `remove_dkim_headers` is registered: docs,
  `src/etc`, `po`, `default/edit_list.conf`. Add `dkim2_message_instance`
  wherever `remove_dkim_headers` appears in a parameter list. Translations
  are not needed.

- [ ] **Step 5: Run it again.** Expected: PASS. Also run Sympa's existing
  config tests (`prove -Isrc/lib t/Config*.t` if present) with the same
  PERL5LIB.

- [ ] **Step 6: Commit** (in `~/src/sympa`, branch `dkim2-wrap`):
  `git commit -am "Add the dkim2_message_instance list parameter (default off)"`
  plus `git add t/DKIM2.t`, with the Co-Authored-By trailer.

---

### Task 3: `Sympa::DKIM2` skeleton, `as_rfc822_string`, and the header pseudo-header

**Files:**
- Create: `~/src/sympa/src/lib/Sympa/DKIM2.pm`
- Modify: `~/src/sympa/src/lib/Sympa/Message.pm`: `to_string` (about line
  343); the attribute loop in the constructor (about lines 80-125);
  `as_rfc822_string` placed after `body_as_string`
- Modify: `~/src/sympa/src/lib/Makefile.am`: add `Sympa/DKIM2.pm` to the
  module list (find where `Sympa/Message.pm` is listed)
- Test: `t/DKIM2.t`

**Interfaces:**
- **Produces:**
  - `Sympa::DKIM2::enabled($that)` returns 1 only for a `Sympa::List` with
    the switch on and Mail::DKIM2 loadable. When it can't be loaded it logs
    `err` once per call.
  - `Sympa::DKIM2::anonymous($list)` is true when
    `$list->{admin}{anonymous_sender}` is set.
  - `$message->{dkim2_headers}` is a string: the header block, LF line ends,
    no trailing blank line.
  - `$message->as_rfc822_string` returns header, a blank line, then the
    body, all CRLF.
  - `to_string` emits `X-Sympa-DKIM2-Headers: <b64>` when `dkim2_headers` is
    defined; the constructor decodes it back.

- [ ] **Step 1: Failing tests.** Append to `t/DKIM2.t`:

```perl
my $plain = "From: a\@example.org\nTo: test\@mail.example.org\nSubject: hi\nMessage-ID: <1\@example.org>\n\nhello\n";

subtest 'enabled' => sub {
    ok Sympa::DKIM2::enabled(list()), 'on';
    ok !Sympa::DKIM2::enabled(list(dkim2_message_instance => 'off')), 'off';
    ok !Sympa::DKIM2::enabled('mail.example.org'), 'robot context';
};

subtest 'pseudo-header round trip' => sub {
    my $m = Sympa::Message->new($plain, context => list());
    $m->{dkim2_headers} = "From: a\@example.org\nSubject: hi\n";
    my $s = $m->to_string;
    like $s, qr/^X-Sympa-DKIM2-Headers: [A-Za-z0-9+\/=]+\n/m, 'serialised';
    unlike $m->as_string, qr/X-Sympa-DKIM2/, 'not in the message proper';
    my $back = Sympa::Message->new($s, context => list());
    is $back->{dkim2_headers}, $m->{dkim2_headers}, 'decoded';
    is $back->dup->{dkim2_headers}, $m->{dkim2_headers}, 'dup keeps it';
};

subtest 'as_rfc822_string' => sub {
    my $m = Sympa::Message->new($plain, context => list());
    my $r = $m->as_rfc822_string;
    unlike $r, qr/(?<!\r)\n/, 'CRLF only';
    like $r, qr/\r\n\r\nhello\r\n\z/, 'body';
    unlike $r, qr/^(Return-Path|X-Sympa-)/m, 'no pseudo-headers';
};
```

  Add `use Sympa::DKIM2;` to the test's `use` lines.

- [ ] **Step 2: Run them.** Expected: FAIL (`Sympa::DKIM2` not found).

- [ ] **Step 3: Implement** `src/lib/Sympa/DKIM2.pm`:

```perl
# -*- indent-tabs-mode: nil; -*-
# vim:ft=perl:et:sw=4

# Sympa - SYsteme de Multi-Postage Automatique
# (licence header: copy the GPL block from Sympa/Message.pm verbatim)

package Sympa::DKIM2;

use strict;
use warnings;
use English qw(-no_match_vars);

use Sympa::Log;

my $log = Sympa::Log->instance;

# True if $that is a list with dkim2_message_instance on and Mail::DKIM2
# loadable.  Mail::DKIM2 is loaded on first use, never at compile time.
sub enabled {
    my $that = shift;
    return 0 unless ref $that eq 'Sympa::List';
    return 0
        unless ($that->{'admin'}{'dkim2_message_instance'} || 'off') eq 'on';
    return 1 if eval {
        require Mail::DKIM2::MessageInstance;
        require Mail::DKIM2::Common;
        1;
    };
    $log->syslog('err',
        'dkim2_message_instance is on for %s but Mail::DKIM2 cannot be loaded: %s',
        $that, $EVAL_ERROR);
    return 0;
}

sub anonymous {
    my $list = shift;
    return ($list->{'admin'}{'anonymous_sender'} // '') ne '' ? 1 : 0;
}

1;
__END__

=encoding utf-8

=head1 NAME

Sympa::DKIM2 - DKIM2 Message-Instance support

=head1 DESCRIPTION

(Filled in by Task 10: what each function does, the switch, the
pseudo-header.)

=cut
```

  Replace the `(Filled in by Task 10 ...)` POD line in this step with a
  two-sentence description: "Records what a list changed in each message as
  a DKIM2 Message-Instance header field, so DKIM2 verifiers downstream can
  undo the list's changes. See DKIM2-MESSAGE-INSTANCE.md." Task 10 expands
  it.

  In `Message.pm`:
  - in `to_string`, after the `X-Sympa-Spam-Status` block, add:

```perl
    if (defined $self->{'dkim2_headers'}) {
        $serialized .= sprintf "X-Sympa-DKIM2-Headers: %s\n",
            MIME::Base64::encode_base64($self->{'dkim2_headers'}, '');
    }
```

  - in the constructor's attribute `elsif` chain, before the final `else`:

```perl
        } elsif ($k eq 'X-Sympa-DKIM2-Headers') {
            $self->{'dkim2_headers'} = MIME::Base64::decode_base64($v);
```

  - add `use MIME::Base64 qw();` if Message.pm doesn't already load it.
  - add `as_rfc822_string` after `body_as_string`:

```perl
# The message as it goes on the wire, for DKIM2 hashing: header fields
# (no Sympa pseudo-headers, no synthesized Return-Path), a blank line and
# the body, with CRLF line ends.
sub as_rfc822_string {
    my $self = shift;

    die 'Bug in logic.  Ask developer' unless $self->{_head};
    my $string = $self->{_head}->as_string . "\n"
        . (defined $self->{_body} ? $self->{_body} : '');
    $string =~ s/\r?\n/\r\n/g;
    return $string;
}
```

- [ ] **Step 4: Run the tests.** Expected: PASS.

- [ ] **Step 5: Commit:**
  `"Sympa::DKIM2 skeleton, as_rfc822_string, X-Sympa-DKIM2-Headers pseudo-header"`.

---

### Task 4: Ingress, before S/MIME decryption

**Files:**
- Modify: `src/lib/Sympa/DKIM2.pm`: add `ingress` and `_prepend_instance`
- Modify: `src/lib/Sympa/Spindle/ProcessIncoming.pm`, just before
  `# Decrypt message.` (about line 203 in 6.2.78)
- Test: `t/DKIM2.t`

**Interfaces:**
- **Consumes:** `enabled`, `anonymous`, `as_rfc822_string`.
- **Produces:**
  - `Sympa::DKIM2::ingress($message)`: when enabled and not anonymous, adds
    m=1 if there is no Message-Instance and sets `$message->{dkim2_headers}`
    to `$message->{_head}->as_string`. Never dies.
  - `Sympa::DKIM2::_prepend_instance($message, $mi)` folds `$mi->as_string`
    and prepends `Message-Instance:`. Task 8 adds X-DKIM2-Info here.

- [ ] **Step 1: Failing tests:**

```perl
subtest 'ingress' => sub {
    my $m = Sympa::Message->new($plain, context => list());
    Sympa::DKIM2::ingress($m);
    is $m->{_head}->count('Message-Instance'), 1, 'm=1 added';
    like $m->{dkim2_headers}, qr/^Message-Instance: m=1;/m, 'saved after m=1';
    my ($ok, $err) = Mail::DKIM2::MessageInstance->chain_verifies($m->as_rfc822_string);
    ok $ok, 'm=1 verifies' or diag $err;

    my $again = Sympa::Message->new($m->as_string, context => list());
    Sympa::DKIM2::ingress($again);
    is $again->{_head}->count('Message-Instance'), 1, 'existing instance kept';

    my $off = Sympa::Message->new($plain, context => list(dkim2_message_instance => 'off'));
    Sympa::DKIM2::ingress($off);
    ok !$off->{_head}->count('Message-Instance') && !defined $off->{dkim2_headers}, 'off: nothing';

    my $anon = Sympa::Message->new($plain, context => list(anonymous_sender => 'anon@mail.example.org'));
    Sympa::DKIM2::ingress($anon);
    ok !defined $anon->{dkim2_headers}, 'anonymous: no saved headers';
};
```

- [ ] **Step 2: Run them.** Expected: FAIL.

- [ ] **Step 3: Implement** in `DKIM2.pm`:

```perl
# At ingress, before any change (including S/MIME decryption): describe the
# message as received with m=1 unless it already carries an instance, and
# keep the header block for egress.  Anonymous lists keep nothing: their
# chain is stripped at egress.
sub ingress {
    my $message = shift;
    my $list    = $message->{context};
    return unless enabled($list);
    return if anonymous($list);

    eval {
        unless ($message->{_head}->count('Message-Instance')) {
            my $mi = Mail::DKIM2::MessageInstance->calculate(
                $message->as_rfc822_string);
            _prepend_instance($message, $mi);
        }
        $message->{'dkim2_headers'} = $message->{_head}->as_string;
        1;
    } or $log->syslog('err', 'DKIM2 ingress failed for %s: %s',
        $message, $EVAL_ERROR);
}

sub _prepend_instance {
    my ($message, $mi) = @_;
    my $folded = Mail::DKIM2::Common::fold_header(
        'Message-Instance: ' . $mi->as_string);
    $folded =~ s/\AMessage-Instance:\s*//;
    $folded =~ s/\r\n/\n/g;
    $message->{_head}->add('Message-Instance', $folded, 0);
    delete $message->{_entity_cache};
}
```

  Check `fold_header`'s return form (CRLF or LF, trailing newline) in
  `interop/perl/lib/Mail/DKIM2/Common.pm:221` and adjust the two
  substitutions so the value has no trailing newline and folds with
  `"\n\t"`.

  In `ProcessIncoming.pm`, immediately before `# Decrypt message.`:

```perl
    # DKIM2: record the message as received, before decryption or any
    # other change.
    Sympa::DKIM2::ingress($message);
```

  Add `use Sympa::DKIM2;` at the top.

- [ ] **Step 4: Run the tests.** Expected: PASS.

- [ ] **Step 5: Commit:** `"DKIM2 ingress: m=1 and saved header block, before S/MIME decryption"`.

---

### Task 5: Always-wrap in `decorate`

**Files:**
- Modify: `src/lib/Sympa/DKIM2.pm`: add `wrap`, `_boundary`, `_parts`
- Modify: `src/lib/Sympa/Message.pm`: `decorate`, right after
  `return unless ref $list eq 'Sympa::List';`
- Test: `t/DKIM2.t`

**Interfaces:**
- **Consumes:** `enabled`; `Sympa::Message::_footer_text($file, $list,
  $rcpt, $data, mode => ..., type => ...)` (stock); `$self->_personalize_attrs`.
- **Produces:**
  - `Sympa::DKIM2::wrap($message, $list, $rcpt, %options)` returns 1. It
    rewrites the body to the wrapped form and sets
    `$message->{_dkim2_body_lines}` to `[first, last]`, the 1-based lines of
    the original body inside the new body, or `[]` for an empty original
    body.
  - It leaves the message alone (`_dkim2_body_lines` undefined) when there
    is nothing to add, or when the type is `multipart/signed`,
    `multipart/encrypted`, `application/pkcs7-mime` or
    `application/x-pkcs7-mime`.

- [ ] **Step 1: Failing tests.** Use a helper that runs ingress, the spool
  round trip, decorate and a Recipe check:

```perl
# Ingress, spool round trip, decorate; then check the Recipe built from the
# recorded lines undoes to the original body hash.
sub wrapped {
    my ($raw, %listopts) = @_;
    my $l = list(%listopts);
    my $m = Sympa::Message->new($raw, context => $l);
    Sympa::DKIM2::ingress($m);
    my $b = Sympa::Message->new($m->to_string, context => $l)->dup;
    $b->decorate($l, undef);
    return $b;
}
sub orig_body_lines_ok {
    my ($b, $raw) = @_;
    my ($first, $last) = @{ $b->{_dkim2_body_lines} || [] };
    (my $orig = $raw) =~ s/\A.*?\n\n//s;
    my @lines = split /\r?\n/, $b->{_body}, -1;
    my $copied = defined $first ? join("\n", @lines[$first-1 .. $last-1]) . "\n" : '';
    is Mail::DKIM2::MessageInstance::body_digest_raw($copied),
       Mail::DKIM2::MessageInstance::body_digest_raw($orig), 'copy range is the original body';
}

set_file('message_footer', "-- \nfooter text\n");
set_file('message_header', "header text\n");

subtest 'wrap: text/plain with header and footer' => sub {
    my $b = wrapped($plain);
    like $b->get_header('Content-Type'), qr{^multipart/mixed;\s*boundary=}i, 'outer multipart/mixed';
    like $b->{_body}, qr/header text\n.*hello\n.*footer text\n/s, 'order';
    orig_body_lines_ok($b, $plain);
};

subtest 'wrap: no final newline, empty body, boundary collision, 8bit' => sub {
    for my $case (
        ["From: a\@x\nSubject: s\n\nno newline", 'no final newline'],
        ["From: a\@x\nSubject: s\n\n", 'empty body'],
        ["From: a\@x\nSubject: s\n\n--=_dkim2_0000\nx\n", 'boundary-like line'],
        ["From: a\@x\nSubject: s\nContent-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: 8bit\n\ncaf\xe9\n", '8bit'],
    ) {
        my ($raw, $name) = @$case;
        my $b = wrapped($raw);
        my ($bd) = $b->get_header('Content-Type') =~ /boundary="?([^";]+)/;
        ok index($raw, $bd) < 0, "$name: boundary not in body";
        orig_body_lines_ok($b, $raw);
        like $b->get_header('Content-Transfer-Encoding') // '', qr/^8bit$/i, "$name: outer 8bit"
            if $name eq '8bit';
    }
};

subtest 'wrap: skipped types and switch off' => sub {
    for my $ct ('multipart/signed; protocol="application/pgp-signature"; boundary=b',
                'application/pkcs7-mime; smime-type=signed-data') {
        my $raw = "From: a\@x\nSubject: s\nMIME-Version: 1.0\nContent-Type: $ct\n\nbody\n";
        my $b = wrapped($raw);
        ok !defined $b->{_dkim2_body_lines}, "$ct untouched";
    }
    my $off = wrapped($plain, dkim2_message_instance => 'off');
    ok !defined $off->{_dkim2_body_lines}, 'off: stock decorate ran';
};
```

- [ ] **Step 2: Run them.** Expected: FAIL.

- [ ] **Step 3: Implement.** In `Message.pm` `decorate`, after the list
  check:

```perl
    # DKIM2 lists wrap the original body in a MIME container instead of
    # editing it (Sympa::DKIM2).
    if (defined $self->{'dkim2_headers'} and Sympa::DKIM2::enabled($list)) {
        return Sympa::DKIM2::wrap($self, $list, $rcpt, %options);
    }
```

  In `DKIM2.pm`:

```perl
use Sympa;

my @SKIP_TYPES = qw(multipart/signed multipart/encrypted
    application/pkcs7-mime application/x-pkcs7-mime);

sub wrap {
    my ($message, $list, $rcpt, %options) = @_;
    my $mode = $options{mode} || '';

    my $type = lc($message->{_head}->mime_type || 'text/plain');
    return 1 if grep { $type eq $_ } @SKIP_TYPES;

    my $data = $mode ? $message->_personalize_attrs : undef;
    my @before = _parts($list, $rcpt, $data, $mode, 'header');
    my @after  = (_parts($list, $rcpt, $data, $mode, 'footer'),
                  _parts($list->{'domain'}, $rcpt, $data, $mode, 'global footer', $list));
    return 1 unless @before or @after;

    my $body = $message->{_body} // '';
    my $boundary = _boundary($body);
    my $head = $message->{_head};

    # The original part: its Content-* fields move off the top level.
    my $orig_part = '';
    for my $tag (grep { /^content-/i } $head->tags) {
        $orig_part .= "$tag: $_" for $head->get_all($tag);   # values keep their "\n"
        $head->delete($tag);
    }
    my $cte = lc(($orig_part =~ /^content-transfer-encoding:\s*(\S+)/mi)[0] // '7bit');

    my $pre = "This is a multi-part message in MIME format.\n";
    $pre .= "\n--$boundary\n$_" for @before;
    $pre .= "\n--$boundary\n$orig_part\n";
    my $first = ($pre =~ tr/\n//) + 1;
    my $nlines = ($body =~ tr/\n//) + (length($body) && $body !~ /\n\z/ ? 1 : 0);
    my $post = ($body =~ /\n\z/ || !length $body) ? '' : "\n";
    $post .= "\n--$boundary\n$_" for @after;
    $post .= "\n--$boundary--\n";

    $head->replace('MIME-Version', '1.0') unless $head->count('MIME-Version');
    $head->replace('Content-Type', qq{multipart/mixed; boundary="$boundary"});
    my $eight = $cte =~ /^(8bit|binary)$/ || grep { /[^\x00-\x7F]/ } @before, @after;
    $head->replace('Content-Transfer-Encoding', $cte eq 'binary' ? 'binary' : '8bit')
        if $eight;

    $message->{_body} = $pre . $body . $post;
    delete $message->{_entity_cache};
    $message->{_dkim2_body_lines} = $nlines ? [$first, $first + $nlines - 1] : [];
    return 1;
}

# One MIME part (header + body text, "\n" line ends, final "\n") per
# configured decoration file of this kind; personalised when $mode is set.
sub _parts {
    my ($that, $rcpt, $data, $mode, $kind, $list) = @_;
    $list ||= $that;
    (my $base = "message_$kind") =~ s/ /_/;    # message_global_footer
    my $mime = Sympa::search_fullpath($that, "$base.mime");
    if ($mime and -s $mime and ($list->{'admin'}{'footer_type'} || '') eq 'mime') {
        my $t = Sympa::Message::_footer_text($mime, $list, $rcpt, $data,
            mode => $mode, type => $kind);
        return () unless length $t;
        $t .= "\n" unless $t =~ /\n\z/;
        return ($t);
    }
    my $file = Sympa::search_fullpath($that, $base);
    return () unless $file and -s $file;
    my $t = Sympa::Message::_footer_text($file, $list, $rcpt, $data,
        mode => $mode, type => $kind);
    return () unless length $t;
    $t .= "\n" unless $t =~ /\n\z/;
    my $cte = $t =~ /[^\x00-\x7F]/ ? '8bit' : '7bit';
    return ("Content-Type: text/plain; charset=UTF-8\n"
          . "Content-Transfer-Encoding: $cte\n"
          . "Content-Disposition: inline\n\n" . $t);
}

sub _boundary {
    my $body = shift;
    while (1) {
        my $b = sprintf '=_dkim2_%08x%08x', int rand 0xffffffff, int rand 0xffffffff;
        return $b if index($body, $b) < 0;
    }
}
```

  Check these against stock and adjust:
  - the exact file names Sympa searches (`message_header`,
    `message_footer`, `message_global_footer` and their `.mime` variants,
    as in stock `decorate` lines 1792-1806);
  - that `_footer_text` exists under that name and signature in 6.2.78
    (`Message.pm:1878`);
  - that `MIME::Head::get_all` returns values with their trailing newline,
    and that `tags` returns names in their original case;
  - that `_personalize_attrs` is callable on the message.

  The test's `orig_body_lines_ok` checks the line arithmetic. An original
  body without a final newline gets one added before the boundary, which
  the body hash ignores; the test pins this.

- [ ] **Step 4: Run the tests.** Expected: PASS.

- [ ] **Step 5: Commit:** `"DKIM2 lists: decorate by MIME-wrapping the original body (always-wrap)"`.

---

### Task 6: Egress: Message-Instance with a layout Recipe or a null body Recipe

**Files:**
- Modify: `src/lib/Sympa/DKIM2.pm`: add `egress_context` and `egress_add`
- Modify: `src/lib/Sympa/Spindle/ProcessOutgoing.pm`: `_twist` (compute
  the context once, pass it as the 6th argument to `__twist_one`) and
  `__twist_one` (reorder; call `egress_add`)
- Test: `t/DKIM2.t`

**Interfaces:**
- **Consumes:** Task 1's `calculate(... BodyRecipe => ...)`,
  `body_digest_raw` and `body_hash`; `_dkim2_body_lines` from Task 5;
  `_prepend_instance`.
- **Produces:**
  - `Sympa::DKIM2::egress_context($message)` returns `undef` (do nothing),
    `{strip => 1}`, or `{prev => $crlf_headers_blank_line, unchanged => 0|1}`.
  - `Sympa::DKIM2::egress_add($message, $ctx, body_rewritten => 0|1)` adds
    the next instance, or strips the chain when `strip` is set (Task 7).
    Never dies.

- [ ] **Step 1: Failing tests.** Add a driver that mirrors `__twist_one`
  and the wire form:

```perl
# Ingress -> spool -> (mod) -> decorate -> egress; returns the wire text (CRLF).
sub through {
    my ($raw, $mod, %listopts) = @_;
    my $l = list(%listopts);
    my $m = Sympa::Message->new($raw, context => $l);
    Sympa::DKIM2::ingress($m);
    my $b = Sympa::Message->new($m->to_string, context => $l);
    my $ctx = Sympa::DKIM2::egress_context($b);
    my $one = $b->dup;
    $mod->($one) if $mod;
    $one->decorate($l, undef);
    Sympa::DKIM2::egress_add($one, $ctx, body_rewritten => 0);
    return $one->as_rfc822_string;
}
sub chain_ok { my ($w, $name) = @_;
    my ($ok, $err) = Mail::DKIM2::MessageInstance->chain_verifies($w);
    ok $ok, $name or diag $err }
sub top_recipe { my $w = shift;
    my ($v) = $w =~ /^Message-Instance: (m=2;.*?)\r\n(?![ \t])/ms or return;
    Mail::DKIM2::MessageInstance->parse($v) }

subtest 'egress: wrap verifies' => sub {
    my $w = through($plain, sub { $_[0]->add_header('List-Id', '<test.mail.example.org>');
                                  $_[0]->replace_header('Subject', '[test] hi') });
    chain_ok($w, 'wrapped + headers changed');
    ok !top_recipe($w)->unrecoverable, 'body recoverable';
    cmp_ok length(($w =~ /^(Message-Instance: m=2;.*?)\r\n(?![ \t])/ms)[0]), '<', 2000, 'small header';
};

subtest 'egress: body changed -> null' => sub {
    my $w = through($plain, sub { $_[0]->{_body} = "rewritten\n"; delete $_[0]->{_entity_cache} });
    ok top_recipe($w)->unrecoverable, 'b null';
    chain_ok($w, 'header history still verifies');
};

subtest 'egress: no saved headers -> nothing, no error' => sub {
    my $l = list();
    my $b = Sympa::Message->new($plain, context => $l);
    is Sympa::DKIM2::egress_context($b), undef, 'no context';
    Sympa::DKIM2::egress_add($b, undef);
    is $b->{_head}->count('Message-Instance'), 0, 'no instance';
};

subtest 'egress: Bcc removed and recorded' => sub {
    my $w = through("Bcc: x\@example.org\n$plain");
    unlike $w, qr/^Bcc:/mi, 'Bcc gone';
    chain_ok($w, 'verifies');
};
```

- [ ] **Step 2: Run them.** Expected: FAIL.

- [ ] **Step 3: Implement** in `DKIM2.pm`:

```perl
# Once per packet, before any per-recipient change.
sub egress_context {
    my $message = shift;
    my $list    = $message->{context};
    return undef unless enabled($list);
    return {strip => 1}
        if anonymous($list) or $message->{shelved}{dkim2_strip};
    unless (defined $message->{'dkim2_headers'}) {
        $log->syslog('info',
            'DKIM2: %s has no saved header block; no Message-Instance added',
            $message);
        return undef;
    }
    my $ctx = eval {
        (my $prev = $message->{'dkim2_headers'} . "\n") =~ s/\r?\n/\r\n/g;
        my ($ok, $why) = Mail::DKIM2::MessageInstance->verify($prev,
            HeadersOnly => 1);
        die "saved header block does not verify: " . ($why // '') . "\n"
            unless $ok;
        my $top = _top_instance($prev);
        my $unchanged = Mail::DKIM2::MessageInstance::body_digest_raw(
            $message->{_body}) eq $top->body_hash;
        {prev => $prev, unchanged => ($unchanged ? 1 : 0)};
    };
    $log->syslog('err', 'DKIM2: %s: %s; no Message-Instance added',
        $message, $EVAL_ERROR) unless $ctx;
    return $ctx;
}

sub _top_instance {
    my $prev = shift;
    my @mi = Mail::DKIM2::Common::parse_mime($prev)->header_raw('Message-Instance');
    my ($top) = sort {
        Mail::DKIM2::Common::extract_mi_version($b)
            <=> Mail::DKIM2::Common::extract_mi_version($a)
    } @mi;
    return Mail::DKIM2::MessageInstance->parse($top);
}

# Last step before DKIM/ARC: describe this copy's changes.
sub egress_add {
    my ($message, $ctx, %opts) = @_;
    return unless $ctx;
    eval {
        if ($ctx->{strip}) {
            _strip_chain($message);
            return 1;
        }
        $message->delete_header($_) for qw(Bcc Resent-Bcc);
        my $br;
        if (!$ctx->{unchanged} or $opts{body_rewritten}) {
            $br = 'null';
        } elsif (my $lines = $message->{_dkim2_body_lines}) {
            $br = @$lines ? [[@$lines]] : [];
        } else {
            $br = 'none';
        }
        my $cur = $message->as_rfc822_string;
        my $mi  = Mail::DKIM2::MessageInstance->calculate($cur, $ctx->{prev},
            BodyRecipe => $br);
        # Nothing changed at all: no instance (spec: r= needs "h" or "b").
        return 1 if $br eq 'none' and $mi->as_string !~ /; r=/;
        _prepend_instance($message, $mi);
        1;
    } or $log->syslog('err',
        'DKIM2: Message-Instance for %s failed: %s; sent without it',
        $message, $EVAL_ERROR);
}

sub _strip_chain { }    # Task 7
```

  Confirm `verify`'s return in list context, `extract_mi_version`'s
  export and argument form, and that `HeadersOnly` skips only the body hash
  (`MessageInstance.pm:877-950`). `$br eq 'none'` must not be evaluated on
  an array ref: write it as `!ref $br && $br eq 'none'`.

  In `ProcessOutgoing.pm`:
  1. In `_twist`, after the context variables are set and before the
     recipient/packet loop calls `__twist_one`, add
     `my $dkim2 = Sympa::DKIM2::egress_context($message);`. Pass `$dkim2` as
     an extra trailing argument on **every** `__twist_one` call.
  2. In `__twist_one`, read it: `my $dkim2 = shift;` after `$rm_sig`.
  3. Move the whole tracking block (`# Determine envelope sender and
     envelope ID.` through the end of its `if/else`), and the first
     `if ($rm_sig) { delete DKIM-Signature, Domainkey-Signature }`, to just
     after the `smime_encrypt` block, unchanged.
  4. After them, before `if ($message->{shelved}{dkim_sign} or %arc)`:

```perl
    # DKIM2: describe this copy's changes, after every transformation and
    # before DKIM/ARC signing.
    Sympa::DKIM2::egress_add($message, $dkim2,
        body_rewritten => (($personalize_all or $smime_encrypt) ? 1 : 0));
```

     where `$personalize_all` is set to true before `$personalize` is
     reassigned to `'footer'` in the existing
     `if ($personalize and $personalize ne 'footer')` branch:
     `my $personalize_all = ($personalize and $personalize ne 'footer');`
     placed just above that branch.
  5. Check whether `Authentication-Results` is hashed
     (`Mail::DKIM2::Common` `%SKIP_EXACT`). If it is, move the second
     `rm_sig` block (A-R removal) before `egress_add` as well, and note it
     in the commit message.

- [ ] **Step 4: Run the tests.** Expected: PASS.

- [ ] **Step 5: Commit:**
  `"DKIM2 egress: Message-Instance from the saved headers, layout or null body Recipe"`.

---

### Task 7: Strip the chain for anonymous lists and resend-from-archive; check the archive copy

**Files:**
- Modify: `src/lib/Sympa/DKIM2.pm` (`_strip_chain`)
- Modify: `src/lib/Sympa/Spindle/ResendArchive.pm` (`_twist`)
- Possibly modify: wherever Sympa writes the archive copy (find with
  `grep -rn "store\|to_string" src/lib/Sympa/Archive.pm src/lib/Sympa/Spindle/*Archive*`)
- Test: `t/DKIM2.t`

**Interfaces:**
- **Consumes:** `egress_context`'s `{strip => 1}`.
- **Produces:** `$message->{shelved}{dkim2_strip} = 1` set by
  ResendArchive. It travels through `X-Sympa-Shelved`.

- [ ] **Step 1: Failing tests:**

```perl
subtest 'anonymous list strips the chain, original From nowhere' => sub {
    my $signed_in = "DKIM2-Signature: i=1; d=example.org; fake\nMessage-Instance: m=1; h=sha256:x:y;\nX-DKIM2-Info: action=mi-m=1;\n"
                  . "From: Whistle Blower <whistle\@corp.example>\nOrganization: Corp Inc\nSubject: s\n\nbody\n";
    my $w = through($signed_in, sub {
        $_[0]->replace_header('From', 'anon@mail.example.org');
        $_[0]->delete_header('Organization');
    }, anonymous_sender => 'anon@mail.example.org');
    unlike $w, qr/^(DKIM2-Signature|Message-Instance|X-DKIM2-Info):/mi, 'chain stripped';
    unlike $w, qr/whistle|Corp Inc/i, 'original sender nowhere';
};

subtest 'resend from archive strips the chain' => sub {
    my $w = through($plain, sub { $_[0]->{shelved}{dkim2_strip} = 1 });
    unlike $w, qr/^(Message-Instance|X-DKIM2-Info):/mi, 'stripped';
    my $m = Sympa::Message->new($plain, context => list());
    $m->{shelved}{dkim2_strip} = 1;
    like $m->to_string, qr/^X-Sympa-Shelved: .*dkim2_strip/m, 'flag is spooled';
};
```

  Note: the anonymous `through` path skips ingress (no saved headers), so
  `egress_context` must return `{strip => 1}` before it checks
  `dkim2_headers`. The Task 6 code already does this.

- [ ] **Step 2: Run them.** Expected: FAIL (chain still present).

- [ ] **Step 3: Implement:**

```perl
sub _strip_chain {
    my $message = shift;
    $message->delete_header($_)
        for 'DKIM2-Signature', 'Message-Instance', 'X-DKIM2-Info';
}
```

  In `ResendArchive.pm` `_twist`, after `$message->smime_decrypt;`:

```perl
    # DKIM2: the archived copy can't describe the message as received, so
    # the resend starts a new chain (Sympa::DKIM2).
    $message->{shelved}{dkim2_strip} = 1;
```

  Archive check: find how the archive copy is written. If it goes through
  `to_string`, make the archiver drop `dkim2_headers`: `delete
  $copy->{dkim2_headers}` on the copy it stores, never on the message being
  delivered. Add a test that archives a message through that code path, or
  through `to_string` on the archive copy, and asserts there is no
  `X-Sympa-DKIM2-Headers`. If the archive uses `as_string` or
  `as_rfc822_string`, add a one-line test asserting the archived text has no
  pseudo-header.

- [ ] **Step 4: Run the tests.** Expected: PASS.

- [ ] **Step 5: Commit:**
  `"DKIM2: anonymous lists and resend-from-archive start a new chain"`.

---

### Task 8: X-DKIM2-Info, ported from the old series

**Files:**
- Modify: `src/lib/Sympa/DKIM2.pm`: add `_dkim2_info`, the constants and
  `_header_list_for_hash`; call them from `_prepend_instance`
- Test: `t/DKIM2.t`

**Interfaces:**
- **Consumes:** `_prepend_instance`.
- **Produces:** every instance Sympa adds has `X-DKIM2-Info` directly above
  it, in the debug-header-01 form.

- [ ] **Step 1: Failing test** (adapt the old series' assertions:
  `git -C ~/src/sympa show bc6d4413b -- t/Message_DKIM2.t`):

```perl
subtest 'X-DKIM2-Info above each instance Sympa adds' => sub {
    my $w = through($plain, sub { $_[0]->replace_header('Subject', '[test] hi') });
    like $w, qr/\AX-DKIM2-Info: [^\r\n]*action=mi-m=2;.*?\r\nMessage-Instance: m=2;/s, 'above m=2';
    like $w, qr/X-DKIM2-Info: [^\r\n]*action=mi-m=1;.*?\r\nMessage-Instance: m=1;/s, 'above m=1';
    my ($info) = $w =~ /\AX-DKIM2-Info: (.*?)\r\n(?![ \t])/s;
    $info =~ s/\r\n[ \t]+/ /g;
    like $info, qr/\A(?:[a-z0-9-]+=[^;]*; ?)+\z/, 'tag-list, every tag ends in ;';
    like $info, qr/draft=ietf-dkim-dkim2-spec-06;/, 'draft';
    like $info, qr/hc=\d+; hn=[a-z0-9,-]+;/, 'hashed header count and names';
};
```

- [ ] **Step 2: Run it.** Expected: FAIL.

- [ ] **Step 3: Implement.** Copy `_dkim2_info` and the constants from
  `git show bc6d4413b:src/lib/Sympa/Message.pm` (the block starting
  `# DKIM2 implementation metadata`) into `DKIM2.pm`. Set `DKIM2_DATE` to
  the date of this commit.

  Re-implement `_header_list_for_hash` to take an Email::MIME object, so
  the message is parsed once:

```perl
sub _header_list_for_hash {
    my $em = shift;
    my @names;
    for my $h (sort { lc($a) cmp lc($b) } $em->header_names) {
        next if Mail::DKIM2::Common::should_skip($h);
        push @names, (lc $h) x scalar(my @v = $em->header_raw($h));
    }
    return (scalar(@names), join(',', @names));
}
```

  In `_prepend_instance`, after adding `Message-Instance`:

```perl
    my ($hc, $hn) = _header_list_for_hash(
        Mail::DKIM2::Common::parse_mime($message->as_rfc822_string));
    my $m = $mi->get_tag('m');
    $message->{_head}->add('X-DKIM2-Info',
        _dkim2_info("mi-m=$m", hc => $hc, hn => $hn), 0);
```

  The hn= list describes the message **with** the new instance, as the old
  series did. Check against `bc6d4413b`, and keep whichever the old test
  asserted.

- [ ] **Step 4: Run the tests.** Expected: PASS. Also run
  `~/src/interop/perl/bin/validate.pl` on one `through()` output saved to a
  file, and check that it reports the X-DKIM2-Info as parsed.

- [ ] **Step 5: Commit:** `"Add the X-DKIM2-Info debug header"`.

---

### Task 9: Regression cases from the review, personalisation, moderation, and the off-identical check

**Files:**
- Test: `t/DKIM2.t`
- Create: `~/src/interop/util/sympa-bench/off-identical.pl` and
  `off-identical.sh`

**Interfaces:**
- **Consumes:** everything above.

- [ ] **Step 1: Write the tests.** Each one is a subtest using `through()`,
  or the real spindle code where noted. The review scripts in
  `.../scratchpad/sympa-review-correctness/exp/` hold the exact inputs:
  `e1_qp.pl`, `e3_cases.pl`, `e6_charset.pl`, `e7_smime_mdn.pl`,
  `e9_moderation.pl`, `e10_notice.pl`, `e12_resend.pl`, `e13_txtmode.pl`,
  `e15_anon.pl`. Port their inputs, not their old-API calls.
  1. **The 19 real-decorate cases** from `e3_cases.pl` (7bit, CRLF input,
     no final newline, latin1 8bit, html-only, empty body, 1200-char line,
     multipart/alternative with mime footer, mixed with PDF, PGP/MIME,
     header-only changes, odd folding, `Keywords:abc`, Bcc, image-only, dot
     lines, trailing blank lines, bare CR), each with `chain_ok`. Drop
     the "append footer" variant: append is ignored on DKIM2 lists. Add one
     case asserting that `footer_type => 'append'` still gives a wrap.
  2. **QP post with DKIM2 on:** the wrapped original part is byte-identical
     to the received body, and the footer part decodes to the footer text.
  3. **Non-ASCII footer** (`"Euro €, 日本\n"`, UTF-8) on a us-ascii post:
     the footer part is `charset=UTF-8` and the bytes are intact (no `?`).
  4. **S/MIME stand-in:** call `egress_add` with `body_rewritten => 1`. The
     instance has `"b": null` and the plaintext is not in any header. Use
     `e7`'s approach: stub `smime_encrypt` by replacing `_body`.
  5. **Moderation round trip:** ingress, `to_string`, then
     `Sympa::Message->new` twice (moderation spool, then bulk spool), then
     decorate and egress. Must pass `chain_ok`.
  6. **Notice mode:** `_body` replaced with the notice text and the
     Content-* fields changed (port from `e10_notice.pl`). Expect
     `"b": null` and a Message-Instance under 4 KB.
  7. **Txt mode:** the same, from `e13_txtmode.pl`.
  8. **MDN:** after decorate, `replace_header('Disposition-Notification-To', ...)`
     before `egress_add`. Must pass `chain_ok`. This mirrors the new order.
  9. **Footer-only personalisation, three recipients:** set the footer to
     `"for [% user.email %]\n"`. Stub `_personalize_attrs` and
     `personalize_text` only if the test can't reach the DB: check how
     `e3`/`e16` did it. Call `decorate($l, $rcpt, mode => 'footer')` per
     recipient on a `dup`. Each output passes `chain_ok`. Each output's
     `_dkim2_body_lines` are equal. The bodies differ only after the last
     copied line.
  10. **Upstream instance kept:** a message that arrives with a valid m=1
      (built with `Mail::DKIM2::MessageInstance->calculate`) keeps it, and
      gets m=2 that verifies (from `e4_upstream.pl`).

- [ ] **Step 2: Run them.** Expected: all PASS without code changes. Any
  failure is a bug in Tasks 3-8: fix it there, in this task's commit, and
  describe the fix in the commit message.

- [ ] **Step 3: Off-identical script.**
  `util/sympa-bench/off-identical.pl BUILD_LIB` loads the given
  `src/lib`. With `dkim2_message_instance => 'off'`, for each input file it
  runs ingress, the spool round trip, decorate (`footer_type` mime, then
  append) and egress. It prints `sha256(as_string)` per input. On stock,
  where `Sympa::DKIM2` doesn't exist, it skips the DKIM2 calls (guard with
  `eval { require Sympa::DKIM2 }`).

  `off-identical.sh` runs it against a `git worktree` of `6.2.78` and of
  `dkim2-wrap` over `~/src/interop/corpus/` (the 317 charset samples) plus
  the review inputs, and diffs the outputs. Put the worktrees in a
  scratchpad dir and remove them at the end. Expected: no differences.

- [ ] **Step 4: Run it.**

```bash
cd ~/src/interop && bash util/sympa-bench/off-identical.sh
```

  Expected: `identical: 317+N/317+N`.

- [ ] **Step 5: Commit** in both repos. Sympa:
  `"t/DKIM2.t: review regression cases, personalisation, moderation"`.
  Interop: `"util/sympa-bench: off-identical check against stock 6.2.78"`.

---

### Task 10: Docs, squash into the upstream series, export patches

**Files:**
- Modify: `~/src/sympa/DKIM2-MESSAGE-INSTANCE.md` (rewrite), the POD in
  `src/lib/Sympa/DKIM2.pm`, `Makefile.am` (`check_SCRIPTS` gets
  `t/DKIM2.t`)
- Modify: `~/src/interop/sympa/README.md`, replace
  `~/src/interop/sympa/patches-6.2.78/*.patch`
- Modify: `~/src/interop/docs/dkim2-postfix-list-host-guide.md` (Sympa
  sections)

- [ ] **Step 1: Write `DKIM2-MESSAGE-INSTANCE.md`** to cover:
  - the switch;
  - ingress before decryption, and the pseudo-header;
  - always-wrap and its layout;
  - the null body Recipe rule, compared with the top instance's `h=`;
  - the special-cases table from the spec;
  - the `remove_headers` note: removed hashed fields (not `X-`, not trace)
    stay in the header Recipe, as spec §5.1 requires;
  - the dependency: Mail::DKIM2 0.15 or later;
  - resource figures: leave a sentence pointing at Task 13's numbers, then
    fill them in during Task 13.

  Use the spec-06 wire format only. No `v=`, no spec-08.

- [ ] **Step 2: Expand the POD** of `Sympa::DKIM2`: one `=item` per public
  function (`enabled`, `anonymous`, `ingress`, `wrap`, `egress_context`,
  `egress_add`).

- [ ] **Step 3: Squash** `dkim2-wrap` into three commits on `6.2.78`, in this
  order:
  1. `Add the dkim2_message_instance list parameter`: Schema.pm plus the
     docs/registration of the parameter.
  2. `Add DKIM2 Message-Instance support with always-wrap decoration`:
     DKIM2.pm without X-DKIM2-Info, plus the Message.pm and spindle hooks,
     `t/DKIM2.t` and `DKIM2-MESSAGE-INSTANCE.md`.
  3. `Add the X-DKIM2-Info debug header`.

  Commit messages follow the style of the old series' messages: what and
  why, no task numbers. Each ends with the Co-Authored-By trailer. After
  each commit the tests pass:
  `git rebase -x "PERL5LIB=... prove -Isrc/lib t/DKIM2.t" 6.2.78`.

  Then `git branch -f dkim2 dkim2-wrap`. This is a local move. The old
  state is safe in tag `dkim2-cte-preserve-6.2.78`. **Do not push.** Ask
  Bron whether to force-push `brong/dkim2` and push the tag.

- [ ] **Step 4: Export the patches:**

```bash
cd ~/src/interop && git rm -q sympa/patches-6.2.78/*.patch
git -C ~/src/sympa format-patch -o ~/src/interop/sympa/patches-6.2.78 6.2.78..dkim2
```

  Rewrite `sympa/README.md`'s patch list. Dependencies: Mail::DKIM2 0.15,
  with no Algorithm::Diff needed. Add the switch, and a pointer to the old
  series tag. Update the list-host guide's Sympa parts: the switch must be
  on per list, and `--allow-null-body-recipe` is needed on the outbound
  milter.

- [ ] **Step 5: Check the patches apply** to a clean 6.2.78 worktree with
  `git am` and that `t/DKIM2.t` passes there. Commit in interop:
  `"sympa: rebuilt always-wrap series (patches, README, list-host guide)"`.

---

### Task 11: Benchmark builds and the in-process driver

**Files:**
- Create: `~/src/interop/util/sympa-bench/README.md`, `setup-builds.sh`,
  `bench_inproc.pl`, `run-inproc.sh`, `make-corpus.py` (or reuse
  `util/mailman-bench/make-corpus.py` with a `--sympa` flag if the
  differences are small)

**Interfaces:**
- **Produces:** JSON lines in `/opt/sympa-bench/results/inproc-BUILD.jsonl`,
  one record per (message, list configuration, run):
  `{build, msg_id, size, signed, config, members, stage_cpu:{ingress,tolist,spool,decorate,egress,total}, peak_rss_kb, spool_bytes, wire_bytes_per_rcpt, mi_len_max, verifies, undo_ok, timeout, oom}`.

- [ ] **Step 1: `setup-builds.sh`** (runs on the box) installs Sympa libs
  for `up` (`6.2.78`), `cte` (tag `dkim2-cte-preserve-6.2.78`) and `wrap`
  (`dkim2`). It does not run a full `make install`: copy `src/lib` and
  generate `Constants.pm` the way the box build does. See `deploy/SERVER.md`
  §4, which builds `/opt/sympa-dkim2`.
  - Targets: `/opt/sympa-bench/{up,cte,wrap}/lib`.
  - Mail::DKIM2 goes in `/opt/sympa-bench/dkim2lib` (a copy of interop
    `perl/lib` at master).
  - `cte-nomod` is `cte` without `dkim2lib` on `@INC`; `wrap-off` is
    `wrap` with the switch off.
  - Sources come from a git bundle of `~/src/sympa`, because the box can't
    fetch. Use the bundle procedure from the interop deploy notes.

- [ ] **Step 2: `bench_inproc.pl BUILD LIBDIR [--dkim2lib DIR] [--switch on|off]`**
  loads the build's libs with a throwaway `%Conf::Conf` and a stub list,
  the same bootstrap as `t/DKIM2.t`. Per message and per configuration it
  runs the old or new pipeline:
  - **`wrap`:** `Sympa::DKIM2::ingress`, the `to_string`/`new` round trip,
    `egress_context`, then per packet or recipient `dup`, `decorate` and
    `egress_add`.
  - **`cte`:** the old series' ingress/egress calls
    (`add_message_instance_ingress`, `mi_original`, `decorate`,
    `add_message_instance_egress`).
  - **`up`:** decorate only.

  Measurements and checks:
  - CPU per stage with `Time::HiRes` and `times()`;
  - peak RSS from `/proc/self/status` VmHWM, reset per case by running each
    case in a forked child;
  - spool bytes as `length to_string`, plus the `.mi_orig` length for
    `cte`;
  - wire bytes and the longest `Message-Instance` line;
  - `chain_verifies` on the CRLF wire text.

  Each case runs in a child with `alarm 300`. A timeout or a death is
  recorded and the run moves on.

  Configurations come from the spec, §2 "List configurations":
  - footer only, and header plus footer, each in mime and append;
  - personalisation off, footer-only and all;
  - verp 0% and 100%, where 100% means one `__twist_one` per recipient;
  - reception modes mail, txt and notice, applied by calling the same body
    rewrite ToList uses: `prepare_message_according_to_mode`. Look it up
    and call it directly;
  - 25 and 1000 members (packets of 25 recipients, or per recipient for
    verp, personalisation and merge).

  Median of 5 runs.

- [ ] **Step 3: Corpus.** Build it with `make-corpus.py` locally and copy it
  to `/opt/sympa-bench/corpus/` with an `index.tsv`. Contents:
  - the 317 charset samples;
  - single-part base64 text and HTML at 10 KB, 30 KB, 100 KB, 1 MB and
    5 MB;
  - single-part QP;
  - multipart/alternative with a QP HTML part;
  - attachments of 1, 10, 25 and 50 MB, base64-wrapped at both 76 and 72
    columns;
  - latin1 and ISO-2022-JP bodies;
  - pre-signed copies of each, made with the interop signer, as Mailman's
    corpus did.

- [ ] **Step 4: `run-inproc.sh`** runs every build in turn under
  `systemd-run --scope -p MemoryMax=700M`, never two at once. Wait for no
  Sympa or Mailman test suite to be running, as in
  `util/mailman-bench/run-soaks.sh`. Smoke-run it on 5 messages × 2
  configurations first and check that the JSON fields are filled. Then
  start the full run in the background (`nohup`), and record the PID and
  log path in the task report.

- [ ] **Step 5: Commit:**
  `"util/sympa-bench: builds, corpus and in-process driver"`.

---

### Task 12 (conditional): reuse the per-recipient hash for footer personalisation

Run this only if Task 11's results show that `egress` exceeds 20% of
per-recipient CPU in the footer-only personalisation configuration at
1 MB or more. Otherwise record "not needed" with the numbers in the task
report and in `docs/sympa-dkim2-performance.md`, and skip it.

**Files:**
- Modify: `src/lib/Sympa/DKIM2.pm`
- Possibly: `perl/lib/Mail/DKIM2/MessageInstance.pm`. `calculate` would
  need to accept a precomputed body hash (`BodyHash => $b64`). Add that
  option with a test proving `calculate(..., BodyHash => body_digest_raw($b))`
  equals the computed one.

- [ ] **Step 1: Failing test:**
  `Sympa::DKIM2::_body_hash_with_prefix($prefix_state, $suffix)` equals
  `body_digest_raw($prefix . $suffix)` for these cases:
  - a suffix with trailing blank lines;
  - a prefix that does not end in a newline;
  - an empty suffix.
- [ ] **Step 2: Implement** with `Digest::SHA->new(256)` (or
  `Crypt::Digest::SHA256`, whichever Mail::DKIM2 uses), `->clone` per
  recipient. Canonicalise the suffix, accounting for the trailing-CRLF
  stripping that crosses the prefix/suffix boundary. Cache the prefix state
  in the egress context, keyed on the wrapped body up to the first footer
  part.
- [ ] **Step 3: Re-run** the footer-personalisation configuration and
  record the before/after numbers.
- [ ] **Step 4: Commit** in both repos where touched, then re-squash into
  commit 2 of the series and re-export the patches (Task 10, steps 3-5).

---

### Task 13: Soak, report and performance document

**Files:**
- Create: `util/sympa-bench/soak.sh`, `run-soaks.sh`, `bench_report.py`
- Reuse: `util/mailman-bench/sink.py` (SMTP sink)
- Create: `docs/sympa-dkim2-performance.md` and an HTML report page
  (scratchpad, then publish as an artifact)

- [ ] **Step 1: `soak.sh BUILD on|off|na`** runs one real Sympa instance per
  build under `/opt/sympa-bench/soak-BUILD/`. It has:
  - its own config dir, spool dir and SQLite DB;
  - `sendmail` pointed at a wrapper that hands off to `sink.py` on its own
    port;
  - its own systemd units, `sympasoak-*`, holding `sympa_msg.pl` and
    `bulk.pl` with `bulk_max_count 3`;
  - a 700M cgroup;
  - one list with header and footer, 1000 members over 200 domains, and
    the switch per the argument.

  Messages are injected with `queue` (Sympa's queue program) as fast as it
  accepts: the under-2 MB corpus, three times. Every second it samples per
  process VmRSS, VmHWM and utime+stime from `/proc`, and `du` of every
  spool dir.

  Outputs: `results/soak-BUILD.{tsv,json}` with peak and mean RSS per
  process, total CPU, peak spool bytes and inodes, drain time, and the
  orphaned spool files left after the drain.

  Builds: up, cte, cte-nomod, wrap, wrap-off, one at a time. Production
  Sympa, Postfix and the DB are untouched. Check this by diffing
  `systemctl list-units 'sympa*'` and the production spool listing before
  and after.
- [ ] **Step 2: `run-soaks.sh`** waits for quiet as Mailman's does, runs the
  five soaks, and touches `results/SOAKS-DONE`. Start it in the background
  once the in-process run has finished.
- [ ] **Step 3: `bench_report.py`** compares each build with `up`: median,
  p95 and max of CPU, RSS, spool, wire bytes and MI header length. It
  breaks these out by size class, configuration and signed/unsigned, and
  lists timeouts, OOMs and verify failures per build. It writes the
  markdown and the HTML page.
- [ ] **Step 4: Write `docs/sympa-dkim2-performance.md`** with the
  headline table, the spec's success criteria answered one by one, and the
  method. Fill in the resource section of `DKIM2-MESSAGE-INSTANCE.md` from
  it, and re-squash and re-export if the Sympa doc changed. Publish the
  HTML page as an artifact, following the artifact-design skill, and link
  it from the doc.
- [ ] **Step 5: Commit:**
  `"util/sympa-bench: soak and report; docs/sympa-dkim2-performance.md"`.

---

### Task 14: Deploy and acceptance on dkim2-dev

**Files:**
- Modify: `deploy/SERVER.md` §4 (Sympa: the switch, the series description)
- Memory: update `project_mailman_always_wrap.md` and
  `project_mailman_sympa_deploy_from_branch.md`

- [ ] **Step 1: Interop.**
  - Merge any interop work branch locally.
  - Run, all green:
    - `prove -lr perl/t`;
    - `util/negative-vectors.sh` (115);
    - `util/signer-gate.sh` (104);
    - `util/hash-matrix.sh` (60);
    - `util/interop-fold-mi.sh` (57/0).

    Rebuild the C and Go CLIs first (`make -C c tools`; `go build` in
    `go/`).
  - Deploy interop to the box with the bundle procedure and
    `deploy/deploy.sh`.
- [ ] **Step 2: Sympa.**
  - Bundle `~/src/sympa` `dkim2` to the box.
  - In `/opt/sympa-dkim2`: fetch the bundle, `git checkout -B dkim2
    bundle/dkim2`. The old state is in the tag, so tag
    `dkim2-cte-preserve-6.2.78` on the box too, before moving.
  - Rebuild and install with the `deploy/SERVER.md` §4 configure line plus
    `make && make install`.
  - Restart `sympa`, `sympa-bulk`, `sympa-archived`, `sympa-bounced`,
    `sympa-task_manager` and `wwsympa`.
  - Set `dkim2_message_instance on` in the config of the DKIM2 test lists:
    dkim2corpus, dkim2test, and the smoke and capture lists. List them with
    `ls /var/lib/sympa/list_data/*/`.
  - Remove leftover `*.mi_orig` files from `/var/spool/sympa/bulk/msg`
    after the bulk spool drains.
  - Run Sympa's `t/DKIM2.t` on the box, alone (no other suite running).
- [ ] **Step 3: Acceptance**, each recorded in the task report:
  - **Smoke list:** round-trips, verified by all five verifiers.
  - **Charset corpus:** replay through the Sympa corpus list, expect
    317/317, verified by all five verifiers. Use the existing corpus runner
    (see `project_charset_corpus` notes, `corpus/` logs).
  - **QP post** on an append-footer list with the switch on: renders
    correctly (footer readable, body intact).
  - **Notice- or txt-mode subscriber delivery:** signed, with `"b": null`.
  - **Anonymous test list** (create one): the delivered copy has no
    original From, no upstream DKIM2 headers, and a fresh m=1 from the
    milter.
  - **Moderated test list:** a post approved through the web UI or
    `sympa.pl`'s moderation command verifies.
  - **Milter journal** (`journalctl -u dkim2-milter-outbound`): no new
    errors.
- [ ] **Step 4: Update** `deploy/SERVER.md` and the memory files. Commit:
  `"deploy: Sympa always-wrap series on dkim2-dev"`. Report to Bron, and
  ask about pushing `brong/dkim2` (force), the tag, and the Mail::DKIM2 0.15
  CPAN upload.
