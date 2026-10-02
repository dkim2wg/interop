# Postfix List-Host Guide and Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give a Postfix operator one guide and installable pieces to run a DKIM2-participating mailing-list host with Mailman 3 or Sympa.

**Architecture:** The Perl dist installs the standalone milter and the split daemon as programs. The two list-manager forks are rewritten into three-commit series and exported as patches into `mailman/` and `sympa/` by a script that also checks they apply. Generic systemd units and Postfix fragments live in `deploy/examples/` and are what the dkim2.com box itself installs. The guide in `docs/` ties these together and is linked from dkim2.com and the Perl README.

**Tech Stack:** Perl 5.20+/ExtUtils::MakeMaker, git (rebase, format-patch, apply --check), bash, systemd, Postfix, Mailman 3 (Python), Sympa 6.2.78 (Perl).

**Spec:** `docs/superpowers/specs/2026-10-02-postfix-list-host-guide-design.md`

## Global Constraints

- One Perl distribution; no dist split. `dkim2-milter` and `dkim2-split-lmtp` are installed programs; Sendmail::PMilter, Net::SMTP, Sys::Syslog, Mail::Milter::Authentication, Mail::AuthenticationResults are runtime *recommends*, never requires.
- Sympa 6.2.78 is the only supported Sympa base. Mailman patches target the fork's upstream base `687b9e4dc` (v3.3.10+466); the README records whether they also apply to `v3.3.10`.
- Rewriting a fork branch changes history, not content: `git diff dkim2-history-2026-10-02 dkim2` must be empty afterwards.
- Both milters are documented as equal paths; the guide never references dkim2.com-specific paths except as a worked example.
- Any change to what the milter emits (the `sw=` tag of `X-DKIM2-Info` changes with the rename) bumps `DKIM2_DATE` in `perl/lib/Mail/DKIM2/Common.pm` and `perl/t/version.t`.
- Finish tidy: `perl/MANIFEST` regenerated and `make distcheck` clean; stale installed `*.pl` programs removed from the box; no dead files.
- Done means deployed: `deploy/deploy.sh` on the box, `deploy/dkim2-list-smoke.sh` green, validator good/bad check.

## Review Focus

1. An operator applies the Mailman series to the `v3.3.10` release rather than master; they expect either a clean apply or a README sentence telling them it will not. (Task 4: the export script's `--check` tries `v3.3.10` and the README records the result.)
2. `/usr/local/bin/dkim2-milter --help` run with no repo checkout anywhere; it must start and print usage, not die on a missing library path. (Task 1: the `use lib` line is guarded; Task 7 runs it on the box.)
3. `dkim2-split-lmtp` installed by the dist is started by the example unit as `nobody`; it must bind and re-inject without reading anything under the repo. (Task 7: `systemctl status dkim2-split` after deploy.)
4. The Sympa patches applied to a pristine 6.2.78 tree must build the test list: `t/Message_DKIM2.t` is added to `Makefile.am`'s `check_SCRIPTS`. (Task 3: the series contains the Makefile.am hunk; Task 4 `--check` applies the full series.)
5. A reader who follows only the authentication_milter path must get a configuration that signs list mail: the JSON fragment's `sign_local`/`sign_authenticated` and the loopback listener are consistent with the Postfix fragment. (Task 5: fragment cross-checked against the handler's `default_config` in a test that parses the fragment.)

---

### Task 1: Perl dist installs `dkim2-milter` and `dkim2-split-lmtp`

**Files:**
- Rename: `perl/bin/dkim2-milter.pl` → `perl/bin/dkim2-milter`; `perl/bin/dkim2-split-lmtp.pl` → `perl/bin/dkim2-split-lmtp`
- Modify: `perl/Makefile.PL` (EXE_FILES, META_MERGE recommends), `perl/MANIFEST`, `perl/Changes`, `perl/README`
- Modify: `perl/lib/Mail/DKIM2/Common.pm:44-46` (`DKIM2_DATE`), `perl/t/version.t`
- Modify: `perl/bin/dkim2-milter` (constant `DKIM2_SOFTWARE`, POD status paragraph, `=encoding`, guarded `use lib`), `perl/bin/dkim2-split-lmtp` (guarded `use lib`), `perl/bin/dkim2sign`, `perl/bin/dkim2verify` (guarded `use lib`)
- Modify: `perl/t/milter-script.t:3,35,245`, `perl/t/split-lmtp.t:8,56`
- Modify: `deploy/deploy.sh:43` (drop the manual install of the split daemon), `deploy/SERVER.md` (paths), `deploy/setup-dkim2-demo.sh:184,201` (unit name stays; ExecStart changes in Task 5)

**Interfaces:**
- Produces: installed programs `/usr/local/bin/dkim2-milter`, `/usr/local/bin/dkim2-split-lmtp`. `X-DKIM2-Info` from the milter carries `sw=dkim2-milter;`. `DKIM2_DATE` is `2026-10-02`.

- [ ] **Step 1: Write the failing tests.** In `perl/t/milter-script.t` change line 35 to `my $SCRIPT = "$FindBin::Bin/../bin/dkim2-milter";` and line 245's regex to `sw=dkim2-milter; action=`. In `perl/t/split-lmtp.t` line 56 to `exec($^X, '-Ilib', 'bin/dkim2-split-lmtp');`. In `perl/t/version.t` change the date assertion to `is(DKIM2_DATE, '2026-10-02', 'software date is the last DKIM2 behaviour change (installed milter name in X-DKIM2-Info sw=)');`. Append to `perl/t/sign-cli.t` before `done_testing`:

```perl
# Every installed program must compile with no repo checkout beside it.
for my $prog (qw(dkim2sign dkim2verify dkim2-milter dkim2-split-lmtp)) {
    my $out = `$^X -c bin/$prog 2>&1`;
    like($out, qr/syntax OK/, "bin/$prog compiles");
    open my $fh, '<', "bin/$prog" or die $!;
    my $src = do { local $/; <$fh> };
    like($src, qr/use lib .* if -d/, "bin/$prog only adds the checkout lib dir when it exists");
}
```

- [ ] **Step 2: Run them.** `cd perl && prove -l t/milter-script.t t/split-lmtp.t t/version.t t/sign-cli.t` — Expected: FAIL (scripts not found, date mismatch, `use lib` unguarded).

- [ ] **Step 3: Rename and edit.**

```bash
cd perl && git mv bin/dkim2-milter.pl bin/dkim2-milter && git mv bin/dkim2-split-lmtp.pl bin/dkim2-split-lmtp
```

In each of the four `bin/` programs replace `use lib "$FindBin::Bin/../lib";` with:

```perl
use lib "$FindBin::Bin/../lib" if -d "$FindBin::Bin/../lib/Mail/DKIM2";   # running from a checkout
```

(`dkim2-milter` has no `use lib` today because the units pass `-I`; add the guarded line after `use FindBin;`, adding `use FindBin;` if absent.) In `bin/dkim2-milter` set `use constant DKIM2_SOFTWARE => 'dkim2-milter';`, replace the POD paragraph beginning `B<EXPERIMENTAL> — This tool implements` with:

```pod
This program implements draft-ietf-dkim-dkim2-spec-06; see L<Mail::DKIM2/STATUS>.
```

and ensure `=encoding utf8` is the first POD line after `__END__`. In `bin/dkim2-milter`'s POD, fix the DEPENDENCIES section to say Sendmail::PMilter is a recommended dependency of Mail-DKIM2 and point at `deploy/patches/pmilter-null-sender-envfrom.patch`. In `Common.pm` set `DKIM2_DATE => '2026-10-02'`.

In `Makefile.PL`:

```perl
    EXE_FILES => [
        'bin/dkim2sign',
        'bin/dkim2verify',
        'bin/dkim2-milter',
        'bin/dkim2-split-lmtp',
    ],
```

and in `META_MERGE` → `prereqs` → `runtime` → `recommends` add:

```perl
                    # dkim2-milter
                    'Sendmail::PMilter' => '1.27',
                    # dkim2-split-lmtp
                    'Net::SMTP'   => '0',
                    'Sys::Syslog' => '0',
                    # the authentication_milter handlers
                    'Mail::Milter::Authentication' => '0',
                    'Mail::AuthenticationResults'  => '0',
```

In `deploy/deploy.sh` delete line 43 (`install -m 755 bin/dkim2-split-lmtp.pl /usr/local/bin/dkim2-split-lmtp`) and add after `make install`:

```bash
# Programs an older `make install` left behind under their previous names.
rm -f /usr/local/bin/calculate-dkim2.pl /usr/local/bin/calculate-mailversion.pl \
      /usr/local/bin/reverse-mailversion.pl /usr/local/bin/validate-mailversion.pl \
      /usr/local/bin/verify-sig.pl /usr/local/bin/validate.pl /usr/local/bin/dkim2sign.pl
```

In `deploy/SERVER.md` replace every `perl/bin/dkim2-milter.pl` with `perl/bin/dkim2-milter` (installed as `/usr/local/bin/dkim2-milter`) and `dkim2-split-lmtp.pl` with `dkim2-split-lmtp`. Add a `Changes` line under 0.10: `- dkim2-milter and dkim2-split-lmtp are installed programs (were bin/*.pl, run from the checkout).` Regenerate `MANIFEST`: `perl Makefile.PL && make manifest && rm -f MANIFEST.bak`, then fix the two renamed entries if `mkmanifest` kept the old names.

- [ ] **Step 4: Run.** `prove -l -j8 t` from `perl/` — Expected: PASS. `make distcheck` — Expected: no "Not in MANIFEST"/"No such file" lines. `grep -rn 'dkim2-milter\.pl\|dkim2-split-lmtp\.pl' --exclude-dir=.git --exclude-dir=docs ..` — Expected: nothing.

- [ ] **Step 5: Commit.** `git commit -am "Install dkim2-milter and dkim2-split-lmtp from the dist"` (with the Co-Authored-By trailer).

### Task 2: Rewrite the Mailman `dkim2` branch into three commits

**Files:** `~/src/mailman` (fork checkout, branch `dkim2`, remote `brong`)

**Interfaces:**
- Produces: `dkim2` = 3 commits on `687b9e4dc`: (1) `bc803b46b` as is; (2) `9209d4a19` + `084f19a1a` squashed, subject "Add DKIM2 Message-Instance headers at ingress and egress"; (3) `25965b9d8` as is. Tag `dkim2-history-2026-10-02` on the old tip `084f19a1a`.

- [ ] **Step 1: Tag the history and record the content.**

```bash
cd ~/src/mailman && git checkout dkim2 && git tag dkim2-history-2026-10-02 && git diff 687b9e4dc dkim2 > /tmp/mailman-before.diff
```

- [ ] **Step 2: Rebase with a scripted todo.** Order `084f19a1a` before `25965b9d8` as a fixup of `9209d4a19`:

```bash
GIT_SEQUENCE_EDITOR='sh -c "printf \"pick bc803b46b\npick 9209d4a19\nfixup 084f19a1a\npick 25965b9d8\n\" > \"$1\"" --' git rebase -i 687b9e4dc
```

If the fixup conflicts (only `DKIM2-MESSAGE-INSTANCE.md` is shared with the flag commit, so none is expected), resolve by taking the combined text, `git add`, `git rebase --continue`. Then amend commit 2's message to describe the final `X-DKIM2-Info` form (fold the one sentence from `084f19a1a`'s message in): `git rebase -i` with `reword` is fine, or `git commit --amend` at that point.

- [ ] **Step 3: Verify content unchanged.** `git diff dkim2-history-2026-10-02 dkim2 | wc -c` — Expected: `0`. `git log --oneline 687b9e4dc..dkim2 | wc -l` — Expected: `3`.

- [ ] **Step 4: Push.** `git push brong dkim2-history-2026-10-02 && git push --force-with-lease brong dkim2`.

### Task 3: Rewrite the Sympa `dkim2` branch into three commits

**Files:** `~/src/sympa` (fork checkout, branch `dkim2`, remote `brong`)

**Interfaces:**
- Produces: `dkim2` = 3 commits on tag `6.2.78`: (1) "Preserve the body encoding when decorating" = `be57b5d53 9ad08ec27 6124b6f7b a711e094f`; (2) "Add DKIM2 Message-Instance header support" = `455e6dcc0 a9b5187fd 823152e00`; (3) "Add the X-DKIM2-Info debug header" = `2ccb5df11 1cac3cdf3 9a3dc8330 b4a30a977 dfd8807cb fabcc72cb 0d67f55fe 78d000ea2 61c6a91d0 be015cc15 f73472132`. Tag `dkim2-history-2026-10-02` on the old tip `f73472132`.

- [ ] **Step 1: Tag and record.** `cd ~/src/sympa && git checkout dkim2 && git tag dkim2-history-2026-10-02 && git diff 6.2.78 dkim2 > /tmp/sympa-before.diff`

- [ ] **Step 2: Rebase.** Target todo (encoding group first, then MI, then info):

```
pick be57b5d53
fixup 9ad08ec27
fixup 6124b6f7b
fixup a711e094f
pick 455e6dcc0
fixup a9b5187fd
fixup 823152e00
pick 2ccb5df11
fixup 1cac3cdf3
fixup 9a3dc8330
fixup b4a30a977
fixup dfd8807cb
fixup fabcc72cb
fixup 0d67f55fe
fixup 78d000ea2
fixup 61c6a91d0
fixup be015cc15
fixup f73472132
```

Write it to a file and run `GIT_SEQUENCE_EDITOR="cp /tmp/sympa-todo" git rebase -i 6.2.78`. Moving `a711e094f` (Message.pm) ahead of `455e6dcc0` (Message.pm) and `a9b5187fd`/`823152e00` ahead of the info commits will conflict in `Message.pm` and `t/Message_DKIM2.t`. Resolve each conflict toward the final content (`git show dkim2-history-2026-10-02:src/lib/Sympa/Message.pm` is the oracle for what the *last* commit must produce; intermediate states only need to compile: `perl -c -Isrc/lib src/lib/Sympa/Message.pm` with the stub libs under `t/stub` if needed). If a reorder cannot be resolved in reasonable time, fall back to keeping that commit in the group it chronologically follows and note the resulting group in the commit message; three or four commits are both acceptable, eighteen are not. After the rebase, `reword` the three subjects and write bodies that describe the whole group (the old messages are in `git log dkim2-history-2026-10-02`).

- [ ] **Step 3: Verify content unchanged.** `git diff dkim2-history-2026-10-02 dkim2 | wc -c` — Expected: `0`. `git log --oneline 6.2.78..dkim2 | wc -l` — Expected: `3` (or `4` with the fallback).

- [ ] **Step 4: Push.** `git push brong dkim2-history-2026-10-02 && git push --force-with-lease brong dkim2`.

### Task 4: Export script and the `mailman/` and `sympa/` series

**Files:**
- Create: `util/export-list-patches.sh`
- Create: `mailman/README.md`, `mailman/patches/0001-*.patch`..`0003-*.patch`
- Create: `sympa/README.md`, `sympa/patches/0001-*.patch`..`0003-*.patch`

**Interfaces:**
- Consumes: the rewritten branches from Tasks 2 and 3.
- Produces: `util/export-list-patches.sh [--check] [--mailman DIR] [--sympa DIR]`. Without `--check` it writes the patch files. With `--check` it applies each series with `git apply --check` to its base in a temporary worktree (and, for Mailman, to `v3.3.10`) and exits non-zero on failure, printing one `ok`/`FAIL` line per base.

- [ ] **Step 1: Write the script.**

```bash
#!/bin/bash
# Export the DKIM2 patch series for Mailman 3 and Sympa from their fork
# checkouts into mailman/patches and sympa/patches, or (--check) verify the
# exported series still apply to the bases the READMEs name.
#
#   util/export-list-patches.sh            # regenerate both series
#   util/export-list-patches.sh --check    # apply-check them, exit 1 on failure
#
# Fork checkouts default to ~/src/mailman and ~/src/sympa (branch dkim2).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
MAILMAN=${MAILMAN_DIR:-$HOME/src/mailman}
SYMPA=${SYMPA_DIR:-$HOME/src/sympa}
MAILMAN_BASE=687b9e4dc          # upstream master the fork is based on (v3.3.10+466)
MAILMAN_RELEASE=v3.3.10         # also try the latest release tag; README records the result
SYMPA_BASE=6.2.78
check=0
while [ $# -gt 0 ]; do
  case "$1" in
    --check) check=1 ;;
    --mailman) MAILMAN=$2; shift ;;
    --sympa) SYMPA=$2; shift ;;
    *) echo "usage: $0 [--check] [--mailman DIR] [--sympa DIR]" >&2; exit 2 ;;
  esac
  shift
done

export_series() {  # name checkout base
  local name=$1 dir=$2 base=$3 out="$ROOT/$name/patches"
  rm -rf "$out"; mkdir -p "$out"
  git -C "$dir" format-patch --no-signature --no-stat -o "$out" "$base..dkim2" >/dev/null
  # Strip the per-version trailer so a regeneration with the same content is a no-op.
  sed -i.bak -E '/^-- $/,$d' "$out"/*.patch && rm -f "$out"/*.bak
  echo "exported $(ls "$out" | wc -l | tr -d ' ') patches to $name/patches (base $base, $(git -C "$dir" rev-parse --short dkim2))"
}

check_series() {  # name checkout base
  # A disposable worktree at the base; `git am` applies the series for real,
  # which is the only honest check when patch 2 depends on patch 1.
  local name=$1 dir=$2 base=$3 wt rc=0
  wt=$(mktemp -d)
  git -C "$dir" worktree add -q --detach "$wt" "$base"
  if git -C "$wt" am -q "$ROOT/$name"/patches/*.patch 2>/tmp/apply-err; then
    echo "ok    $name series applies to $base"
  else
    echo "FAIL  $name series does not apply to $base:"; sed 's/^/      /' /tmp/apply-err
    git -C "$wt" am --abort 2>/dev/null || true
    rc=1
  fi
  git -C "$dir" worktree remove --force "$wt"
  return $rc
}

if [ $check -eq 0 ]; then
  export_series mailman "$MAILMAN" "$MAILMAN_BASE"
  export_series sympa   "$SYMPA"   "$SYMPA_BASE"
  exit 0
fi

fail=0
check_series mailman "$MAILMAN" "$MAILMAN_BASE" || fail=1
check_series mailman "$MAILMAN" "$MAILMAN_RELEASE" || echo "      (release-tag result is informational; the README states it)"
check_series sympa   "$SYMPA"   "$SYMPA_BASE"   || fail=1
exit $fail
```

- [ ] **Step 2: Run `--check` before exporting.** `chmod +x util/export-list-patches.sh && util/export-list-patches.sh --check` — Expected: FAIL (no patches directory yet).

- [ ] **Step 3: Export and check.** `util/export-list-patches.sh && util/export-list-patches.sh --check` — Expected: three `ok` lines for the two bases, and for `v3.3.10` either `ok` or `FAIL` with the conflicting file named. Record the `v3.3.10` outcome for the README.

- [ ] **Step 4: Write `mailman/README.md`.** Sections: what the patches add (one paragraph per patch: encoding-preserving decoration; the `message-instance-ingress`/`-egress` handlers, `MessageInstanceMixin`, `[mta] message_instance`, tests, `DKIM2-MESSAGE-INSTANCE.md`; the per-list `dkim2_message_instance` flag with its Alembic migration); base (`687b9e4dc`, upstream master after v3.3.10, and the measured `v3.3.10` result); install options in this order: `pip install git+https://github.com/brong/mailman@dkim2` into the Mailman venv, or `git am mailman/patches/*.patch` on a checkout then `pip install .`; after either, `mailman shell -r mailman.database.initialize:initialize` or `alembic upgrade head` for the new column, `message_instance: yes` and `max_recipients: 1` in `mailman.cfg` under `[mta]`, restart; pointer to the full guide; how the series is regenerated (`util/export-list-patches.sh`). Link to the fork's `DKIM2-MESSAGE-INSTANCE.md` for the design.

- [ ] **Step 5: Write `sympa/README.md`.** Same shape: the three patches; base `6.2.78` only; install: `git am sympa/patches/*.patch` on a 6.2.78 source tree and build as usual, or overlay the patched files onto an installed 6.2.78 (list them: `src/lib/Sympa/Message.pm`, `src/lib/Sympa/Spool/Outgoing.pm`, `src/lib/Sympa/Spindle/{ProcessIncoming,ProcessOutgoing,ResendArchive,ToList,ToMailer}.pm`); the runtime dependency on the Mail::DKIM2 Perl library (`Message.pm` requires `Mail::DKIM2::MessageInstance` and `::Common`); `sympa.conf`: `sendmail` pointing at the wrapper from `deploy/examples/sympa-sendmail`, `nrcpt 1`; restart `sympa sympa-bulk sympa-archived sympa-bounced`; pointer to the guide.

- [ ] **Step 6: Commit.** `git add util/export-list-patches.sh mailman sympa && git commit -m "Ship the Mailman and Sympa DKIM2 changes as patch series"`.

### Task 5: Operator templates in `deploy/examples/`, used by the box too

**Files:**
- Move: `deploy/dkim2-milter-inbound.service`, `deploy/dkim2-milter-outbound.service`, `deploy/dkim2-milter.service`, `deploy/dkim2-split.service` → `deploy/examples/`
- Create: `deploy/examples/postfix-main.cf.fragment`, `deploy/examples/postfix-master.cf.fragment`, `deploy/examples/authentication_milter.json.fragment`
- Move: `deploy/sympa-sendmail` → `deploy/examples/sympa-sendmail` (port from `DKIM2_SIGN_PORT` env, default 10587)
- Modify: `deploy/deploy.sh` (install units from examples, `daemon-reload`), `deploy/setup-dkim2-demo.sh:184`, `deploy/SERVER.md` (paths; the ProtectHome note is obsolete), `deploy/postfix-dkim2-split.master.cf` (keep; the fragment is the generic version of it)
- Test: `perl/t/examples.t` (create)

**Interfaces:**
- Produces: units whose `ExecStart` is `/usr/local/bin/dkim2-milter ...` and `/usr/local/bin/dkim2-split-lmtp`, `ProtectHome=yes`; fragments that reference each other's ports: 25 inbound, `127.0.0.1:10587` list submission (signing milter only), `127.0.0.1:10589`/`10590` for the split gateway variant.

- [ ] **Step 1: Write `perl/t/examples.t`.**

```perl
use strict; use warnings; use Test::More; use JSON;
my $ex = "$FindBin::Bin/../../deploy/examples"; use FindBin;
ok(-f "$ex/$_", "$_ exists") for qw(dkim2-milter-inbound.service dkim2-milter-outbound.service
    dkim2-milter.service dkim2-split.service postfix-main.cf.fragment postfix-master.cf.fragment
    authentication_milter.json.fragment sympa-sendmail);
for my $u (qw(dkim2-milter-inbound dkim2-milter-outbound dkim2-milter)) {
    my $t = do { local (@ARGV, $/) = "$ex/$u.service"; <> };
    like($t, qr{^ExecStart=/usr/local/bin/dkim2-milter\b}m, "$u runs the installed program");
    unlike($t, qr{/root/|/opt/dkim2|-I/}m, "$u names no checkout path");
    like($t, qr{^ProtectHome=yes}m, "$u can protect home");
}
my $json = do { local (@ARGV, $/) = "$ex/authentication_milter.json.fragment"; <> };
my $cfg = eval { decode_json("{$json}") };
ok($cfg, 'authentication_milter fragment is a valid JSON object body') or diag($@);
is($cfg->{DKIM2Sign}{sign_local}, 1, 'the sign handler signs mail from local listeners');
is($cfg->{DKIM2Sign}{snapshot_directory}, $cfg->{DKIM2Verify}{snapshot_directory},
   'both handlers share one snapshot directory');
my $master = do { local (@ARGV, $/) = "$ex/postfix-master.cf.fragment"; <> };
like($master, qr/^127\.0\.0\.1:10587 inet/m, 'master fragment defines the list submission listener');
like($master, qr/dkim2-milter-out\.sock/, '  ... with the signing milter');
is(system($^X, '-c', "$ex/sympa-sendmail") >> 8, 0, 'sympa-sendmail compiles');
done_testing;
```

- [ ] **Step 2: Run.** `cd perl && prove -l t/examples.t` — Expected: FAIL (files missing).

- [ ] **Step 3: Create the files.** `git mv` the four units and `sympa-sendmail` into `deploy/examples/`. Edit the three milter units: `ExecStart=/usr/local/bin/dkim2-milter \` with the same options as now (inbound: `--mode inbound --socket unix:/var/spool/postfix/var/run/dkim2-milter-in.sock --snapshot-dir /var/spool/dkim2/snapshots`; outbound: `--mode outbound --socket unix:/var/spool/postfix/var/run/dkim2-milter-out.sock --keydir /etc/dkim2/keys --snapshot-dir /var/spool/dkim2/snapshots`; combined `dkim2-milter.service`: `--socket unix:/var/spool/postfix/var/run/dkim2-milter.sock --keydir /etc/dkim2/keys --snapshot-dir /var/spool/dkim2/snapshots`), `ProtectHome=yes`, a `Documentation=https://github.com/dkim2wg/interop/blob/master/docs/dkim2-postfix-list-host-guide.md` line. In `sympa-sendmail` replace the literal `10587` with `my $port = $ENV{DKIM2_SIGN_PORT} // 10587;` and use `$port`; add a top comment naming the env var.

`postfix-main.cf.fragment`:

```
# DKIM2 for a mailing-list host: main.cf settings. See
# docs/dkim2-postfix-list-host-guide.md ("Postfix").

# Verify inbound mail and stamp a Message-Instance (inbound milter); sign
# anything Postfix generates itself, such as bounces (outbound milter).
smtpd_milters = unix:var/run/dkim2-milter-in.sock
non_smtpd_milters = unix:var/run/dkim2-milter-out.sock
milter_default_action = accept
milter_protocol = 6

# Run non_smtpd_milters on Postfix-generated bounces so they are signed.
internal_mail_filter_classes = bounce

# Never rewrite a signed body on the way out: an 8bit->7bit conversion after
# signing changes Content-Transfer-Encoding and breaks the header hash.
disable_mime_output_conversion = yes
```

`postfix-master.cf.fragment`: the list submission listener, and (commented, as the alternative) the split gateway pair:

```
# DKIM2 for a mailing-list host: master.cf listeners. See
# docs/dkim2-postfix-list-host-guide.md ("Postfix").
#
# 1. List submission. Mailman's smtp_port and Sympa's sendmail wrapper deliver
#    here. Only the signing milter runs; the inbound milter must not, or the
#    list's own copy would get an Authentication-Results and a second
#    Message-Instance before it is signed. Loopback only.
127.0.0.1:10587 inet n  -       y       -       -       smtpd
  -o syslog_name=postfix/dkim2-list
  -o smtpd_milters=unix:var/run/dkim2-milter-out.sock
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o smtpd_relay_restrictions=permit_mynetworks,reject
  -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks

# 2. Split gateway (only if software you cannot set to one recipient per
#    transaction submits here). Replace listener 1 with these two:
#
# 127.0.0.1:10587 inet n  -       y       -       -       smtpd
#   -o syslog_name=postfix/dkim2-split-in
#   -o content_filter=lmtp:[127.0.0.1]:10590
#   -o smtpd_milters=
#   -o smtpd_client_restrictions=permit_mynetworks,reject
#   -o smtpd_relay_restrictions=permit_mynetworks,reject
#   -o receive_override_options=no_unknown_recipient_checks,no_address_mappings,no_header_body_checks
# 127.0.0.1:10589 inet n  -       n       -       -       smtpd
#   -o syslog_name=postfix/dkim2-sign-out
#   -o content_filter=
#   -o smtpd_milters=unix:var/run/dkim2-milter-out.sock
#   -o smtpd_relay_restrictions=permit_mynetworks,reject
#   -o receive_override_options=no_unknown_recipient_checks,no_address_mappings,no_header_body_checks
```

`authentication_milter.json.fragment` (a JSON object *body*, to paste into the `"handlers"` object of `authentication_milter.json`):

```
"DKIM2Verify" : {
    "hide_none"              : 0,
    "add_message_instance"   : 1,
    "snapshot_directory"     : "/var/spool/dkim2/snapshots",
    "ignore_header_prefixes" : []
},
"DKIM2Sign" : {
    "domains" : {
        "lists.example.org" : { "selector" : "sel1", "keyfile" : "/etc/dkim2/keys/lists.example.org/sel1.key" }
    },
    "sign_authenticated"     : 1,
    "sign_local"             : 1,
    "add_message_instance"   : 1,
    "record_smtp_params"     : 1,
    "snapshot_directory"     : "/var/spool/dkim2/snapshots",
    "ignore_header_prefixes" : []
}
```

In `deploy/deploy.sh` after the `make install` block add:

```bash
# systemd units are the generic ones every operator gets.
install -m 644 "$REPO"/deploy/examples/dkim2-milter-inbound.service \
               "$REPO"/deploy/examples/dkim2-milter-outbound.service \
               "$REPO"/deploy/examples/dkim2-split.service /etc/systemd/system/
systemctl daemon-reload
```

Update `deploy/setup-dkim2-demo.sh:184` to copy `deploy/examples/dkim2-milter.service`. In `SERVER.md` update the unit paths and delete the sentence about `ProtectHome=no` on the server.

- [ ] **Step 4: Run.** `prove -l t/examples.t` — PASS. `grep -rn 'deploy/dkim2-milter.*service\|deploy/sympa-sendmail\|deploy/dkim2-split.service' --exclude-dir=.git .` — Expected: only `deploy/examples/` paths.

- [ ] **Step 5: Commit.** `git commit -m "Operator templates in deploy/examples, and the box installs them"`.

### Task 6: The guide, and the links to it

**Files:**
- Create: `docs/dkim2-postfix-list-host-guide.md`
- Modify: `docs/dkim2-operator-guide.md` ("Milter integration" section → pointer; add "Installing" pointer at top)
- Modify: `deploy/README.md` (first paragraph), `perl/README` (SEE ALSO), `perl/lib/Mail/DKIM2.pm` (SEE ALSO), `deploy/www/index.html` ("Learn more" list)
- Test: `perl/t/guide-links.t` (create)

**Interfaces:**
- Consumes: everything above: program names, unit names, fragment paths, `mailman/README.md`, `sympa/README.md`.

- [ ] **Step 1: Write `perl/t/guide-links.t`.** It keeps the guide honest about the repository: every relative path in a backtick that looks like a repo path must exist.

```perl
use strict; use warnings; use Test::More; use FindBin;
my $root = "$FindBin::Bin/../..";
my $guide = "$root/docs/dkim2-postfix-list-host-guide.md";
ok(-f $guide, 'the guide exists') or BAIL_OUT('no guide');
my $text = do { local (@ARGV, $/) = $guide; <> };
my %seen;
for my $path ($text =~ /`((?:perl|deploy|mailman|sympa|util|docs)\/[A-Za-z0-9_.\/-]+)`/g) {
    next if $seen{$path}++;
    ok(-e "$root/$path", "guide path $path exists in the repo");
}
like($text, qr/^## .*Mailman/m, 'has a Mailman section');
like($text, qr/^## .*Sympa/m,   'has a Sympa section');
like($text, qr/max_recipients: 1/, 'tells Mailman to deliver one recipient per transaction');
like($text, qr/\bnrcpt 1\b/,     'tells Sympa the same');
like($text, qr/disable_mime_output_conversion = yes/, 'warns about transport conversion');
like($text, qr/pmilter-null-sender-envfrom\.patch/, 'covers the PMilter null-sender patch');
unlike($text, qr{/root/interop|/opt/dkim2}, 'no dkim2.com box paths');
my $index = do { local (@ARGV, $/) = "$root/deploy/www/index.html"; <> };
like($index, qr{docs/dkim2-postfix-list-host-guide\.md}, 'dkim2.com links to the guide');
done_testing;
```

- [ ] **Step 2: Run.** `prove -l t/guide-links.t` — Expected: BAIL_OUT, no guide.

- [ ] **Step 3: Write the guide.** Follow the spec's eleven sections exactly, in order, with these specifics:

  1. *What you get.* Mermaid or ASCII diagram of: port 25 → inbound milter (verify, A-R, `m=1`, snapshot) → Postfix → list manager (LMTP in; changes; `m=2` + Recipe) → `127.0.0.1:10587` → outbound milter (sign `i=N`) → delivery. One paragraph on what a `pass` does and does not mean (lift from the operator guide).
  2. *Prerequisites.* Debian 12/Ubuntu 22.04+, Postfix 3.x with milter support, Perl 5.20+, `cpanminus`, root, DNS control. Mailman 3.3.10+ venv or Sympa 6.2.78.
  3. *Keys and DNS.* Link to the operator guide's "Generating keys"; show the keydir layout `/etc/dkim2/keys/<domain>/<selector>.key` (mode 0640, group the milter runs as) and one `openssl` + TXT example for Ed25519.
  4. *Install Mail::DKIM2.* `apt-get install build-essential libssl-dev cpanminus`; `git clone https://github.com/dkim2wg/interop && cd interop/perl && cpanm --installdeps . && cpanm Sendmail::PMilter && cpanm .` (note `cpanm --installdeps` does not install recommends; list them). First check: `dkim2verify --help`; sign+verify round trip with `dkim2sign`/`dkim2verify --dns-json` on a test message? No: show `dkim2verify < any-signed-mail.eml` instead.
  5. *Milter.* 5a: `useradd -r dkim2`, `/var/spool/dkim2/snapshots` owned by it, `cp deploy/examples/dkim2-milter-*.service /etc/systemd/system/`, the two sockets inside the Postfix chroot, `systemctl enable --now`, then the PMilter patch: what breaks without it (null sender hang, 30 s timeout, bounces unsigned), `patch` command against `$(perldoc -l Sendmail::PMilter::Context)`, how to tell (`deploy/smoke-null-sender-milter.pl`). 5b: `cpanm Mail::Milter::Authentication`, the fragment, `authentication_milter.json` handlers list order (`DKIM2Verify` before any handler that adds headers; `DKIM2Sign` last), the single socket both directions use, and that `sign_local` is what makes list mail on `127.0.0.1:10587` get signed.
  6. *Postfix.* Apply the two fragments; explain each setting in one sentence; then "Recipient privacy": why one recipient per transaction, `max_recipients: 1` / `nrcpt 1`, and the split-gateway alternative with `dkim2-split.service`.
  7. *Mailman 3.* From `mailman/README.md`, expanded: venv install, migration, `mailman.cfg` block, REST per-list flag example, `/var/log/mailman3/` and the `mi-cache` dir.
  8. *Sympa.* From `sympa/README.md`, expanded: 6.2.78 only, patch or overlay, `sympa.conf` block (`sendmail /usr/local/bin/sympa-sendmail`, `nrcpt 1`), `install -m 755 deploy/examples/sympa-sendmail /usr/local/bin/`, restart list.
  9. *Check it works.* Post to a list, `grep -i '^X-DKIM2-Info\|^Message-Instance\|^DKIM2-Signature\|^Authentication-Results'` on a received copy; `dkim2verify received.eml` → `pass (i=1..2 verified)`; https://dkim2.com/validate/; send to `reflector@dkim2.com` to get the chain verified by another implementation.
  10. *Operations.* Rotation (new selector, DNS, 14 days), `find /var/spool/dkim2/snapshots -mtime +7 -delete` cron, logs (`journalctl -u dkim2-milter-outbound`), troubleshooting table: symptom → cause → fix for `Delivered-To`, CTE conversion, `temperror`, timestamp, `m=N is not signed`, Mailman `mi-cache` orphans.
  11. *Not covered.* One paragraph.

  Header: title, "Spec: draft-ietf-dkim-dkim2-spec-06", "Status: tested on the dkim2.com host (Debian, Postfix 3.7, Mailman 3.3.10+, Sympa 6.2.78)", date. Keep sentences short; one command per fenced block.

- [ ] **Step 4: Links.** In `docs/dkim2-operator-guide.md` replace the "Milter integration" section body with two sentences pointing at the guide and listing the two milters; add after the title block: `**Installing it:** see the [Postfix mailing-list host guide](dkim2-postfix-list-host-guide.md).` In `deploy/README.md` insert as the first paragraph: "This describes the dkim2.com demonstration box. To run DKIM2 on your own Postfix list host, follow [the guide](../docs/dkim2-postfix-list-host-guide.md)." In `perl/README` SEE ALSO and `Mail/DKIM2.pm` SEE ALSO add the guide URL `https://github.com/dkim2wg/interop/blob/master/docs/dkim2-postfix-list-host-guide.md`. In `deploy/www/index.html` add to the "Learn more" list, before the IETF item: `<li><a href="https://github.com/dkim2wg/interop/blob/master/docs/dkim2-postfix-list-host-guide.md">Run your own DKIM2 list host</a> — install guide for Postfix with Mailman 3 or Sympa</li>` matching the existing item markup.

- [ ] **Step 5: Run.** `prove -l t/guide-links.t t/pod.t` — PASS; `podchecker lib/Mail/DKIM2.pm` clean.

- [ ] **Step 6: Commit.** `git commit -m "Guide: DKIM2 for a Postfix mailing-list host"`.

### Task 7: Deploy, acceptance, memory

- [ ] **Step 1:** `cd perl && prove -l -j8 t && make distcheck` — PASS, clean. `git push origin master` (after merging the working branch locally per repo convention).
- [ ] **Step 2:** `ssh dkim2 'cd /root/interop && git pull --ff-only && deploy/deploy.sh'` — Expected: tests pass, units installed, `smoke test: pass`, null-sender smoke ok, `config drift` may now report the unit files: refresh the snapshot with `deploy/capture-server-config.sh` if it tracks units, else note.
- [ ] **Step 3:** `ssh dkim2 'systemctl status dkim2-milter-inbound dkim2-milter-outbound dkim2-split --no-pager | grep -E "Active|ExecStart"; /usr/local/bin/dkim2-milter --help | head -3; ls /usr/local/bin | grep dkim2'` — Expected: three `active (running)`, ExecStart from `/usr/local/bin`, usage printed, no `*.pl` left.
- [ ] **Step 4:** `ssh dkim2 'cd /root/interop && deploy/dkim2-list-smoke.sh'` — PASS for all six lines.
- [ ] **Step 5:** Validator good/bad check as in the previous deploy (fresh `Reflector::generate` message → `pass`; tampered → `fail`).
- [ ] **Step 6:** Memory: update `project_mailman_sympa_deploy_from_branch.md` (branches rewritten 2026-10-02; history tags; patches exported by `util/export-list-patches.sh`; Sympa base 6.2.78 only), `project_mail_dkim2_api_0_10.md` (dist split dropped for good; milter installed; guide path), and `project_pmilter_null_sender.md` (now documented for operators in the guide).
