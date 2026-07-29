#!/bin/bash
#
# Authoritative deploy for the DKIM2 Perl library + milters + reflector +
# validator on the demo server (mail.dkim2.com). This is the live
# signing/verification path; the C/Go/Python trees are reference code and are
# NOT deployed here.
#
# Run ON the server:
#   ssh dkim2 'cd /root/interop && git pull --ff-only && deploy/deploy.sh'
#
# Why this script exists: deploys used to be ad-hoc "git pull && make &&
# make install" steps. That left stale artifacts (e.g. a CLI rebuilt with
# `make test` only — which does NOT build the CLIs — or blib/ retaining a
# removed module). This script guarantees:
#   1. a CLEAN rebuild (make clean) so nothing stale survives,
#   2. a hard test gate (make test must pass BEFORE install),
#   3. a post-deploy SMOKE TEST that signs + verifies against live DNS, so a
#      stale or broken deploy fails loudly instead of silently serving bad code.
#
# Mailman and Sympa deploy separately by rsync from your local checkout (they
# are not git-pulled here) — see SERVER.md "Updating Code on the Server".

set -euo pipefail

REPO=/root/interop
cd "$REPO"
echo ">> interop HEAD: $(git rev-parse --short HEAD) on $(git rev-parse --abbrev-ref HEAD)"

# 1. Perl library: clean rebuild + mandatory test gate, then install.
cd "$REPO/perl"
echo ">> clean rebuild of Mail::DKIM2 ..."
make clean >/dev/null 2>&1 || true
perl Makefile.PL >/dev/null
make >/dev/null
echo ">> Mail::DKIM2 test suite (deploy gate; aborts on failure) ..."
make test
make install >/dev/null

# 2. Binaries that embed the library (reflector wrapper + validator CGI) plus
#    the delayed-bounce demo's failing delivery agent.
install -m 755 bin/dkim2-reflector.pl        /usr/local/bin/dkim2-reflect
install -m 755 bin/dkim2-delayedbounce-fail.pl /usr/local/bin/dkim2-delayedbounce-fail
install -m 755 bin/dkim2-split-lmtp.pl       /usr/local/bin/dkim2-split-lmtp
install -m 755 bin/validate.cgi              /usr/local/bin/dkim2-validate.cgi

# 2b. Static web assets: apex landing page + the validator UI + the standalone
#     browser verifier. Kept here so a change to validate.js/.css/.html can't
#     be left stale relative to the Mail::DKIM2::Validate report shape it
#     renders. The browser verifier (deploy/www/verify/) is pure static
#     files (HTML/CSS/JS, no CGI/backend) — same install-and-copy treatment,
#     just no fastcgi wiring.
if [ -d /var/www/dkim2.com ]; then
    install -m 644 "$REPO/deploy/www/index.html" "$REPO/deploy/www/style.css" /var/www/dkim2.com/
    install -d -m 755 /var/www/dkim2.com/validate
    install -m 644 "$REPO"/deploy/www/validate/* /var/www/dkim2.com/validate/
    # Cache-bust the validator assets: stamp __VER__ with the current commit so
    # browsers always fetch fresh JS/CSS after a deploy (no stale-asset confusion).
    VER=$(git -C "$REPO" rev-parse --short HEAD)
    sed -i "s/__VER__/$VER/g" /var/www/dkim2.com/validate/index.html
    install -d -m 755 /var/www/dkim2.com/verify
    install -m 644 "$REPO"/deploy/www/verify/*.html "$REPO"/deploy/www/verify/*.css \
        "$REPO"/deploy/www/verify/*.js /var/www/dkim2.com/verify/
fi

# 3. Postfix reflector transport map (idempotent: picks up new addresses).
install -m 644 "$REPO/deploy/postfix-dkim2-transport" /etc/postfix/dkim2-transport
postmap /etc/postfix/dkim2-transport
# 3b. Delayed-bounce demo map (idempotent). Its main.cf transport_maps/
#     local_recipient_maps hookup and the dkim2-delayedbounce master.cf pipe
#     service are one-time manual steps (see SERVER.md); this just keeps the
#     installed map in sync with the repo.
install -m 644 "$REPO/deploy/postfix-dkim2-delayedbounce" /etc/postfix/dkim2-delayedbounce
postmap /etc/postfix/dkim2-delayedbounce
postfix reload

# 3c. Patch the (effectively unmaintained) Sendmail::PMilter for the null-sender
#     hang: its SMFIC_MAIL handler skips the envfrom hook and sends NO reply when
#     the sender arg list is empty (MAIL FROM:<>), so Postfix blocks until
#     milter_command_timeout and internally-generated bounces ship unsigned.
#     Idempotent: re-applies after a CPAN reinstall, skips if already patched.
PMILTER_CTX=$(perl -MSendmail::PMilter::Context -e 'print $INC{"Sendmail/PMilter/Context.pm"}' 2>/dev/null)
if [ -n "$PMILTER_CTX" ]; then
    if grep -q 'null sender MAIL FROM' "$PMILTER_CTX"; then
        echo ">> Sendmail::PMilter null-sender patch already applied"
    else
        patch --forward --backup "$PMILTER_CTX" < "$REPO/deploy/patches/pmilter-null-sender-envfrom.patch"
        echo ">> applied Sendmail::PMilter null-sender patch to $PMILTER_CTX"
    fi
else
    echo ">> WARNING: Sendmail::PMilter::Context not found; skipping null-sender patch" >&2
fi

# 4. Restart the long-running milters so they load the freshly-installed lib
#    (and the patched Sendmail::PMilter above).
#    (The reflector wrapper and validator CGI run per-invocation, so they pick
#    up the new lib without a restart — but the milters are daemons.)
systemctl restart dkim2-milter-inbound dkim2-milter-outbound
# The Bcc-safe split daemon is also long-running; restart it if installed (it
# uses the freshly-installed Mail::DKIM2::Split). try-restart is a no-op if the
# service isn't set up on this host.
systemctl try-restart dkim2-split 2>/dev/null || true

# 5. POST-DEPLOY SMOKE TEST. Sign a fresh message as dkim2.com/sel1 with the
#    freshly-installed library and verify it against LIVE DNS. This exercises
#    the real installed code path end to end; if anything is stale or broken
#    the deploy fails here instead of silently serving bad signatures.
echo ">> smoke test: sign + verify round-trip against live DNS ..."
perl -e '
  use strict; use warnings;
  use Mail::DKIM2::Reflector;   # from the just-installed site_perl
  use Mail::DKIM2::Verifier;
  my $msg = Mail::DKIM2::Reflector::generate(
      sender  => q{smoke@dkim2.com}, domain => q{dkim2.com}, selector => q{sel1},
      keyfile => q{/etc/dkim2/reflector/sel1.key});
  my $v = Mail::DKIM2::Verifier->new; $v->skip_timestamp_check(1);
  $v->PRINT($msg); $v->CLOSE;
  die "SMOKE TEST FAILED: verify = " . $v->result . " (" . ($v->result_detail // q{}) . ")\n"
      unless $v->result eq q{pass};
  print "   smoke test: pass (" . $v->result_detail . ")\n";
'

# 7. NULL-SENDER SMOKE TEST. Confirm the outbound milter answers a MAIL FROM:<>
#    envelope instead of hanging (regression guard for the Sendmail::PMilter
#    null-sender bug patched in step 3c). Fails in ~8s if the patch is missing.
echo ">> smoke test: null-sender MAIL FROM:<> through the outbound milter ..."
perl "$REPO/deploy/smoke-null-sender-milter.pl" /var/spool/postfix/var/run/dkim2-milter-out.sock

# 8. CONFIG DRIFT CHECK. Report where the server's live nginx/Mailman/Sympa/
#    Postfix config has diverged from the tracked snapshot in deploy/config/.
#    Deliberately a WARNING, not a gate: a stale snapshot needs to be visible on
#    every deploy (that is how it rotted unnoticed for months before it was
#    tracked at all), but it must never block shipping a signing fix.
echo ">> config drift check (deploy/config/) ..."
bash "$REPO/deploy/check-server-config.sh" || \
    echo "   WARNING: config drift above — refresh with deploy/capture-server-config.sh"

echo ">> deploy complete and verified."
