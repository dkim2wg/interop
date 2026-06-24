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
cd "$REPO/brong"
echo ">> clean rebuild of Mail::DKIM2 ..."
make clean >/dev/null 2>&1 || true
perl Makefile.PL >/dev/null
make >/dev/null
echo ">> Mail::DKIM2 test suite (deploy gate; aborts on failure) ..."
make test
make install >/dev/null

# 2. Binaries that embed the library (reflector wrapper + validator CGI).
install -m 755 bin/dkim2-reflector.pl /usr/local/bin/dkim2-reflect
install -m 755 bin/validate.cgi       /usr/local/bin/dkim2-validate.cgi

# 3. Postfix reflector transport map (idempotent: picks up new addresses).
install -m 644 "$REPO/deploy/postfix-dkim2-transport" /etc/postfix/dkim2-transport
postmap /etc/postfix/dkim2-transport
postfix reload

# 4. Restart the long-running milters so they load the freshly-installed lib.
#    (The reflector wrapper and validator CGI run per-invocation, so they pick
#    up the new lib without a restart — but the milters are daemons.)
systemctl restart dkim2-milter-inbound dkim2-milter-outbound

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

echo ">> deploy complete and verified."
