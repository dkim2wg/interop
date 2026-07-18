#!/bin/bash
#
# DKIM2 list smoke test — inject a message through the Mailman and Sympa DKIM2
# test lists, capture the outbound (list-modified + milter-signed) copy locally,
# and confirm it (a) advertises draft-ietf-dkim-dkim2-spec-04 and (b) verifies.
#
# Run ON the demo server (mail.dkim2.com):
#   deploy/dkim2-list-smoke.sh
#
# Infra it relies on (set up once — see SERVER.md "DKIM2 list smoke test"):
#   - dkim2capture@dkim2.com  -> /var/spool/dkim2-capture/Maildir/  (local, byte-exact)
#   - dkim2test@mailman.dkim2.com  (DKIM2 list, sole member dkim2capture@)
#   - a Sympa DKIM2 list with sole/added member dkim2capture@ (default: test@sympa.dkim2.com)
#
# Two capture caveats baked into the verify step below (both are artifacts of
# reading mail back out of a local mailbox, NOT signature problems):
#   1. Scope `local $/` around the slurp — a leaked undef $/ breaks Net::DNS
#      key lookups inside the verifier (see project_milter_signed_mail_verify).
#   2. Local MDA delivery rewrites CRLF -> LF; the milter signed CRLF, so
#      normalise back to CRLF before verifying (else a body-hash mismatch).

set -u
REPO=/root/interop
LIB=$REPO/perl/lib
CAP=/var/spool/dkim2-capture/Maildir/new
FROM=dkim2capture@dkim2.com
MAILMAN_LIST=${1:-dkim2test@mailman.dkim2.com}
SYMPA_LIST=${2:-dkim2test@sympa.dkim2.com}

export LIB
rc=0
rm -f "$CAP"/* 2>/dev/null

for L in "$MAILMAN_LIST" "$SYMPA_LIST"; do
  echo ">> injecting to $L (from $FROM)"
  swaks --server 127.0.0.1:25 --from "$FROM" --to "$L" \
        --h-Subject "DKIM2 -04 smoke $(hostname)" \
        --body "DKIM2 draft-04 list smoke test." >/dev/null 2>&1 \
    || { echo "   FAIL: injection rejected"; rc=1; }
done

echo ">> waiting for list pipelines + outbound milter ..."
sleep 18

n=0
for f in "$CAP"/*; do
  [ -e "$f" ] || continue
  n=$((n+1))
  perl -e '
    use lib $ENV{LIB}; use Mail::DKIM2::Verifier;
    my $raw = do { local $/; open my $h,"<",$ARGV[0] or die $!; <$h> };  # scoped $/
    $raw =~ s/\r\n/\n/g; $raw =~ s/\n/\r\n/g;                            # normalise to CRLF
    my ($subj) = $raw =~ /^Subject:\s*(.*)/mi;
    my $has04 = $raw =~ /draft=ietf-dkim-dkim2-spec-04/ ? "yes" : "NO";
    my $v = Mail::DKIM2::Verifier->new; $v->skip_timestamp_check(1);
    $v->PRINT($raw); $v->CLOSE;
    my $ok = ($v->result eq "pass" && $has04 eq "yes");
    printf "   %s  [-04=%s verify=%s]  %s\n", ($ok?"PASS":"FAIL"), $has04, $v->result, ($subj//"");
    exit($ok?0:1);
  ' "$f" || rc=1
done
[ "$n" -ge 2 ] || { echo "   FAIL: expected >=2 captured messages, got $n"; rc=1; }

echo ">> dkim2-list-smoke: $([ $rc -eq 0 ] && echo PASS || echo FAIL)"
exit $rc
