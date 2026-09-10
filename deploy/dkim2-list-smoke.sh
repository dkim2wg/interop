#!/bin/bash
#
# DKIM2 list smoke test — inject a message through the Mailman and Sympa DKIM2
# test lists, capture the outbound (list-modified + milter-signed) copy locally,
# and confirm it (a) advertises the current spec draft (Mail::DKIM2::Common's
# DKIM2_DRAFT, currently ietf-dkim-dkim2-spec-06) in its X-DKIM2-Info header,
# and (b) verifies.
#
# Two rounds, because the outbound signer takes a different path for each:
#
#   1. UNSIGNED upstream: a plain message. The inbound milter stamps m=1, the
#      list records its changes as m=2, the outbound milter has no upstream
#      chain to check and originates i=1 over m=2.
#   2. SIGNED upstream: the same message first signed as dkim2.com/sel1 (m=1 +
#      i=1), as a post from a DKIM2-signing sender arrives. The list records
#      m=2 UNSIGNED and hands it over; the outbound milter must verify i=1,
#      accept the list's unsigned m=2 as the instance it is about to sign, and
#      add i=2. Round 1 alone passed for weeks while this path was broken (the
#      milter's pre-sign verify treated the list's m=2 as spec-06 §11's "is not
#      signed" PERMERROR and refused; 2026-09-10, the first day Fastmail signed).
#      The captured copy must therefore verify with i=1..2.
#
# Run ON the demo server (mail.dkim2.com):
#   deploy/dkim2-list-smoke.sh
#
# Infra it relies on (set up once — see SERVER.md "DKIM2 list smoke test"):
#   - dkim2capture@dkim2.com  -> /var/spool/dkim2-capture/Maildir/  (local, byte-exact)
#   - dkim2test@mailman.dkim2.com  (DKIM2 list, sole member dkim2capture@)
#   - a Sympa DKIM2 list with sole/added member dkim2capture@ (default: test@sympa.dkim2.com)
#   - /etc/dkim2/reflector/sel1.key, the dkim2.com/sel1 private key (root-readable)
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
SIGN_KEY=/etc/dkim2/reflector/sel1.key
MAILMAN_LIST=${1:-dkim2test@mailman.dkim2.com}
SYMPA_LIST=${2:-dkim2test@sympa.dkim2.com}

export LIB
rc=0
rm -f "$CAP"/* 2>/dev/null
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Round 1: unsigned upstream.
for L in "$MAILMAN_LIST" "$SYMPA_LIST"; do
  echo ">> injecting unsigned to $L (from $FROM)"
  swaks --server 127.0.0.1:25 --from "$FROM" --to "$L" \
        --h-Subject "DKIM2 smoke $(hostname)" \
        --body "DKIM2 list smoke test." >/dev/null 2>&1 \
    || { echo "   FAIL: injection rejected"; rc=1; }
done

# Round 2: DKIM2-signed upstream (m=1 + i=1 as dkim2.com/sel1), delivered over
# raw SMTP so the signed bytes reach port 25 exactly as signed. swaks is not
# used here because it rewrites the message it is given.
for L in "$MAILMAN_LIST" "$SYMPA_LIST"; do
  echo ">> injecting DKIM2-signed to $L (from $FROM, d=dkim2.com s=sel1)"
  src="$work/signed-src.eml"; signed="$work/signed.eml"
  printf 'From: %s\r\nTo: %s\r\nSubject: DKIM2 smoke signed %s\r\nDate: %s\r\nMessage-ID: <smoke-signed-%s-%s@dkim2.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nDKIM2 list smoke test, signed upstream.\r\n' \
    "$FROM" "$L" "$(hostname)" "$(date -R)" "$(date +%s)" "$$" > "$src"
  if ! perl -I"$LIB" "$REPO/perl/bin/dkim2sign.pl" -s sel1 -d dkim2.com -k "$SIGN_KEY" \
        --mailfrom "<$FROM>" --rcptto "<$L>" "$src" > "$signed"; then
    echo "   FAIL: could not sign the injected message"; rc=1; continue
  fi
  perl -MNet::SMTP -e '
    my ($from, $to, $file) = @ARGV;
    my $raw = do { local $/; open my $h, "<", $file or die $!; binmode $h; <$h> };
    my $s = Net::SMTP->new("127.0.0.1", Port => 25, Timeout => 30) or die "connect: $!";
    $s->mail($from) && $s->to($to) && $s->data($raw) && $s->quit or die "smtp: " . $s->message;
  ' "$FROM" "$L" "$signed" >/dev/null 2>&1 \
    || { echo "   FAIL: signed injection rejected"; rc=1; }
done

echo ">> waiting for list pipelines + outbound milter ..."
sleep 18

n_plain=0; n_signed=0
for f in "$CAP"/*; do
  [ -e "$f" ] || continue
  if grep -q '^Subject:.*DKIM2 smoke signed' "$f"; then
    n_signed=$((n_signed+1)); want='i=1\.\.2'    # list's m=2 signed as i=2 above our i=1
  else
    n_plain=$((n_plain+1));  want='i=1\.\.1'     # originated by the outbound milter
  fi
  perl -e '
    use lib $ENV{LIB}; use Mail::DKIM2::Verifier; use Mail::DKIM2::Common qw(DKIM2_DRAFT);
    my ($file, $want) = @ARGV;
    my $raw = do { local $/; open my $h,"<",$file or die $!; <$h> };  # scoped $/
    $raw =~ s/\r\n/\n/g; $raw =~ s/\n/\r\n/g;                           # normalise to CRLF
    my ($subj) = $raw =~ /^Subject:\s*(.*)/mi;
    # Derived from the library'"'"'s own DKIM2_DRAFT constant (not hardcoded) so
    # this check never goes stale on the next spec-version bump.
    my $draft = DKIM2_DRAFT;
    my $has_draft = $raw =~ /\Qdraft=$draft\E/ ? "yes" : "NO";
    my $v = Mail::DKIM2::Verifier->new; $v->skip_timestamp_check(1);
    $v->PRINT($raw); $v->CLOSE;
    my $detail = $v->result_detail // "";
    my $chain_ok = $detail =~ /$want/ ? "yes" : "NO";
    my $ok = ($v->result eq "pass" && $has_draft eq "yes" && $chain_ok eq "yes");
    printf "   %s  [draft=%s:%s verify=%s chain(%s):%s]  %s\n",
        ($ok?"PASS":"FAIL"), $draft, $has_draft, $detail, $want, $chain_ok, ($subj//"");
    exit($ok?0:1);
  ' "$f" "$want" || rc=1
done
[ "$n_plain"  -ge 2 ] || { echo "   FAIL: expected >=2 captured unsigned-upstream copies, got $n_plain"; rc=1; }
[ "$n_signed" -ge 2 ] || { echo "   FAIL: expected >=2 captured signed-upstream copies, got $n_signed"; rc=1; }

echo ">> dkim2-list-smoke: $([ $rc -eq 0 ] && echo PASS || echo FAIL)"
exit $rc
