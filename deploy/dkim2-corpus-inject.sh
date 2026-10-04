#!/bin/bash
#
# Replay a directory of raw messages through the Mailman and Sympa DKIM2
# *corpus* lists and collect what they emit. The on-box half of
# util/charset-corpus.sh; run it there, or by hand:
#
#   deploy/dkim2-corpus-inject.sh <sample-dir> <capture-out-dir>
#
# Each sample is signed as dkim2.com/sel1 first (m=1 + i=1), as a post from a
# DKIM2-signing sender arrives, so the list's m=2 recipe can be checked
# cryptographically: the verifier must rebuild m=1 from m=2 and find the i=1
# signature intact. An unsigned upstream would only test self-consistency
# between the inbound milter's hashes and the list's recipe.
#
# The one header added is `X-DKIM2-Corpus: <sample id>` at the top, so the
# captured copies can be matched back to their sample without trusting
# Message-ID (spam often has none, or a duplicate). It is signed over, like
# any other header, and Mailman/Sympa leave it alone.
#
# Lists: dkim2corpus@mailman.dkim2.com and dkim2corpus@sympa.dkim2.com, both
# created 2026-10-04 (see SERVER.md "DKIM2 charset corpus lists"): open posting,
# no implicit-destination / recipient-count / size holds, NO archive, and
# subscription closed. Their only members are the local capture addresses.
# Corpus mail is other people's real mail plus 2003 spam, so before injecting
# anything this script re-reads both rosters and refuses to run if any member
# is not a dkim2capture@ address -- a list with an outside subscriber would
# forward the whole corpus to them.
#
# Capture caveats are the smoke test's (deploy/dkim2-list-smoke.sh): Maildir
# not mbox, and local delivery turns CRLF into LF, so the collector restores
# CRLF before verifying.

set -u
SAMPLES=${1:?usage: $0 <sample-dir> <capture-out-dir>}
OUT=${2:?usage: $0 <sample-dir> <capture-out-dir>}

REPO=/root/interop
LIB=$REPO/perl/lib
CAP=/var/spool/dkim2-capture/Maildir/new
FROM=dkim2capture@dkim2.com
SIGN_KEY=/etc/dkim2/reflector/sel1.key
MAILMAN_LIST=dkim2corpus@mailman.dkim2.com
SYMPA_LIST=dkim2corpus@sympa.dkim2.com
REST=http://localhost:8001/3.1
RESTAUTH=restadmin:dkim2demo

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# --- Guardrail: both rosters must be capture addresses only -------------------
echo ">> checking list rosters"
mm_members=$(curl -s -u "$RESTAUTH" "$REST/lists/${MAILMAN_LIST/@/.}/roster/member" \
  | python3 -c 'import json,sys; print("\n".join(e["email"] for e in json.load(sys.stdin).get("entries",[])))')
# `sympa review` prints a "N member(s) in list x@y." banner first; keep only
# lines that are a bare address.
sy_members=$(sudo -u sympa sympa review "$SYMPA_LIST" 2>/dev/null | grep -E '^[^[:space:]]+@[^[:space:]]+$')
for who in "mailman:$mm_members" "sympa:$sy_members"; do
  tag=${who%%:*}; list=${who#*:}
  [ -n "$list" ] || { echo "   ABORT: $tag roster is empty or unreadable"; exit 2; }
  bad=$(printf '%s\n' "$list" | grep -v '^dkim2capture@' || true)
  if [ -n "$bad" ]; then
    echo "   ABORT: $tag list has a non-capture member:"; printf '      %s\n' $bad
    echo "   Remove them before replaying a corpus through it."
    exit 2
  fi
  printf '   %-8s %s\n' "$tag" "$(printf '%s' "$list" | tr '\n' ' ')"
done

# --- Inject -------------------------------------------------------------------
mkdir -p "$OUT"
rm -f "$OUT"/* "$CAP"/* 2>/dev/null
log=$OUT/inject.log
: > "$log"
n=0; nsign=0; nsmtp=0
for f in "$SAMPLES"/*.eml; do
  [ -e "$f" ] || continue
  id=$(basename "$f" .eml)
  n=$((n+1))
  src="$work/src.eml"
  { printf 'X-DKIM2-Corpus: %s\r\n' "$id"; cat "$f"; } > "$src"
  for L in "$MAILMAN_LIST" "$SYMPA_LIST"; do
    signed="$work/signed.eml"
    if ! perl -I"$LIB" "$REPO/perl/bin/dkim2sign" -s sel1 -d dkim2.com -k "$SIGN_KEY" \
          --mailfrom "<$FROM>" --rcptto "<$L>" "$src" > "$signed" 2> "$work/sign.err"; then
      nsign=$((nsign+1))
      printf 'SIGNFAIL\t%s\t%s\t%s\n' "$id" "$L" "$(tr '\n' ' ' < "$work/sign.err" | cut -c1-300)" >> "$log"
      continue
    fi
    if perl -MNet::SMTP -e '
        my ($from, $to, $file) = @ARGV;
        my $raw = do { local $/; open my $h, "<", $file or die $!; binmode $h; <$h> };
        my $s = Net::SMTP->new("127.0.0.1", Port => 25, Timeout => 60) or die "connect: $!";
        $s->mail($from) && $s->to($to) && $s->data($raw) && $s->quit
          or die "smtp: " . ($s->code // "?") . " " . ($s->message // "");
      ' "$FROM" "$L" "$signed" 2> "$work/smtp.err"; then
      printf 'SENT\t%s\t%s\n' "$id" "$L" >> "$log"
    else
      nsmtp=$((nsmtp+1))
      printf 'SMTPFAIL\t%s\t%s\t%s\n' "$id" "$L" "$(tr '\n' ' ' < "$work/smtp.err" | cut -c1-300)" >> "$log"
    fi
  done
done
echo ">> injected $n samples x 2 lists: $nsign sign failures, $nsmtp SMTP rejections"

# --- Wait for the pipelines to drain ------------------------------------------
# Done when the capture count has not changed for `quiet` seconds, capped.
quiet=20; maxwait=600; waited=0; last=-1; still=0
while [ $waited -lt $maxwait ]; do
  cur=$(ls "$CAP" 2>/dev/null | wc -l)
  if [ "$cur" -eq "$last" ]; then still=$((still+5)); else still=0; last=$cur; fi
  [ $still -ge $quiet ] && break
  sleep 5; waited=$((waited+5))
done
echo ">> captured $last copies after ${waited}s"

# --- Collect ------------------------------------------------------------------
# Name each copy by its sample id and list so the collector needn't parse much:
#   <id>.<mailman|sympa>.<n>.eml
python3 - "$CAP" "$OUT" <<'PY'
import os, re, sys
cap, out = sys.argv[1], sys.argv[2]
seen = {}
for name in sorted(os.listdir(cap)):
    data = open(os.path.join(cap, name), 'rb').read()
    hdr = data.split(b'\n\n', 1)[0]
    m = re.search(rb'^X-DKIM2-Corpus:\s*(\S+)', hdr, re.M | re.I)
    sid = m.group(1).decode() if m else 'unmatched'
    m = re.search(rb'^List-Id:.*?<([^>]+)>', hdr, re.M | re.I | re.S)
    lid = m.group(1).decode() if m else ''
    which = 'mailman' if 'mailman' in lid else 'sympa' if 'sympa' in lid else 'unknown'
    k = (sid, which); seen[k] = seen.get(k, 0) + 1
    open(os.path.join(out, f'{sid}.{which}.{seen[k]}.eml'), 'wb').write(data)
print(f'>> wrote {sum(seen.values())} captures to {out}')
PY
[ $nsign -eq 0 ] && [ $nsmtp -eq 0 ]
