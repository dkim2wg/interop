#!/bin/bash
#
# Charset corpus run: how do our DKIM2 tools cope with real-world mail in
# charsets and encodings the hand-written fixtures never use?
#
#   ./util/charset-corpus.sh [-n PER_SOURCE] [--only src,src] [--stage S]...
#
# Stages (default: all three, in order):
#
#   fetch   util/charset-corpus-sample.py downloads public archives that still
#           serve FULL raw messages (Apache ponymail mbox API, a HyperKitty
#           export, the SpamAssassin public corpus) and keeps a sample spread
#           across every charset/CTE combination each one contains.
#           -> corpus/sample/*.eml (CRLF), corpus/sample/index.tsv
#
#   matrix  Every sample signed by every signer (python, go, c, perl), every
#           output verified by every verifier (those four + browser JS). This
#           is util/hash-matrix.sh's shape on real bytes: iso-2022-jp 7bit,
#           gb18030 base64, 8-bit headers, charset=3Dbig5, 1000-char lines.
#           -> corpus/results/matrix.tsv, matrix-summary.txt, fail/<id>/
#
#   lists   The sample replayed on the demo box through the Mailman and Sympa
#           *corpus* lists (deploy/dkim2-corpus-inject.sh: signed upstream as
#           dkim2.com/sel1, list records m=2, outbound milter adds i=2), the
#           captured copies pulled back and verified by all five verifiers.
#           The chain must be i=1..2 -- i.e. each list's m=2 recipe must
#           rebuild the signed m=1 byte-for-byte. A sample with no capture at
#           all means the list held, dropped or mangled it; that's reported
#           too, since Mailman's and Sympa's charset handling is as much under
#           test as ours.
#           -> corpus/results/capture/, lists.tsv, lists-summary.txt
#
#   captures  Re-verify the captures already pulled back by `lists` (after a
#           verifier fix) without touching the box. Implied by `lists`.
#
# Nothing under corpus/ is committed (see .gitignore). The upstream archives
# are the source of truth; the sampler is deterministic over them, so a
# failing message is named by its id and can be re-fetched. Promote a message
# to a fixture only after its failure is understood.
#
# Needs: the four native tools built (make), node, and for `lists` ssh access
# to the box as `dkim2` plus `dig` for the live dkim2.com key records.
#
set -u
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root" || exit 1
. "$root/util/lib-sign.sh"

CACHE=corpus                      # repo-relative: lib-sign.sh's Perl branch needs it so
HOST=${CORPUS_HOST:-dkim2}
PER=15
ONLY=
STAGES=
while [ $# -gt 0 ]; do
  case $1 in
    -n) PER=$2; shift 2 ;;
    --only) ONLY=$2; shift 2 ;;
    --stage) STAGES="$STAGES $2"; shift 2 ;;
    -h|--help) sed -n '2,/^set -u/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$STAGES" ] || STAGES="fetch matrix lists"

RES=$CACHE/results
mkdir -p "$RES"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rc=0

has_stage() { case " $STAGES " in *" $1 "*) return 0 ;; esac; return 1; }

# ---------------------------------------------------------------- fetch -----
if has_stage fetch; then
  echo "== fetch: sampling $PER per source${ONLY:+ ($ONLY)}"
  python3 util/charset-corpus-sample.py -n "$PER" --cache "$CACHE" ${ONLY:+--only "$ONLY"} || rc=1
fi
[ -f "$CACHE/sample/index.tsv" ] || { echo "no sample at $CACHE/sample -- run the fetch stage"; exit 1; }

# --------------------------------------------------------------- matrix -----
if has_stage matrix; then
  echo "== matrix: $(ls "$CACHE"/sample/*.eml | wc -l | tr -d ' ') samples x ($SIGNERS) signers x ($VERIFIERS) verifiers"
  rm -rf "$RES/fail"; mkdir -p "$RES/fail"
  printf 'id\tsigner\tverifier\tresult\n' > "$RES/matrix.tsv"
  for f in "$CACHE"/sample/*.eml; do
    id=$(basename "$f" .eml)
    line="$id"
    for signer in $SIGNERS; do
      out="$tmp/$id.$signer.eml"
      if ! SRC=$f sign "$signer" sha256 "$out"; then
        printf '%s\t%s\t-\tSIGNFAIL\n' "$id" "$signer" >> "$RES/matrix.tsv"
        mkdir -p "$RES/fail/$id"; cp "$tmp/err" "$RES/fail/$id/$signer.sign.err"
        line="$line $signer:SIGNFAIL"
        continue
      fi
      bad=
      for verifier in $VERIFIERS; do
        if verify "$verifier" "$out" > "$tmp/v.log" 2>&1; then
          printf '%s\t%s\t%s\tok\n' "$id" "$signer" "$verifier" >> "$RES/matrix.tsv"
        else
          printf '%s\t%s\t%s\tFAIL\n' "$id" "$signer" "$verifier" >> "$RES/matrix.tsv"
          mkdir -p "$RES/fail/$id"; cp "$out" "$RES/fail/$id/$signer.eml"
          cp "$tmp/v.log" "$RES/fail/$id/$signer.$verifier.log"
          bad="$bad$verifier,"
        fi
      done
      [ -n "$bad" ] && line="$line $signer->${bad%,}"
    done
    [ "$line" = "$id" ] && echo "   ok   $id" || { echo "   FAIL $line"; rc=1; }
  done
  python3 - "$CACHE/sample/index.tsv" "$RES/matrix.tsv" <<'PY' | tee "$RES/matrix-summary.txt"
import csv, sys
from collections import defaultdict
idx = {r['id']: r for r in csv.DictReader(open(sys.argv[1]), delimiter='\t')}
rows = list(csv.DictReader(open(sys.argv[2]), delimiter='\t'))
by = defaultdict(lambda: {'n': set(), 'bad': defaultdict(set)})
for r in rows:
    k = (idx[r['id']]['charset'], idx[r['id']]['cte'])
    by[k]['n'].add(r['id'])
    if r['result'] != 'ok':
        by[k]['bad'][f"{r['signer']}->{r['verifier']}" if r['verifier'] != '-' else f"{r['signer']} sign"].add(r['id'])
print(f"\n== matrix summary: {len(idx)} samples, {sum(1 for r in rows if r['result']!='ok')} failing cells of {len(rows)}")
print(f"{'charset':<22}{'cte':<18}{'n':>3}  failures (cell: samples)")
for (cs, cte), v in sorted(by.items()):
    bad = '; '.join(f"{cell}: {len(ids)}" for cell, ids in sorted(v['bad'].items()))
    print(f"{cs:<22}{cte:<18}{len(v['n']):>3}  {bad or '-'}")
PY
fi

# ---------------------------------------------------------------- lists -----
if has_stage lists; then
  echo "== lists: replaying through dkim2corpus@{mailman,sympa}.dkim2.com on $HOST"
  remote=/root/dkim2-corpus
  ssh "$HOST" "mkdir -p $remote" || { echo "ssh $HOST failed"; exit 1; }
  rsync -a --delete "$CACHE/sample/" "$HOST:$remote/sample/" || { echo "rsync to $HOST failed"; exit 1; }
  scp -q deploy/dkim2-corpus-inject.sh "$HOST:$remote/inject.sh"
  ssh "$HOST" "bash $remote/inject.sh $remote/sample $remote/capture" || rc=1
  rm -rf "$RES/capture"; mkdir -p "$RES/capture"
  rsync -a "$HOST:$remote/capture/" "$RES/capture/" || { echo "rsync from $HOST failed"; exit 1; }
  STAGES="$STAGES captures"
fi

# -------------------------------------------------------------- captures ----
if has_stage captures; then
  [ -f "$RES/capture/inject.log" ] || { echo "no captures at $RES/capture -- run the lists stage"; exit 1; }
  echo "== captures: verifying $(ls "$RES"/capture/*.eml 2>/dev/null | wc -l | tr -d ' ') captured copies"

  # The outbound milter and our upstream signature both use live dkim2.com
  # keys, which the repo's dns.json (interop test domains only) lacks. Build a
  # merged copy from live DNS for the four verifiers that take a dns.json; the
  # Perl check below uses Net::DNS directly, as the smoke test does.
  python3 - dns.json "$RES/dns-live.json" <<'PY'
import json, subprocess, sys
d = json.load(open(sys.argv[1]))
live = {}
for sel in ("sel1", "sel2", "sel3", "ed25519", "rsa1024", "dkim2test"):
    out = subprocess.run(["dig", "+short", "TXT", f"{sel}._domainkey.dkim2.com"],
                         capture_output=True, text=True).stdout
    txt = "".join(part for line in out.splitlines() for part in line.split('" "')).replace('"', '')
    if txt.startswith("v=DKIM1"):
        live[f"{sel}._domainkey"] = [["txt", txt]]
if not live:
    sys.exit("no live dkim2.com key records from dig; cannot verify captures")
d["dkim2.com"] = live
json.dump(d, open(sys.argv[2], "w"), indent=1)
print(f"   live dkim2.com selectors: {' '.join(s.split('.')[0] for s in live)}")
PY
  export DNS_JSON="$root/$RES/dns-live.json"

  printf 'id\tlist\tcopy\tperl\tchain\tpython\tgo\tc\tjs\n' > "$RES/lists.tsv"
  for f in "$RES"/capture/*.eml; do
    [ -e "$f" ] || continue
    base=$(basename "$f" .eml)
    id=${base%.*.*}; rest=${base#"$id".}; list=${rest%.*}; copy=${rest#*.}
    # Local delivery rewrote CRLF to LF; the milter signed CRLF.
    crlf="$tmp/$base.eml"
    perl -pe 's/\r?\n/\r\n/' "$f" > "$crlf"
    # Perl: live DNS, and the chain detail we assert on.
    read -r presult pchain < <(perl -e '
      use lib "perl/lib"; use Mail::DKIM2::Verifier;
      my $raw = do { local $/; open my $h, "<", $ARGV[0] or die $!; binmode $h; <$h> };
      my $v = Mail::DKIM2::Verifier->new; $v->skip_timestamp_check(1);
      $v->PRINT($raw); $v->CLOSE;
      my $d = $v->result_detail // ""; my ($chain) = $d =~ /(i=\d+\.\.\d+)/;
      print $v->result, " ", ($chain // "-"), "\n";' "$crlf" 2>/dev/null || echo "error -")
    cells=
    for verifier in python go c js; do
      if verify "$verifier" "$crlf" > "$tmp/v.log" 2>&1; then cells="$cells\tok"; else
        cells="$cells\tFAIL"; mkdir -p "$RES/fail/$id"; cp "$crlf" "$RES/fail/$id/capture.$list.$copy.eml"
        cp "$tmp/v.log" "$RES/fail/$id/capture.$list.$copy.$verifier.log"
      fi
    done
    printf "%s\t%s\t%s\t%s\t%s$cells\n" "$id" "$list" "$copy" "$presult" "$pchain" >> "$RES/lists.tsv"
    if [ "$presult" = pass ] && [ "$pchain" = "i=1..2" ] && [[ $cells != *FAIL* ]]; then
      echo "   ok   $id $list#$copy"
    else
      echo "   FAIL $id $list#$copy perl=$presult chain=$pchain$(printf "$cells" | tr '\t' ' ')"
      [ "$presult" = pass ] || { mkdir -p "$RES/fail/$id"; cp "$crlf" "$RES/fail/$id/capture.$list.$copy.eml"; }
      rc=1
    fi
  done
  python3 - "$CACHE/sample/index.tsv" "$RES/lists.tsv" "$RES/capture/inject.log" <<'PY' | tee "$RES/lists-summary.txt"
import csv, sys
from collections import defaultdict
idx = {r['id']: r for r in csv.DictReader(open(sys.argv[1]), delimiter='\t')}
rows = list(csv.DictReader(open(sys.argv[2]), delimiter='\t'))
inject = [l.rstrip('\n').split('\t') for l in open(sys.argv[3])]
sent = defaultdict(set)
for l in inject:
    if l[0] == 'SENT':
        sent[l[1]].add('mailman' if 'mailman' in l[2] else 'sympa')
got = defaultdict(lambda: defaultdict(list))
for r in rows:
    ok = r['perl'] == 'pass' and r['chain'] == 'i=1..2' and all(r[v] == 'ok' for v in ('python', 'go', 'c', 'js'))
    got[r['id']][r['list']].append(ok)
by = defaultdict(lambda: defaultdict(int))
print(f"\n== lists summary: {len(idx)} samples, {len(rows)} captured copies")
print(f"{'charset':<22}{'cte':<18}{'n':>3}  {'mailman':<14}{'sympa':<14} (ok / fail / missing)")
for sid, meta in sorted(idx.items()):
    k = (meta['charset'], meta['cte'])
    by[k]['n'] += 1
    for lst in ('mailman', 'sympa'):
        res = got[sid].get(lst, [])
        if lst not in sent[sid]:
            by[k][lst + '_notsent'] += 1
        elif not res:
            by[k][lst + '_missing'] += 1
        elif all(res):
            by[k][lst + '_ok'] += 1
        else:
            by[k][lst + '_fail'] += 1
for (cs, cte), v in sorted(by.items()):
    def cell(l):
        s = f"{v[l+'_ok']}/{v[l+'_fail']}/{v[l+'_missing']}"
        return s + (f"+{v[l+'_notsent']}unsent" if v[l+'_notsent'] else '')
    print(f"{cs:<22}{cte:<18}{v['n']:>3}  {cell('mailman'):<14}{cell('sympa'):<14}")
bad = [l for l in inject if l[0] != 'SENT']
if bad:
    print(f"\n{len(bad)} injection problems (see capture/inject.log):")
    for l in bad[:20]:
        print('  ' + ' '.join(l))
PY
fi

echo "== charset-corpus: $([ $rc -eq 0 ] && echo PASS || echo FAIL) (results in $RES)"
exit $rc
