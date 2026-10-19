#!/bin/bash
# Cross-implementation verify benchmark: every verifier, in-process, over the
# same messages, keys from dns.json (no DNS), timestamp checks off, planned
# walk and undo walk, best of N runs. Verdict counts are printed so a harness
# that silently verified nothing shows up.
#
#   util/xbench.sh [impl ...]      impls: c go perl python js (default: all)
#
# Message sets:
#   corpus  the charset corpus captures (corpus/results/capture, if present)
#           plus perl/tests/expected -- small real list mail, 2-3 instances
#   big-N   a three-hop chain (originator; a list that tags the Subject and
#           wraps the body with a footer part; a relay re-sign) with an N MB
#           body, made by util/xbench/genbig.pl with the test keys
#
# XB_REPS (default 3) runs per set; XB_SIZES (default "1 10") the big sizes.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
B=$ROOT/util/xbench
W=${XB_WORK:-${TMPDIR:-/tmp}/dkim2-xbench}
REPS=${XB_REPS:-3}
SIZES=${XB_SIZES:-"1 10"}
IMPLS=${*:-c go perl python js}
mkdir -p "$W/big"
PY=$ROOT/python/venv/bin/python; [ -x "$PY" ] || PY=python3

# Keys: dns.json, plus the live keys the corpus was signed with.
python3 - "$ROOT" "$W/dns.json" <<'PYEOF'
import json, os, sys
root, out = sys.argv[1], sys.argv[2]
keys = json.load(open(os.path.join(root, 'dns.json')))
live = os.path.join(root, 'corpus/results/dns-live.json')
if os.path.exists(live):
    for d, v in json.load(open(live)).items():
        keys.setdefault(d, {}).update(v)
json.dump(keys, open(out, 'w'))
PYEOF

ls "$ROOT"/corpus/results/capture/*.eml "$ROOT"/perl/tests/expected/*.eml 2>/dev/null > "$W/corpus.list" || true
SETS=corpus
for s in $SIZES; do
    f=$(printf '%s/big/big-%05.1fMB.eml' "$W" "$s")
    [ -f "$f" ] || perl "$B/genbig.pl" "$W/big" "$s"
    echo "$f" > "$W/big-$s.list"
    SETS="$SETS big-$s"
done

if [[ " $IMPLS " == *" c "* ]]; then
    (cd "$ROOT/c" && cc -std=c11 -D_DEFAULT_SOURCE -O2 -I. \
        $(pkg-config --cflags openssl) \
        $(PKG_CONFIG_PATH=/opt/homebrew/lib/pkgconfig pkg-config --cflags libcjson) \
        -o "$W/cbench" "$B/cbench.c" eml_parse.c \
        $(sed -n '/^CORE_SRCS *=/,/[^\\]$/p' Makefile | sed 's/^CORE_SRCS *=//; s/\\//g') \
        $(pkg-config --libs openssl) \
        $(PKG_CONFIG_PATH=/opt/homebrew/lib/pkgconfig pkg-config --libs libcjson) \
        -lresolv -pthread)
fi

run() {   # impl list
    case $1 in
        c)      "$W/cbench" "$2" "$W/dns.json" "$REPS" ;;
        go)     (cd "$ROOT/go" && XB_LIST=$2 XB_DNS=$W/dns.json XB_REPS=$REPS \
                    go test ./dkim2 -run '^TestXBench$' -count=1 -v | grep '^go ') ;;
        perl)   perl "$B/perl.pl" "$2" "$W/dns.json" "$REPS" ;;
        python) "$PY" "$B/python.py" "$2" "$W/dns.json" "$REPS" ;;
        js)     node "$B/js.mjs" "$2" "$W/dns.json" "$REPS" ;;
    esac
}

for set in $SETS; do
    [ -s "$W/$set.list" ] || continue
    echo "## $set ($(wc -l < "$W/$set.list" | tr -d ' ') messages; seconds, best of $REPS)"
    for impl in $IMPLS; do run "$impl" "$W/$set.list"; done
done
