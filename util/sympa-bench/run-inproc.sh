#!/bin/bash
# Run the in-process benchmark (bench_inproc.pl) for every build, one at a
# time, each in its own memory-capped scope.  Runs on the box.
#
#   bash run-inproc.sh --quick       # ~10 minutes: see QUICK below
#   nohup bash run-inproc.sh > /opt/sympa-bench/results/run-inproc.out 2>&1 &
#   WAIT=0 OUT=/opt/sympa-bench/results/smoke \
#     BENCH_ARGS='--limit 5 --configs f-mime,m1000' bash run-inproc.sh
#
# Before each build it waits until no Sympa or Mailman test suite has been
# running for WAIT minutes (WAIT_BETWEEN after the first build), so a test
# run on the same box can't skew the numbers.  bench_inproc.pl forks a child
# per case, so a timeout or an OOM kill inside the 700M cap costs one case,
# not the build (OOMPolicy=continue keeps systemd from stopping the whole
# scope on the first kill); it always runs with --resume, so re-running this script
# continues where a killed run stopped (delete OUT/inproc-*.jsonl to start
# over).  Writes OUT/inproc-BUILD.jsonl, OUT/log-BUILD.txt, and touches
# OUT/INPROC-DONE at the end.
#
# --quick: up, cte and wrap only (cte-nomod and wrap-off add nothing here:
# Sympa's util/off-identical.sh already shows switch-off output is
# byte-identical to stock), 8 signed messages, 3 configs, 3 runs per case,
# cte capped at 60 s per case, no 1000-member run above 2 MB.  Waits only
# while a test suite is running.  Writes to OUT=$B/results/quick.
# Overrides: B, OUT, MEMMAX, WAIT, WAIT_BETWEEN, BUILDS, BENCH_ARGS,
# CTE_ARGS (extra options for cte only).
set -uo pipefail
B=${B:-/opt/sympa-bench}
QUICK_IDS=syn-plain-2k,syn-outlook,syn-b64-text-100k,syn-attach-1mb-b76,syn-attach-1mb-b72,syn-attach-10mb-b76,syn-qp-100k,syn-latin1
if [ "${1:-}" = --quick ]; then
  OUT=${OUT:-$B/results/quick}
  WAIT=${WAIT:-1}; WAIT_BETWEEN=${WAIT_BETWEEN:-1}
  BUILDS=${BUILDS:-up cte wrap}
  BENCH_ARGS=${BENCH_ARGS:---signed signed --repeat 3 --ids $QUICK_IDS --configs f-mime,pers-footer,m1000 --heavy-max-size 2000000}
  CTE_ARGS=${CTE_ARGS:---timeout 60 --budget 50}
fi
OUT=${OUT:-$B/results}
MEMMAX=${MEMMAX:-700M}
WAIT=${WAIT:-15}
WAIT_BETWEEN=${WAIT_BETWEEN:-1}
BUILDS=${BUILDS:-up cte cte-nomod wrap wrap-off}
BENCH_ARGS=${BENCH_ARGS:-}
CTE_ARGS=${CTE_ARGS:-}
mkdir -p $OUT

wait_quiet() { # minutes
  local quiet=0
  while [ $quiet -lt $1 ]; do
    if pgrep -f '(^|/)prove |nose2|test-venv' >/dev/null; then quiet=0; else quiet=$((quiet+1)); fi
    [ $quiet -ge $1 ] && break
    [ $quiet -lt $1 ] && sleep 60
  done
}

args() { # build -> lib dir and options
  local L="--dkim2lib $B/dkim2lib"
  case $1 in
    up)        echo "$B/up/lib" ;;
    cte)       echo "$B/cte/lib $L" ;;
    cte-nomod) echo "$B/cte/lib" ;;
    wrap)      echo "$B/wrap/lib $L --switch on" ;;
    wrap-off)  echo "$B/wrap/lib $L --switch off" ;;
    *) echo "unknown build $1" >&2; return 1 ;;
  esac
}

rm -f $OUT/INPROC-DONE
w=$WAIT
for id in $BUILDS; do
  a=$(args $id) || continue
  extra=; [ "${id#cte}" != "$id" ] && extra=$CTE_ARGS
  wait_quiet $w; w=$WAIT_BETWEEN
  echo "== $(date -Is) $id ($a)"
  systemd-run --scope -q -p MemoryMax=$MEMMAX -p MemorySwapMax=0 -p OOMPolicy=continue \
    perl $B/bench_inproc.pl $id $a --out $OUT --resume $BENCH_ARGS \
      $extra \
    >> $OUT/log-$id.txt 2>&1 \
    || echo "$id: exit $? (see $OUT/log-$id.txt)" | tee -a $OUT/failures.txt
  echo "== $(date -Is) $id done: $(wc -l < $OUT/inproc-$id.jsonl) records"
done
touch $OUT/INPROC-DONE
