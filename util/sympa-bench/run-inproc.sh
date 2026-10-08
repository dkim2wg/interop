#!/bin/bash
# Run the in-process benchmark (bench_inproc.pl) for every build, one at a
# time, each in its own memory-capped scope.  Runs on the box.
#
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
# Overrides: B, OUT, MEMMAX, WAIT, WAIT_BETWEEN, BUILDS, BENCH_ARGS.
set -uo pipefail
B=${B:-/opt/sympa-bench}
OUT=${OUT:-$B/results}
MEMMAX=${MEMMAX:-700M}
WAIT=${WAIT:-15}
WAIT_BETWEEN=${WAIT_BETWEEN:-1}
BUILDS=${BUILDS:-up cte cte-nomod wrap wrap-off}
BENCH_ARGS=${BENCH_ARGS:-}
mkdir -p $OUT

wait_quiet() { # minutes
  local quiet=0
  while [ $quiet -lt $1 ]; do
    if pgrep -f '(^|/)prove |nose2|test-venv' >/dev/null; then quiet=0; else quiet=$((quiet+1)); fi
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
  wait_quiet $w; w=$WAIT_BETWEEN
  echo "== $(date -Is) $id ($a)"
  systemd-run --scope -q -p MemoryMax=$MEMMAX -p MemorySwapMax=0 -p OOMPolicy=continue \
    perl $B/bench_inproc.pl $id $a --out $OUT --resume $BENCH_ARGS \
    >> $OUT/log-$id.txt 2>&1 \
    || echo "$id: exit $? (see $OUT/log-$id.txt)" | tee -a $OUT/failures.txt
  echo "== $(date -Is) $id done: $(wc -l < $OUT/inproc-$id.jsonl) records"
done
touch $OUT/INPROC-DONE
