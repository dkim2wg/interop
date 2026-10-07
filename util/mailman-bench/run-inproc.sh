#!/bin/bash
# Run the in-process benchmark for every build, one at a time, memory-capped.
# Each attempt is a transient systemd service, so systemd says why it ended
# (Result: success | oom-kill | timeout | exit-code | signal ...), scoped to
# that unit.  bench_inproc.py writes the id it is working on to .current; if
# an attempt fails, that id gets a row (oom / timeout / crash), the leaked temp
# dir is removed and the run resumes after it.
# Overrides for testing: B, MEMMAX, RUNTIME (backstop seconds), BENCH_ARGS.
set -uo pipefail
B=${B:-/opt/mailman/bench}; OUT=$B/results; mkdir -p $OUT
MEMMAX=${MEMMAX:-700M}; RUNTIME=${RUNTIME:-600}; BENCH_ARGS=${BENCH_ARGS:-}
n=0
run() { # build venv dkim2
  for s in unsigned signed; do
    cur=$OUT/inproc-$1-$s.current
    rm -f $cur
    resume=
    while :; do
      n=$((n+1)); unit=mmbench-$1-$s-$$-$n
      rc=0
      systemd-run --wait --quiet --unit=$unit \
        -p MemoryMax=$MEMMAX -p MemorySwapMax=0 -p RuntimeMaxSec=$RUNTIME \
        -p WorkingDirectory=$B \
        -p StandardOutput=append:$OUT/log-$1-$s.txt \
        -p StandardError=append:$OUT/log-$1-$s.txt \
        $B/$2/venv/bin/python $B/bench_inproc.py --build $1 --dkim2 $3 \
          --corpus $B/corpus --signed $s --out $OUT $BENCH_ARGS $resume || rc=$?
      result=$(systemctl show -p Result --value $unit 2>/dev/null)
      [ $rc -eq 0 ] && [ "${result:-success}" = success ] && { systemctl reset-failed $unit 2>/dev/null; break; }
      rc=$(systemctl show -p ExecMainStatus --value $unit 2>/dev/null || echo $rc)
      systemctl reset-failed $unit 2>/dev/null || true
      rm -rf /tmp/mmbench-*     # the killed process cannot clean up
      [ -s $cur ] || { echo "$1 $s: failed result=$result rc=$rc before any message" >> $OUT/failures.txt; break; }
      IFS=$'\t' read -r id size cls filt < $cur
      rm -f $cur
      common=$(printf '"build":"%s","dkim2":"%s","signed":"%s","id":"%s","size":%s,"cls":"%s","filter":%s' \
        "$1" "$3" "$s" "$id" "$size" "$cls" "$filt")
      # A kill can leave a partial last line; start on a fresh one.
      [ -s $OUT/inproc-$1-$s.jsonl ] && [ -n "$(tail -c1 $OUT/inproc-$1-$s.jsonl)" ] && echo >> $OUT/inproc-$1-$s.jsonl
      case $result in
        oom-kill) echo "{$common,\"oom\":true}" >> $OUT/inproc-$1-$s.jsonl
             echo "$1 $s: OOM on $id" >> $OUT/failures.txt ;;
        timeout) echo "{$common,\"oom\":false,\"timeout\":true,\"timeout_s\":$RUNTIME,\"stage\":\"backstop\"}" >> $OUT/inproc-$1-$s.jsonl
             echo "$1 $s: backstop timeout on $id" >> $OUT/failures.txt ;;
        *)   echo "{$common,\"oom\":false,\"crash\":true,\"result\":\"$result\",\"rc\":${rc:-0}}" >> $OUT/inproc-$1-$s.jsonl
             echo "$1 $s: crash result=$result rc=$rc on $id" >> $OUT/failures.txt ;;
      esac
      resume=--resume
    done
  done
}
run up       up   na
run cte      cte  on
run cte-off  cte  off
run wrap     wrap on
run wrap-off wrap off
