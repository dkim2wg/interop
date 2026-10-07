#!/bin/bash
# Run the in-process benchmark for every build, one at a time, memory-capped.
# bench_inproc.py writes the id it is working on to .current; if the process
# dies, that id gets a row saying how (oom / timeout / crash) and the run
# resumes after it.  OOM = non-zero exit and a new "Memory cgroup out of
# memory" line in dmesg (the killed process may exit 137 or 143); if dmesg
# is unreadable, exit 137 alone.  124 = the 600 s backstop timeout below.
set -uo pipefail
B=/opt/mailman/bench; OUT=$B/results; mkdir -p $OUT
oom_events() { dmesg 2>/dev/null | grep -c 'Memory cgroup out of memory' || true; }
run() { # build venv dkim2
  for s in unsigned signed; do
    cur=$OUT/inproc-$1-$s.current
    rm -f $cur
    resume=
    while :; do
      rc=0; ev0=$(oom_events)
      systemd-run --scope -q -p MemoryMax=700M -p MemorySwapMax=0 \
        timeout -s KILL 600 \
        $B/$2/venv/bin/python $B/bench_inproc.py --build $1 --dkim2 $3 \
          --corpus $B/corpus --signed $s --out $OUT $resume || rc=$?
      [ $rc -eq 0 ] && break
      rm -rf /tmp/mmbench-*     # the killed process cannot clean up
      [ -s $cur ] || { echo "$1 $s: failed rc=$rc before any message" >> $OUT/failures.txt; break; }
      IFS=$'\t' read -r id size cls filt < $cur
      rm -f $cur
      common=$(printf '"build":"%s","dkim2":"%s","signed":"%s","id":"%s","size":%s,"cls":"%s","filter":%s' \
        "$1" "$3" "$s" "$id" "$size" "$cls" "$filt")
      oom=0; [ "$(oom_events)" -gt "$ev0" ] && oom=1
      [ $rc -eq 137 ] && [ -z "$(dmesg 2>/dev/null | head -1)" ] && oom=1
      [ $rc -eq 124 ] && oom=0
      [ $oom -eq 1 ] && rc=137
      case $rc in
        137) echo "{$common,\"oom\":true}" >> $OUT/inproc-$1-$s.jsonl
             echo "$1 $s: OOM on $id" >> $OUT/failures.txt ;;
        124) echo "{$common,\"oom\":false,\"timeout\":true,\"timeout_s\":600,\"stage\":\"backstop\"}" >> $OUT/inproc-$1-$s.jsonl
             echo "$1 $s: backstop timeout on $id" >> $OUT/failures.txt ;;
        *)   echo "{$common,\"oom\":false,\"crash\":true,\"rc\":$rc}" >> $OUT/inproc-$1-$s.jsonl
             echo "$1 $s: crash rc=$rc on $id" >> $OUT/failures.txt ;;
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
