#!/bin/bash
# Run the in-process benchmark for every build, one at a time, memory-capped.
set -euo pipefail
B=/opt/mailman/bench; OUT=$B/results; mkdir -p $OUT
run() { # build venv dkim2
  for s in unsigned signed; do
    resume=
    while ! systemd-run --scope -q -p MemoryMax=700M -p MemorySwapMax=0 \
        $B/$2/venv/bin/python $B/bench_inproc.py --build $1 --dkim2 $3 \
          --corpus $B/corpus --signed $s --out $OUT $resume; do
      cur=$OUT/inproc-$1-$s.current
      [ -s $cur ] || { echo "$1 $s: failed, not an OOM" >> $OUT/failures.txt; break; }
      IFS=$'\t' read -r id size cls filt < $cur
      printf '{"build":"%s","dkim2":"%s","signed":"%s","id":"%s","size":%s,"cls":"%s","filter":%s,"oom":true}\n' \
        "$1" "$3" "$s" "$id" "$size" "$cls" "$filt" >> $OUT/inproc-$1-$s.jsonl
      echo "$1 $s: OOM on $id" >> $OUT/failures.txt
      resume=--resume
    done
  done
}
run up       up   na
run cte      cte  on
run cte-off  cte  off
run wrap     wrap on
run wrap-off wrap off
