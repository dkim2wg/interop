#!/bin/bash
# Soak every build in turn, never two at once.  Runs on the box.
#
#   bash run-soaks.sh            # wait for the box to be quiet, then soak
#   WAIT=0 bash run-soaks.sh     # start straight away
#
# Soaks use only the corpus messages under 2 MB (corpus-soak/, built here from
# corpus/ by symlink): stock Mailman 3.3.10 cannot sustain the 5-50 MB
# synthetics x 100 members inside the 700 MB cap (runners were OOM-killed and
# mail shunted on the first attempt, 2026-10-07); the in-process benchmark
# covers those.  Before starting it waits until no Mailman test suite has run
# for 15 minutes, so a test run on the same box can't skew the numbers.
# Writes results/run-soaks.out and touches results/SOAKS-DONE at the end.
set -u
B=${B:-/opt/mailman/bench}
WAIT=${WAIT:-15}

rm -rf $B/corpus-soak
mkdir -p $B/corpus-soak/signed $B/corpus-soak/unsigned
head -1 $B/corpus/index.tsv > $B/corpus-soak/index.tsv
tail -n +2 $B/corpus/index.tsv | awk -F'\t' '$2 < 2000000' >> $B/corpus-soak/index.tsv
tail -n +2 $B/corpus-soak/index.tsv | cut -f1 | while read -r id; do
  for s in signed unsigned; do ln -s $B/corpus/$s/$id.eml $B/corpus-soak/$s/$id.eml; done
done

quiet=0
while [ $quiet -lt $WAIT ]; do
  if pgrep -f "test-venv.*nose2|nose2.*mailman" >/dev/null; then quiet=0; else quiet=$((quiet+1)); fi
  sleep 60
done
rm -f $B/results/SOAKS-DONE
echo "== $(date -Is) starting soaks ($(($(wc -l < $B/corpus-soak/index.tsv) - 1)) messages)"
for spec in "up up na" "cte cte on" "cte-off cte off" "wrap wrap on" "wrap-off wrap off"; do
  set -- $spec
  echo "== $(date -Is) soak $1 (venv $(cat $B/$2/ref))"
  CORPUS=$B/corpus-soak bash $B/soak.sh $1 $B/$2/venv $3 || echo "soak $1 exit $?"
done
echo "== $(date -Is) all soaks done"
touch $B/results/SOAKS-DONE
