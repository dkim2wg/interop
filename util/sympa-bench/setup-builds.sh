#!/bin/bash
# Install the Sympa libraries of each benchmark build side by side, and
# assemble the corpus.  Runs ON the box (dkim2); production (/opt/sympa-dkim2,
# /usr/share/sympa, /root/interop) is only read, never modified.
#
# Shipped from the laptop first (the box cannot fetch from GitHub), see
# README.md:
#   $ROOT/sympa.bundle   git bundle of ~/src/sympa: 6.2.78,
#                        dkim2-cte-preserve-6.2.78 and dkim2
#   $ROOT/dkim2lib/      interop perl/lib (Mail::DKIM2 0.15)
#   $ROOT/corpus-sympa/  make-corpus.py --sympa output
#
# No `make install`: each build is the ref's src/lib, plus the Constants.pm
# that the production build generated (/usr/share/sympa/lib, same 6.2.78
# configure); Constants.pm.in is identical in all three refs.
# Idempotent: a build is redone only when its ref now resolves to a
# different commit than the one recorded in $ROOT/<id>/ref.
set -euo pipefail
ROOT=${ROOT:-/opt/sympa-bench}
MAILMAN_CORPUS=${MAILMAN_CORPUS:-/opt/mailman/bench/corpus}
CONSTANTS=/usr/share/sympa/lib/Sympa/Constants.pm
declare -A REF=(
  [up]=6.2.78
  [cte]=dkim2-cte-preserve-6.2.78
  [wrap]=dkim2
)
SRC=$ROOT/src.git
[ -d $SRC ] || git clone -q --bare $ROOT/sympa.bundle $SRC
git -C $SRC fetch -q --force $ROOT/sympa.bundle \
  '+refs/heads/*:refs/heads/*' '+refs/tags/*:refs/tags/*'
for id in up cte wrap; do
  d=$ROOT/$id
  want=$(git -C $SRC rev-parse --verify "${REF[$id]}^{commit}")
  if [ -f $d/lib/Sympa/Constants.pm ] && [ "$(cat $d/ref 2>/dev/null)" = "$want" ]; then
    echo "$id: up to date at $want"; continue
  fi
  echo "$id: installing $want (${REF[$id]})"
  rm -rf $d && mkdir -p $d
  git -C $SRC archive $want src/lib | tar -x -C $d --strip-components=1
  cp $CONSTANTS $d/lib/Sympa/Constants.pm
  echo $want > $d/ref
done

v=$(perl -I$ROOT/dkim2lib -MMail::DKIM2::MessageInstance -e 'print Mail::DKIM2::MessageInstance->VERSION')
echo "dkim2lib: Mail::DKIM2 $v"
[ "$v" = 0.15 ] || { echo "error: dkim2lib must be Mail::DKIM2 0.15" >&2; exit 1; }

# Corpus: the charset samples from the Mailman benchmark corpus (symlinked),
# plus the Sympa synthetics.
C=$ROOT/corpus
rm -rf $C && mkdir -p $C/signed $C/unsigned
{
  head -1 $MAILMAN_CORPUS/index.tsv
  tail -n +2 $MAILMAN_CORPUS/index.tsv | grep -v '^syn-'
  tail -n +2 $ROOT/corpus-sympa/index.tsv
} > $C/index.tsv
tail -n +2 $MAILMAN_CORPUS/index.tsv | grep -v '^syn-' | cut -f1 | while read -r id; do
  for s in signed unsigned; do ln -s $MAILMAN_CORPUS/$s/$id.eml $C/$s/$id.eml; done
done
tail -n +2 $ROOT/corpus-sympa/index.tsv | cut -f1 | while read -r id; do
  for s in signed unsigned; do ln -s $ROOT/corpus-sympa/$s/$id.eml $C/$s/$id.eml; done
done
echo "corpus: $(($(wc -l < $C/index.tsv) - 1)) messages"
