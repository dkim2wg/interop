#!/bin/bash
# Build one venv per Mailman variant for the benchmark.  Runs ON the box
# (dkim2), never touches /opt/mailman/venv beyond reading its `pip freeze`.
# Idempotent: a build is redone only when its ref now resolves to a different
# commit than the one recorded in $ROOT/<id>/ref (so re-run after the remote
# branch moves, e.g. a force-pushed dkim2-3.3.10).
set -euo pipefail
ROOT=/opt/mailman/bench
PY=/opt/mailman/venv/bin/python3       # the production interpreter (3.13)
declare -A REF=(
  # v3.3.10 + the two py3.13 fixes (upstream 3.3.10 cannot run on 3.13)
  [up]=a63d71e55823a3e88172110be7b7ad7cae910eb6
  [cte]=dkim2-cte-preserve-3.3.10
  [wrap]=dkim2-3.3.10
)
# Web UI packages are not needed by the MTA-side benchmark; leave them out
# to keep the build small on a 2 GB box.
SKIP='^(mailman|mailman-web|mailman-hyperkitty|django-mailman3|postorius|hyperkitty|django[-_a-z0-9]*)(==| @ )|^-e '
SRC=$ROOT/src
mkdir -p $ROOT
[ -d $SRC ] || git clone https://github.com/brong/mailman $SRC
git -C $SRC fetch --all --tags --force -q
resolve() { git -C $SRC rev-parse --verify -q "origin/$1^{commit}" || git -C $SRC rev-parse --verify "$1^{commit}"; }
/opt/mailman/venv/bin/pip freeze | grep -viE "$SKIP" > $ROOT/freeze.txt
for id in up cte wrap; do
  d=$ROOT/$id
  want=$(resolve "${REF[$id]}")
  if [ -x $d/venv/bin/mailman ] && [ "$(cat $d/ref 2>/dev/null)" = "$want" ]; then
    echo "$id: up to date at $want"; continue
  fi
  echo "$id: building at $want (${REF[$id]})"
  git -C $SRC worktree remove --force $d/src 2>/dev/null || true
  rm -rf $d && git -C $SRC worktree prune && mkdir -p $d
  $PY -m venv $d/venv
  systemd-run --scope -q -p MemoryMax=700M $d/venv/bin/pip -q install -r $ROOT/freeze.txt
  git -C $SRC worktree add -f --detach $d/src $want -q
  systemd-run --scope -q -p MemoryMax=700M $d/venv/bin/pip -q install --no-deps $d/src
  echo $want > $d/ref
done
