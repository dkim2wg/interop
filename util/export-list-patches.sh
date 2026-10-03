#!/bin/bash
# Export the DKIM2 patch series for Mailman 3 and Sympa from their fork
# checkouts into mailman/patches and sympa/patches, or (--check) verify that
# the exported series still apply to the bases the READMEs name.
#
#   util/export-list-patches.sh            # regenerate both series
#   util/export-list-patches.sh --check    # apply them to their bases; exit 1 on failure
#
# The fork checkouts default to ~/src/mailman and ~/src/sympa, each with the
# DKIM2 work on its `dkim2` branch (3 commits on top of the base below).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
MAILMAN=${MAILMAN_DIR:-$HOME/src/mailman}
SYMPA=${SYMPA_DIR:-$HOME/src/sympa}
MAILMAN_BASE=687b9e4dc          # upstream master the fork is based on (v3.3.10+466)
MAILMAN_RELEASE=v3.3.10         # also tried; the README records the result
SYMPA_BASE=6.2.78
check=0
while [ $# -gt 0 ]; do
  case "$1" in
    --check) check=1 ;;
    --mailman) MAILMAN=$2; shift ;;
    --sympa) SYMPA=$2; shift ;;
    *) echo "usage: $0 [--check] [--mailman DIR] [--sympa DIR]" >&2; exit 2 ;;
  esac
  shift
done

export_series() {  # name checkout base
  local name=$1 dir=$2 base=$3
  local out="$ROOT/$name/patches"
  rm -rf "$out"; mkdir -p "$out"
  # --no-signature drops the "-- \n<git version>" trailer so regenerating with
  # the same content is a no-op in git; --zero-commit keeps the From: line
  # stable too.
  git -C "$dir" format-patch --no-signature --zero-commit -o "$out" "$base..dkim2" >/dev/null
  echo "exported $(ls "$out" | wc -l | tr -d ' ') patches to $name/patches (base $base, dkim2 at $(git -C "$dir" rev-parse --short dkim2))"
}

check_series() {  # name checkout base
  # A disposable worktree at the base; `git am` applies the series for real,
  # which is the only honest check when patch 2 depends on patch 1.
  local name=$1 dir=$2 base=$3 wt rc=0 err
  err=$(mktemp)
  wt=$(mktemp -d)
  rmdir "$wt"   # worktree add wants to create it
  git -C "$dir" worktree add -q --detach "$wt" "$base" 2>"$err" || { echo "FAIL  cannot check out $base in $dir:"; sed 's/^/      /' "$err"; return 1; }
  if git -C "$wt" am -q "$ROOT/$name"/patches/*.patch 2>"$err"; then
    echo "ok    $name series applies to $base"
  else
    echo "FAIL  $name series does not apply to $base:"; sed 's/^/      /' "$err"
    git -C "$wt" am --abort 2>/dev/null || true
    rc=1
  fi
  git -C "$dir" worktree remove --force "$wt"
  rm -f "$err"
  return $rc
}

if [ $check -eq 0 ]; then
  export_series mailman "$MAILMAN" "$MAILMAN_BASE"
  export_series sympa   "$SYMPA"   "$SYMPA_BASE"
  exit 0
fi

fail=0
check_series mailman "$MAILMAN" "$MAILMAN_BASE" || fail=1
check_series mailman "$MAILMAN" "$MAILMAN_RELEASE" \
  || echo "      (the release-tag result is informational: mailman/README.md states it)"
check_series sympa   "$SYMPA"   "$SYMPA_BASE"   || fail=1
exit $fail
