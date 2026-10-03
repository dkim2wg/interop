#!/bin/bash
# Export the DKIM2 patch series for Mailman 3 and Sympa from their fork
# checkouts into mailman/patches-3.3.10, mailman/patches-3.3.8,
# mailman/patches-master and sympa/patches-6.2.78, or (--check) verify that the
# exported series still apply to the bases the READMEs name.
#
#   util/export-list-patches.sh            # regenerate both series
#   util/export-list-patches.sh --check    # apply them to their bases; exit 1 on failure
#
# The fork checkouts default to ~/src/mailman and ~/src/sympa. Mailman carries
# the work three times: branch dkim2-3.3.10 on the v3.3.10 release (plus two
# upstream Python 3.13 fixes), dkim2-3.3.8 on the 3.3.8 release, and dkim2 on
# upstream master; Sympa has branch dkim2 on tag 6.2.78.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
MAILMAN=${MAILMAN_DIR:-$HOME/src/mailman}
SYMPA=${SYMPA_DIR:-$HOME/src/sympa}
MAILMAN_3310=v3.3.10            # branch dkim2-3.3.10: current release (Debian 13, Ubuntu 25.04+)
MAILMAN_338=3.3.8               # branch dkim2-3.3.8: LTS release (Debian 12, Ubuntu 24.04)
MAILMAN_MASTER=687b9e4dc        # branch dkim2: the same change on upstream master
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

export_series() {  # name checkout base branch subdir
  local name=$1 dir=$2 base=$3 branch=$4 sub=$5
  local out="$ROOT/$name/$sub"
  rm -rf "$out"; mkdir -p "$out"
  # --no-signature drops the "-- \n<git version>" trailer so regenerating with
  # the same content is a no-op in git; --zero-commit keeps the From: line
  # stable too.
  git -C "$dir" format-patch --no-signature --zero-commit -o "$out" "$base..$branch" >/dev/null
  echo "exported $(ls "$out" | wc -l | tr -d ' ') patches to $name/$sub (base $base, $branch at $(git -C "$dir" rev-parse --short "$branch"))"
}

check_series() {  # name checkout base subdir
  # A disposable worktree at the base; `git am` applies the series for real,
  # which is the only honest check when patch 2 depends on patch 1.
  local name=$1 dir=$2 base=$3 sub=$4 wt rc=0 err
  err=$(mktemp)
  wt=$(mktemp -d)
  rmdir "$wt"   # worktree add wants to create it
  git -C "$dir" worktree add -q --detach "$wt" "$base" 2>"$err" || { echo "FAIL  cannot check out $base in $dir:"; sed 's/^/      /' "$err"; return 1; }
  if git -C "$wt" am -q "$ROOT/$name/$sub"/*.patch 2>"$err"; then
    echo "ok    $name/$sub applies to $base"
  else
    echo "FAIL  $name/$sub does not apply to $base:"; sed 's/^/      /' "$err"
    git -C "$wt" am --abort 2>/dev/null || true
    rc=1
  fi
  git -C "$dir" worktree remove --force "$wt"
  rm -f "$err"
  return $rc
}

if [ $check -eq 0 ]; then
  export_series mailman "$MAILMAN" "$MAILMAN_3310"   dkim2-3.3.10 patches-3.3.10
  export_series mailman "$MAILMAN" "$MAILMAN_338"    dkim2-3.3.8  patches-3.3.8
  export_series mailman "$MAILMAN" "$MAILMAN_MASTER" dkim2        patches-master
  export_series sympa   "$SYMPA"   "$SYMPA_BASE"     dkim2        patches-6.2.78
  exit 0
fi

fail=0
check_series mailman "$MAILMAN" "$MAILMAN_3310"   patches-3.3.10 || fail=1
check_series mailman "$MAILMAN" "$MAILMAN_338"    patches-3.3.8  || fail=1
check_series mailman "$MAILMAN" "$MAILMAN_MASTER" patches-master || fail=1
check_series sympa   "$SYMPA"   "$SYMPA_BASE"     patches-6.2.78 || fail=1
exit $fail
