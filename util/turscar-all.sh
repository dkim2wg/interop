#!/bin/sh
# Run the Turscar dkim2tests conformance vectors (git submodule at
# <repo>/dkim2tests) against every verifier in this repo, and print one
# summary line per implementation. Intended as a demo/one-shot check:
#
#   ./util/turscar-all.sh
#
# Each per-language runner gates on the accept/reject decision, skips cleanly
# if the submodule isn't checked out, and is also runnable on its own:
#
#   python3 python/tests/test_turscar.py
#   cd perl && prove -l t/turscar.t
#   cd go   && go test ./dkim2/ -run Turscar -v
#   make -C c dkim2verify && ./c/tests/turscar.sh
#   cd deploy/www/verify && node --test tests/vectors.test.mjs
set -u

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

if [ ! -d dkim2tests/tests ]; then
    echo "dkim2tests submodule not checked out; run:"
    echo "    git submodule update --init"
    exit 1
fi

vectors=$(ls dkim2tests/tests/*.toml | wc -l | tr -d ' ')
echo "Turscar dkim2tests: $vectors vectors at $(git -C dkim2tests describe --always) ($root/dkim2tests)"
echo

rc=0
# run <label> <summary-grep> <shell command>: run the command, print its
# matching summary line (or the last line, if the grep finds nothing).
run() {
    label=$1; pattern=$2; shift 2
    log="$tmp/$label.log"
    status=ok
    sh -c "$*" >"$log" 2>&1 || { status=FAILED; rc=1; }
    summary=$(grep -E "$pattern" "$log" | tail -n 1)
    # node --test reports "pass N"/"skipped N" on separate lines rather than a
    # single summary; fold them into the same shape the other runners print.
    if [ -z "$summary" ] && grep -q ' pass [0-9]' "$log"; then
        summary=$(awk '/ pass [0-9]/{p=$NF} / skipped [0-9]/{s=$NF}
                       END{printf "%s gated vectors agree on accept/reject; %s skipped", p, s+0}' "$log")
    fi
    [ -n "$summary" ] || summary=$(tail -n 1 "$log")
    # strip leading indent, TAP "# " markers and go's "file.go:NN: " prefix
    summary=$(echo "$summary" | sed -e 's/^ *//' -e 's/^# *//' -e 's/^[a-z_]*\.go:[0-9]*: //')
    printf '  %-8s %-7s %s\n' "$label" "$status" "$summary"
    [ "$status" = ok ] || echo "           full output: $log"
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

run python 'gated vectors agree' "python3 python/tests/test_turscar.py"
run perl   'gated vectors agree' "cd perl && prove -l t/turscar.t"
run go     'gated vectors agree' "cd go && go test ./dkim2/ -run Turscar -count=1 -v"
run c      'gated vectors agree' "make -C c dkim2verify && ./c/tests/turscar.sh"
run js     'gated vectors agree' "cd deploy/www/verify && node --test tests/vectors.test.mjs"

echo
if [ "$rc" -eq 0 ]; then
    echo "All verifiers agree with the vectors."
else
    trap - EXIT                          # keep the logs for the failing runner(s)
    echo "At least one verifier disagrees; full logs kept in $tmp"
fi
exit "$rc"
