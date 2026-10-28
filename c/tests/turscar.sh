#!/bin/sh
# Conformance runner for the Turscar dkim2tests vectors (Steve Atkins),
# checked out as the git submodule at <repo>/dkim2tests. Drives the compiled
# ./dkim2verify CLI (which reads our nested dns.json) and compares the
# accept/reject decision to each vector's ExpectedState ("pass" == accept).
#
# The vectors target spec-02. The tag rules (any order, single occurrence,
# FWS) and the >=1024-bit key requirement (§3.2) still apply; the ones -08
# reverses are known divergences (below).
#
# Exact status-code differences (permerror vs fail) are not distinguished: the
# CLI exits 0 (pass) or non-zero (reject), which is the gated invariant.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
cdir=$(dirname "$here")                  # c/
tests="${TURSCAR_TESTS:-$cdir/../dkim2tests/tests}"   # TURSCAR_TESTS: another checkout
cli="$cdir/dkim2verify"

[ -d "$tests" ] || { echo "SKIP: submodule not checked out ($tests)"; exit 0; }
[ -x "$cli" ]  || { echo "SKIP: build $cli first (make -C c dkim2verify)"; exit 0; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
dns="$tmp/dns.json"

# Build a combined dns.json (our nested format) from every vector's [DNS]
# table, and emit a manifest line per vector: name|expected|signedfile|mf|rt,rt
python3 - "$tests" "$dns" > "$tmp/manifest" <<'PY'
import sys, tomllib, json, os
tests, dnspath = sys.argv[1], sys.argv[2]
dns = {}
lines = []
for f in sorted(os.listdir(tests)):
    if not f.endswith(".toml"):
        continue
    d = tomllib.load(open(os.path.join(tests, f), "rb"))
    for host, key in (d.get("DNS") or {}).items():
        i = host.find("._domainkey.")
        sel, dom = host[:i], host[i + len("._domainkey."):]
        dns.setdefault(dom, {})[f"{sel}._domainkey"] = [["txt", key]]
    lines.append("|".join([
        d.get("Name", f[:-5]),
        d.get("ExpectedState", "?"),
        d.get("SignedFile", ""),
        d.get("MailFrom", ""),
        ",".join(d.get("RcptTo") or []),
    ]))
json.dump(dns, open(dnspath, "w"))
print("\n".join(lines))
PY

# Known divergences: vectors whose expectation draft -08 (contract
# docs/superpowers/specs/2026-10-28-dkim2-spec-08-design.md) reverses.
# - d2_duplicate_*_tag (8 of them): each repeats a tag with its name in
#   uppercase; -08 tag names are strictly lowercase (D10), so the uppercase
#   twin is an unknown tag and the signature verifies. (d2_duplicate_s_tag
#   still rejects: its second s= breaks the signed input.)
# - tags_mixed_case: uppercase tag names are unknown tags (D10), so the
#   required tags are missing.
# - algorithm_with_future: an unknown algorithm beside a good signature in a
#   "," list is a PERMERROR item, which the list requires (-08 §14.6, D3).
known_skip="d2_duplicate_d_tag d2_duplicate_f_tag d2_duplicate_i_tag d2_duplicate_m_tag
            d2_duplicate_mf_tag d2_duplicate_n_tag d2_duplicate_rt_tag d2_duplicate_t_tag
            tags_mixed_case algorithm_with_future"
known_skip=$(echo $known_skip)

fail=0; gated=0; skipped=0
while IFS='|' read -r name expected signed mf rt; do
    [ -n "$signed" ] || continue
    case " $known_skip " in *" $name "*)
        echo "skip $name (known-divergence)"; skipped=$((skipped+1)); continue;; esac
    set -- "$tests/$signed" --dns-json "$dns" --ignore-timestamps
    [ -n "$mf" ] && set -- "$@" --mailfrom "$mf"
    OLDIFS=$IFS; IFS=,
    for r in $rt; do [ -n "$r" ] && set -- "$@" --rcptto "$r"; done
    IFS=$OLDIFS
    if "$cli" "$@" >/dev/null 2>&1; then got=pass; else got=reject; fi
    want=reject; [ "$expected" = pass ] && want=pass
    gated=$((gated+1))
    if [ "$got" = "$want" ] || { [ "$want" = reject ] && [ "$got" = reject ]; }; then
        :
    else
        echo "FAIL $name: expected=$expected got=$got"; fail=$((fail+1))
    fi
done < "$tmp/manifest"

echo "$((gated-fail))/$gated gated vectors agree on accept/reject; $skipped skipped"
[ "$fail" -eq 0 ]
