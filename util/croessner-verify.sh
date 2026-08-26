#!/bin/sh
# Cross-implementation runner against croessner/dkim2 -- Christian Roessner's
# Go reference implementation, the other actively developed DKIM2 codebase:
#
#     ./util/croessner-verify.sh
#     DKIM2_GO_PEER=/path/to/dkim2 ./util/croessner-verify.sh
#
# Feeds his verifier the output of all four of our signers at all three hash
# algorithms, then the whole negative-vector set, and gates on his verdict.
# This is the direction that has already found real bugs: both fixes on his
# closed PR #1 came from hand-feeding our signers' output through his verifier
# (our Perl signer folds header hashes with a tab, which his parser refused),
# and nothing in either repo would have caught that automatically.
#
# WHY THIS IS NOT PART util/hash-matrix.sh
#
# His implementation has no file-based CLI. The whole surface is dkim2d, an
# HTTP daemon with an OpenAPI contract, so a peer cell means building the
# daemon, minting a capability, booting it and POSTing JSON -- not adding a
# case to hash-matrix.sh's verify(). And dkim2d resolves DNS live: his config
# exposes cache tuning but no offline records file, so unlike every other
# runner here this one needs the network and the published test1.dkim2.com
# keys. hash-matrix.sh stays offline-clean; the network dependency is confined
# to this script.
#
# WHY IT SKIPS RATHER THAN FAILS
#
# Unlike the dkim2tests submodule, his repository is a separate project on its
# own release cadence and is NOT vendored here -- a pin would rot and drag in
# his vendored dependency tree. So a missing peer checkout, a missing Go
# toolchain, or no DNS is a SKIP with exit 0, not the exit 1 that
# util/turscar-all.sh uses for its own submodule. An absent optional peer is
# not a failure of this repo.
set -u

root=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$root"

PEER=${DKIM2_GO_PEER:-$root/../mailde-dkim2}

skip() {
    echo "SKIPPED: $1"
    [ $# -gt 1 ] && echo "  $2"
    exit 0
}

# ---------------------------------------------------------------- preflight

[ -d "$PEER/cmd/dkim2d" ] || skip \
    "no croessner/dkim2 checkout at $PEER" \
    "clone https://github.com/croessner/dkim2 beside this repo, or set DKIM2_GO_PEER"

command -v go >/dev/null 2>&1 || skip \
    "no Go toolchain on PATH" \
    "his daemon must be built from source; there is no released binary to test against"

# His resolver requires a live v=DKIM1 record (lib/internal/keyresolver/
# record.go insists v= is present and first), and our published test keys are
# real. Checking here turns "every cell mysteriously fails" into one clear
# line. Only gate when we actually have a resolver tool to ask with.
if command -v dig >/dev/null 2>&1; then
    [ -n "$(dig +short sel1._domainkey.test1.dkim2.com TXT 2>/dev/null)" ] || skip \
        "sel1._domainkey.test1.dkim2.com does not resolve" \
        "dkim2d has no offline resolver, so this runner needs working DNS"
fi

PEER_REV=$(git -C "$PEER" rev-parse --short HEAD 2>/dev/null || echo unknown)
echo "peer: croessner/dkim2 at $PEER ($PEER_REV)"

# ------------------------------------------------------------------- fixture

. "$root/util/lib-sign.sh"

ALGS="sha256 sha512 both"

# Negative fixtures from util/build-negative-vectors.py, the same set
# util/negative-vectors.sh feeds our own five verifiers. Each is otherwise
# cryptographically valid and breaks exactly one spec-05 rule, so a verifier
# that never reaches the check ACCEPTS it rather than failing on the signature.
NEG_VECTORS="dup-hash-algorithm.eml dup-selector.eml too-many-signatures.eml malformed-json-r.eml"
POS_VECTORS="positive-control-two-selectors.eml positive-control-bottom-recipe.eml"

# Expected cell count is DERIVED, never hardcoded, so that adding a signer or
# a vector keeps it honest and silently dropping one is a failure rather than
# an invisibly smaller "all passed". Same rule as the other runners.
count() { n=0; for _x in $1; do n=$((n + 1)); done; echo "$n"; }
expected=$(( $(count "$SIGNERS") * $(count "$ALGS") \
             + $(count "$NEG_VECTORS") + $(count "$POS_VECTORS") ))

# pwd -P is load-bearing, not tidiness: dkim2d resolves its protected paths
# with EvalSymlinks and refuses anything that was reached through a symlink.
# On macOS mktemp -d hands back /var/folders/... where /var is a symlink to
# /private/var, so the raw path earns a bare "dkim2d: runtime failure".
tmp=$(cd "$(mktemp -d)" && pwd -P)
GEN=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
state="$tmp/state/$GEN"

cleanup() {
    [ -n "${daemon_pid:-}" ] && kill "$daemon_pid" 2>/dev/null
    # The generation directory is sealed to 0500 below; rm -rf cannot remove
    # its contents until it is writable again.
    chmod 0700 "$state" 2>/dev/null
    rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

echo "building dkim2d..."
(cd "$PEER/cmd/dkim2d" && go build -o "$tmp/dkim2d" .) || {
    echo "dkim2d build FAILED"; exit 1; }

# dkim2d demands a "protected generation": the capability is 32 opaque bytes,
# mode 0600, inside a directory named by a 32-hex generation id that must
# itself be SEALED non-writable (0500) before the daemon will load it, with
# every path free of symlinks. Getting any of that wrong yields a bare
# "dkim2d: runtime failure" -- his diagnostics are deliberately content-free --
# so the sequence is spelled out rather than left to be rediscovered. Cribbed
# from his own cmd/dkim2d/internal/app/daemon_smoke_test.go.
mkdir -p "$tmp/state" && mkdir -m 0700 "$state"
head -c 32 /dev/urandom > "$state/capability" && chmod 0600 "$state/capability"
chmod 0500 "$state"

# Port 0 to let the kernel pick, then reuse the number: his daemon accepts only
# canonical loopback authorities, and a fixed port would collide with a real
# dkim2d or a second run of this script.
port=$(python3 -c 'import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
url="http://127.0.0.1:$port"

cat > "$tmp/dkim2d.yaml" <<EOF
config:
  version: dkim2d-config-v1
protected:
  generation: $GEN
server:
  listen: 127.0.0.1:$port
  capability_file: $state/capability
replay:
  backend: disabled
EOF
chmod 0600 "$tmp/dkim2d.yaml"

"$tmp/dkim2d" validate --config "$tmp/dkim2d.yaml" || {
    echo "dkim2d rejected the generated config"; exit 1; }

"$tmp/dkim2d" serve --config "$tmp/dkim2d.yaml" > "$tmp/daemon.log" 2>&1 &
daemon_pid=$!

ready=0
i=0
while [ "$i" -lt 60 ]; do
    if python3 - "$url" <<'EOF' 2>/dev/null
import json, sys, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(sys.argv[1] + "/readyz", timeout=2) as response:
    sys.exit(0 if json.loads(response.read()).get("status") == "ready" else 1)
EOF
    then ready=1; break; fi
    kill -0 "$daemon_pid" 2>/dev/null || break
    i=$((i + 1))
    sleep 0.25
done
[ "$ready" -eq 1 ] || {
    echo "dkim2d never became ready; log follows"
    sed 's/^/    /' "$tmp/daemon.log" | tail -10
    exit 1; }

draft=$(python3 - "$url" <<'EOF'
import json, sys, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(sys.argv[1] + "/readyz", timeout=5) as response:
    print(json.loads(response.read()).get("draft", "?"))
EOF
)
echo "dkim2d ready on $url, draft $draft"
echo

process() { # process <message> [extra args...]
    python3 util/croessner-process.py "$@" --url "$url" --capability "$state/capability"
}

rc=0
cells=0

# ------------------------------------------- our signers -> his verifier

echo "our signers at each hash algorithm -> his verifier (must ACCEPT):"
for signer in $SIGNERS; do
    for alg in $ALGS; do
        out="$tmp/$signer-$alg.eml"
        cells=$((cells + 1))
        if ! sign "$signer" "$alg" "$out"; then
            printf '  %-7s %-7s SIGN FAILED (ours): %s\n' "$signer" "$alg" \
                "$(tr '\n' ' ' < "$tmp/err" | cut -c1-120)"
            rc=1; continue
        fi
        # Envelope passed explicitly here: these are our messages and
        # util/lib-sign.sh fixed the envelope that produced them, so there is
        # no need to re-derive it from the signature we are testing.
        if verdict=$(process "$out" --mail-from "$MF" --rcpt-to "$RT" 2>&1); then
            printf '  %-7s %-7s ACCEPTED (ok)   : %s\n' "$signer" "$alg" "$verdict"
        else
            printf '  %-7s %-7s REJECTED (BUG!) : %s\n' "$signer" "$alg" "$verdict"
            rc=1
        fi
    done
done
echo

# --------------------------------------------- negative vectors -> his verifier

python3 util/build-negative-vectors.py "$tmp" >/dev/null || {
    echo "negative fixture build FAILED"; exit 1; }

# Envelopes are derived from each fixture's top Message-Instance rather than
# fixed, because malformed-json-r.eml is a two-hop chain travelling under the
# forwarder's envelope, not the originator's.
echo "spec-05 negative vectors -> his verifier (must REJECT):"
for f in $NEG_VECTORS; do
    cells=$((cells + 1))
    if verdict=$(process "$tmp/$f" 2>&1); then
        printf '  %-34s ACCEPTED (BUG!) : %s\n' "$f" "$verdict"
        rc=1
    else
        printf '  %-34s rejected (ok)   : %s\n' "$f" "$verdict"
    fi
done
echo

echo "positive controls -> his verifier (must ACCEPT):"
for f in $POS_VECTORS; do
    cells=$((cells + 1))
    if verdict=$(process "$tmp/$f" 2>&1); then
        printf '  %-34s accepted (ok)   : %s\n' "$f" "$verdict"
    else
        printf '  %-34s REJECTED (BUG!) : %s\n' "$f" "$verdict"
        rc=1
    fi
done
echo

if [ "$cells" -ne "$expected" ]; then
    echo "Ran $cells of $expected expected cells -- coverage shortfall, not just a pass/fail count."
    rc=1
else
    echo "Ran all $expected expected cells."
fi
[ "$rc" -eq 0 ] && echo "croessner/dkim2 agrees with this repo on every cell." \
                || echo "croessner/dkim2 disagrees on at least one cell -- see above."
exit "$rc"
