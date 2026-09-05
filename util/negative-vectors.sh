#!/bin/sh
# Hand-built §8.9/§11.2 negative vectors, fed through every verifier's REAL
# entry point (spec-06 upgrade Task 21, CONTROLLER RULING).
#
#   ./util/negative-vectors.sh
#
# The design doc calls for one hand-built negative vector per new PERMERROR,
# run through the real verify path -- not a parsing helper called directly.
# That distinction is not academic: during this upgrade the C implementation
# shipped a correct duplicate-algorithm check that NO production path ever
# reached (the parser returned the error; the caller silently dropped the
# header), and its unit tests passed the whole time because they called the
# checker function directly. The same shape later turned up in Perl (a `die`
# crashing the whole verifier), C again (a fail-open truncating the body),
# and Python. These vectors are the regression net for that class of bug.
#
# Each negative fixture (built by util/build-negative-vectors.py) is
# otherwise cryptographically VALID -- correct hashes, correct signature
# bytes -- and violates exactly one rule, so a verifier that silently never
# reaches the corresponding check would ACCEPT it instead of rejecting it.
# One positive control (same algorithm twice, distinct Selectors -- §8.9
# explicitly permits this) must be ACCEPTED; a verifier that rejects it has
# a false positive that would reject conformant mail.
set -u

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# Single source of truth for the vector set: the expected cell count is
# DERIVED from these lists (not hardcoded), so it stays correct if a vector
# or verifier is deliberately added, and so it CATCHES one being silently
# dropped -- a runner that quietly covers less than it claims is worse than
# no runner, because it still reads as proof.
NEG_VECTORS="dup-hash-algorithm.eml dup-selector.eml too-many-signatures.eml malformed-json-r.eml unsigned-mi.eml nd-bridge-wrong-domain.eml"
POS_VECTORS="positive-control-two-selectors.eml positive-control-bottom-recipe.eml positive-control-nd-bridge.eml"
VERIFIERS="python go c perl js"
n_vectors=0;   for _f in $NEG_VECTORS $POS_VECTORS; do n_vectors=$((n_vectors + 1));     done
n_verifiers=0; for _v in $VERIFIERS;                 do n_verifiers=$((n_verifiers + 1)); done
expected=$((n_vectors * n_verifiers))

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rc=0
cells=0

python3 util/build-negative-vectors.py "$tmp" || { echo "fixture build FAILED"; exit 1; }

# vector <file> <want: reject|accept> <label>
# want=reject -> Must be rejected with (desirable exact text, informational)
want_text() {
    case $1 in
    dup-hash-algorithm.eml)  echo "Message-Instance m=<x> has a duplicate hash algorithm" ;;
    dup-selector.eml)        echo "DKIM2-Signature i=<x> has a duplicate selector" ;;
    too-many-signatures.eml) echo "DKIM2-Signature i=<x> has more selectors than allowed" ;;
    malformed-json-r.eml)    echo "Message-Instance m=<x> contains invalid JSON" ;;
    unsigned-mi.eml)         echo "Message-Instance m=<x> is not signed" ;;
    nd-bridge-wrong-domain.eml) echo "DKIM2-Signature i=<x> nd= hop d=<domain> did not match RCPT TO" ;;
    esac
}

# verify <impl> <file> -- same invocations as util/hash-matrix.sh, verified
# against each tool's source (see the notes there re: Go's stdin-only input
# and Perl's absolute-path handling).
verify() {
    case $1 in
    python) python3 python/dkim2verify.py "$2" --dns-json dns.json --ignore-timestamps ;;
    go)     ./go/dkim2verify -dns dns.json -ignore-timestamps < "$2" ;;
    c)      ./c/dkim2verify "$2" --dns-json dns.json --ignore-timestamps ;;
    perl)   (cd perl && perl -Ilib bin/validate.pl --ignore-timestamps "$2") ;;
    js)     (cd deploy/www/verify && node tests/verify-file.mjs "$2") ;;
    *)      echo "verify: unknown implementation '$1'" >&2; return 1 ;;
    esac
}

run_vector() { # run_vector <file> <want: reject|accept>
    file=$1; want=$2
    path="$tmp/$file"
    printf '%s (must %s)\n' "$file" "$want"
    [ "$want" = reject ] && printf '  expected text: %s\n' "$(want_text "$file")"
    for impl in $VERIFIERS; do
        cells=$((cells + 1))
        out=$(verify "$impl" "$path" 2>&1)
        status=$?
        if [ "$want" = reject ]; then
            if [ "$status" -ne 0 ]; then
                printf '  %-7s REJECTED (ok)   : %s\n' "$impl" "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)"
            else
                printf '  %-7s ACCEPTED (BUG!) : %s\n' "$impl" "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)"
                rc=1
            fi
        else
            if [ "$status" -eq 0 ]; then
                printf '  %-7s ACCEPTED (ok)   : %s\n' "$impl" "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)"
            else
                printf '  %-7s REJECTED (BUG!) : %s\n' "$impl" "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)"
                rc=1
            fi
        fi
    done
    echo
}

for f in $NEG_VECTORS; do run_vector "$f" reject; done
for f in $POS_VECTORS; do run_vector "$f" accept; done

if [ "$cells" -ne "$expected" ]; then
    echo "Ran $cells of $expected expected combinations -- coverage shortfall, not just a pass/fail count."
    rc=1
else
    echo "Ran all $expected expected combinations."
fi
[ "$rc" -eq 0 ] && echo "All verifiers agree: every negative vector rejected, positive control accepted." \
                || echo "At least one verifier disagreed, or coverage was short -- see above."
exit "$rc"
