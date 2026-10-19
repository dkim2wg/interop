#!/bin/sh
# Hand-built negative vectors (-07 §14), fed through every verifier's REAL
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
# The positive controls (e.g. the same algorithm twice with distinct
# Selectors, which -07 §10.9 explicitly permits; null body Recipes; empty bodies)
# must be ACCEPTED; a verifier that rejects one has a false positive that
# would reject conformant mail.
#
# draft -07 added the Chain of Custody vectors (custody-*, nd-*, mf-d-*:
# contract C4), the From-Authentic vectors (from-*: C5), the "u" step and
# step-schema vectors (recipe-u-*, recipe-b-step, recipe-two-step-keys,
# recipe-empty-step: C1) and the key-case vectors (recipe-case-duplicate-key,
# positive-control-recipe-uppercase-keys: decision 2), and every expected
# reason is now the exact -07 string (C6), matched as a substring because
# Go joins several errors with newlines and Perl wraps its summary.
set -u

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# Single source of truth for the vector set: the expected cell count is
# DERIVED from these lists (not hardcoded), so it stays correct if a vector
# or verifier is deliberately added, and so it CATCHES one being silently
# dropped -- a runner that quietly covers less than it claims is worse than
# no runner, because it still reads as proof.
NEG_VECTORS="dup-hash-algorithm.eml dup-selector.eml too-many-signatures.eml malformed-json-r.eml unsigned-mi.eml nd-bridge-wrong-domain.eml duplicate-mi-version.eml recipe-descending-ranges.eml recipe-overlapping-ranges.eml null-body-forged-history.eml empty-body-forged-history.eml malformed-body-recipe-below-null.eml signature-gap.eml instance-gap.eml unkeyable-signature-no-i.eml unkeyable-signature-i-abc.eml lone-junk-signature.eml signature-i-33.eml signature-i-101.eml signature-i-huge.eml signature-m-huge.eml instance-m-huge.eml signature-m-malformed.eml instance-m-malformed.eml recipe-duplicate-b-null-last.eml recipe-duplicate-b-null-first.eml recipe-duplicate-h-key.eml custody-bounce-d-mismatch.eml nd-subdomain-swapped.eml nd-next-hop-mismatch.eml custody-mf-domain-literal.eml mf-d-mismatch.eml from-not-authentic.eml from-changed-not-authentic.eml recipe-u-nonzero-pad.eml recipe-b-step.eml recipe-two-step-keys.eml recipe-empty-step.eml recipe-case-duplicate-key.eml"
POS_VECTORS="positive-control-two-selectors.eml positive-control-bottom-recipe.eml positive-control-nd-bridge.eml positive-control-unreferenced-lower-mi.eml positive-control-u-literal.eml positive-control-null-body.eml positive-control-null-body-over-recipe.eml positive-control-null-below.eml positive-control-empty-body-chain.eml positive-control-custody-bounce.eml positive-control-nd-subdomain-rt.eml positive-control-from-folded-2047.eml positive-control-from-changed.eml positive-control-recipe-uppercase-keys.eml"
VERIFIERS="python go c perl js"
n_vectors=0;   for _f in $NEG_VECTORS $POS_VECTORS; do n_vectors=$((n_vectors + 1));     done
n_verifiers=0; for _v in $VERIFIERS;                 do n_verifiers=$((n_verifiers + 1)); done
expected=$((n_vectors * n_verifiers))

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rc=0
cells=0

python3 util/build-negative-vectors.py "$tmp" || { echo "fixture build FAILED"; exit 1; }

# want_text <file>: the reason every verifier's output MUST contain, one
# fixed string per line.  Where -07 defines the text (contract C6) there is
# exactly one line, and it is the exact -07 string.  A second line appears
# only for a local check that -07 has no text for (chain-number bounds, a
# missing i=, a duplicated m=), where the implementations kept their -06
# wording with the "PERMERROR: " prefix; see c/INTEROP-NOTES.md (-07).
want_text() {
    case $1 in
    dup-hash-algorithm.eml)  echo "PERMERROR: Message-Instance m=1 has a duplicate hash algorithm" ;;
    dup-selector.eml)        echo "PERMERROR: DKIM2-Signature i=1 has a duplicate selector" ;;
    too-many-signatures.eml) echo "PERMERROR: DKIM2-Signature i=1 has more selectors than allowed" ;;
    # Ruling 10: every Recipe error is "contains invalid JSON".
    malformed-json-r.eml|recipe-*.eml|malformed-body-recipe-below-null.eml)
                             echo "PERMERROR: Message-Instance m=2 contains invalid JSON" ;;
    null-body-forged-history.eml|empty-body-forged-history.eml)
                             echo "FAIL: Message-Instance m=1 header hash sha256 mismatch" ;;
    signature-gap.eml)       echo "PERMERROR: DKIM2-Signature i=2 missing" ;;
    instance-gap.eml)        echo "PERMERROR: Message-Instance m=2 missing" ;;
    unsigned-mi.eml)         echo "PERMERROR: Message-Instance m=2 is not signed" ;;
    duplicate-mi-version.eml)
        echo "PERMERROR: duplicate Message-Instance m=1"
        echo "PERMERROR: Message-Instance m=1 appears more than once" ;;
    unkeyable-signature-no-i.eml|lone-junk-signature.eml)
        echo "PERMERROR: DKIM2-Signature has a missing or malformed i= tag"
        echo "PERMERROR: DKIM2-Signature i=None tag=i missing"
        echo "PERMERROR: DKIM2-Signature i= syntax error" ;;
    unkeyable-signature-i-abc.eml)
        echo "PERMERROR: DKIM2-Signature i=abc syntax error"
        echo "PERMERROR: DKIM2-Signature has a missing or malformed i= tag" ;;
    signature-i-33.eml)      echo "exceeds the maximum chain length of 32" ;;
    signature-i-*.eml|signature-m-huge.eml|instance-m-huge.eml)
                             echo "exceeds the maximum chain number of 100" ;;
    signature-m-malformed.eml)
        echo "PERMERROR: DKIM2-Signature i=2 syntax error"
        echo "PERMERROR: DKIM2-Signature m=4294967297x syntax error"
        echo "PERMERROR: DKIM2-Signature has a malformed m= tag" ;;
    instance-m-malformed.eml)
        echo "PERMERROR: Message-Instance m=4294967297x syntax error"
        echo "PERMERROR: Message-Instance has a malformed m= tag" ;;
    nd-bridge-wrong-domain.eml|custody-bounce-d-mismatch.eml|nd-subdomain-swapped.eml)
                             echo "PERMERROR: DKIM2-Signature i=2 d= does not match the rt= of i=1" ;;
    nd-next-hop-mismatch.eml) echo "PERMERROR: DKIM2-Signature i=2 nd= does not match" ;;
    custody-mf-domain-literal.eml) echo "PERMERROR: DKIM2-Signature i=2 mf= does not match the rt= of i=1" ;;
    mf-d-mismatch.eml)       echo "PERMERROR: DKIM2-Signature i=1 MAIL FROM and d= do not match" ;;
    from-not-authentic.eml)  echo "PERMERROR: DKIM2-Signature i=1 matching From is not authentic" ;;
    from-changed-not-authentic.eml) echo "PERMERROR: DKIM2-Signature i=2 matching From is not authentic" ;;
    *) echo "want_text: no expected text for $1" >&2; return 1 ;;
    esac
}

# verify() comes from util/lib-sign.sh (the same invocations as
# util/hash-matrix.sh), with every verifier pointed at the repo's dns.json.
. "$root/util/lib-sign.sh"

run_vector() { # run_vector <file> <want: reject|accept>
    file=$1; want=$2
    path="$tmp/$file"
    printf '%s (must %s)\n' "$file" "$want"
    [ "$want" = reject ] && printf '  expected text: %s\n' "$(want_text "$file" | head -1)"
    for impl in $VERIFIERS; do
        cells=$((cells + 1))
        out=$(verify "$impl" "$path" 2>&1)
        status=$?
        if [ "$want" = reject ]; then
            # The reason is load-bearing: a rejection for some incidental
            # cause would hide a verifier that never reaches the check under
            # test.  Every reject vector names its reason (want_text).
            want_text "$file" > "$tmp/must" || rc=1
            if [ "$status" -ne 0 ] && ! printf '%s' "$out" | grep -qF -f "$tmp/must"; then
                printf '  %-7s REJECTED, WRONG REASON (BUG!) : %s\n' "$impl" "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)"
                rc=1
            elif [ "$status" -ne 0 ]; then
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
