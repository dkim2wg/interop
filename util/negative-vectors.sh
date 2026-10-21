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
# reason is now the exact -07 string (C6). The
# Ruling 19 vectors (contract C5 corrected 2026-10-18) check that i=1 is
# compared with the From at state m(i=1): an author's From replaced before
# the first signature is not checked (positive-control-ingress-from-
# rewritten), but the From at that state is (from-not-authentic-at-signed-
# state).
#
# Contract C9 (final review I1/I2): every reject vector is checked on the
# verifier's PRIMARY error -- the first line of its output carrying a
# "PERMERROR: ", "FAIL: " or "TEMPERROR: " token, from that token to the end
# of the line -- compared EXACTLY with want_text, not as a substring of the
# whole output.  The state is asserted separately (want_state): the primary
# error's own token, and, for the CLIs that also report an overall result
# (JS's "<overall>: ", Perl's "<result> ("), that result too.  The multi-*
# vectors carry two faults each and pin which one is primary (the first in
# C9's order: the Message-Instances, walk included, before the signatures).  multi-expired-* is verified with the real clock
# (no --ignore-timestamps): its expiry is the point.
set -u

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# Single source of truth for the vector set: the expected cell count is
# DERIVED from these lists (not hardcoded), so it stays correct if a vector
# or verifier is deliberately added, and so it CATCHES one being silently
# dropped -- a runner that quietly covers less than it claims is worse than
# no runner, because it still reads as proof.
NEG_VECTORS="dup-hash-algorithm.eml dup-selector.eml too-many-signatures.eml malformed-json-r.eml unsigned-mi.eml nd-bridge-wrong-domain.eml duplicate-mi-version.eml recipe-descending-ranges.eml recipe-overlapping-ranges.eml null-body-forged-history.eml empty-body-forged-history.eml malformed-body-recipe-below-null.eml signature-gap.eml instance-gap.eml unkeyable-signature-no-i.eml unkeyable-signature-i-abc.eml lone-junk-signature.eml signature-i-33.eml signature-i-101.eml signature-i-huge.eml signature-m-huge.eml instance-m-huge.eml signature-m-malformed.eml instance-m-malformed.eml recipe-duplicate-b-null-last.eml recipe-duplicate-b-null-first.eml recipe-duplicate-h-key.eml custody-bounce-d-mismatch.eml nd-subdomain-swapped.eml nd-next-hop-mismatch.eml custody-mf-domain-literal.eml mf-d-mismatch.eml from-not-authentic.eml from-changed-not-authentic.eml from-not-authentic-at-signed-state.eml recipe-u-nonzero-pad.eml recipe-b-step.eml recipe-two-step-keys.eml recipe-empty-step.eml recipe-case-duplicate-key.eml from-display-no-brackets.eml multi-from-tampered.eml multi-header-and-body-tampered.eml multi-expired-custody.eml multi-custody-bad-signature.eml multi-bad-signature-header-hash.eml multi-tamper-two-instances.eml multi-expired-recipe-json.eml multi-expired-recipe-order.eml multi-expired-recipe-past-end.eml multi-tamper-recipe-past-end.eml"
POS_VECTORS="positive-control-two-selectors.eml positive-control-bottom-recipe.eml positive-control-nd-bridge.eml positive-control-unreferenced-lower-mi.eml positive-control-u-literal.eml positive-control-null-body.eml positive-control-null-body-over-recipe.eml positive-control-null-below.eml positive-control-empty-body-chain.eml positive-control-custody-bounce.eml positive-control-nd-subdomain-rt.eml positive-control-from-folded-2047.eml positive-control-from-changed.eml positive-control-ingress-from-rewritten.eml positive-control-recipe-uppercase-keys.eml"
VERIFIERS="python go c perl js"
n_vectors=0;   for _f in $NEG_VECTORS $POS_VECTORS; do n_vectors=$((n_vectors + 1));     done
n_verifiers=0; for _v in $VERIFIERS;                 do n_verifiers=$((n_verifiers + 1)); done
expected=$((n_vectors * n_verifiers))

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rc=0
cells=0

python3 util/build-negative-vectors.py "$tmp" || { echo "fixture build FAILED"; exit 1; }

# want_text <file>: the exact PRIMARY error every verifier MUST report.
# Where -07 defines the text (contract C6) it is that string; for a local
# check with no -07 text (chain-number bounds, a duplicated m=) it is the
# wording all five implementations agree on, in the C6 shape (the field
# named by its own i=, or m= for a Message-Instance, as written).
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
    duplicate-mi-version.eml) echo "PERMERROR: Message-Instance m=1 appears more than once" ;;
    unkeyable-signature-no-i.eml|lone-junk-signature.eml)
                             echo "PERMERROR: DKIM2-Signature i= tag=i missing" ;;
    unkeyable-signature-i-abc.eml) echo "PERMERROR: DKIM2-Signature i=abc syntax error" ;;
    signature-i-33.eml)      echo "PERMERROR: DKIM2-Signature i=33 exceeds the maximum chain length of 32" ;;
    signature-i-101.eml)     echo "PERMERROR: DKIM2-Signature i=101 exceeds the maximum chain number of 100" ;;
    signature-i-huge.eml)    echo "PERMERROR: DKIM2-Signature i=99999999999999999999 exceeds the maximum chain number of 100" ;;
    signature-m-huge.eml)    echo "PERMERROR: DKIM2-Signature i=2 m=4294967297 exceeds the maximum chain number of 100" ;;
    instance-m-huge.eml)     echo "PERMERROR: Message-Instance m=99999999999999999999 exceeds the maximum chain number of 100" ;;
    signature-m-malformed.eml) echo "PERMERROR: DKIM2-Signature i=2 syntax error" ;;
    instance-m-malformed.eml)  echo "PERMERROR: Message-Instance m=4294967297x syntax error" ;;
    nd-bridge-wrong-domain.eml|custody-bounce-d-mismatch.eml|nd-subdomain-swapped.eml)
                             echo "PERMERROR: DKIM2-Signature i=2 d= does not match the rt= of i=1" ;;
    nd-next-hop-mismatch.eml) echo "PERMERROR: DKIM2-Signature i=2 nd= does not match" ;;
    custody-mf-domain-literal.eml) echo "PERMERROR: DKIM2-Signature i=2 mf= does not match the rt= of i=1" ;;
    mf-d-mismatch.eml)       echo "PERMERROR: DKIM2-Signature i=1 MAIL FROM and d= do not match" ;;
    from-not-authentic.eml|from-not-authentic-at-signed-state.eml)
                             echo "PERMERROR: DKIM2-Signature i=1 matching From is not authentic" ;;
    from-changed-not-authentic.eml) echo "PERMERROR: DKIM2-Signature i=2 matching From is not authentic" ;;
    from-display-no-brackets.eml) echo "PERMERROR: DKIM2-Signature i=1 matching From is not authentic" ;;
    # C9: two faults, the first in -07 §14 section order is primary.
    multi-from-tampered.eml) echo "FAIL: Message-Instance m=1 header hash sha256 mismatch" ;;  # §14.7 < §14.8
    multi-header-and-body-tampered.eml) echo "FAIL: Message-Instance m=1 header hash sha256 mismatch" ;;  # header before body
    multi-expired-custody.eml) echo "PERMERROR: DKIM2-Signature i=1 signature expired" ;;       # §14.3 < §14.4
    multi-custody-bad-signature.eml) echo "PERMERROR: DKIM2-Signature i=1 MAIL FROM and d= do not match" ;;  # §14.4 < §14.6
    multi-bad-signature-header-hash.eml) echo "FAIL: Message-Instance m=1 header hash sha256 mismatch" ;;  # §14.7 < §14.6
    multi-tamper-two-instances.eml) echo "FAIL: Message-Instance m=2 header hash sha256 mismatch" ;;  # §14.7 top down
    # A Recipe malformed on its own is §14.2; one that only fails against
    # the message is found by the §14.7 walk, in walk order.
    multi-expired-recipe-json.eml|multi-expired-recipe-order.eml)
                             echo "PERMERROR: Message-Instance m=2 contains invalid JSON" ;;  # §14.2 < §14.3
    multi-expired-recipe-past-end.eml) echo "PERMERROR: Message-Instance m=2 contains invalid JSON" ;;  # walk < §14.3
    multi-tamper-recipe-past-end.eml) echo "FAIL: Message-Instance m=2 body hash sha256 mismatch" ;;  # top hash, then undo
    *) echo "want_text: no expected text for $1" >&2; return 1 ;;
    esac
}

# want_state <file>: the result state the primary error carries.
want_state() {
    case $(want_text "$1") in
    PERMERROR:*) echo permerror ;;
    FAIL:*)      echo fail ;;
    TEMPERROR:*) echo temperror ;;
    *)           echo "want_state: no state for $1" >&2; return 1 ;;
    esac
}

# primary <output>: the first "STATE: text" in a verifier's output, from the
# state token to the end of its line (Python and Go put "ERROR: " before it).
primary() {
    printf '%s\n' "$1" | grep -m1 -oE '(PERMERROR|FAIL|TEMPERROR): .*'
}

# reported_state <impl> <output>: the overall result a CLI reports apart
# from its error strings, where it reports one (empty otherwise).
reported_state() {
    case $1 in
    js)   printf '%s\n' "$2" | sed -n '1s/^\([a-z]*\): .*/\1/p' ;;
    perl) printf '%s\n' "$2" | sed -n 's/^DKIM2-Signature i=[0-9]*: \([a-z]*\) (.*/\1/p' | head -1 ;;
    esac
}

# verify() comes from util/lib-sign.sh (the same invocations as
# util/hash-matrix.sh), with every verifier pointed at the repo's dns.json.
. "$root/util/lib-sign.sh"

run_vector() { # run_vector <file> <want: reject|accept>
    file=$1; want=$2
    path="$tmp/$file"
    printf '%s (must %s)\n' "$file" "$want"
    [ "$want" = reject ] && printf '  expected text: %s\n' "$(want_text "$file")"
    for impl in $VERIFIERS; do
        cells=$((cells + 1))
        case $file in
        multi-expired-*) out=$(VERIFY_REAL_CLOCK=1 verify "$impl" "$path" 2>&1) ;;
        *)               out=$(verify "$impl" "$path" 2>&1) ;;
        esac
        status=$?
        if [ "$want" = reject ]; then
            # The reason is load-bearing: a rejection for some incidental
            # cause would hide a verifier that never reaches the check under
            # test.  Every reject vector names its reason (want_text), and
            # it must be the PRIMARY error, word for word (contract C9).
            must=$(want_text "$file") || rc=1
            state=$(want_state "$file") || rc=1
            got=$(primary "$out")
            got_state=$(printf '%s' "$got" | sed -n 's/^\([A-Z]*\): .*/\1/p' | tr 'A-Z' 'a-z')
            rep_state=$(reported_state "$impl" "$out")
            if [ "$status" -ne 0 ] && [ "$got" != "$must" ]; then
                printf '  %-7s REJECTED, WRONG PRIMARY (BUG!) : %s\n' "$impl" "${got:-$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)}"
                rc=1
            elif [ "$status" -ne 0 ] && { [ "$got_state" != "$state" ] || { [ -n "$rep_state" ] && [ "$rep_state" != "$state" ]; }; }; then
                printf '  %-7s REJECTED, WRONG STATE (BUG!) : want %s, got %s%s\n' "$impl" "$state" "$got_state" "${rep_state:+ (reported $rep_state)}"
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
