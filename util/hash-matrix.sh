#!/bin/sh
# Cross-implementation hash-agility matrix (spec-05 §3.1, §7.3).
#
#   ./util/hash-matrix.sh
#
# Signs one message with each signer at --hash sha256, sha512 and both, then
# verifies every output with every verifier. Proves algorithm dexterity across
# implementations, which no single-language suite can.
set -u

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# Verified against the actual CLIs on 2026-08-26 -- note each one spells its
# flags differently.
#
# Two invocations below differ from a first draft that looked plausible but
# hung/broke in practice, so they're spelled out here:
#   - Go's dkim2verify reads the message ONLY on stdin -- it never looks at a
#     positional filename arg -- so it must be invoked with `< "$file"`, not
#     `dkim2verify ... "$file"` (the latter silently blocks forever on the
#     inherited stdin).
#   - Perl's validate.pl resolves the message path AS GIVEN (its `../dns.json`
#     load is relative to its own cwd, `perl/`, not to the message argument),
#     so an absolute message path must be passed through unmodified rather
#     than prefixed with `../`.
SRC=perl/tests/emails/brong-orig.eml
KEY=keys/sel1._domainkey.test1.dkim2.com.pem
DOM=test1.dkim2.com
SEL=sel1
MF='<brong@test1.dkim2.com>'
RT='<user@test2.dkim2.com>'

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rc=0

sign() { # sign <impl> <alg> <out>
    case $1 in
    python) python3 python/dkim2sign.py "$SRC" -s "$SEL" -d "$DOM" -k "$KEY" \
                --mailfrom "$MF" --rcptto "$RT" --hash "$2" > "$3" 2>"$tmp/err" ;;
    go)     ./go/dkim2sign -selector "$SEL" -domain "$DOM" -key "$KEY" \
                -mail-from "$MF" -rcpt-to "$RT" -hash "$2" < "$SRC" > "$3" 2>"$tmp/err" ;;
    c)      ./c/dkim2sign "$SRC" -s "$SEL" -d "$DOM" -k "$KEY" \
                --mailfrom "$MF" --rcptto "$RT" --hash "$2" > "$3" 2>"$tmp/err" ;;
    perl)   (cd perl && perl -Ilib bin/dkim2sign.pl "../$SRC" -s "$SEL" -d "$DOM" \
                -k "../$KEY" --mailfrom "$MF" --rcptto "$RT" --hash "$2") > "$3" 2>"$tmp/err" ;;
    esac
}

# All four native verifiers load DNS from the repo-root dns.json (the Perl
# tools resolve '../dns.json' relative to their own cwd, perl/), so the
# message path passed to them must be absolute -- which is what $tmp (from
# mktemp -d) already gives us.
verify() { # verify <impl> <file>
    case $1 in
    python) python3 python/dkim2verify.py "$2" --dns-json dns.json --ignore-timestamps ;;
    go)     ./go/dkim2verify -dns dns.json -ignore-timestamps < "$2" ;;
    c)      ./c/dkim2verify "$2" --dns-json dns.json --ignore-timestamps ;;
    perl)   (cd perl && perl -Ilib bin/validate.pl --ignore-timestamps "$2") ;;
    js)     (cd deploy/www/verify && node tests/verify-file.mjs "$2") ;;
    esac
}

for signer in python go c perl; do
    for alg in sha256 sha512 both; do
        out="$tmp/$signer-$alg.eml"
        if ! sign "$signer" "$alg" "$out"; then
            printf '  %-7s %-7s SIGN FAILED\n' "$signer" "$alg"; rc=1; continue
        fi
        for verifier in python go c perl js; do
            if verify "$verifier" "$out" >"$tmp/v.log" 2>&1; then
                printf '  %-7s %-7s -> %-7s ok\n' "$signer" "$alg" "$verifier"
            else
                printf '  %-7s %-7s -> %-7s FAILED\n' "$signer" "$alg" "$verifier"
                sed 's/^/           /' "$tmp/v.log" | head -3
                rc=1
            fi
        done
    done
done

echo
[ "$rc" -eq 0 ] && echo "All signer/algorithm/verifier combinations agree." \
                || echo "At least one combination disagrees."
exit "$rc"
