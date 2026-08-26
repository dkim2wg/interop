# Shared signer invocations for the cross-implementation runners.
# Sourced, not executed:
#
#     . "$root/util/lib-sign.sh"
#     sign python sha256 /tmp/out.eml
#
# Callers must have cd'd to the repo root first, and must set $tmp to a
# writable directory (sign() puts each tool's stderr in $tmp/err).
#
# This lives in one file because the invocations are not guessable and were
# each verified against the actual CLI on 2026-08-26 -- note they all spell
# their flags differently, and two of them broke a first draft that looked
# perfectly plausible:
#
#   - Go's dkim2sign/dkim2verify read the message ONLY on stdin -- they never
#     look at a positional filename arg -- so they must be invoked with
#     `< "$file"`. Passing the name positionally silently blocks forever on
#     the inherited stdin instead of failing.
#   - Perl's tools resolve paths relative to their OWN cwd (perl/), because
#     that is where their `../dns.json` load is anchored, so a repo-relative
#     message path needs the `../` prefix while an absolute one must be
#     passed through unmodified.
#
# util/hash-matrix.sh and util/croessner-verify.sh both source this, so a
# corrected invocation reaches every runner at once.

SRC=perl/tests/emails/brong-orig.eml
KEY=keys/sel1._domainkey.test1.dkim2.com.pem
DOM=test1.dkim2.com
SEL=sel1
MF='<brong@test1.dkim2.com>'
RT='<user@test2.dkim2.com>'

SIGNERS="python go c perl"

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
    *)      echo "sign: unknown implementation '$1'" >&2; return 1 ;;
    esac
}
