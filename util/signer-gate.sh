#!/bin/sh
# Signer gate: every signer must verify an existing DKIM2 chain before it
# adds its own signature, and refuse to sign a chain that does not check out.
#
#   ./util/signer-gate.sh
#
# Fixtures (util/build-signer-gate-fixtures.py) are messages as they arrive at
# the next hop, test3.dkim2.com, which is about to sign.  Each is run through
# each signer CLI twice: plain, and with --allow-null-body-recipe.  Expected:
#
#   fixture              plain    with flag
#   fresh                SIGN     SIGN
#   valid-chain          SIGN     SIGN
#   broken-signature     REFUSE   REFUSE
#   broken-mi-chain      REFUSE   REFUSE
#   null-top             REFUSE   SIGN
#   null-top-forged      REFUSE   REFUSE   (flag must not excuse a forged history)
#   mi-only              SIGN     SIGN     (no signature; list added unsigned m=1, m=2)
#   mi-only-broken       REFUSE   REFUSE
#   mi-only-null         REFUSE   SIGN
#   nd-to-us             SIGN     SIGN     (top sig is a bridge with nd= the signer's own d=)
#   nd-to-other          REFUSE   REFUSE   (nd= names another domain)
#
# SIGN   = exit 0 and stdout carries a new DKIM2-Signature i=<N+1>.
# REFUSE = non-zero exit and no new DKIM2-Signature on stdout.
# A refusal caused by the signer not knowing the flag at all is reported as
# FLAG-ERR and counts as a disagreement (even where a refusal was wanted),
# so a signer that has not grown the flag yet cannot pass by accident.
#
# Verification keys: dns.json is exported as $DKIM2_DNS_JSON.  A signer that
# needs it as a flag instead gets it from gate_dns_args() below.
set -u

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# Single source of truth: the expected cell count is DERIVED from these lists,
# so a silently dropped fixture/signer/mode shows up as a coverage shortfall.
# fixture:plain-want:flag-want
FIXTURES="fresh:sign:sign valid-chain:sign:sign broken-signature:refuse:refuse broken-mi-chain:refuse:refuse null-top:refuse:sign null-top-forged:refuse:refuse mi-only:sign:sign mi-only-broken:refuse:refuse mi-only-null:refuse:sign nd-to-us:sign:sign nd-to-other:refuse:refuse"
SIGNERS="python go c perl"
MODES="plain flag"
n=0; for _f in $FIXTURES; do n=$((n + 1)); done
n_signers=0; for _s in $SIGNERS; do n_signers=$((n_signers + 1)); done
n_modes=0;   for _m in $MODES;   do n_modes=$((n_modes + 1));     done
expected=$((n * n_signers * n_modes))

for _b in c/dkim2sign go/dkim2sign; do
    [ -x "$_b" ] || { echo "missing $_b -- build it first (make -C c dkim2sign; cd go && go build -o dkim2sign ./cmd/dkim2sign)"; exit 1; }
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rc=0
cells=0

python3 util/build-signer-gate-fixtures.py "$tmp/in" || { echo "fixture build FAILED"; exit 1; }

# The next hop: test3.dkim2.com, selector sel1.
DOM=test3.dkim2.com
SEL=sel1
KEY=keys/sel1._domainkey.test3.dkim2.com.pem
MF='<list@test3.dkim2.com>'
RT='<subscriber@test4.dkim2.com>'
export DKIM2_DNS_JSON="$root/dns.json"

# Extra per-signer flags: the fixtures are old, so every signer must be told to
# ignore timestamps (Go no longer does so by itself when $DKIM2_DNS_JSON is set).
gate_dns_args() {
    case $1 in
    python|perl|c) echo --ignore-timestamps ;;   # fixtures are old; keys via $DKIM2_DNS_JSON
    go) echo -ignore-timestamps ;;
    esac
}

# gate_sign <impl> <abs input> <flag-or-empty>; stdout=signed message.
gate_sign() {
    _impl=$1; _in=$2; _flag=$3
    _extra=$(gate_dns_args "$_impl")
    case $_impl in
    python) python3 python/dkim2sign.py "$_in" -s "$SEL" -d "$DOM" -k "$KEY" \
                --mailfrom "$MF" --rcptto "$RT" $_extra $_flag ;;
    go)     ./go/dkim2sign -selector "$SEL" -domain "$DOM" -key "$KEY" \
                -mail-from "$MF" -rcpt-to "$RT" $_extra $_flag < "$_in" ;;
    c)      ./c/dkim2sign "$_in" -s "$SEL" -d "$DOM" -k "$KEY" \
                --mailfrom "$MF" --rcptto "$RT" $_extra $_flag ;;
    perl)   (cd perl && perl -Ilib bin/dkim2sign "$_in" -s "$SEL" -d "$DOM" \
                -k "../$KEY" --mailfrom "$MF" --rcptto "$RT" $_extra $_flag) ;;
    esac
}

# Highest i= among DKIM2-Signature headers in a file (0 if none).
max_i() {
    awk 'BEGIN{IGNORECASE=1}
         /^$/ {exit}
         /^DKIM2-Signature:/ { if (match($0, /[ \t]i=[0-9]+/)) { v=substr($0,RSTART+3,RLENGTH-3)+0; if (v>m) m=v } }
         END{print m+0}' "$1"
}

for spec in $FIXTURES; do
    fx=${spec%%:*}; rest=${spec#*:}
    want_plain=${rest%%:*}; want_flag=${rest#*:}
    in="$tmp/in/$fx.eml"
    have=$(max_i "$in"); need=$((have + 1))
    printf '%s (chain i=%s; plain must %s, with flag must %s)\n' "$fx" "$have" "$want_plain" "$want_flag"
    for mode in $MODES; do
        if [ "$mode" = flag ]; then want=$want_flag; else want=$want_plain; fi
        for impl in $SIGNERS; do
            cells=$((cells + 1))
            flag=""
            if [ "$mode" = flag ]; then
                if [ "$impl" = go ]; then flag=-allow-null-body-recipe; else flag=--allow-null-body-recipe; fi
            fi
            out="$tmp/out.$fx.$mode.$impl"
            gate_sign "$impl" "$in" "$flag" > "$out" 2> "$out.err"
            status=$?
            got_i=$(max_i "$out")
            err=$(tr '\n' ' ' < "$out.err" | cut -c1-110)
            if [ "$status" -eq 0 ] && [ "$got_i" -eq "$need" ]; then
                got=sign
            elif [ "$status" -ne 0 ] && [ "$got_i" -lt "$need" ]; then
                got=refuse
                if [ -n "$flag" ] && grep -qiE "unknown option|unrecognized|not defined|invalid option|unrecognised|unexpected argument" "$out.err"; then
                    got=flagerr
                fi
            else
                got=weird   # exit status and output disagree with each other
            fi
            case $got in
            sign)    desc="SIGNED i=$got_i" ;;
            refuse)  desc="REFUSED (exit $status)" ;;
            flagerr) desc="FLAG-ERR (exit $status)" ;;
            weird)   desc="INCONSISTENT (exit $status, max i=$got_i)" ;;
            esac
            if [ "$got" = "$want" ]; then verdict="ok     "; else verdict="BUG!   "; rc=1; fi
            printf '  %-6s %-7s want %-6s: %s %s%s\n' "$mode" "$impl" "$want" "$verdict" "$desc" "${err:+ : $err}"
        done
    done
    echo
done

if [ "$cells" -ne "$expected" ]; then
    echo "Ran $cells of $expected expected combinations -- coverage shortfall, not just a pass/fail count."
    rc=1
else
    echo "Ran all $expected expected combinations."
fi
[ "$rc" -eq 0 ] && echo "All signers gate on the upstream chain as specified." \
                || echo "At least one signer disagreed, or coverage was short -- see above."
exit "$rc"
