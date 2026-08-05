#!/bin/bash
#
# Cross-implementation interop matrix for two spec-04 behaviours that only show
# up when implementations meet each other:
#
#   1. Folding whitespace in tag values (§2.12).  FWS may appear inside a base64
#      string and around the colons of an s= item, and MUST be ignored when the
#      value is used.  A signer that folds long headers (which is normal) must
#      not break any verifier.  The awkward position is a fold between the
#      selector colon and the algorithm token.
#
#   2. Recipe-less Message-Instance (§9.1/§9.2.5).  A hop that leaves both
#      hashes unchanged adds no Message-Instance at all and reuses the existing
#      m=.  A recipe-less instance is legal to receive (it asserts no change),
#      so every verifier must accept one, but no signer should produce one.
#
# Every signer's output is checked by every verifier.  Run from the repo root:
#
#   ./util/interop-fold-mi.sh
#
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

DNS="$ROOT/dns.json"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

TS=1740000000
PASS=0
FAIL=0

key() { echo "$ROOT/keys/sel1._domainkey.$1.pem"; }

have_go=0;   command -v go >/dev/null 2>&1 && [ -d "$ROOT/go" ] && have_go=1
have_c=0;    [ -x "$ROOT/c/dkim2verify" ] && [ -x "$ROOT/c/dkim2sign" ] && have_c=1
have_perl=0; [ -d "$ROOT/perl/lib" ] && have_perl=1

[ -f "$DNS" ] || { echo "missing dns.json — run 'make' first"; exit 1; }

# ---------------------------------------------------------------------------
# Verifier drivers.  Each takes a message path and exits 0 on pass.
# ---------------------------------------------------------------------------
verify_python() {
    python3 "$ROOT/python/dkim2verify.py" --dns-json "$DNS" \
        --ignore-timestamps "$1" >/dev/null 2>&1
}
verify_go() {
    (cd "$ROOT/go" && go run ./cmd/dkim2verify -dns "$DNS" \
        -ignore-timestamps < "$1" >/dev/null 2>&1)
}
verify_c() {
    "$ROOT/c/dkim2verify" "$1" --dns-json "$DNS" --ignore-timestamps >/dev/null 2>&1
}
verify_perl() {
    perl -I"$ROOT/perl/lib" -e '
        use strict; use warnings;
        use Path::Tiny; use JSON;
        use Mail::DKIM2::Common qw(parse_dkim_pubkey);
        use Mail::DKIM2::Verifier;
        my ($dnsfile, $msgfile) = @ARGV;
        my $dns = decode_json(path($dnsfile)->slurp);
        my $raw = do { local $/; open my $fh, "<:raw", $msgfile or die $!; <$fh> };
        my $v = Mail::DKIM2::Verifier->new();
        $v->set_pubkey_callback(sub {
            my ($sig, $idx) = @_; $idx //= 0;
            my $txt = $dns->{$sig->domain}{$sig->selector($idx)."._domainkey"}[0][1];
            return parse_dkim_pubkey($txt);
        });
        $v->skip_timestamp_check(1);
        $v->PRINT($raw); $v->CLOSE;
        exit($v->result eq "pass" ? 0 : 1);
    ' "$DNS" "$1" >/dev/null 2>&1
}

VERIFIERS="python"
[ $have_go   = 1 ] && VERIFIERS="$VERIFIERS go"
[ $have_c    = 1 ] && VERIFIERS="$VERIFIERS c"
[ $have_perl = 1 ] && VERIFIERS="$VERIFIERS perl"

check_all_verify() {
    local msg="$1" desc="$2"
    for v in $VERIFIERS; do
        if "verify_$v" "$msg"; then
            PASS=$((PASS + 1))
        else
            FAIL=$((FAIL + 1))
            echo "  FAIL  $desc -> $v rejected it"
        fi
    done
}

# ---------------------------------------------------------------------------
# Base message and a single-hop signature
# ---------------------------------------------------------------------------
printf 'From: sender@test1.dkim2.com\r\nTo: rcpt@test2.dkim2.com\r\nSubject: interop fold/mi\r\nDate: Fri, 24 Jul 2026 12:00:00 +0000\r\nMessage-ID: <interop@test1.dkim2.com>\r\n\r\nHello interop world.\r\n' \
    > "$WORK/base.eml"

python3 "$ROOT/python/dkim2sign.py" -s sel1 -d test1.dkim2.com \
    -k "$(key test1.dkim2.com)" --mailfrom '<sender@test1.dkim2.com>' \
    --rcptto '<rcpt@test2.dkim2.com>' --timestamp $TS \
    "$WORK/base.eml" > "$WORK/hop1.eml"

# ---------------------------------------------------------------------------
# 1. Folding: insert a fold at each position, every verifier must still pass
# ---------------------------------------------------------------------------
echo "== §2.12 folding whitespace in tag values =="

fold_at() {  # fold_at <name> <python-regex> <replacement>
    python3 - "$WORK/hop1.eml" "$2" "$3" <<'PY' > "$WORK/fold.eml"
import re, sys
path, pattern, repl = sys.argv[1], sys.argv[2], sys.argv[3]
# newline="" — text mode would translate CRLF to LF and silently corrupt the
# signed bytes.
data = open(path, encoding="utf-8", newline="").read()
head, sep, body = data.partition("\r\n\r\n")
logical = []
for line in head.split("\r\n"):
    if line[:1] in (" ", "\t") and logical:
        logical[-1] += " " + line.lstrip()
    else:
        logical.append(line)
out = []
for h in logical:
    name = h.split(":", 1)[0].lower()
    out.append(re.sub(pattern, repl, h)
               if name in ("dkim2-signature", "message-instance") else h)
sys.stdout.write("\r\n".join(out) + sep + body)
PY
    if cmp -s "$WORK/fold.eml" "$WORK/hop1.eml"; then
        echo "  FAIL  $1: fold was not actually inserted"
        FAIL=$((FAIL + 1))
        return
    fi
    check_all_verify "$WORK/fold.eml" "fold in $1"
}

check_all_verify "$WORK/hop1.eml" "unfolded baseline"
fold_at "mf= base64"   '(mf=)([A-Za-z0-9+/=]{6})'       '\1\2\r\n\t'
fold_at "rt= base64"   '(rt=)([A-Za-z0-9+/=]{6})'       '\1\2\r\n\t'
fold_at "s= selector"  '(s=[A-Za-z0-9_-]+:)'            '\1\r\n\t'
fold_at "s= algorithm" '(:rsa-sha256:)'                 '\1\r\n\t'
fold_at "h= hashes"    '(h=sha256:)([A-Za-z0-9+/=]{6})' '\1\2\r\n\t'

# ---------------------------------------------------------------------------
# 2. Recipe-less Message-Instance: no signer emits one on an unchanged relay,
#    and every verifier accepts one that arrives anyway.
# ---------------------------------------------------------------------------
echo "== §9.1/§9.2.5 unchanged hop reuses the instance =="

count_hdr() { grep -ci "^$1:" "$2" | tr -d ' '; }

resign_python() {
    python3 "$ROOT/python/dkim2sign.py" -s sel1 -d test2.dkim2.com \
        -k "$(key test2.dkim2.com)" --mailfrom '<sender@test2.dkim2.com>' \
        --rcptto '<final@test3.dkim2.com>' --timestamp $((TS + 100)) "$1" > "$2"
}
resign_go() {
    (cd "$ROOT/go" && go run ./cmd/dkim2sign -selector sel1 -domain test2.dkim2.com \
        -key "$(key test2.dkim2.com)" -mail-from '<sender@test2.dkim2.com>' \
        -rcpt-to '<final@test3.dkim2.com>' -timestamp $((TS + 100)) < "$1" > "$2")
}
resign_c() {
    "$ROOT/c/dkim2sign" "$1" -s sel1 -d test2.dkim2.com \
        -k "$(key test2.dkim2.com)" --mailfrom '<sender@test2.dkim2.com>' \
        --rcptto '<final@test3.dkim2.com>' --timestamp $((TS + 100)) > "$2"
}
resign_perl() {
    perl "$ROOT/perl/bin/dkim2sign.pl" -s sel1 -d test2.dkim2.com \
        -k "$(key test2.dkim2.com)" --mailfrom '<sender@test2.dkim2.com>' \
        --rcptto '<final@test3.dkim2.com>' --timestamp $((TS + 100)) "$1" > "$2"
}

SIGNERS="python"
[ $have_go   = 1 ] && SIGNERS="$SIGNERS go"
[ $have_c    = 1 ] && SIGNERS="$SIGNERS c"
[ $have_perl = 1 ] && SIGNERS="$SIGNERS perl"

for s in $SIGNERS; do
    out="$WORK/resign_$s.eml"
    if ! "resign_$s" "$WORK/hop1.eml" "$out"; then
        echo "  FAIL  $s signer errored on an unchanged relay"
        FAIL=$((FAIL + 1))
        continue
    fi
    n_mi=$(count_hdr "Message-Instance" "$out")
    n_sig=$(count_hdr "DKIM2-Signature" "$out")
    if [ "$n_mi" = "1" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL  $s signer added a Message-Instance on an unchanged relay ($n_mi present)"
    fi
    if [ "$n_sig" = "2" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL  $s signer produced $n_sig DKIM2-Signature headers, expected 2"
    fi
    # The new signature must reference the reused instance (m=1).
    if grep -i "^DKIM2-Signature:" "$out" | grep -q "i=2; m=1;"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL  $s signer's i=2 signature does not reference the reused m=1"
    fi
    check_all_verify "$out" "$s unchanged relay"
done

echo "== recipe-less instance from an upstream is accepted =="

# Graft a recipe-less m=2 carrying the same hashes as m=1, then re-sign so a
# signature covers it.
python3 - "$WORK/hop1.eml" <<'PY' > "$WORK/grafted.eml"
import re, sys
data = open(sys.argv[1], encoding="utf-8", newline="").read()
mi = re.search(r"^Message-Instance:[^\r\n]*(?:\r\n[ \t][^\r\n]*)*\r\n", data, re.M)
if mi is None:
    sys.exit("no Message-Instance header found")
sys.stdout.write(mi.group(0).replace("m=1;", "m=2;", 1) + data)
PY
resign_python "$WORK/grafted.eml" "$WORK/recipeless.eml"
n_mi=$(count_hdr "Message-Instance" "$WORK/recipeless.eml")
if [ "$n_mi" = "2" ]; then
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
    echo "  FAIL  fixture should carry the recipe-less m=2 ($n_mi MIs present)"
fi
check_all_verify "$WORK/recipeless.eml" "recipe-less m=2 from upstream"

echo ""
echo "verifiers: $VERIFIERS"
echo "signers:   $SIGNERS"
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" = "0" ]
