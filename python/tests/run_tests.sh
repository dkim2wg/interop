#!/bin/bash
#
# DKIM2 signing test suite
#
# Generates signed messages and compares against expected output.
# Run with --generate to create/update expected output files.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_DIR="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="$(dirname "$PYTHON_DIR")/keys"
EMAILS_DIR="$SCRIPT_DIR/emails"
EXPECTED_DIR="$SCRIPT_DIR/expected"
SIGNER="$PYTHON_DIR/dkim2sign.py"

# Activate venv if present
if [ -f "$PYTHON_DIR/venv/bin/activate" ]; then
    source "$PYTHON_DIR/venv/bin/activate"
fi

# Fixed timestamp for reproducibility
TIMESTAMP=1740000000

GENERATE=false
if [ "${1:-}" = "--generate" ]; then
    GENERATE=true
    mkdir -p "$EXPECTED_DIR"
    echo "Generating expected output files..."
fi

PASS=0
FAIL=0
ERRORS=""

run_test() {
    local name="$1"
    local email="$2"
    local selector="$3"
    local domain="$4"
    local keyfile="$5"
    local mailfrom="$6"
    shift 6
    local rcptto_args=("$@")

    local outfile="$EXPECTED_DIR/${name}.eml"

    # Build rcptto flags
    local rcptto_flags=()
    for r in "${rcptto_args[@]}"; do
        rcptto_flags+=(--rcptto "$r")
    done

    local result
    result=$(python3 "$SIGNER" "$email" \
        -s "$selector" -d "$domain" -k "$keyfile" \
        --mailfrom "$mailfrom" --timestamp "$TIMESTAMP" \
        "${rcptto_flags[@]}" 2>&1)

    if [ "$GENERATE" = true ]; then
        printf '%s' "$result" > "$outfile"
        echo "  GENERATED: $name"
        return
    fi

    if [ ! -f "$outfile" ]; then
        echo "  MISSING:   $name (run with --generate first)"
        FAIL=$((FAIL + 1))
        ERRORS="${ERRORS}  ${name}: expected file missing\n"
        return
    fi

    local expected
    expected=$(cat "$outfile")

    if [ "$result" = "$expected" ]; then
        echo "  PASS:      $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL:      $name"
        FAIL=$((FAIL + 1))
        ERRORS="${ERRORS}  ${name}: output differs from expected\n"
        diff <(echo "$expected") <(echo "$result") | head -20
    fi
}

echo "=== DKIM2 Signing Tests ==="
echo ""

# Test 1: Simple message with Ed25519
run_test "simple-ed25519" \
    "$EMAILS_DIR/simple.eml" \
    "ed25519" "test1.dkim2.com" \
    "$KEYS_DIR/ed25519._domainkey.test1.dkim2.com.pem" \
    "sender@test1.dkim2.com" \
    "recipient@example.com"

# Test 2: Simple message with RSA-1024
run_test "simple-rsa1024" \
    "$EMAILS_DIR/simple.eml" \
    "rsa1024" "test1.dkim2.com" \
    "$KEYS_DIR/rsa1024._domainkey.test1.dkim2.com.pem" \
    "sender@test1.dkim2.com" \
    "recipient@example.com"

# Test 3: Simple message with RSA-2048 (sel1)
run_test "simple-rsa2048" \
    "$EMAILS_DIR/simple.eml" \
    "sel1" "test1.dkim2.com" \
    "$KEYS_DIR/sel1._domainkey.test1.dkim2.com.pem" \
    "sender@test1.dkim2.com" \
    "recipient@example.com"

# Test 4: Multi-header message with continuation lines, X- header excluded
run_test "multiheader-ed25519" \
    "$EMAILS_DIR/multiheader.eml" \
    "ed25519" "test2.dkim2.com" \
    "$KEYS_DIR/ed25519._domainkey.test2.dkim2.com.pem" \
    "sender@test2.dkim2.com" \
    "recipient@example.com"

# Test 5: Message with trailing blank lines (body canonicalization)
run_test "trailingblank-ed25519" \
    "$EMAILS_DIR/trailingblank.eml" \
    "ed25519" "test3.dkim2.com" \
    "$KEYS_DIR/ed25519._domainkey.test3.dkim2.com.pem" \
    "sender@test3.dkim2.com" \
    "recipient@example.com"

# Test 6: Empty body message
run_test "emptybody-ed25519" \
    "$EMAILS_DIR/emptybody.eml" \
    "ed25519" "test4.dkim2.com" \
    "$KEYS_DIR/ed25519._domainkey.test4.dkim2.com.pem" \
    "sender@test4.dkim2.com" \
    "recipient@example.com"

# Test 7: Multiple recipients
run_test "multirecipient-ed25519" \
    "$EMAILS_DIR/multirecipient.eml" \
    "ed25519" "test5.dkim2.com" \
    "$KEYS_DIR/ed25519._domainkey.test5.dkim2.com.pem" \
    "sender@test5.dkim2.com" \
    "alice@example.com" "bob@example.com" "charlie@example.com"

# Test 8: DSN (empty MAIL FROM)
run_test "dsn-ed25519" \
    "$EMAILS_DIR/simple.eml" \
    "ed25519" "test1.dkim2.com" \
    "$KEYS_DIR/ed25519._domainkey.test1.dkim2.com.pem" \
    "<>" \
    "recipient@example.com"

# Test 9: Different selectors on same domain (sel2)
run_test "simple-sel2" \
    "$EMAILS_DIR/simple.eml" \
    "sel2" "test1.dkim2.com" \
    "$KEYS_DIR/sel2._domainkey.test1.dkim2.com.pem" \
    "sender@test1.dkim2.com" \
    "recipient@example.com"

# Test 10: Different selectors on same domain (sel3)
run_test "simple-sel3" \
    "$EMAILS_DIR/simple.eml" \
    "sel3" "test1.dkim2.com" \
    "$KEYS_DIR/sel3._domainkey.test1.dkim2.com.pem" \
    "sender@test1.dkim2.com" \
    "recipient@example.com"

# Test 11: Duplicate headers (bottom-up ordering)
run_test "dupheaders-ed25519" \
    "$EMAILS_DIR/dupheaders.eml" \
    "ed25519" "test1.dkim2.com" \
    "$KEYS_DIR/ed25519._domainkey.test1.dkim2.com.pem" \
    "sender@test1.dkim2.com" \
    "recipient@example.com"

echo ""
if [ "$GENERATE" = true ]; then
    echo "Expected output files generated in $EXPECTED_DIR"
    echo ""
fi

# ---------------------------------------------------------------------------
# Multi-hop tests (generated via Python)
# ---------------------------------------------------------------------------

MULTIHOP_GEN="$SCRIPT_DIR/generate_multihop.py"

echo "=== DKIM2 Multi-hop Tests ==="
echo ""

if [ "$GENERATE" = true ]; then
    python3 "$MULTIHOP_GEN"
    echo ""
fi

# ---------------------------------------------------------------------------
# Verification tests - verify each expected output file
# ---------------------------------------------------------------------------

DNS_JSON="$(dirname "$PYTHON_DIR")/dns.json"
VERIFIER="$PYTHON_DIR/dkim2verify.py"

echo "=== DKIM2 Verification Tests ==="
echo ""

for signed in "$EXPECTED_DIR"/*.eml; do
    name="$(basename "$signed" .eml)"

    # Use --full-chain for multihop tests
    CHAIN_FLAG=""
    if [[ "$name" == multihop-* ]]; then
        CHAIN_FLAG="--full-chain"
    fi

    if python3 "$VERIFIER" "$signed" --dns-json "$DNS_JSON" $CHAIN_FLAG --skip-timestamp-check 2>/dev/null; then
        echo "  PASS:      verify $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL:      verify $name"
        FAIL=$((FAIL + 1))
        ERRORS="${ERRORS}  verify ${name}: signature verification failed\n"
        python3 "$VERIFIER" "$signed" --dns-json "$DNS_JSON" $CHAIN_FLAG --skip-timestamp-check -v 2>&1 | head -10
    fi
done

echo ""
echo "Results: $PASS passed, $FAIL failed"
if [ -n "$ERRORS" ]; then
    echo ""
    echo "Failures:"
    printf "$ERRORS"
    exit 1
fi
