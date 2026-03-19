#!/bin/bash
#
# generate-dns-records.sh — Extract public keys and output DNS zone fragments
#
# Reads keys from /etc/dkim2/keys/ (production) and the interop repo's
# dns.json (test domains) to produce TXT records for DKIM2 selectors,
# plus MX/SPF/DMARC records needed for the demo server.
#
# Usage:
#   bash deploy/generate-dns-records.sh

set -euo pipefail

KEYDIR="${KEYDIR:-/etc/dkim2/keys}"
DOMAIN="dkim2.com"
MAIL_HOST="mail.dkim2.com"
TEST_DOMAINS="test1.dkim2.com test2.dkim2.com test3.dkim2.com test4.dkim2.com test5.dkim2.com"
LIST_DOMAINS="sympa.dkim2.com mailman.dkim2.com"

echo "; ============================================"
echo "; DNS records for DKIM2 demo server"
echo "; ============================================"
echo ""

# ------------------------------------------------------------------
# MX records
# ------------------------------------------------------------------
echo "; --- MX records ---"
echo "$DOMAIN.    IN  MX  10  $MAIL_HOST."
for td in $TEST_DOMAINS $LIST_DOMAINS; do
    echo "$td.    IN  MX  10  $MAIL_HOST."
done
echo ""

# ------------------------------------------------------------------
# A records for mailing list subdomains
# ------------------------------------------------------------------
echo "; --- A records (mailing list subdomains) ---"
for td in $LIST_DOMAINS; do
    echo "$td.    IN  A  134.209.211.166"
done
echo ""

# ------------------------------------------------------------------
# SPF
# ------------------------------------------------------------------
echo "; --- SPF ---"
echo "$DOMAIN.    IN  TXT  \"v=spf1 a mx -all\""
for td in $TEST_DOMAINS $LIST_DOMAINS; do
    echo "$td.    IN  TXT  \"v=spf1 a mx -all\""
done
echo ""

# ------------------------------------------------------------------
# DMARC
# ------------------------------------------------------------------
echo "; --- DMARC (relaxed for demo) ---"
echo "_dmarc.$DOMAIN.    IN  TXT  \"v=DMARC1; p=none; rua=mailto:dmarc@$DOMAIN\""
for td in $TEST_DOMAINS $LIST_DOMAINS; do
    echo "_dmarc.$td.    IN  TXT  \"v=DMARC1; p=none\""
done
echo ""

# ------------------------------------------------------------------
# Production DKIM2 selector records (from generated keys)
# ------------------------------------------------------------------
echo "; --- DKIM2 selector records (production: $DOMAIN) ---"

if [ -d "$KEYDIR/$DOMAIN" ]; then
    for keyfile in "$KEYDIR/$DOMAIN"/*.key; do
        [ -f "$keyfile" ] || continue
        selector=$(basename "$keyfile" .key)
        filesize=$(stat -c%s "$keyfile" 2>/dev/null || stat -f%z "$keyfile")

        if [ "$filesize" -lt 500 ]; then
            # Ed25519 key — extract raw public key
            pubkey=$(openssl pkey -in "$keyfile" -pubout -outform DER 2>/dev/null \
                | tail -c 32 | openssl base64 -A)
            echo "${selector}._domainkey.$DOMAIN.    IN  TXT  \"v=DKIM1; k=ed25519; p=$pubkey\""
        else
            # RSA key — extract public key in DER, base64
            pubkey=$(openssl rsa -in "$keyfile" -pubout -outform DER 2>/dev/null \
                | openssl base64 -A)
            echo "${selector}._domainkey.$DOMAIN.    IN  TXT  \"v=DKIM1; k=rsa; p=$pubkey\""
        fi
    done
else
    echo "; WARNING: $KEYDIR/$DOMAIN not found — run setup first to generate keys"
fi
echo ""

# ------------------------------------------------------------------
# Test domain DKIM2 selector records (from dns.json)
# ------------------------------------------------------------------
echo "; --- DKIM2 selector records (test domains from dns.json) ---"

REPO_DIR="$(dirname "$0")/.."
DNS_JSON="$REPO_DIR/dns.json"

if [ -f "$DNS_JSON" ]; then
    # Use perl to parse dns.json and emit zone records (only for testN.dkim2.com)
    perl -MJSON::XS -e '
        local $/;
        my $data = decode_json(<STDIN>);
        for my $domain (sort keys %$data) {
            next unless $domain =~ /\.dkim2\.com$/;
            for my $sel (sort keys %{$data->{$domain}}) {
                my $val = $data->{$domain}{$sel}[0][1];
                print "${sel}.${domain}.    IN  TXT  \"$val\"\n";
            }
        }
    ' < "$DNS_JSON"
else
    echo "; WARNING: dns.json not found at $DNS_JSON"
fi
echo ""

echo "; --- End of DNS records ---"
echo "; Remember to also set:"
echo ";   A record:   $MAIL_HOST -> <VPS IP>"
echo ";   PTR record: <VPS IP> -> $MAIL_HOST"
