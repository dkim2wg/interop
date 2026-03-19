#!/bin/bash
#
# setup-dkim2-demo.sh — Bootstrap a DKIM2 demonstration server on Ubuntu
#
# Usage:
#   ssh root@dkim2.com 'bash -s' < deploy/setup-dkim2-demo.sh
#
# Prerequisites:
#   - Fresh Ubuntu 22.04+ VPS
#   - DNS A record for mail.dkim2.com pointing to this server
#   - DNS MX records for dkim2.com and test1-5.dkim2.com pointing to mail.dkim2.com
#
# See deploy/README.md for full instructions.

set -euo pipefail

REPO_URL="https://github.com/dkim2wg/interop.git"
INSTALL_DIR="/opt/dkim2/interop"
KEYDIR="/etc/dkim2/keys"
SNAPSHOT_DIR="/var/spool/dkim2/snapshots"
MILTER_SOCK="/var/spool/postfix/var/run/dkim2-milter.sock"
DOMAIN="dkim2.com"
MAIL_HOST="mail.dkim2.com"
ADMIN_EMAIL="admin@dkim2.com"
TEST_DOMAINS="test1.dkim2.com test2.dkim2.com test3.dkim2.com test4.dkim2.com test5.dkim2.com"
LIST_DOMAINS="sympa.dkim2.com mailman.dkim2.com"
ALL_DOMAINS="$DOMAIN $TEST_DOMAINS $LIST_DOMAINS"

echo "=== DKIM2 Demo Server Setup ==="
echo ""

# ------------------------------------------------------------------
# 1. System packages
# ------------------------------------------------------------------
echo ">>> Installing system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq postfix libsasl2-modules certbot \
    cpanminus build-essential libssl-dev git

# ------------------------------------------------------------------
# 2. Perl dependencies (from Makefile.PL PREREQ_PM + milter)
# ------------------------------------------------------------------
echo ">>> Installing Perl dependencies..."
cpanm --notest \
    CryptX \
    Email::MIME \
    JSON::XS \
    Algorithm::Diff \
    MIME::Base64 \
    Sendmail::PMilter \
    Path::Tiny

# ------------------------------------------------------------------
# 3. System user
# ------------------------------------------------------------------
echo ">>> Creating dkim2 system user..."
if ! id dkim2 &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --groups postfix dkim2
fi

# ------------------------------------------------------------------
# 4. Clone repo
# ------------------------------------------------------------------
echo ">>> Cloning interop repository..."
mkdir -p /opt/dkim2
if [ -d "$INSTALL_DIR" ]; then
    echo "    Repository already exists, pulling latest..."
    git -C "$INSTALL_DIR" pull --ff-only
else
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

# ------------------------------------------------------------------
# 5. Generate production keys for dkim2.com
# ------------------------------------------------------------------
echo ">>> Generating production signing keys for $DOMAIN..."
mkdir -p "$KEYDIR/$DOMAIN"

if [ ! -f "$KEYDIR/$DOMAIN/sel1.key" ]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$KEYDIR/$DOMAIN/sel1.key"
    echo "    Created RSA-2048 key: $KEYDIR/$DOMAIN/sel1.key"
else
    echo "    RSA key already exists, skipping."
fi

if [ ! -f "$KEYDIR/$DOMAIN/ed25519.key" ]; then
    openssl genpkey -algorithm ed25519 \
        -out "$KEYDIR/$DOMAIN/ed25519.key"
    echo "    Created Ed25519 key: $KEYDIR/$DOMAIN/ed25519.key"
else
    echo "    Ed25519 key already exists, skipping."
fi

# ------------------------------------------------------------------
# 6. Copy interop test keys
# ------------------------------------------------------------------
echo ">>> Copying interop test keys..."

for td in $TEST_DOMAINS; do
    mkdir -p "$KEYDIR/$td"
    # Map repo key filenames to keydir structure
    # Repo: keys/sel1._domainkey.test1.dkim2.com.pem -> keydir: test1.dkim2.com/sel1.key
    for keyfile in "$INSTALL_DIR/keys/"*"._domainkey.${td}.pem"; do
        [ -f "$keyfile" ] || continue
        basename_pem=$(basename "$keyfile")
        # Extract selector: everything before ._domainkey
        selector="${basename_pem%%._domainkey.*}"
        cp "$keyfile" "$KEYDIR/$td/${selector}.key"
        echo "    $td/${selector}.key"
    done
done

# ------------------------------------------------------------------
# 7. Permissions
# ------------------------------------------------------------------
echo ">>> Setting permissions..."
chown -R dkim2:postfix "$KEYDIR"
chmod 750 "$KEYDIR"
find "$KEYDIR" -type d -exec chmod 750 {} \;
find "$KEYDIR" -name '*.key' -exec chmod 640 {} \;

mkdir -p "$SNAPSHOT_DIR"
chown -R dkim2:postfix "$SNAPSHOT_DIR"
chmod 750 "$SNAPSHOT_DIR"

# Ensure milter socket directory exists inside Postfix chroot
mkdir -p /var/spool/postfix/var/run
chown dkim2:postfix /var/spool/postfix/var/run
chmod 750 /var/spool/postfix/var/run

# ------------------------------------------------------------------
# 8. TLS certificate
# ------------------------------------------------------------------
echo ">>> Obtaining TLS certificate for $MAIL_HOST..."
if [ ! -d "/etc/letsencrypt/live/$MAIL_HOST" ]; then
    # Stop anything on port 80 temporarily
    systemctl stop postfix 2>/dev/null || true
    certbot certonly --standalone -d "$MAIL_HOST" \
        --non-interactive --agree-tos -m "$ADMIN_EMAIL"
else
    echo "    Certificate already exists, skipping."
fi

# ------------------------------------------------------------------
# 9. Postfix configuration
# ------------------------------------------------------------------
echo ">>> Configuring Postfix..."

# Build mydestination list
MYDEST="$DOMAIN"
for td in $TEST_DOMAINS $LIST_DOMAINS; do
    MYDEST="$MYDEST, $td"
done
MYDEST="$MYDEST, localhost"

# Apply config via postconf (idempotent)
postconf -e "myhostname = $MAIL_HOST"
postconf -e "mydomain = $DOMAIN"
postconf -e "myorigin = \$mydomain"
postconf -e "mydestination = $MYDEST"

# Milter — socket path relative to Postfix chroot
postconf -e "smtpd_milters = unix:var/run/dkim2-milter.sock"
postconf -e "non_smtpd_milters = unix:var/run/dkim2-milter.sock"
postconf -e "milter_default_action = accept"
postconf -e "milter_protocol = 6"

# TLS
postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/$MAIL_HOST/fullchain.pem"
postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/$MAIL_HOST/privkey.pem"
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtp_tls_security_level = may"

# Keep it lean (1GB RAM)
postconf -e "default_process_limit = 20"

# ------------------------------------------------------------------
# 10. systemd unit for milter
# ------------------------------------------------------------------
echo ">>> Installing systemd unit..."
cp "$INSTALL_DIR/deploy/dkim2-milter.service" /etc/systemd/system/
systemctl daemon-reload

# ------------------------------------------------------------------
# 11. Snapshot cleanup cron
# ------------------------------------------------------------------
echo ">>> Installing snapshot cleanup cron..."
cat > /etc/cron.d/dkim2-snapshot-cleanup <<'CRON'
# Clean up DKIM2 message snapshots older than 7 days
0 3 * * * root find /var/spool/dkim2/snapshots -type f -mtime +7 -delete
CRON
chmod 644 /etc/cron.d/dkim2-snapshot-cleanup

# ------------------------------------------------------------------
# 12. Start services
# ------------------------------------------------------------------
echo ">>> Starting services..."
systemctl enable --now dkim2-milter
systemctl restart postfix

# ------------------------------------------------------------------
# 13. Print DNS records
# ------------------------------------------------------------------
echo ""
echo "=== Setup complete ==="
echo ""
echo ">>> Generating DNS records you need to publish..."
echo ""
bash "$INSTALL_DIR/deploy/generate-dns-records.sh"
echo ""
echo "After publishing DNS records, test with:"
echo "  swaks --to test@$DOMAIN --server $MAIL_HOST"
echo "  dig +short TXT sel1._domainkey.$DOMAIN"
echo ""
echo "Logs:"
echo "  journalctl -u dkim2-milter -f"
echo "  tail -f /var/log/mail.log"
