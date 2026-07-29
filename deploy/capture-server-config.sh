#!/bin/bash
#
# Capture the demo server's configuration into deploy/config/.
#
# Run this LOCALLY (it fetches over ssh), matching the normal workflow where you
# edit in your checkout and the box pulls:
#
#   deploy/capture-server-config.sh [ssh-host]      # default host: dkim2
#
# Why this exists: deploy/ used to cover only the DKIM2 mail path. The nginx
# vhosts, both list managers' configuration, the live Postfix state and
# /usr/local/bin/sympa-sendmail existed ONLY on the server -- losing the box
# meant reconstructing them from SERVER.md prose. This script makes refreshing
# the tracked snapshot one command, so it can't rot silently again. Its
# counterpart deploy/check-server-config.sh (run ON the box by deploy.sh)
# reports when live and tracked have diverged.
#
# SECRETS: dkim2wg/interop is a PUBLIC repo. Three values are replaced with
# placeholders on the way in (see redact() below). Nothing else in the captured
# set contains a credential -- sympa.conf uses SQLite with no password, and the
# nginx vhosts reference certificate PATHS, not keys. If you add a file here,
# check it for secrets first.
#
# Restore is a documented sequence in SERVER.md ("Restoring server config"), not
# a script: rebuilding the box also means apt-installing mailman3/sympa/nginx,
# which no amount of captured config replaces.

set -euo pipefail

HOST=${1:-dkim2}
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEST="$REPO/deploy/config"

echo ">> capturing $HOST config into deploy/config/"

# Keys whose values are credentials. Each appears under two names -- once in the
# Mailman core/archiver config and once on the Django side of the same secret --
# so both spellings must be redacted or the credential is still published.
SECRET_KEYS='admin_pass|api_key|SECRET_KEY|MAILMAN_REST_API_PASS|MAILMAN_ARCHIVER_KEY'

# Replace credentials with placeholders. Keyed on the setting NAME, not the
# value, so rotating a secret on the box does not silently defeat the redaction.
redact() {
    sed -E \
        -e 's/^([[:space:]]*admin_pass[[:space:]]*:[[:space:]]*).*/\1__MAILMAN_REST_PASS__/' \
        -e 's/^([[:space:]]*api_key[[:space:]]*:[[:space:]]*).*/\1__HYPERKITTY_API_KEY__/' \
        -e "s/^([[:space:]]*SECRET_KEY[[:space:]]*=[[:space:]]*).*/\1'__DJANGO_SECRET_KEY__'/" \
        -e "s/^([[:space:]]*MAILMAN_REST_API_PASS[[:space:]]*=[[:space:]]*).*/\1'__MAILMAN_REST_PASS__'/" \
        -e "s/^([[:space:]]*MAILMAN_ARCHIVER_KEY[[:space:]]*=[[:space:]]*).*/\1'__HYPERKITTY_API_KEY__'/"
}

# fetch <remote-path> <dest-relative-path>
fetch() {
    local src=$1 dst="$DEST/$2"
    mkdir -p "$(dirname "$dst")"
    if ! ssh "$HOST" "test -r '$src'"; then
        echo "   !! MISSING on server: $src" >&2
        return 1
    fi
    ssh "$HOST" "cat '$src'" | redact > "$dst"
    echo "   $2"
}

# nginx vhosts: sites-available is the source of truth (sites-enabled symlinks).
for site in dkim2.com mail.dkim2.com mailman.dkim2.com sympa.dkim2.com; do
    fetch "/etc/nginx/sites-available/$site" "nginx/$site"
done

# Mailman 3: core, archiver bridge, and the Django web settings.
fetch /etc/mailman3/mailman.cfg              mailman3/mailman.cfg
fetch /etc/mailman3/mailman-hyperkitty.cfg   mailman3/mailman-hyperkitty.cfg
fetch /etc/mailman3/web/settings.py          mailman3/web-settings.py

# Sympa: the live conf (the /etc/sympa/sympa/ dir also holds ~150 dated backup
# copies -- only the live one is tracked) and its Postfix alias file.
fetch /etc/sympa/sympa/sympa.conf            sympa/sympa.conf
fetch /etc/sympa/sympa/aliases               sympa/aliases

# Postfix live state. main.cf.live is `postconf -n`, which records the real
# transport_maps / local_recipient_maps values that postfix-main.cf.patch
# deliberately leaves out (it can only document, not carry, multi-map settings).
mkdir -p "$DEST/postfix"
ssh "$HOST" 'postconf -n' > "$DEST/postfix/main.cf.live"
echo "   postfix/main.cf.live"
ssh "$HOST" 'cat /etc/postfix/master.cf' > "$DEST/postfix/master.cf.live"
echo "   postfix/master.cf.live"

fetch /etc/aliases aliases

# The one outbound script that exists nowhere but the box. Lives at deploy/ top
# level, not under config/, because it is installed code rather than config.
ssh "$HOST" 'cat /usr/local/bin/sympa-sendmail' > "$REPO/deploy/sympa-sendmail"
chmod 755 "$REPO/deploy/sympa-sendmail"
echo "   ../sympa-sendmail"

# Fail loudly if a redaction missed: better to abort than to commit a credential.
# Checked against the same SECRET_KEYS list the redactions are built from, so
# adding a key there without a matching sed rule fails here instead of leaking.
if grep -rnE "^[[:space:]]*($SECRET_KEYS)[[:space:]]*[:=]" "$DEST" | grep -v '__'; then
    echo "!! a credential survived redaction -- do NOT commit" >&2
    exit 1
fi

echo ">> capture complete; review with: git -C $REPO diff deploy/"
