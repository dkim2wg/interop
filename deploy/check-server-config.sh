#!/bin/bash
#
# Report drift between this server's live configuration and the tracked snapshot
# in deploy/config/. Run ON the server (deploy.sh calls it last):
#
#   deploy/check-server-config.sh
#
# Exits 0 when clean, 1 when anything has drifted. deploy.sh treats a non-zero
# exit as a WARNING, not a gate: a stale snapshot must be visible on the next
# deploy, but must never block shipping a signing fix.
#
# Refresh the snapshot from your local checkout with:
#   deploy/capture-server-config.sh
#
# Lines holding a redacted placeholder (__FOO__) are skipped -- the real values
# are not in the repo, so they can never match.

set -uo pipefail   # NOT -e: every file must be checked even after a diff

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SRC="$REPO/deploy/config"
drift=0

# compare <live-path> <tracked-relative-path>
compare() {
    local live=$1 tracked="$SRC/$2"
    if [ ! -r "$tracked" ]; then
        echo "   ?? not tracked: $2"; drift=1; return
    fi
    if [ ! -r "$live" ]; then
        echo "   !! missing on server: $live (tracked as $2)"; drift=1; return
    fi
    # Drop placeholder lines from BOTH sides so a redacted secret never reads as
    # drift; the line is removed by position, so a genuine change elsewhere in
    # the file is still caught.
    if ! diff -q <(grep -v '__[A-Z_]*__' "$tracked") \
                 <(grep -v '__[A-Z_]*__' "$live") >/dev/null; then
        echo "   ~~ DRIFTED: $2"
        diff -u <(grep -v '__[A-Z_]*__' "$tracked") \
                <(grep -v '__[A-Z_]*__' "$live") | sed -n '3,12p' | sed 's/^/      /'
        drift=1
    fi
}

for site in dkim2.com mail.dkim2.com mailman.dkim2.com sympa.dkim2.com; do
    compare "/etc/nginx/sites-available/$site" "nginx/$site"
done
compare /etc/mailman3/mailman.cfg            mailman3/mailman.cfg
compare /etc/mailman3/mailman-hyperkitty.cfg mailman3/mailman-hyperkitty.cfg
compare /etc/mailman3/web/settings.py        mailman3/web-settings.py
compare /etc/sympa/sympa/sympa.conf          sympa/sympa.conf
compare /etc/sympa/sympa/aliases             sympa/aliases
compare /etc/postfix/master.cf               postfix/master.cf.live
compare /etc/aliases                         aliases

# main.cf is compared as `postconf -n` (normalised, defaults elided) rather than
# the raw file, which is how it was captured.
if ! diff -q <(postconf -n) "$SRC/postfix/main.cf.live" >/dev/null; then
    echo "   ~~ DRIFTED: postfix/main.cf.live (postconf -n)"
    diff -u "$SRC/postfix/main.cf.live" <(postconf -n) | sed -n '3,12p' | sed 's/^/      /'
    drift=1
fi

# Installed code, not config, so it lives at deploy/ top level.
compare /usr/local/bin/sympa-sendmail "../sympa-sendmail"

if [ "$drift" -eq 0 ]; then
    echo ">> server config matches deploy/config/"
else
    echo ">> server config has DRIFTED from deploy/config/ (see above)"
    echo "   refresh from your local checkout: deploy/capture-server-config.sh"
fi
exit "$drift"
