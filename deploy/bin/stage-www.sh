#!/bin/bash
#
# Assemble the dkim2.com site into DEST:
#
#   deploy/bin/stage-www.sh DEST
#
# Writes the static pages (home, how/, get-ready/, try/, implementations/),
# the shared stylesheet, and deployments/index.html built from
# deploy/www/deployments/{sites,software}/*.json. Does not touch validate/ or
# verify/ (deploy.sh installs those).
#
# Every link between these pages is relative, so DEST can be the web root
# (deploy.sh does that) or a subdirectory for a preview, e.g.
#   deploy/bin/stage-www.sh /tmp/site && rsync -r --delete /tmp/site/ dkim2:/var/www/dkim2.com/preview/
#
# The site tests run first; if they fail, DEST is left untouched.

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 DEST" >&2
    exit 2
fi
DEST=$1
REPO=$(cd "$(dirname "$0")/../.." && pwd)
WWW=$REPO/deploy/www

prove "$REPO"/deploy/t/ >&2

install -d -m 755 "$DEST"
install -m 644 "$WWW/index.html" "$WWW/style.css" "$DEST/"
for page in how get-ready try implementations; do
    install -d -m 755 "$DEST/$page"
    install -m 644 "$WWW/$page/index.html" "$DEST/$page/"
done
install -d -m 755 "$DEST/deployments"
perl "$REPO/deploy/bin/build-deployments.pl" \
    --data "$WWW/deployments" \
    --template "$WWW/deployments/index.html.in" \
    --out "$DEST/deployments/index.html"
chmod 644 "$DEST/deployments/index.html"

echo ">> site staged in $DEST"
