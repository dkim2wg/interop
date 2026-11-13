#!/bin/bash
#
# Assemble the dkim2.com site into DEST:
#
#   deploy/bin/stage-www.sh DEST
#
# Writes the static pages (home, how/, get-ready/, try/, implementations/),
# the shared stylesheets, deployments/index.html built from
# deploy/www/deployments/{sites,software}/*.json, and the two verifier tools
# (verify/ in the browser, validate/ on the server).
#
# Every link between these pages is relative, so DEST can be the web root
# (deploy.sh does that) or a subdirectory for a preview, e.g.
#   deploy/bin/stage-www.sh /tmp/site && rsync -r --delete /tmp/site/ dkim2:/var/www/dkim2.com/preview/
#
# Run it from deploy.sh before anything else is installed: the site tests run
# first, and if they fail DEST is left untouched.

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
install -m 644 "$WWW/index.html" "$WWW/style.css" "$WWW/nav.css" "$DEST/"
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

# The tools. The validator's assets are cache-busted with the commit, so
# browsers fetch fresh JS/CSS after a deploy; its API stays at /validate/api,
# so a preview copy still talks to the live CGI.
install -d -m 755 "$DEST/validate" "$DEST/verify"
install -m 644 "$WWW"/validate/*.html "$WWW"/validate/*.css "$WWW"/validate/*.js "$DEST/validate/"
VER=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || date +%s)
sed -i.bak "s/__VER__/$VER/g" "$DEST/validate/index.html" && rm -f "$DEST/validate/index.html.bak"
install -m 644 "$WWW"/verify/*.html "$WWW"/verify/*.css "$WWW"/verify/*.js "$DEST/verify/"

echo ">> site staged in $DEST"
