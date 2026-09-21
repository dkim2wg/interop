#!/bin/sh
# Run by certbot after any successful renewal (deploy hook).
# nginx serves dkim2.com/www/mailman/sympa; postfix uses mail.dkim2.com.
# Both only read cert files at (re)start, so reload them here.
set -e
systemctl reload nginx
systemctl reload postfix
