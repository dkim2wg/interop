#!/bin/bash
#
# Shared credential redaction for the server-config snapshot. Sourced by BOTH
# deploy/capture-server-config.sh (which writes deploy/config/) and
# deploy/check-server-config.sh (which diffs live against it).
#
# It has to be shared, not duplicated: if the two scripts disagree about what a
# redacted line looks like, every affected file reads as permanent drift.
#
# dkim2wg/interop is a PUBLIC repo, so no captured file may carry a real
# credential. Redaction is keyed on the setting NAME rather than the value, so
# rotating a secret on the box cannot silently defeat it.
#
# Each Mailman secret exists under TWO spellings — once in the Mailman
# core/archiver config and once on the Django side — and both must be listed, or
# the credential is still published from the file that was missed.

# Setting names whose values are credentials. The post-capture guard checks this
# same list, so adding a name here without a matching rule in redact_config()
# fails the capture instead of leaking.
SECRET_KEYS='admin_pass|api_key|SECRET_KEY|MAILMAN_REST_API_PASS|MAILMAN_ARCHIVER_KEY'

# redact_config < file > redacted
redact_config() {
    sed -E \
        -e 's/^([[:space:]]*admin_pass[[:space:]]*:[[:space:]]*).*/\1__MAILMAN_REST_PASS__/' \
        -e 's/^([[:space:]]*api_key[[:space:]]*:[[:space:]]*).*/\1__HYPERKITTY_API_KEY__/' \
        -e "s/^([[:space:]]*SECRET_KEY[[:space:]]*=[[:space:]]*).*/\1'__DJANGO_SECRET_KEY__'/" \
        -e "s/^([[:space:]]*MAILMAN_REST_API_PASS[[:space:]]*=[[:space:]]*).*/\1'__MAILMAN_REST_PASS__'/" \
        -e "s/^([[:space:]]*MAILMAN_ARCHIVER_KEY[[:space:]]*=[[:space:]]*).*/\1'__HYPERKITTY_API_KEY__'/"
}

# Non-zero if any line still holds a real credential (a SECRET_KEYS setting whose
# value is not a __PLACEHOLDER__).
redact_leaks() {
    grep -rnE "^[[:space:]]*($SECRET_KEYS)[[:space:]]*[:=]" "$@" | grep -v '__'
}
