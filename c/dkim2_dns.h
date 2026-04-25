#pragma once
#include "dkim2_internal.h"

/* Optional DNS override hook for testing.
   If non-NULL, called with the query name before live DNS.
   Return malloc'd TXT string to use, or NULL to fall through to live DNS. */
extern char *(*dkim2_dns_override)(const char *qname);

/* Look up the DKIM public key for selector._domainkey.domain.
   On success: returns allocated dkim2_pubkey_t, sets *statusp = DKIM2_OK.
   On failure: returns NULL, sets *statusp and *errp appropriately.
   TEMPERROR → DNS timeout/transient; PERMERROR → absent/malformed/revoked. */
dkim2_pubkey_t *dkim2_dns_getkey(const char *selector, const char *domain,
    dkim2_status_t *statusp, const char **errp);

void dkim2_pubkey_free(dkim2_pubkey_t *k);
