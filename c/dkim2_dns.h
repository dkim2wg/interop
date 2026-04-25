#pragma once
#include "dkim2_internal.h"

/* Look up the DKIM public key for selector._domainkey.domain.
   On success: returns allocated dkim2_pubkey_t, sets *statusp = DKIM2_OK.
   On failure: returns NULL, sets *statusp and *errp appropriately.
   TEMPERROR → DNS timeout/transient; PERMERROR → absent/malformed/revoked. */
dkim2_pubkey_t *dkim2_dns_getkey(const char *selector, const char *domain,
    dkim2_status_t *statusp, const char **errp);

void dkim2_pubkey_free(dkim2_pubkey_t *k);
