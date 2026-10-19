#pragma once
#include "dkim2_internal.h"

/* Public-key prefetch: as soon as the header fields are known, look up
   every distinct selector._domainkey.domain the DKIM2-Signatures name (for
   the signing algorithms implemented here), each in a thread of its own,
   so the lookups overlap each other and the body. A signature check then
   takes its key from that answer when it is definitive -- records, NXDOMAIN,
   NOERROR with no TXT -- and arrived within dkim2_prefetch_timeout_ms of
   the query being sent. Anything else (no reply in time, SERVFAIL, any
   other failure) is looked up again the ordinary synchronous way
   (dkim2_dns_getkey), so every verdict, temperror text included, is what
   the synchronous lookups give. */

typedef struct dkim2_prefetch dkim2_prefetch_t;

/* The resolver the prefetch threads use: the answer length, or -1 with
   *herr an h_errno value (HOST_NOT_FOUND, NO_DATA, TRY_AGAIN, ...). NULL
   (the default): res_nquery() on a resolver of the thread's own. A test
   seam, like dkim2_dns_query_hook. */
extern int (*dkim2_prefetch_query_hook)(const char *qname, unsigned char *answer,
                                        int anslen, int *herr);

/* How long a prefetched answer is waited for, from when it was sent. */
extern int dkim2_prefetch_timeout_ms;   /* default 5000 */

/* Start the lookups for ctx->sig_list. NULL when there is nothing to look
   up, on failure, or when keys do not come from DNS: dkim2_dns_override
   (dns.json) is set, or dkim2_dns_query_hook is without a prefetch hook. */
dkim2_prefetch_t *dkim2_prefetch_start(const dkim2_ctx_t *ctx);

/* The names being looked up (tests). */
int dkim2_prefetch_count(const dkim2_prefetch_t *pf);
const char *dkim2_prefetch_name(const dkim2_prefetch_t *pf, int i);

/* dkim2_dns_getkey(), from the prefetched answer when it settles the
   lookup (see above), else synchronously. pf may be NULL. */
dkim2_pubkey_t *dkim2_prefetch_getkey(dkim2_prefetch_t *pf, const char *selector,
    const char *domain, dkim2_status_t *statusp, const char **errp);

/* Lookups still running are left to finish on their own. */
void dkim2_prefetch_free(dkim2_prefetch_t *pf);
