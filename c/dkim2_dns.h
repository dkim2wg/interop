#pragma once
#include "dkim2_internal.h"

/* Optional DNS override hook for testing (and dns.json harness use).
   If non-NULL, called with the query name before live DNS; *n_records is 1
   on entry. Return a malloc'd TXT string (one record, its strings already
   concatenated) to use; set *n_records > 1 as well to report that the name
   has several TXT records. Return NULL with *n_records == 0 for "absent"
   (NXDOMAIN / no TXT), NULL with *n_records < 0 for a DNS failure, or NULL
   leaving *n_records alone to fall through to live DNS. */
extern char *(*dkim2_dns_override)(const char *qname, int *n_records);

/* Test seam below the override: if non-NULL, used instead of res_query() for
   the TXT query (same contract: returns the answer length, or -1). Lets tests
   feed wire-format RRsets -- several RRs, one RR in several strings. */
extern int (*dkim2_dns_query_hook)(const char *qname, unsigned char *answer, int anslen);

/* *errp values (-08 §14.5 wording, to follow "public key <selector> ").
   The first five mean a record is present but unusable; ABSENT and FETCH
   are lookup outcomes. ("OOM" is the only other value, as TEMPERROR.) */
extern const char DKIM2_KEYERR_MULTIPLE[];  /* "has multiple records" */
extern const char DKIM2_KEYERR_SYNTAX[];    /* "has a syntax error" */
extern const char DKIM2_KEYERR_REVOKED[];   /* "has been revoked" */
extern const char DKIM2_KEYERR_ALG[];       /* "algorithm mismatch" (unknown k=) */
extern const char DKIM2_KEYERR_MALFORMED[]; /* "is malformed": p= is base64 but no
                                               key of its type -- an Ed25519 key
                                               not 32 octets, an RSA key that
                                               does not load or is under 1024
                                               bits (-08 §3.2, §14.5; D7) */

extern const char DKIM2_KEYERR_ABSENT[];   /* "does not exist" (PERMERROR) */
extern const char DKIM2_KEYERR_FETCH[];    /* "could not be fetched" (TEMPERROR) */

/* Look up the DKIM public key for selector._domainkey.domain.
   On success: returns allocated dkim2_pubkey_t, sets *statusp = DKIM2_OK.
   On failure: returns NULL, sets *statusp and *errp appropriately.
   TEMPERROR → DNS timeout/transient; PERMERROR → absent/malformed/revoked.
   A revoked key (empty p=) is returned with ->revoked set, status PERMERROR
   and *errp DKIM2_KEYERR_REVOKED. */
dkim2_pubkey_t *dkim2_dns_getkey(const char *selector, const char *domain,
    dkim2_status_t *statusp, const char **errp);

void dkim2_pubkey_free(dkim2_pubkey_t *k);

/* The answer-handling half of dkim2_dns_getkey: a TXT answer (answer,
   anslen as res_query returns them; anslen < 0 with herr the h_errno of a
   failed query) to a key, with the same outcomes. */
dkim2_pubkey_t *dkim2_dns_key_from_answer(const unsigned char *answer, int anslen,
    int herr, dkim2_status_t *statusp, const char **errp);

/* Whether an answer settles a lookup: it parses (records or none), or the
   name does not exist / has no data. A SERVFAIL, a timeout or any other
   failure does not. */
int dkim2_dns_answer_settles(const unsigned char *answer, int anslen, int herr);
