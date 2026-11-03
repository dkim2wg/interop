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

/* Every TXT record at a name, each RR's strings joined with nothing in
   between (dns-00 §3.4.2.2), with its length (a record may hold a NUL). */
typedef struct {
    char **rec;
    size_t *len;
    int n;
} dkim2_txt_t;

void dkim2_txt_free(dkim2_txt_t *t);
/* Append a copy of s[0..len). 0, or -1 out of memory. */
int dkim2_txt_push(dkim2_txt_t *t, const char *s, size_t len);

/* The record source ahead of dkim2_dns_override and live DNS, for key
   names (selector._domainkey.domain) and policy names (_domainkey.domain)
   alike; dkim2_dns_json_load() installs one. Returns 0 with the records in
   *out (none: NXDOMAIN / no TXT), -1 for a temporary failure, or 1 (out
   untouched) to fall through to the next source. */
extern int (*dkim2_dns_txt_hook)(const char *qname, dkim2_txt_t *out);

/* The first tag of a record (-09 §3.7, §3.8; contract E3.2/E4): 1 when it
   is v= with the value exactly "DKIM1" (case-sensitive, WSP allowed around
   '=' and before the tag), 2 when it is v= with any other value, 0 when
   the first tag is not v= at all or does not parse. Linear in len. */
int dkim2_txt_first_tag(const char *rec, size_t len);

/* An answer as res_query gives it (anslen < 0 with herr the h_errno of a
   failed query) to its TXT records: 0 (none for NXDOMAIN / NODATA), -1 a
   temporary failure (SERVFAIL, timeout, an answer that does not parse),
   -2 out of memory. */
int dkim2_dns_txt_from_answer(const unsigned char *answer, int anslen, int herr,
                              dkim2_txt_t *out);

/* The TXT records at qname from live DNS (or dkim2_dns_query_hook), with
   a buffer that holds any DNS message. As dkim2_dns_txt_from_answer. */
int dkim2_dns_txt_live(const char *qname, dkim2_txt_t *out);

/* Domain Policy Record outcome for a From domain (-09 §3.8, §14.8). */
typedef enum {
    DKIM2_POLICY_OPEN = 0,  /* no v=DKIM1 record, or one without "strict":
                               subdomains are authorized */
    DKIM2_POLICY_STRICT,    /* f= holds "strict", or the one v=DKIM1 record
                               does not parse (fail closed, contract E3.2) */
    DKIM2_POLICY_MULTIPLE,  /* more than one v=DKIM1 record */
    DKIM2_POLICY_TEMP,      /* the lookup failed for now */
} dkim2_policy_t;

/* E3.2 over a record set: keep the records whose first tag is v=DKIM1,
   count them, and parse the one left as a key record is parsed; f= is a
   colon-separated list of hyphenated-words, [FWS] around each ':'. */
dkim2_policy_t dkim2_policy_from_records(const dkim2_txt_t *t);

/* Look up the TXT records at _domainkey.<dom> (dom: an A-label,
   lowercased, no trailing dot) -- dkim2_dns_txt_hook, then
   dkim2_dns_override, then live DNS -- and judge them. */
dkim2_policy_t dkim2_dns_get_policy(const char *dom);

/* Test seam below the override: if non-NULL, used instead of res_query() for
   the TXT query (same contract: returns the answer length, or -1). Lets tests
   feed wire-format RRsets -- several RRs, one RR in several strings. */
extern int (*dkim2_dns_query_hook)(const char *qname, unsigned char *answer, int anslen);

/* *errp values (-09 §14.5 wording, to follow "public key <selector> ").
   The first six mean a record is present but unusable; ABSENT and FETCH
   are lookup outcomes. ("OOM" is the only other value, as TEMPERROR.) */
extern const char DKIM2_KEYERR_MULTIPLE[];  /* "has multiple records" */
extern const char DKIM2_KEYERR_SYNTAX[];    /* "has a syntax error" */
extern const char DKIM2_KEYERR_REVOKED[];   /* "has been revoked" */
extern const char DKIM2_KEYERR_ALG[];       /* "algorithm mismatch" (unknown k=) */
extern const char DKIM2_KEYERR_MALFORMED[]; /* "is malformed": p= is base64 but no
                                               key of its type -- an Ed25519 key
                                               not 32 octets, an RSA key that
                                               does not load (-09 §14.5; D7) */
extern const char DKIM2_KEYERR_SHORT[];     /* "too short": an RSA key under 1024
                                               bits (-09 §3.2, §14.5; E5) */

extern const char DKIM2_KEYERR_ABSENT[];   /* "does not exist" (PERMERROR) */
extern const char DKIM2_KEYERR_FETCH[];    /* "could not be fetched" (TEMPERROR) */

/* Look up the DKIM public key for selector._domainkey.domain:
   dkim2_dns_txt_hook, then dkim2_dns_override, then live DNS. Records whose
   first tag is v= other than DKIM1 are dropped before counting (-09 §3.7,
   contract E4).
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
