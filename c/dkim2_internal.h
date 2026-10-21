#pragma once
#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>
#include "dkim2_hash.h"

typedef enum {
    DKIM2_OK = 0,
    DKIM2_FAIL,
    DKIM2_PERMERROR,
    DKIM2_TEMPERROR,
    DKIM2_NONE,         /* no DKIM2 header fields at all (A-R dkim2=none) */
} dkim2_status_t;

/* One hash-set from h= tag: "sha256:headerhash:bodyhash" */
typedef struct dkim2_hashset {
    char *alg;          /* "sha256" */
    char *hdr_hash;     /* base64 header hash */
    char *body_hash;    /* base64 body hash */
} dkim2_hashset_t;

/* Parsed Message-Instance header (-07 §9) */
typedef struct dkim2_mi {
    int m;                      /* m= revision number */
    char *r_raw;                /* r= base64 recipe (NULL if absent) */
    dkim2_hashset_t *hsets;     /* h= hash sets */
    int n_hsets;
    char *raw_value;            /* full header value, for signature canon */
    struct dkim2_mi *next;
} dkim2_mi_t;

/* One entry in s= tag: selector:alg:sig */
typedef struct dkim2_sigset {
    char *selector;
    char *alg;          /* "rsa-sha256" or "ed25519-sha256" */
    char *sig_b64;      /* base64 signature value */
} dkim2_sigset_t;

/* Parsed DKIM2-Signature header (-07 §10) */
typedef struct dkim2_sig {
    int i;                  /* i= sequence number */
    int m;                  /* m= highest MI signed */
    char *n;                /* n= nonce (optional) */
    uint64_t t;             /* t= timestamp (unix) */
    char *mf;               /* mf= decoded MAIL FROM e.g. "<user@example.com>" */
    char **rt;              /* rt= decoded RCPT TO values (NULL-terminated) */
    char *d;                /* d= signing domain */
    char *nd;               /* nd= next-domain (-07 §10.7); NULL if absent */
    dkim2_sigset_t *ssets;  /* s= signature sets */
    int n_ssets;
    char **flags;           /* f= flags (NULL-terminated) */
    char *raw_value;        /* full header value */
    struct dkim2_sig *next;
} dkim2_sig_t;

/* A Message-Instance or DKIM2-Signature field that did not parse. It is
   kept (in header order, top down) rather than dropped: its number still
   counts for the §14.2 structure checks, and its error ranks with the
   other fields' by contract C9 (dkim2_do_verify). */
typedef struct dkim2_badfield {
    int is_sig;             /* 0 = Message-Instance, 1 = DKIM2-Signature */
    int num;                /* its usable m= (Message-Instance) or i=, else 0 */
    int sig_m;              /* a DKIM2-Signature's usable m=, else 0 */
    int structural;         /* the error is about the field's number (no
                               usable m=, or no usable i=/m=): §14.2 b or d */
    char *err;              /* the PERMERROR to report */
    struct dkim2_badfield *next;
} dkim2_badfield_t;

/* Per-message context */
typedef struct dkim2_ctx {
    /* Collected headers in order received */
    char **headers;         /* each "Name: value\r\n" */
    int n_headers;
    int hdr_cap;

    /* Parsed DKIM2 headers (populated as headers are fed) */
    dkim2_mi_t  *mi_list;   /* ascending m= order */
    dkim2_sig_t *sig_list;  /* ascending i= order */

    /* The first parse error of a Message-Instance / DKIM2-Signature field
       (dkim2_ctx_add_field), for the signer, which refuses on any. The
       verifier ranks every such field from bad_list instead (contract C9).
       Empty string means none. */
    char mi_error[256];
    char sig_error[256];

    /* Every field that did not parse, top down (dkim2_ctx_add_field). */
    dkim2_badfield_t *bad_list;

    /* How many Message-Instance / DKIM2-Signature fields there are, parsed
       or not (dkim2_ctx_add_field; contract C9 step a). */
    int n_mi_fields, n_sig_fields;

    /* Body hash — computed incrementally, never buffered.
       Holds every implemented algorithm's digest (-07 §3.1). */
    dkim2_digests_t body_digests;               /* valid once body_hasher is NULL */
    dkim2_body_hasher_t *body_hasher;           /* non-NULL during body accumulation */

    /* Optional: CRLF-normalised body bytes for full-chain MI hash verification.
       If NULL and there is no plan either, only the topmost MI's body hash is
       checked (via body_digests). */
    char *body;
    size_t body_len;

    /* SMTP envelope */
    char *mail_from;        /* "<addr>" with angle brackets */
    char **rcpt_to;         /* NULL-terminated array of "<addr>" */
    int n_rcpt;

    /* Optional: the planned chain walk, made at end of headers and fed the
       body as it arrives (dkim2_plan.h; the milter). Owned by the caller.
       If NULL, dkim2_do_verify plans from ctx->body itself. */
    struct dkim2_plan *plan;

    /* Optional: key lookups started at end of headers (dkim2_prefetch.h).
       Owned by the caller; NULL = look every key up when it is needed. */
    struct dkim2_prefetch *prefetch;

    /* Verifier options */
    int undo_walk;             /* 1 = check the chain with the undo walk (the
                                  reference) instead of the planned walk */
    int skip_timestamp_check;  /* 1 = skip t= expiry check (for testing) */
    int outbound;              /* 1 = signer gate: an unsigned top Message-Instance
                                  is allowed, and the envelope in mail_from/rcpt_to
                                  is OUR next hop, not checked against the top sig */

    /* Result */
    dkim2_status_t status;
    char errmsg[512];
} dkim2_ctx_t;

/* DNS key record (from selector._domainkey.domain TXT) */
typedef struct dkim2_pubkey {
    char *alg;          /* "rsa" or "ed25519" */
    EVP_PKEY *pkey;
    int revoked;        /* p= is empty */
} dkim2_pubkey_t;
