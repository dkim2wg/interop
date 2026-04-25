#pragma once
#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>

typedef enum {
    DKIM2_OK = 0,
    DKIM2_FAIL,
    DKIM2_PERMERROR,
    DKIM2_TEMPERROR,
} dkim2_status_t;

/* One hash-set from h= tag: "sha256:headerhash:bodyhash" */
typedef struct dkim2_hashset {
    char *alg;          /* "sha256" */
    char *hdr_hash;     /* base64 header hash */
    char *body_hash;    /* base64 body hash */
} dkim2_hashset_t;

/* Parsed Message-Instance header (§6) */
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

/* Parsed DKIM2-Signature header (§7) */
typedef struct dkim2_sig {
    int i;                  /* i= sequence number */
    int m;                  /* m= highest MI signed */
    char *n;                /* n= nonce (optional) */
    uint64_t t;             /* t= timestamp (unix) */
    char *mf;               /* mf= decoded MAIL FROM e.g. "<user@example.com>" */
    char **rt;              /* rt= decoded RCPT TO values (NULL-terminated) */
    char *d;                /* d= signing domain */
    dkim2_sigset_t *ssets;  /* s= signature sets */
    int n_ssets;
    char **flags;           /* f= flags (NULL-terminated) */
    char *raw_value;        /* full header value */
    struct dkim2_sig *next;
} dkim2_sig_t;

/* Per-message context */
typedef struct dkim2_ctx {
    /* Collected headers in order received */
    char **headers;         /* each "Name: value\r\n" */
    int n_headers;
    int hdr_cap;

    /* Parsed DKIM2 headers (populated as headers are fed) */
    dkim2_mi_t  *mi_list;   /* ascending m= order */
    dkim2_sig_t *sig_list;  /* ascending i= order */

    /* Body accumulation for hashing */
    unsigned char *body_buf;
    size_t body_len;
    size_t body_cap;

    /* SMTP envelope */
    char *mail_from;        /* "<addr>" with angle brackets */
    char **rcpt_to;         /* NULL-terminated array of "<addr>" */
    int n_rcpt;

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
