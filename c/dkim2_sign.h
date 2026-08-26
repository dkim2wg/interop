#pragma once
#include "dkim2_internal.h"

typedef struct {
    char *domain;           /* d= signing domain */
    char *selector;         /* selector for DNS key lookup */
    char *privkey_path;     /* path to PEM private key file */
    char *alg;              /* "rsa-sha256" or "ed25519-sha256"; NULL = auto-detect from key */
    uint64_t timestamp;     /* t= unix timestamp; 0 = use current time */
    const char *hash;       /* spec-05 §3.1: "sha256" (default when NULL), "sha512", or "both" */
} dkim2_sign_config_t;

/* Sign the message in ctx.
   ctx must have: headers[], n_headers, body_buf, body_len, mail_from, rcpt_to set.
   On success: returns 0, sets *mi_out and *sig_out to allocated header value strings
   (NOT full "Name: value" — just the value; caller frees).
   On failure: returns -1, ctx->errmsg is set. */
int dkim2_do_sign(dkim2_ctx_t *ctx, const dkim2_sign_config_t *cfg,
    char **mi_out, char **sig_out);
