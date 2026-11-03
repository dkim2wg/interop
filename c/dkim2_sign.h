#pragma once
#include "dkim2_internal.h"

typedef struct {
    char *domain;           /* d= signing domain */
    char *selector;         /* selector for DNS key lookup */
    char *privkey_path;     /* path to PEM private key file */
    char *alg;              /* "rsa-sha256" or "ed25519-sha256"; NULL = auto-detect from key */
    uint64_t timestamp;     /* t= unix timestamp; 0 = use current time */
    const char *hash;       /* -09 §3.1: "sha256" (default when NULL), "sha512", or "both" */
    /* Signer gate: before extending an existing DKIM2 chain, dkim2_do_sign
       verifies it (outbound mode: Message-Instances above every signature's
       m= are the ones being signed) and refuses on any failure, with -1 and
       ctx->errmsg starting "not signing: ". A null body Recipe ("b": null)
       on such an unsigned instance is signed over; one an upstream
       signature covers fails that verify (-09 §14.2, contract E2).
       Deprecated and ignored: the -08 option that allowed signing over an
       unsigned null, now the only behaviour. Kept so callers still build. */
    int allow_null_body_recipe;
    /* -09 §12.5: this hop sends copies to more than one address. Adds
       "exploded" to f= when i > 1 (also added, requested or not, when rt=
       holds more than one address); ignored at i = 1. */
    int exploded;
    int skip_timestamp_check;   /* the chain gate ignores t= expiry (harness use) */
    int skip_chain_check;       /* DO NOT USE outside tests: sign without running the
                                   gate, to build deliberately broken chains */
} dkim2_sign_config_t;

/* Sign the message in ctx.
   ctx must have: headers[], n_headers, body_buf, body_len, mail_from, rcpt_to set.
   On success: returns 0, sets *mi_out and *sig_out to allocated header value strings
   (NOT full "Name: value" — just the value; caller frees).
   On failure: returns -1, ctx->errmsg is set. */
int dkim2_do_sign(dkim2_ctx_t *ctx, const dkim2_sign_config_t *cfg,
    char **mi_out, char **sig_out);
