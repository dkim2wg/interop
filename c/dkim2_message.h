#pragma once
#include <stdio.h>
#include "dkim2_sign.h"
#include "dkim2_verify.h"

/* Sign a .eml file, writing the signed message to out.
   Output is: DKIM2-Signature header, Message-Instance header (if new),
   original headers, blank line, original body — all with CRLF line endings.
   Returns 0 on success, -1 on error (errbuf set). */
int dkim2_sign_message(const char *eml_path, FILE *out,
                       const dkim2_sign_config_t *cfg,
                       const char *mail_from, char **rcpt_to,
                       char *errbuf, size_t errbufsz);

/* Verify a .eml file. Parses headers + body, builds verify context,
   runs dkim2_do_verify, frees everything, returns result.
   DNS lookup uses the currently-registered dkim2_dns_override.
   Keys are prefetched from the end of the headers (dkim2_prefetch.h) and
   the chain is checked by the planned walk (dkim2_plan.h). */
dkim2_verify_result_t dkim2_verify_message(const char *eml_path,
                                            const char *mail_from,
                                            char **rcpt_to,
                                            int skip_timestamp_check);

typedef struct {
    int undo_walk;      /* check the MI chain with the undo walk (reference) */
    int no_prefetch;    /* look each key up only when it is needed */
    size_t chunk;       /* feed the planned walk the body this many bytes at
                           a time (0: in one go) -- tests */
} dkim2_verify_opts_t;

/* dkim2_verify_message with options; opts NULL = the defaults. */
dkim2_verify_result_t dkim2_verify_message_opts(const char *eml_path,
                                                 const char *mail_from,
                                                 char **rcpt_to,
                                                 int skip_timestamp_check,
                                                 const dkim2_verify_opts_t *opts);

/* Parse ctx->headers' Message-Instance and DKIM2-Signature fields into
   ctx->mi_list / ctx->sig_list (and ctx->bad_list, ctx->mi_error /
   ctx->sig_error), as dkim2_ctx_add_field(). */
void dkim2_ctx_collect(dkim2_ctx_t *ctx);
