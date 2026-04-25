#pragma once
#include "dkim2_internal.h"

typedef struct {
    dkim2_status_t status;
    char message[512];  /* human-readable result per §10.1 */
    int sig_i;          /* i= of the DKIM2-Signature that was checked */
} dkim2_verify_result_t;

/* Verify the message in ctx.
   ctx must have: headers[], n_headers, body_buf, body_len, mail_from, rcpt_to,
   mi_list, sig_list set (populated during header processing).
   Populates result with PASS/FAIL/PERMERROR/TEMPERROR and a message. */
void dkim2_do_verify(dkim2_ctx_t *ctx, dkim2_verify_result_t *result);
