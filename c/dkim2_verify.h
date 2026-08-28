#pragma once
#include "dkim2_internal.h"

typedef struct {
    dkim2_status_t status;
    char message[512];  /* human-readable result per §10.1 */
    int sig_i;          /* i= of the DKIM2-Signature that was checked */
    char domain[256];   /* d= value of the signature where failure/success occurred */
} dkim2_verify_result_t;

/* Verify the message in ctx.
   ctx must have: headers[], n_headers, body_buf, body_len, mail_from, rcpt_to,
   mi_list, sig_list set (populated during header processing).
   Populates result with PASS/FAIL/PERMERROR/TEMPERROR and a message. */
void dkim2_do_verify(dkim2_ctx_t *ctx, dkim2_verify_result_t *result);

/* spec-06 §8.9: check the s= tag of one DKIM2-Signature for duplicate/limit
   violations -- a Selector MUST NOT be present more than once, and the same
   signing algorithm MUST NOT be present more than twice (and only with
   distinct Selectors). Both checks are independent and case-insensitive.
   Returns 0 if clean, or -1 with the PERMERROR message written to errbuf. */
int dkim2_sig_check_duplicates(const dkim2_sig_t *sig, char *errbuf, size_t errbufsz);
