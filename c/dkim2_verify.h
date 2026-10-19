#pragma once
#include "dkim2_internal.h"
#include "dkim2_plan.h"

/* -07 §14.3: a DKIM2-Signature made more than 14 days before delivery, or
   from more than one day ahead of it, is not Validly Signed. */
#define DKIM2_MAX_AGE_SECS    1209600ULL
#define DKIM2_MAX_FUTURE_SECS 86400ULL

typedef struct {
    dkim2_status_t status;
    char message[512];  /* human-readable result per §10.1 */
    int sig_i;          /* i= of the DKIM2-Signature that was checked */
    char domain[256];   /* d= value of the signature where failure/success occurred */
} dkim2_verify_result_t;

/* Verify the message in ctx.
   ctx must have: headers[], n_headers, mail_from, rcpt_to, mi_list, sig_list
   set (populated during header processing), and the body as a plan already
   fed it (ctx->plan), as bytes (ctx->body/body_len), or only as its digest.
   Keys come from ctx->prefetch when set (dkim2_prefetch.h).
   Populates result with PASS/FAIL/PERMERROR/TEMPERROR and a message. */
void dkim2_do_verify(dkim2_ctx_t *ctx, dkim2_verify_result_t *result);

/* spec-06 §8.9: check the s= tag of one DKIM2-Signature for duplicate/limit
   violations -- a Selector MUST NOT be present more than once, and the same
   signing algorithm MUST NOT be present more than twice (and only with
   distinct Selectors). Both checks are independent and case-insensitive.
   Returns 0 if clean, or -1 with the PERMERROR message written to errbuf. */
int dkim2_sig_check_duplicates(const dkim2_sig_t *sig, char *errbuf, size_t errbufsz);

/* -07 §11: 1 when the header fields hold exactly one From field, with
   exactly one mailbox, whose domain (as an A-label, not a literal)
   relaxed-matches d; else 0. */
int dkim2_from_authentic(char **hdrs, int n_hdrs, const char *d);

/* 1 when the Message-Instance's header Recipe names From (any case) -- or
   cannot be read -- else 0. */
int dkim2_mi_changes_from(const dkim2_mi_t *mi);

/* The undo walk over hand-picked MIs (ascending m=), headers and body,
   recording each instance in trace[n_mi] and carrying on past hash
   mismatches (see dkim2_plan_level_t). For parity tests against the planned
   walk. Returns 0, or -1 with errbuf set at the first Recipe error. */
int dkim2_undo_walk_trace(dkim2_mi_t **mi_arr, int n_mi, char **hdrs, int n_hdrs,
                          const char *body, size_t body_len,
                          dkim2_plan_level_t *trace, char *errbuf, size_t errbufsz);
