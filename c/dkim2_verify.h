#pragma once
#include "dkim2_internal.h"
#include "dkim2_plan.h"

/* -09 §14.3: a DKIM2-Signature made more than 14 days before delivery, or
   from more than one day ahead of it, is not Fully Verified. */
#define DKIM2_MAX_AGE_SECS    1209600ULL
#define DKIM2_MAX_FUTURE_SECS 86400ULL

typedef struct {
    dkim2_status_t status;
    char message[512];  /* human-readable result per -09 §14.1 */
    int sig_i;          /* i= of the DKIM2-Signature that was checked */
    char domain[256];   /* d= value of the signature where failure/success occurred */
    int fully_verified; /* Deprecated (-09, contract E2): 1 exactly when
                           status is DKIM2_OK. Not in A-R. */
} dkim2_verify_result_t;

/* Verify the message in ctx.
   ctx must have: headers[], n_headers, mail_from, rcpt_to, mi_list, sig_list
   set (populated during header processing), and the body as a plan already
   fed it (ctx->plan), as bytes (ctx->body/body_len), or only as its digest.
   Keys come from ctx->prefetch when set (dkim2_prefetch.h).
   Populates result with PASS/FAIL/PERMERROR/TEMPERROR and a message. */
void dkim2_do_verify(dkim2_ctx_t *ctx, dkim2_verify_result_t *result);

/* -09 §14.2 structure (contract C9 steps a..h) of the fields collected in
   ctx, as dkim2_do_verify checks it first; outbound as ctx->outbound (an
   unsigned top Message-Instance allowed). 0, or -1 when it fails -- then
   nothing more is worth doing, key lookups included. */
int dkim2_structure_check(const dkim2_ctx_t *ctx, int outbound);

/* -09 §11, §12.4 for a signer (contract E3.1, E3.4 revised): 1 when the
   From is Authentic for d: exactly one From field holding one mailbox
   whose (A-label, not literal) domain relaxed-matches d (downward), or that
   d is below (upward) when parent(from_domain, arg) returns non-zero --
   from_domain is the A-label, lowercased, no trailing dot. parent NULL
   refuses the upward case. Else 0. No Domain Policy Record is looked up. */
int dkim2_from_authentic(char **hdrs, int n_hdrs, const char *d,
                         int (*parent)(const char *from_domain, void *arg), void *arg);

/* 1 when the Message-Instance's header Recipe names From ("from") -- or
   cannot be read -- else 0. */
int dkim2_mi_changes_from(const dkim2_mi_t *mi);

/* The undo walk over hand-picked MIs (ascending m=), headers and body,
   recording each instance in trace[n_mi] and carrying on past hash
   mismatches (see dkim2_plan_level_t). For parity tests against the planned
   walk. Returns 0, or -1 with errbuf set at the first Recipe error. */
int dkim2_undo_walk_trace(dkim2_mi_t **mi_arr, int n_mi, char **hdrs, int n_hdrs,
                          const char *body, size_t body_len,
                          dkim2_plan_level_t *trace, char *errbuf, size_t errbufsz);
