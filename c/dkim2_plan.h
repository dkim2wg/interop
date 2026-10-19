#pragma once
#include <stddef.h>
#include "dkim2_internal.h"

/* Planned Message-Instance chain walk (§10.7) -- the default verification
   path. Same verdicts and error texts as the undo walk in dkim2_verify.c
   (verify_mi_hashes, still reachable with ctx->undo_walk), without
   rebuilding any earlier message:

   Body: every instance's body is a list of segments, each a run of lines of
   the CURRENT body or a run of entries in one table of Recipe literal lines.
   The top instance is all of the current body; each instance below is the
   one above composed with that MI's body Recipe (an MI with no body Recipe
   shares the list above it). The current body is then read ONCE, in chunks
   cut anywhere, each line going to the digests of every distinct list that
   holds it. Copy ranges are checked against the list they apply to once the
   body's line count is known.

   Headers: the fields are split once and grouped by lowercase name; per
   instance each name has a segment list over [that name's fields | literal
   values], shared while unchanged, and a hashed value is canonicalised once.

   The one thing not modelled: a current body whose last line has no line
   terminator, copied by a Recipe and followed by a literal, then has a
   further Recipe applied (the undo walk would see the two as ONE line).
   dkim2_plan_check() returns 1 for that and the caller uses the undo walk. */

typedef struct dkim2_plan dkim2_plan_t;

/* What the walk saw at one instance (index vi into the m=-sorted MIs), for
   parity tests against the undo walk's trace. */
typedef struct {
    int reached;            /* the walk got this far (no Recipe error above) */
    int have_body;          /* a body hash applies (not below a null body Recipe) */
    dkim2_digests_t body;   /* every implemented algorithm when have_body */
    dkim2_digests_t hdr;    /* header hash, every implemented algorithm */
    int r_err;              /* 1: r= not base64; 2: not (valid) JSON */
    int body_err;           /* this MI's body Recipe is malformed / out of range */
    int hdr_err;            /* this MI's header Recipe is malformed / out of range */
} dkim2_plan_level_t;

/* m=-sorted MIs (ascending, stable) from a list, at most max of them. */
int dkim2_mi_sorted(dkim2_mi_t *list, dkim2_mi_t **arr, int max);

/* Plan the walk over mi_arr (ascending m=, as dkim2_mi_sorted gives) and
   the message's header fields ("Name: value\r\n", every field in order).
   normalise: the body bytes still need CRLF normalisation (bare CR and bare
   LF become CRLF, as eml_parse does) -- the milter's raw SMTP body; 0 when
   they are already the bytes the undo walk would see (ctx->body).
   all_algs: hash every implemented algorithm everywhere (parity tests);
   otherwise only the algorithms each instance's h= names.
   The MIs must outlive the plan. NULL on allocation failure. */
dkim2_plan_t *dkim2_plan_new(dkim2_mi_t **mi_arr, int n_mi,
                             char **hdrs, int n_hdrs, int normalise, int all_algs);
/* As above for a context's MIs and headers. */
dkim2_plan_t *dkim2_plan_new_ctx(const dkim2_ctx_t *ctx, int normalise);

/* Feed body bytes (any chunking); then final once. 0, or -1 on OOM. */
int dkim2_plan_body_update(dkim2_plan_t *p, const char *data, size_t len);
int dkim2_plan_body_final(dkim2_plan_t *p);

/* The §10.7 verdict (after body_final): 0 when every instance verifies,
   -1 with errbuf set exactly as the undo walk would set it, or 1 when the
   message needs the undo walk (see above). */
int dkim2_plan_check(dkim2_plan_t *p, char *errbuf, size_t errbufsz);

/* Per-instance results (after body_final). 0, or -1 if vi is out of range. */
int dkim2_plan_level(dkim2_plan_t *p, int vi, dkim2_plan_level_t *out);

void dkim2_plan_free(dkim2_plan_t *p);
