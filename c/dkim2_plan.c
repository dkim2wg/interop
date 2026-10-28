#include "dkim2_plan.h"
#include "dkim2_recipe.h"
#include "dkim2_hash.h"
#include "base64.h"
#include <cjson/cJSON.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <strings.h>
#include <limits.h>

/* The open end of the top instance's single body segment. */
#define SEG_INF (1LL << 60)

/* A run of items: lit == 0 -- lines from..to (1-based) of the current body,
   or (headers) a name's received fields from..to (0-based, bottom-up);
   lit == 1 -- entries from..to (0-based) of the literal table. */
typedef struct { int lit; long long from, to; } seg_t;
typedef struct { seg_t *s; int n, cap; } seglist_t;

/* All the fields with one lowercase name, as received. */
typedef struct {
    char *name;         /* lowercase bytes before the first ':' */
    int hashed;         /* not on the -07 §4 skip list */
    char **rv;          /* received fields, bottom-up (as Recipes number them) */
    char **rv_canon;    /* canonical lines, made on first use (hashed only) */
    int n_rv;
} hgroup_t;

typedef struct {
    dkim2_mi_t *mi;
    unsigned algs;          /* implemented algorithms in this MI's h= */
    int built;              /* reached while planning */
    int gone;               /* below a null body Recipe */
    int r_err, body_err, hdr_err;
    int applied;            /* body Recipe composed onto blist */
    long long max_end;      /* last copy end of that Recipe (0: none) */
    seglist_t *blist;       /* this instance's body (NULL: none) */
    seglist_t **hmap;       /* per group: this instance's fields (NULL: none) */
    int n_hmap, own_hmap;
    int acc;                /* accumulator of blist, -1 none */
    dkim2_digests_t hdr;
} level_t;

/* One forward-pass digest per distinct body list. */
typedef struct {
    const seglist_t *list;
    unsigned algs;
    EVP_MD_CTX *md[DKIM2_N_HASH_ALGS];
    int seg;                /* next segment of list to consume */
    long long pending;      /* blank lines held back (-07 §6.1) */
    int emitted, last_crlf;
    int active;             /* takes the current run of body lines */
    dkim2_digests_t out;
} acc_t;

typedef struct { unsigned char *s; size_t len; } blit_t;

struct dkim2_plan {
    level_t *lv;
    int n;
    int normalise, all_algs;
    hgroup_t *g;
    int n_g, cap_g;
    char **hlit;            /* header literal canonical lines (NULL: not hashed) */
    int n_hlit, cap_hlit;
    blit_t *blit;           /* body literal lines, CRLF appended */
    int n_blit, cap_blit;
    seglist_t **pool;       /* every seglist, for dkim2_plan_free */
    int n_pool, cap_pool;
    acc_t *acc;
    int n_acc;
    char *part;             /* the partial line between chunks */
    size_t part_len, part_cap;
    int prev_cr;
    long long n_lines;
    int unterminated, finished, fallback;
};

static int grow(void **arr, int *cap, int need, size_t elsz) {
    if (need <= *cap) return 0;
    int nc = *cap ? *cap : 8;
    while (nc < need) nc *= 2;
    void *na = realloc(*arr, (size_t)nc * elsz);
    if (!na) return -1;
    *arr = na;
    *cap = nc;
    return 0;
}

static seglist_t *seglist_new(dkim2_plan_t *p) {
    if (grow((void **)&p->pool, &p->cap_pool, p->n_pool + 1, sizeof *p->pool) < 0) return NULL;
    seglist_t *l = calloc(1, sizeof *l);
    if (l) p->pool[p->n_pool++] = l;
    return l;
}

/* Append a run, coalescing with the last one when contiguous. */
static int seg_add(seglist_t *l, int lit, long long from, long long to) {
    if (l->n) {
        seg_t *t = &l->s[l->n - 1];
        if (t->lit == lit && t->to != SEG_INF && t->to + 1 == from) {
            t->to = to;
            return 0;
        }
    }
    if (grow((void **)&l->s, &l->cap, l->n + 1, sizeof *l->s) < 0) return -1;
    l->s[l->n++] = (seg_t){ lit, from, to };
    return 0;
}

static long long seg_len(const seg_t *g) { return g->to - g->from + 1; }

typedef long long (*lit_add_fn)(void *ctx, const dkim2_recipe_op_t *op);

/* out = the Recipe ops applied to parent (NULL: empty). Copy ranges ascend
   (checked by dkim2_recipe_ops), so one pointer walks the parent forwards.
   0, -1 on OOM, or 1 when a copy runs past the end of a finite parent. */
static int compose(const seglist_t *parent, const dkim2_recipe_op_t *ops, int n_ops,
                   lit_add_fn lit_add, void *lctx, seglist_t *out) {
    int si = 0, np = parent ? parent->n : 0;
    long long off = 0, pos = 0;
    for (int i = 0; i < n_ops; i++) {
        const dkim2_recipe_op_t *op = &ops[i];
        if (op->lit) {
            long long idx = lit_add(lctx, op);
            if (idx < 0 || seg_add(out, 1, idx, idx) < 0) return -1;
            continue;
        }
        long long skip = op->from - 1 - pos;
        while (skip > 0) {
            if (si >= np) return 1;
            long long rem = seg_len(&parent->s[si]) - off;
            if (skip < rem) { off += skip; pos += skip; skip = 0; }
            else { skip -= rem; pos += rem; si++; off = 0; }
        }
        long long k = (long long)op->to - op->from + 1;
        while (k > 0) {
            if (si >= np) return 1;
            const seg_t *g = &parent->s[si];
            long long rem = seg_len(g) - off, t = k < rem ? k : rem;
            if (seg_add(out, g->lit, g->from + off, g->from + off + t - 1) < 0) return -1;
            off += t; pos += t; k -= t;
            if (off == seg_len(g)) { si++; off = 0; }
        }
    }
    return 0;
}

/* ---- body literals ---- */

static long long body_lit_add(void *ctx, const dkim2_recipe_op_t *op) {
    dkim2_plan_t *p = ctx;
    if (grow((void **)&p->blit, &p->cap_blit, p->n_blit + 1, sizeof *p->blit) < 0) return -1;
    unsigned char *s = malloc(op->len + 2);
    if (!s) return -1;
    memcpy(s, op->s, op->len);
    memcpy(s + op->len, "\r\n", 2);
    p->blit[p->n_blit] = (blit_t){ s, op->len + 2 };
    return p->n_blit++;
}

/* ---- header groups ---- */

static int group_find(const dkim2_plan_t *p, const char *name, size_t nl) {
    for (int i = 0; i < p->n_g; i++)
        if (strlen(p->g[i].name) == nl && memcmp(p->g[i].name, name, nl) == 0) return i;
    return -1;
}

/* The group for the (any case) name of nl bytes, created empty if new. */
static int group_get(dkim2_plan_t *p, const char *name, size_t nl) {
    char *ln = malloc(nl + 1);
    if (!ln) return -1;
    for (size_t i = 0; i < nl; i++) ln[i] = (char)tolower((unsigned char)name[i]);
    ln[nl] = '\0';
    int gi = group_find(p, ln, nl);
    if (gi >= 0) { free(ln); return gi; }
    if (grow((void **)&p->g, &p->cap_g, p->n_g + 1, sizeof *p->g) < 0) { free(ln); return -1; }
    p->g[p->n_g] = (hgroup_t){ ln, !dkim2_hdr_ignored(ln, nl), NULL, NULL, 0 };
    return p->n_g++;
}

typedef struct { dkim2_plan_t *p; const char *key; int hashed; } hlit_ctx_t;

/* A header literal is the field "key: value" (as the undo walk builds it);
   only its canonical line is kept, and only for a hashed name. */
static long long hdr_lit_add(void *ctx, const dkim2_recipe_op_t *op) {
    hlit_ctx_t *h = ctx;
    dkim2_plan_t *p = h->p;
    if (grow((void **)&p->hlit, &p->cap_hlit, p->n_hlit + 1, sizeof *p->hlit) < 0) return -1;
    char *canon = NULL;
    if (h->hashed) {
        size_t kl = strlen(h->key);
        char *f = malloc(kl + op->len + 5);
        if (!f) return -1;
        memcpy(f, h->key, kl);
        memcpy(f + kl, ": ", 2);
        memcpy(f + kl + 2, op->s, op->len);
        memcpy(f + kl + 2 + op->len, "\r\n", 3);
        canon = dkim2_header_canon(f);
        free(f);
        if (!canon) return -1;
    }
    p->hlit[p->n_hlit] = canon;
    return p->n_hlit++;
}

/* The undo walk matches a Recipe key (lowercase: dkim2_recipe_parse)
   exactly against each field's lowercased name, and names of 128 bytes or
   more never match. Groups are named that way (lowercase, no ':'), so a key
   with a ':' finds no group; only the length needs checking here. */
static int key_matchable(const char *k) {
    return strlen(k) < 128;
}

/* Undo one header Recipe ("h" object) on map, in key order, as
   dkim2_apply_header_recipe does. 0, 1 malformed, -1 OOM. */
static int apply_hdr(dkim2_plan_t *p, const cJSON *h, seglist_t ***mapp, int *n_mapp) {
    const cJSON *field;
    cJSON_ArrayForEach(field, h) {
        const char *key = field->string;
        if (!key || !cJSON_IsArray(field)) continue;
        int matched = key_matchable(key) ? group_find(p, key, strlen(key)) : -1;
        if (matched >= *n_mapp) matched = -1;   /* not present at this level */
        const seglist_t *cur = matched >= 0 ? (*mapp)[matched] : NULL;

        dkim2_recipe_op_t *ops;
        int n_ops;
        if (dkim2_recipe_ops(field, 1, &ops, &n_ops) < 0) return 1;
        const char *colon = strchr(key, ':');
        int t = group_get(p, key, colon ? (size_t)(colon - key) : strlen(key));
        if (t < 0) { dkim2_recipe_ops_free(ops, n_ops); return -1; }
        if (t >= *n_mapp) {
            seglist_t **nm = realloc(*mapp, (size_t)p->n_g * sizeof *nm);
            if (!nm) { dkim2_recipe_ops_free(ops, n_ops); return -1; }
            for (int i = *n_mapp; i < p->n_g; i++) nm[i] = NULL;
            *mapp = nm;
            *n_mapp = p->n_g;
        }
        seglist_t *nl = seglist_new(p);
        hlit_ctx_t hc = { p, key, p->g[t].hashed };
        int rc = nl ? compose(cur, ops, n_ops, hdr_lit_add, &hc, nl) : -1;
        dkim2_recipe_ops_free(ops, n_ops);
        if (rc) return rc;
        if (matched >= 0) {
            (*mapp)[matched] = NULL;            /* t == matched */
        } else if ((*mapp)[t]) {
            /* New fields go below the ones that stay: first, bottom-up. */
            const seglist_t *old = (*mapp)[t];
            for (int i = 0; i < old->n; i++)
                if (seg_add(nl, old->s[i].lit, old->s[i].from, old->s[i].to) < 0) return -1;
        }
        (*mapp)[t] = nl->n ? nl : NULL;
    }
    return 0;
}

/* ---- planning ---- */

int dkim2_mi_sorted(dkim2_mi_t *list, dkim2_mi_t **arr, int max) {
    int n = 0;
    for (dkim2_mi_t *m = list; m && n < max; m = m->next) arr[n++] = m;
    for (int i = 1; i < n; i++) {
        dkim2_mi_t *key = arr[i]; int j = i - 1;
        while (j >= 0 && arr[j]->m > key->m) { arr[j + 1] = arr[j]; j--; }
        arr[j + 1] = key;
    }
    return n;
}

/* Plan the levels top-down, mirroring verify_mi_hashes: Recipe errors that
   need no body (bad r=, bad JSON, malformed Recipe structure, a header copy
   out of range) end the planning there. 0, or -1 on OOM. */
static int plan_levels(dkim2_plan_t *p) {
    int gone = 0;
    for (int vi = p->n - 1; vi >= 0; vi--) {
        level_t *lv = &p->lv[vi];
        lv->built = 1;
        lv->gone = gone;
        seglist_t *nb = lv->blist;
        seglist_t **nh = lv->hmap;
        int n_nh = lv->n_hmap, own = 0, stop = 0;
        const dkim2_mi_t *mi = lv->mi;

        if (mi->r_raw) {
            size_t rl = strlen(mi->r_raw), dmax = rl * 3 / 4 + 4;
            unsigned char *rj = malloc(dmax + 1);
            if (!rj) return -1;
            int jl = (int)b64_decode(mi->r_raw, rj, dmax);
            cJSON *root = NULL;
            if (jl <= 0) {
                lv->r_err = 1;
                stop = 1;
            } else {
                rj[jl] = '\0';
                root = dkim2_recipe_parse((const char *)rj);
                if (!root) { lv->r_err = 2; stop = 1; }
            }
            free(rj);

            if (root && vi > 0) {
                const cJSON *b = cJSON_GetObjectItemCaseSensitive(root, "b");
                if (b && cJSON_IsNull(b)) {
                    gone = 1;
                    nb = NULL;
                } else if (b) {
                    dkim2_recipe_op_t *ops = NULL;
                    int n_ops = 0;
                    if (!cJSON_IsArray(b) || dkim2_recipe_ops(b, 0, &ops, &n_ops) < 0) {
                        lv->body_err = 1;
                        stop = 1;
                    } else if (!gone) {
                        seglist_t *l = seglist_new(p);
                        int rc = l ? compose(lv->blist, ops, n_ops, body_lit_add, p, l) : -1;
                        if (rc < 0) { dkim2_recipe_ops_free(ops, n_ops); cJSON_Delete(root); return -1; }
                        if (rc > 0) { lv->body_err = 1; stop = 1; }
                        for (int i = 0; i < n_ops; i++)
                            if (!ops[i].lit) lv->max_end = ops[i].to;
                        lv->applied = 1;
                        nb = l;
                    }
                    dkim2_recipe_ops_free(ops, n_ops);
                }
                if (gone) nb = NULL;

                const cJSON *h = cJSON_GetObjectItemCaseSensitive(root, "h");
                if (h && cJSON_IsNull(h)) {
                    lv->hdr_err = 1;
                    stop = 1;
                } else if (h && cJSON_IsObject(h) && !stop) {
                    nh = malloc((size_t)(n_nh ? n_nh : 1) * sizeof *nh);
                    if (!nh) { cJSON_Delete(root); return -1; }
                    if (n_nh) memcpy(nh, lv->hmap, (size_t)n_nh * sizeof *nh);
                    own = 1;
                    int rc = apply_hdr(p, h, &nh, &n_nh);
                    if (rc < 0) { free(nh); cJSON_Delete(root); return -1; }
                    if (rc > 0) { lv->hdr_err = 1; stop = 1; }
                }
            }
            cJSON_Delete(root);
        }
        if (stop) {
            if (own) free(nh);
            break;
        }
        if (vi > 0) {
            level_t *dn = &p->lv[vi - 1];
            dn->blist = nb;
            dn->hmap = nh;
            dn->n_hmap = n_nh;
            dn->own_hmap = own;
        }
    }
    return 0;
}

static const hgroup_t *g_sort_groups;   /* qsort context (single-threaded use) */
static int cmp_group(const void *a, const void *b) {
    return strcmp(g_sort_groups[*(const int *)a].name, g_sort_groups[*(const int *)b].name);
}

/* Header hash (-07 §6.2) of one level: hashed names in byte order, each name's
   fields bottom-up -- what dkim2_header_hash_raw_alg makes of the fields. */
static int hdr_digest(dkim2_plan_t *p, const int *order, level_t *lv, unsigned algs) {
    static const EVP_MD *(*const mds[DKIM2_N_HASH_ALGS])(void) = { EVP_sha256, EVP_sha512 };
    EVP_MD_CTX *md[DKIM2_N_HASH_ALGS] = { 0 };
    int rc = -1;
    for (int a = 0; a < DKIM2_N_HASH_ALGS; a++)
        if (algs & (1u << a)) {
            md[a] = EVP_MD_CTX_new();
            if (!md[a] || EVP_DigestInit_ex(md[a], mds[a](), NULL) != 1) goto out;
        }
    for (int oi = 0; oi < p->n_g; oi++) {
        int gi = order[oi];
        hgroup_t *g = &p->g[gi];
        const seglist_t *l = gi < lv->n_hmap ? lv->hmap[gi] : NULL;
        if (!g->hashed || !l) continue;
        for (int si = 0; si < l->n; si++)
            for (long long k = l->s[si].from; k <= l->s[si].to; k++) {
                const char *c;
                if (l->s[si].lit) {
                    c = p->hlit[k];
                } else {
                    if (!g->rv_canon[k] && !(g->rv_canon[k] = dkim2_header_canon(g->rv[k])))
                        goto out;
                    c = g->rv_canon[k];
                }
                size_t cl = strlen(c);
                for (int a = 0; a < DKIM2_N_HASH_ALGS; a++)
                    if (md[a]) EVP_DigestUpdate(md[a], c, cl);
            }
    }
    for (int a = 0; a < DKIM2_N_HASH_ALGS; a++)
        if (md[a]) {
            unsigned int dl = (unsigned int)dkim2_hash_alg_len(a);
            if (EVP_DigestFinal_ex(md[a], lv->hdr.d[a], &dl) != 1) goto out;
        }
    rc = 0;
out:
    for (int a = 0; a < DKIM2_N_HASH_ALGS; a++) EVP_MD_CTX_free(md[a]);
    return rc;
}

static unsigned mi_algs(const dkim2_mi_t *mi) {
    unsigned m = 0;
    for (int i = 0; i < mi->n_hsets; i++) {
        int a = dkim2_hash_alg_index(mi->hsets[i].alg);
        if (a >= 0) m |= 1u << a;
    }
    return m;
}

dkim2_plan_t *dkim2_plan_new(dkim2_mi_t **mi_arr, int n_mi,
                             char **hdrs, int n_hdrs, int normalise, int all_algs) {
    dkim2_plan_t *p = calloc(1, sizeof *p);
    if (!p) return NULL;
    p->normalise = normalise;
    p->all_algs = all_algs;
    p->n = n_mi;
    p->lv = calloc((size_t)(n_mi ? n_mi : 1), sizeof *p->lv);
    if (!p->lv) goto fail;
    for (int i = 0; i < n_mi; i++) {
        p->lv[i].mi = mi_arr[i];
        p->lv[i].algs = all_algs ? (1u << DKIM2_N_HASH_ALGS) - 1 : mi_algs(mi_arr[i]);
        p->lv[i].acc = -1;
    }
    if (n_mi == 0) return p;

    /* Received fields, bottom-up per name, as the undo walk's content array
       holds them: Message-Instance and DKIM2-Signature fields are not part
       of it, and a field with no colon is never hashed nor matched. */
    for (int i = n_hdrs - 1; i >= 0; i--) {
        const char *colon = strchr(hdrs[i], ':');
        if (!colon) continue;
        size_t nl = (size_t)(colon - hdrs[i]);
        if ((nl == 16 && strncasecmp(hdrs[i], "message-instance", 16) == 0) ||
            (nl == 15 && strncasecmp(hdrs[i], "dkim2-signature", 15) == 0)) continue;
        int gi = group_get(p, hdrs[i], nl);
        if (gi < 0) goto fail;
        hgroup_t *g = &p->g[gi];
        char **nrv = realloc(g->rv, (size_t)(g->n_rv + 1) * sizeof *nrv);
        if (!nrv) goto fail;
        g->rv = nrv;
        g->rv[g->n_rv++] = hdrs[i];
    }
    level_t *top = &p->lv[n_mi - 1];
    top->hmap = calloc((size_t)(p->n_g ? p->n_g : 1), sizeof *top->hmap);
    if (!top->hmap) goto fail;
    top->n_hmap = p->n_g;
    top->own_hmap = 1;
    for (int gi = 0; gi < p->n_g; gi++) {
        hgroup_t *g = &p->g[gi];
        g->rv_canon = calloc((size_t)g->n_rv, sizeof *g->rv_canon);
        seglist_t *l = seglist_new(p);
        if (!g->rv_canon || !l || seg_add(l, 0, 0, g->n_rv - 1) < 0) goto fail;
        top->hmap[gi] = l;
    }
    top->blist = seglist_new(p);
    if (!top->blist || seg_add(top->blist, 0, 1, SEG_INF) < 0) goto fail;

    if (plan_levels(p) < 0) goto fail;

    int *order = malloc((size_t)(p->n_g ? p->n_g : 1) * sizeof *order);
    if (!order) goto fail;
    for (int i = 0; i < p->n_g; i++) order[i] = i;
    g_sort_groups = p->g;
    qsort(order, (size_t)p->n_g, sizeof *order, cmp_group);
    g_sort_groups = NULL;
    for (int vi = n_mi - 1; vi >= 0; vi--) {
        level_t *lv = &p->lv[vi];
        if (!lv->built) break;
        if (vi < n_mi - 1 && lv->hmap == p->lv[vi + 1].hmap &&
            (lv->algs & ~p->lv[vi + 1].algs) == 0) {
            lv->hdr = p->lv[vi + 1].hdr;        /* unchanged: shared */
            continue;
        }
        if (hdr_digest(p, order, lv, lv->algs | (vi ? p->lv[vi - 1].algs : 0)) < 0) {
            free(order);
            goto fail;
        }
    }
    free(order);

    /* One accumulator per distinct body list an instance is checked on. */
    p->acc = calloc((size_t)n_mi, sizeof *p->acc);
    if (!p->acc) goto fail;
    for (int vi = n_mi - 1; vi >= 0; vi--) {
        level_t *lv = &p->lv[vi];
        if (!lv->built || lv->gone || !lv->blist) continue;
        int ai = -1;
        for (int k = 0; k < p->n_acc; k++)
            if (p->acc[k].list == lv->blist) { ai = k; break; }
        if (ai < 0) { ai = p->n_acc++; p->acc[ai].list = lv->blist; }
        p->acc[ai].algs |= lv->algs;
        lv->acc = ai;
    }
    for (int k = 0; k < p->n_acc; k++) {
        static const EVP_MD *(*const mds[DKIM2_N_HASH_ALGS])(void) = { EVP_sha256, EVP_sha512 };
        for (int a = 0; a < DKIM2_N_HASH_ALGS; a++)
            if (p->acc[k].algs & (1u << a)) {
                p->acc[k].md[a] = EVP_MD_CTX_new();
                if (!p->acc[k].md[a] || EVP_DigestInit_ex(p->acc[k].md[a], mds[a](), NULL) != 1)
                    goto fail;
            }
    }
    return p;
fail:
    dkim2_plan_free(p);
    return NULL;
}

dkim2_plan_t *dkim2_plan_new_ctx(const dkim2_ctx_t *ctx, int normalise) {
    dkim2_mi_t *arr[64];
    int n = dkim2_mi_sorted(ctx->mi_list, arr, 64);
    return dkim2_plan_new(arr, n, ctx->headers, ctx->n_headers, normalise, 0);
}

/* ---- the body pass ---- */

static void acc_update(acc_t *a, const void *d, size_t len) {
    for (int i = 0; i < DKIM2_N_HASH_ALGS; i++)
        if (a->md[i]) EVP_DigestUpdate(a->md[i], d, len);
}

/* The blank lines held back, now that a non-blank line follows. */
static void acc_blanks(acc_t *a) {
    while (a->pending > 0) {
        long long k = a->pending < DKIM2_CRLF_RUN ? a->pending : DKIM2_CRLF_RUN;
        acc_update(a, dkim2_crlf_run, (size_t)(2 * k));
        a->pending -= k;
    }
}

/* One line (terminator included) into a body digest. -07 §6.1: a run of blank
   lines is held back until a non-blank line follows; at the end it is
   dropped. The run carries across body lines and literals alike. */
static void acc_emit(acc_t *a, const unsigned char *s, size_t len) {
    if (len == 2 && s[0] == '\r' && s[1] == '\n') { a->pending++; return; }
    acc_blanks(a);
    acc_update(a, s, len);
    a->emitted = 1;
    a->last_crlf = len >= 2 && s[len - 2] == '\r' && s[len - 1] == '\n';
}

static void acc_lits(dkim2_plan_t *p, acc_t *a, const seg_t *g) {
    for (long long k = g->from; k <= g->to; k++)
        acc_emit(a, p->blit[k].s, p->blit[k].len);
}

/* Past k lines of s..e (each up to and including an LF; a last one
   without is a line too), *got the lines passed -- fewer than k only at e.
   LFs are counted a block at a time (vectorisable), and only the block
   holding the k-th is searched -- or the last few bytes, never skipped
   in blocks, which end any line without an LF. */
static const char *skip_lines(const char *s, const char *e, long long k, long long *got) {
    long long n = 0;
    while (e - s > 64) {
        int c = 0;
        for (int i = 0; i < 64; i++) c += s[i] == '\n';
        if (n + c >= k) break;
        n += c;
        s += 64;
    }
    while (s < e && n < k) {
        const char *nl = memchr(s, '\n', (size_t)(e - s));
        s = nl ? nl + 1 : e;
        n++;
    }
    *got = n;
    return s;
}

/* Bytes each digest takes in turn when several share a run. */
#define STRIDE 128

/* A run of whole body lines s..e (split at each LF; only the body's last
   line may lack one) into every active digest: as acc_emit line by line,
   but only the blank lines ending the run need finding, backwards. With
   more than one digest, they take the run a few blocks at a time in turn:
   independent hashes interleaved that finely keep the CPU busy on two at
   once (measured: two SHA-256 over 10 MB, 5.2 ms against 6.1 ms whole). */
static void acc_run(dkim2_plan_t *p, const char *s, const char *e) {
    long long t = 0;
    while (e - s >= 2 && e[-1] == '\n' && e[-2] == '\r' && (e - 2 == s || e[-3] == '\n')) {
        e -= 2;
        t++;
    }
    int n_active = 0;
    for (int k = 0; k < p->n_acc; k++) {
        acc_t *a = &p->acc[k];
        if (!a->active) continue;
        n_active++;
        if (e == s) { a->pending += t; continue; }
        acc_blanks(a);
        a->emitted = 1;
        a->last_crlf = e - s >= 2 && e[-2] == '\r' && e[-1] == '\n';
        a->pending = t;
    }
    size_t stride = n_active > 1 ? STRIDE : (size_t)(e - s);
    for (; s < e; s += stride) {
        size_t len = (size_t)(e - s) < stride ? (size_t)(e - s) : stride;
        for (int k = 0; k < p->n_acc; k++)
            if (p->acc[k].active) acc_update(&p->acc[k], s, len);
    }
}

/* Body lines s..e, the next after p->n_lines (whole lines; only at the
   end of the body may the last lack its LF). Cut wherever some digest's
   segment starts or ends; each piece goes to the digests whose segment
   holds it. */
static void plan_lines(dkim2_plan_t *p, const char *s, const char *e) {
    while (s < e) {
        long long n = p->n_lines + 1, cut = LLONG_MAX;
        for (int k = 0; k < p->n_acc; k++) {
            acc_t *a = &p->acc[k];
            const seglist_t *l = a->list;
            for (; a->seg < l->n; a->seg++) {
                const seg_t *g = &l->s[a->seg];
                if (g->lit) { acc_lits(p, a, g); continue; }
                if (g->to < n) continue;
                long long c = n < g->from ? g->from : g->to + 1;
                if (c < cut) cut = c;
                break;
            }
        }
        long long got;
        const char *q = skip_lines(s, e, cut - n, &got);
        for (int k = 0; k < p->n_acc; k++) {
            acc_t *a = &p->acc[k];
            const seg_t *g = a->seg < a->list->n ? &a->list->s[a->seg] : NULL;
            a->active = g && !g->lit && g->from <= n;
        }
        acc_run(p, s, q);
        p->n_lines += got;
        s = q;
    }
}

static int part_append(dkim2_plan_t *p, const char *d, size_t len) {
    if (p->part_len + len > p->part_cap) {
        size_t nc = p->part_cap ? p->part_cap : 1024;
        while (nc < p->part_len + len) nc *= 2;
        char *np = realloc(p->part, nc);
        if (!np) return -1;
        p->part = np;
        p->part_cap = nc;
    }
    memcpy(p->part + p->part_len, d, len);
    p->part_len += len;
    return 0;
}

/* Lines as dkim2_apply_body_recipe splits them: up to and including each
   LF. Whole lines are hashed from d itself; only a partial line is kept
   between chunks. */
static int split_feed(dkim2_plan_t *p, const char *d, size_t len) {
    const char *e = d + len;
    if (p->part_len) {
        const char *nl = memchr(d, '\n', len);
        if (!nl) return part_append(p, d, len);
        if (part_append(p, d, (size_t)(nl + 1 - d)) < 0) return -1;
        plan_lines(p, p->part, p->part + p->part_len);
        p->part_len = 0;
        d = nl + 1;
    }
    const char *end = e;
    while (end > d && end[-1] != '\n') end--;
    plan_lines(p, d, end);
    return end < e ? part_append(p, end, (size_t)(e - end)) : 0;
}

int dkim2_plan_body_update(dkim2_plan_t *p, const char *data, size_t len) {
    if (p->finished) return -1;
    if (!p->normalise) return split_feed(p, data, len);
    /* As eml_parse: CRLF stays, a bare CR or bare LF becomes CRLF. Runs
       already in that form go through as they are. */
    while (len) {
        if (p->prev_cr) {
            p->prev_cr = 0;
            if (split_feed(p, "\r\n", 2) < 0) return -1;
            if (data[0] == '\n') { data++; len--; }
            continue;
        }
        size_t k = dkim2_crlf_clean(data, len);
        if (k) {
            if (split_feed(p, data, k) < 0) return -1;
        } else {
            if (data[0] == '\r') p->prev_cr = 1;
            else if (split_feed(p, "\r\n", 2) < 0) return -1;
            k = 1;
        }
        data += k;
        len -= k;
    }
    return 0;
}

/* Lines the list holds once the body has n lines. */
static long long list_len(const seglist_t *l, long long n) {
    long long t = 0;
    for (int i = 0; i < l->n; i++) {
        const seg_t *g = &l->s[i];
        if (g->lit) t += seg_len(g);
        else {
            long long e = g->to < n ? g->to : n;
            if (e >= g->from) t += e - g->from + 1;
        }
    }
    return t;
}

int dkim2_plan_body_final(dkim2_plan_t *p) {
    if (p->finished) return 0;
    if (p->normalise && p->prev_cr) {
        p->prev_cr = 0;
        if (split_feed(p, "\r\n", 2) < 0) return -1;
    }
    if (p->part_len) {
        p->unterminated = 1;
        plan_lines(p, p->part, p->part + p->part_len);
        p->part_len = 0;
    }
    p->finished = 1;
    long long n = p->n_lines;
    for (int k = 0; k < p->n_acc; k++) {
        acc_t *a = &p->acc[k];
        for (; a->seg < a->list->n; a->seg++)
            if (a->list->s[a->seg].lit) acc_lits(p, a, &a->list->s[a->seg]);
        /* dkim2_body_hash_raw_alg: the body less trailing CRLFs, plus one. */
        if (!a->emitted || !a->last_crlf) acc_update(a, "\r\n", 2);
        for (int i = 0; i < DKIM2_N_HASH_ALGS; i++)
            if (a->md[i]) {
                unsigned int dl = (unsigned int)dkim2_hash_alg_len(i);
                if (EVP_DigestFinal_ex(a->md[i], a->out.d[i], &dl) != 1) return -1;
            }
    }
    /* Copy ranges against the body each Recipe applies to (the undo walk
       counts every line, trailing blank ones included). */
    for (int vi = p->n - 1; vi >= 0; vi--) {
        level_t *lv = &p->lv[vi];
        if (!lv->built || !lv->applied) continue;
        if (lv->max_end > list_len(lv->blist, n)) lv->body_err = 1;
        /* An unterminated last line followed by a literal is one line to
           the undo walk: numbering it differs from ours. */
        if (p->unterminated) {
            const seglist_t *l = lv->blist;
            for (int i = 0; i < l->n; i++)
                if (!l->s[i].lit && l->s[i].from <= n && n <= l->s[i].to) {
                    for (int j = i + 1; j < l->n; j++)
                        if (l->s[j].lit) p->fallback = 1;
                    break;
                }
        }
    }
    return 0;
}

/* ---- results ---- */

static int level_err(const level_t *lv) {
    return lv->r_err || lv->body_err || lv->hdr_err;
}

int dkim2_plan_level(dkim2_plan_t *p, int vi, dkim2_plan_level_t *out) {
    if (vi < 0 || vi >= p->n) return -1;
    memset(out, 0, sizeof *out);
    const level_t *lv = &p->lv[vi];
    out->reached = lv->built;
    for (int u = p->n - 1; u > vi; u--)
        if (level_err(&p->lv[u])) out->reached = 0;
    if (!out->reached) return 0;
    out->have_body = !lv->gone && lv->acc >= 0;
    if (out->have_body) out->body = p->acc[lv->acc].out;
    out->hdr = lv->hdr;
    out->r_err = lv->r_err;
    out->body_err = lv->body_err;
    out->hdr_err = lv->hdr_err && !lv->body_err;    /* the walk stops at the body */
    return 0;
}

int dkim2_combine(const int *r, const int *g, int n, int n_groups, int *pick) {
    int any_pass = 0, any_temp = 0, any_fail = 0, result;
    for (int k = 0, i = 0; k < (n_groups > 0 ? n_groups : 1); k++) {
        int all_pass = 1, all_temp = 1, fail = 0, gr;
        for (; i < n && g[i] == k; i++) {
            if (r[i] == DKIM2_R_PASS) continue;
            all_pass = 0;
            if (r[i] != DKIM2_R_TEMPERROR) all_temp = 0;
            if (r[i] == DKIM2_R_FAIL) fail = 1;
        }
        gr = all_pass ? DKIM2_R_PASS : all_temp ? DKIM2_R_TEMPERROR :
             fail ? DKIM2_R_FAIL : DKIM2_R_PERMERROR;
        if (gr == DKIM2_R_PASS) any_pass = 1;
        if (gr == DKIM2_R_TEMPERROR) any_temp = 1;
        if (gr == DKIM2_R_FAIL) any_fail = 1;
    }
    result = any_pass ? DKIM2_R_PASS : any_temp ? DKIM2_R_TEMPERROR :
             any_fail ? DKIM2_R_FAIL : DKIM2_R_PERMERROR;
    *pick = -1;
    if (result == DKIM2_R_PASS || (n_groups > 1 && result == DKIM2_R_FAIL)) return result;
    for (int i = 0; i < n; i++)
        if (r[i] == result) { *pick = i; break; }
    return result;
}

int dkim2_mi_hash_verdict(const dkim2_mi_t *mi, const dkim2_digests_t *hdr,
                          const dkim2_digests_t *body, char *errbuf, size_t errbufsz) {
    int n = mi->n_hsets;
    /* per set: its result, its group, and for a FAIL whether only the
       body hash was wrong */
    int *r = malloc((size_t)(n ? n : 1) * 3 * sizeof *r);
    if (!r) { snprintf(errbuf, errbufsz, "TEMPERROR: out of memory"); return -1; }
    int *g = r + n, *body_only = r + 2 * n;
    for (int i = 0; i < n; i++) {
        g[i] = mi->hsets[i].group;
        body_only[i] = 0;
        r[i] = DKIM2_R_PASS;
        int alg = dkim2_hash_alg_index(mi->hsets[i].alg);
        if (alg < 0) { r[i] = DKIM2_R_PERMERROR; continue; }
        size_t alen = dkim2_hash_alg_len(alg);
        unsigned char stored[DKIM2_MAX_HASH_LEN + 3];
        int hl = b64_decode(mi->hsets[i].hdr_hash, stored, sizeof stored);
        if (hl != (int)alen || memcmp(hdr->d[alg], stored, alen) != 0) {
            r[i] = DKIM2_R_FAIL;
            continue;
        }
        if (!body) continue;
        int bl = b64_decode(mi->hsets[i].body_hash, stored, sizeof stored);
        if (bl != (int)alen || memcmp(body->d[alg], stored, alen) != 0) {
            r[i] = DKIM2_R_FAIL;
            body_only[i] = 1;
        }
    }
    int pick, res = dkim2_combine(r, g, n, mi->n_groups, &pick);
    int pick_body = pick >= 0 && body_only[pick];
    free(r);
    if (res == DKIM2_R_PASS) return 0;
    if (pick < 0)
        snprintf(errbuf, errbufsz, "FAIL: Message-Instance m=%d no group of hashes passed", mi->m);
    else if (res == DKIM2_R_PERMERROR)
        snprintf(errbuf, errbufsz, "PERMERROR: Message-Instance m=%d algorithm %s unknown",
                 mi->m, mi->hsets[pick].alg);
    else
        snprintf(errbuf, errbufsz, "FAIL: Message-Instance m=%d %s hash %s mismatch", mi->m,
                 pick_body ? "body" : "header",
                 dkim2_hash_alg_name(dkim2_hash_alg_index(mi->hsets[pick].alg)));
    return -1;
}

int dkim2_plan_check(dkim2_plan_t *p, char *errbuf, size_t errbufsz) {
    if (p->fallback) return 1;
    for (int vi = p->n - 1; vi >= 0; vi--) {
        const level_t *lv = &p->lv[vi];
        const dkim2_mi_t *mi = lv->mi;
        /* -08 §14.7 (contract D4): the hash-sets in h= order, each its
           header hash before its body hash, combined over the groups. */
        const dkim2_digests_t *body =
            !lv->gone && lv->acc >= 0 ? &p->acc[lv->acc].out : NULL;
        if (dkim2_mi_hash_verdict(mi, &lv->hdr, body, errbuf, errbufsz) < 0) return -1;
        if (lv->r_err == 1) {
            snprintf(errbuf, errbufsz, "PERMERROR: Message-Instance m=%d syntax error", mi->m);
            return -1;
        }
        if (lv->r_err == 2 || lv->body_err || lv->hdr_err) {
            snprintf(errbuf, errbufsz,
                "PERMERROR: Message-Instance m=%d contains invalid JSON", mi->m);
            return -1;
        }
    }
    return 0;
}

void dkim2_plan_free(dkim2_plan_t *p) {
    if (!p) return;
    for (int i = 0; i < p->n; i++)
        if (p->lv[i].own_hmap) free(p->lv[i].hmap);
    free(p->lv);
    for (int i = 0; i < p->n_g; i++) {
        hgroup_t *g = &p->g[i];
        if (g->rv_canon)
            for (int k = 0; k < g->n_rv; k++) free(g->rv_canon[k]);
        free(g->rv_canon);
        free(g->rv);
        free(g->name);
    }
    free(p->g);
    for (int i = 0; i < p->n_hlit; i++) free(p->hlit[i]);
    free(p->hlit);
    for (int i = 0; i < p->n_blit; i++) free(p->blit[i].s);
    free(p->blit);
    for (int i = 0; i < p->n_pool; i++) { free(p->pool[i]->s); free(p->pool[i]); }
    free(p->pool);
    if (p->acc)
        for (int k = 0; k < p->n_acc; k++)
            for (int a = 0; a < DKIM2_N_HASH_ALGS; a++) EVP_MD_CTX_free(p->acc[k].md[a]);
    free(p->acc);
    free(p->part);
    free(p);
}
