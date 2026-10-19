/* Planned chain walk (dkim2_plan.c) against the undo walk it replaces:
   per-instance header hashes, body hashes and Recipe errors (the undo
   walk's trace), and the verdict text, on hand-built Message-Instance
   chains -- fed whole, in every two-chunk split, and a byte at a time. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../dkim2_internal.h"
#include "../dkim2_verify.h"
#include "../dkim2_header.h"
#include "../dkim2_hash.h"
#include "../dkim2_plan.h"
#include "../base64.h"

/* The case tables leave trailing lvl_t members out. */
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

static int n_fail = 0, n_cases = 0, n_compared = 0;

#define MAXF 32
#define MAXL 6

/* One instance as it was when its MI was made: header fields in one string
   (split into fields like eml_parse), body, and the MI's Recipe (JSON, or
   NULL). hash_body/hash_hdrs override what the MI's h= claims. m_text
   overrides how m= is written ("01"); raw_r is r= as written. */
typedef struct {
    const char *hdrs, *body, *r;
    const char *hash_body, *hash_hdrs;
    const char *m_text, *raw_r;
} lvl_t;

static int split_fields(const char *s, char **out) {
    int n = 0;
    const char *p = s;
    while (*p) {
        const char *e = p;
        for (;;) {
            const char *nl = strstr(e, "\r\n");
            if (!nl) { e = p + strlen(p); break; }
            e = nl + 2;
            if (*e != ' ' && *e != '\t') break;
        }
        out[n] = strndup(p, (size_t)(e - p));
        n++;
        p = e;
    }
    return n;
}

static void free_fields(char **f, int n) { for (int i = 0; i < n; i++) free(f[i]); }

static dkim2_mi_t *mkmi(int m, const lvl_t *l) {
    char *f[MAXF];
    int nf = split_fields(l->hash_hdrs ? l->hash_hdrs : l->hdrs, f);
    const char *body = l->hash_body ? l->hash_body : l->body;
    unsigned char bh[DKIM2_MAX_HASH_LEN], hh[DKIM2_MAX_HASH_LEN];
    char sets[1024] = "", bb[128], hb[128];
    for (int a = 0; a < DKIM2_N_HASH_ALGS; a++) {
        dkim2_body_hash_raw_alg(body, strlen(body), a, bh);
        dkim2_header_hash_raw_alg((const char **)f, nf, a, hh);
        b64_encode(bh, dkim2_hash_alg_len(a), bb, sizeof bb);
        b64_encode(hh, dkim2_hash_alg_len(a), hb, sizeof hb);
        size_t o = strlen(sets);
        snprintf(sets + o, sizeof sets - o, "%s%s:%s:%s", a ? "," : "",
                 dkim2_hash_alg_name(a), hb, bb);
    }
    free_fields(f, nf);
    char mt[16], v[8192];
    if (l->m_text) snprintf(mt, sizeof mt, "%s", l->m_text);
    else snprintf(mt, sizeof mt, "%d", m);
    if (l->raw_r) {
        snprintf(v, sizeof v, "m=%s; h=%s; r=%s;", mt, sets, l->raw_r);
    } else if (l->r) {
        char rb[4096];
        b64_encode((const unsigned char *)l->r, strlen(l->r), rb, sizeof rb);
        snprintf(v, sizeof v, "m=%s; h=%s; r=%s;", mt, sets, rb);
    } else {
        snprintf(v, sizeof v, "m=%s; h=%s;", mt, sets);
    }
    dkim2_mi_t *mi = dkim2_mi_parse(v);
    if (!mi) { fprintf(stderr, "bad MI %s\n", v); exit(1); }
    return mi;
}

static int lvl_cmp(const char *what, int vi, const dkim2_plan_level_t *a,
                   const dkim2_plan_level_t *b) {
    char why[64] = "";
    if (a->reached != b->reached) strcpy(why, "reached");
    else if (!a->reached) return 0;
    else if (a->have_body != b->have_body) strcpy(why, "have_body");
    else if (a->have_body && memcmp(&a->body, &b->body, sizeof a->body)) strcpy(why, "body hash");
    else if (memcmp(&a->hdr, &b->hdr, sizeof a->hdr)) strcpy(why, "header hash");
    else if (a->r_err != b->r_err) strcpy(why, "r_err");
    else if (a->body_err != b->body_err) strcpy(why, "body_err");
    else if (a->hdr_err != b->hdr_err) strcpy(why, "hdr_err");
    if (!why[0]) return 0;
    fprintf(stderr, "  %s: instance %d differs: %s\n", what, vi, why);
    return 1;
}

/* Plan the chain and feed body in the chunks cuts[] marks (cut offsets,
   ascending, n_cuts of them). Returns the plan, finished. */
static dkim2_plan_t *plan_fed(dkim2_mi_t **mis, int n, char **f, int nf,
                              const char *body, const size_t *cuts, int n_cuts) {
    dkim2_plan_t *p = dkim2_plan_new(mis, n, f, nf, 0, 1);
    assert(p);
    size_t len = strlen(body), at = 0;
    for (int i = 0; i <= n_cuts; i++) {
        size_t to = i < n_cuts ? cuts[i] : len;
        assert(dkim2_plan_body_update(p, body + at, to - at) == 0);
        at = to;
    }
    assert(dkim2_plan_body_final(p) == 0);
    return p;
}

/* The verdict dkim2_do_verify gives (outbound, unsigned chain: the MI chain
   is all it checks), by either walk. */
static void verdict(dkim2_mi_t **mis, int n, char **f, int nf, const char *body,
                    int undo, char *out, size_t outsz) {
    dkim2_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    for (int i = 0; i < n; i++) mis[i]->next = i + 1 < n ? mis[i + 1] : NULL;
    ctx.mi_list = n ? mis[0] : NULL;
    ctx.headers = f;
    ctx.n_headers = nf;
    ctx.body = (char *)body;
    ctx.body_len = strlen(body);
    ctx.outbound = 1;
    ctx.undo_walk = undo;
    dkim2_body_hash_raw_alg(body, strlen(body), 0, ctx.body_digests.d[0]);
    dkim2_body_hash_raw_alg(body, strlen(body), 1, ctx.body_digests.d[1]);
    dkim2_verify_result_t r;
    dkim2_do_verify(&ctx, &r);
    snprintf(out, outsz, "%d %s", (int)r.status, r.message);
    for (int i = 0; i < n; i++) mis[i]->next = NULL;
}

/* want: NULL (any), "PASS", or a substring of the verdict. */
static void run_case(const char *name, const lvl_t *lv, int n, const char *top_extra,
                     const char *want, int want_fallback) {
    n_cases++;
    dkim2_mi_t *mis[MAXL];
    for (int i = 0; i < n; i++) mis[i] = mkmi(i + 1, &lv[i]);
    char hdrs[4096];
    snprintf(hdrs, sizeof hdrs, "%s%s", top_extra ? top_extra : "", lv[n - 1].hdrs);
    char *f[MAXF];
    int nf = split_fields(hdrs, f);
    const char *body = lv[n - 1].body;
    int bad = 0;

    dkim2_plan_level_t tr[MAXL], pl[MAXL];
    char terr[512];
    dkim2_undo_walk_trace(mis, n, f, nf, body, strlen(body), tr, terr, sizeof terr);
    dkim2_plan_t *p = plan_fed(mis, n, f, nf, body, NULL, 0);
    char perr[512];
    int fallback = dkim2_plan_check(p, perr, sizeof perr) == 1;
    if (fallback != (want_fallback != 0)) {
        fprintf(stderr, "  %s: plan %s the undo walk\n", name,
                fallback ? "unexpectedly asks for" : "does not ask for");
        bad = 1;
    }
    /* A message the plan hands to the undo walk is only compared on its
       verdict (below). */
    for (int vi = 0; vi < n && !fallback; vi++) {
        dkim2_plan_level(p, vi, &pl[vi]);
        bad |= lvl_cmp(name, vi, &tr[vi], &pl[vi]);
    }
    for (int vi = 0; vi < n && fallback; vi++) dkim2_plan_level(p, vi, &pl[vi]);
    n_compared++;

    /* Every two-chunk split and one byte at a time: same as whole. */
    size_t len = strlen(body);
    for (size_t c = 0; c <= len && !bad; c++) {
        dkim2_plan_t *q = plan_fed(mis, n, f, nf, body, &c, 1);
        for (int vi = 0; vi < n; vi++) {
            dkim2_plan_level_t x;
            dkim2_plan_level(q, vi, &x);
            if (lvl_cmp("split", vi, &pl[vi], &x)) { bad = 1; fprintf(stderr, "  at %zu\n", c); }
        }
        dkim2_plan_free(q);
    }
    if (!bad && len > 1) {
        size_t *cuts = malloc(len * sizeof *cuts);
        for (size_t i = 0; i < len - 1; i++) cuts[i] = i + 1;
        dkim2_plan_t *q = plan_fed(mis, n, f, nf, body, cuts, (int)len - 1);
        for (int vi = 0; vi < n; vi++) {
            dkim2_plan_level_t x;
            dkim2_plan_level(q, vi, &x);
            bad |= lvl_cmp("bytewise", vi, &pl[vi], &x);
        }
        dkim2_plan_free(q);
        free(cuts);
    }
    dkim2_plan_free(p);

    char vu[600], vp[600];
    verdict(mis, n, f, nf, body, 1, vu, sizeof vu);
    verdict(mis, n, f, nf, body, 0, vp, sizeof vp);
    if (strcmp(vu, vp) != 0) {
        fprintf(stderr, "  %s: verdicts differ:\n    undo: %s\n    plan: %s\n", name, vu, vp);
        bad = 1;
    }
    if (want && !strstr(vp, want)) {
        fprintf(stderr, "  %s: verdict '%s' lacks '%s'\n", name, vp, want);
        bad = 1;
    }
    printf("  %-44s %s  %s\n", name, bad ? "FAIL" : "ok", vp);
    if (bad) n_fail++;
    free_fields(f, nf);
    for (int i = 0; i < n; i++) dkim2_mi_free(mis[i]);
}

#define CASE(name, top, want, ...) do { \
    lvl_t L_[] = { __VA_ARGS__ }; \
    run_case(name, L_, (int)(sizeof L_ / sizeof L_[0]), top, want, 0); } while (0)
/* A case the plan does not model: it must ask for the undo walk. */
#define CASE_FALLBACK(name, top, want, ...) do { \
    lvl_t L_[] = { __VA_ARGS__ }; \
    run_case(name, L_, (int)(sizeof L_ / sizeof L_[0]), top, want, 1); } while (0)

#define H1 "From: a@example.com\r\nTo: list@example.org\r\nSubject: hi\r\n"
#define H2 "From: a@example.com\r\nTo: list@example.org\r\nSubject: [L] hi\r\n"
#define H3 "From: a@example.com\r\nTo: list@example.org\r\nSubject: [M] [L] hi\r\n"
#define RSUB "\"h\":{\"subject\":[{\"d\":[\"hi\"]}]}"
#define RSUB3 "\"h\":{\"subject\":[{\"d\":[\"[L] hi\"]}]}"
#define TOPX "Received: from x by y\r\nDKIM2-Signature: i=1; junk\r\nMessage-Instance: m=7; junk\r\n"

static void body_cases(void) {
    const char *B = "one\r\ntwo\r\n";
    CASE("no Recipe", NULL, "PASS", { H1, B }, { H1, B });
    CASE("no Recipe, header-only Recipe", TOPX, "PASS", { H1, B }, { H2, B, "{" RSUB "}" });
    CASE("footer append", NULL, "PASS", { H1, B },
         { H2, "one\r\ntwo\r\n--\r\nfooter\r\n", "{" RSUB ",\"b\":[{\"c\":[1,2]}]}" });
    CASE("MIME wrap", NULL, "PASS", { H1, B },
         { H2, "--x\r\nContent-Type: text/plain\r\n\r\none\r\ntwo\r\n--x--\r\n",
           "{" RSUB ",\"b\":[{\"c\":[4,5]}]}" });
    CASE("literals before/between/after", NULL, "PASS",
         { H1, "L1\r\na\r\nL2\r\nb\r\nL3\r\n" },
         { H2, "a\r\nX\r\nb\r\n",
           "{" RSUB ",\"b\":[{\"d\":[\"L1\"]},{\"c\":[1,1]},{\"d\":[\"L2\"]},{\"c\":[3,3]},{\"d\":[\"L3\"]}]}" });
    CASE("3 levels, copy of a literal above", NULL, "PASS",
         { H1, "keep\r\nlit\r\n" },
         { H2, "keep\r\nlit\r\nfooter2\r\n", "{" RSUB ",\"b\":[{\"c\":[1,2]}]}" },
         { H3, "new\r\nkeep\r\n", "{" RSUB3 ",\"b\":[{\"c\":[2,2]},{\"d\":[\"lit\",\"footer2\"]}]}" });
    CASE("trailing blank lines", NULL, "PASS", { H1, "a\r\n\r\nb\r\n" },
         { H2, "a\r\n\r\n\r\n", "{" RSUB ",\"b\":[{\"c\":[1,2]},{\"d\":[\"b\"]}]}" });
    CASE("blank run over body line + literal", NULL, "PASS",
         { H1, "a\r\n\r\n\r\nb\r\n" },
         { H2, "a\r\n\r\nz\r\n", "{" RSUB ",\"b\":[{\"c\":[1,2]},{\"d\":[\"\",\"b\"]}]}" });
    CASE("blank literals at the end", NULL, "PASS", { H1, "a\r\n" },
         { H2, "a\r\nfoot\r\n", "{" RSUB ",\"b\":[{\"c\":[1,1]},{\"d\":[\"\",\"\"]}]}" });
    CASE("copy into trailing blanks", NULL, NULL, { H1, "a\r\n\r\n\r\n" },
         { H2, "a\r\n\r\n\r\n", "{" RSUB ",\"b\":[{\"c\":[1,3]}]}" });
    CASE("copy past end", NULL, "contains invalid JSON", { H1, B },
         { H2, B, "{" RSUB ",\"b\":[{\"c\":[1,9]}]}" });
    CASE("copy past end of a rebuilt body", NULL, "m=2 contains invalid JSON",
         { H1, "x\r\ny\r\nq\r\n" },
         { H2, "x\r\ny\r\n", "{" RSUB ",\"b\":[{\"c\":[1,3]}]}" },
         { H3, "x\r\ny\r\nz\r\n", "{" RSUB3 ",\"b\":[{\"c\":[1,2]}]}" });
    CASE("copy past end of an all-literal body", NULL, "m=2 contains invalid JSON",
         { H1, "x\r\ny\r\nq\r\n" },
         { H2, "p\r\nq\r\n", "{" RSUB ",\"b\":[{\"c\":[1,3]}]}" },
         { H3, "z\r\n", "{" RSUB3 ",\"b\":[{\"d\":[\"p\",\"q\"]}]}" });
    CASE("out-of-order copies", NULL, "contains invalid JSON", { H1, B },
         { H2, B, "{" RSUB ",\"b\":[{\"c\":[2,2]},{\"c\":[1,1]}]}" });
    CASE("overlapping copies", NULL, "contains invalid JSON", { H1, B },
         { H2, "a\r\nb\r\nc\r\n", "{" RSUB ",\"b\":[{\"c\":[1,2]},{\"c\":[2,3]}]}" });
    CASE("string copy bounds", NULL, "contains invalid JSON", { H1, B },
         { H2, B, "{" RSUB ",\"b\":[{\"c\":[\"1\",\"2\"]}]}" });
    CASE("b is not an array", NULL, "contains invalid JSON", { H1, B },
         { H2, B, "{" RSUB ",\"b\":5}" });
    CASE("null body Recipe", NULL, "PASS", { H1, B, NULL, "junk\r\n" },
         { H2, "new\r\n", "{" RSUB ",\"b\":null}" });
    CASE("null body Recipe, 3 levels", NULL, "PASS", { H1, B, NULL, "junk\r\n" },
         { H2, "two\r\n", "{" RSUB ",\"b\":[{\"d\":[\"zzz\"]}]}", "junk2\r\n" },
         { H3, "new\r\n", "{" RSUB3 ",\"b\":null}" });
    CASE("bad structure below a null", NULL, "m=2 contains invalid JSON",
         { H1, B }, { H2, "two\r\n", "{" RSUB ",\"b\":[{\"c\":[3,4]},{\"c\":[1,2]}]}" },
         { H3, "new\r\n", "{" RSUB3 ",\"b\":null}" });
    CASE("out of range below a null (not checked)", NULL, "PASS",
         { H1, B }, { H2, "two\r\n", "{" RSUB ",\"b\":[{\"c\":[1,99]}]}", "x\r\n" },
         { H3, "new\r\n", "{" RSUB3 ",\"b\":null}" });
    CASE("unterminated last line", NULL, "PASS", { H1, "a\r\nb" },
         { H2, "a\r\nb", "{" RSUB ",\"b\":[{\"c\":[1,2]}]}" });
#define B64 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    /* LFs are counted in 64-byte blocks: the last line is not one of them. */
    CASE("unterminated last line of 64 bytes", NULL, "PASS", { H1, "a\r\n" B64 },
         { H2, "a\r\n" B64, "{" RSUB ",\"b\":[{\"c\":[1,2]}]}" });
    CASE("unterminated last line of 128 bytes", NULL, "PASS", { H1, "a\r\n" B64 B64 "x\r\n" },
         { H2, "a\r\n" B64 B64, "{" RSUB ",\"b\":[{\"c\":[1,2]},{\"d\":[\"x\"]}]}" });
    CASE("unterminated last line + literal", NULL, "PASS", { H1, "a\r\nbx\r\n" },
         { H2, "a\r\nb", "{" RSUB ",\"b\":[{\"c\":[1,2]},{\"d\":[\"x\"]}]}" });
    CASE_FALLBACK("unterminated + literal, then a Recipe", NULL, "PASS", { H1, "bx\r\n" },
         { H2, "a\r\nbx\r\n", "{" RSUB ",\"b\":[{\"c\":[2,2]}]}" },
         { H3, "a\r\nb", "{" RSUB3 ",\"b\":[{\"c\":[1,2]},{\"d\":[\"x\"]}]}" });
    CASE_FALLBACK("unterminated + literal, Recipe past it", NULL, NULL, { H1, "bx\r\nq\r\n" },
         { H2, "a\r\nbx\r\nq\r\n", "{" RSUB ",\"b\":[{\"c\":[2,3]}]}" },
         { H3, "a\r\nb", "{" RSUB3 ",\"b\":[{\"c\":[1,2]},{\"d\":[\"x\",\"q\"]}]}" });
    CASE("empty body", NULL, "PASS", { H1, "x\r\n" },
         { H2, "", "{" RSUB ",\"b\":[{\"d\":[\"x\"]}]}" });
    CASE("copy from an empty body", NULL, "contains invalid JSON", { H1, "x\r\n" },
         { H2, "", "{" RSUB ",\"b\":[{\"c\":[1,1]}]}" });
    CASE("body of only blank lines", NULL, "PASS", { H1, "\r\n\r\nq\r\n" },
         { H2, "\r\n\r\n", "{" RSUB ",\"b\":[{\"c\":[1,2]},{\"d\":[\"q\"]}]}" });
    CASE("lone CR in a line", NULL, "PASS", { H1, "a\rb\r\n" },
         { H2, "a\rb\r\nc\r\n", "{" RSUB ",\"b\":[{\"c\":[1,1]}]}" });
    CASE("bare LF lines", NULL, "PASS", { H1, "a\nb\r\n\n" },
         { H2, "a\nb\r\n\nc\n", "{" RSUB ",\"b\":[{\"c\":[1,3]}]}" });
    CASE("empty Recipe []", NULL, "PASS", { H1, "" },
         { H2, B, "{" RSUB ",\"b\":[]}" });
    CASE("u literal (UTF-8 is allowed in u)", NULL, "PASS", { H1, "caf\xc3\xa9\r\none\r\n" },
         { H2, B, "{" RSUB ",\"b\":[{\"u\":[\"Y2Fmw6k=\"]},{\"c\":[1,1]}]}" });
    CASE("body hash mismatch at m=1", NULL, "m=1 body hash sha256 mismatch",
         { H1, B, NULL, "other\r\n" }, { H2, B, "{" RSUB "}" });
    CASE("top body hash mismatch", NULL, "m=2 body hash sha256 mismatch",
         { H1, B }, { H2, B, "{" RSUB "}", "other\r\n" });
    CASE("hash mismatch above a bad Recipe", NULL, "m=2 header hash sha256 mismatch",
         { H1, B }, { H2, B, "{" RSUB ",\"b\":[{\"c\":[1,9]}]}", NULL, H1 });
    CASE("m=01", NULL, "PASS", { H1, B, NULL, NULL, NULL, "01" },
         { H2, B, "{" RSUB "}" });
    CASE("r= not base64", NULL, "m=2 syntax error", { H1, B },
         { H2, B, NULL, NULL, NULL, NULL, "!!!!" });
    CASE("r= not JSON", NULL, "m=2 contains invalid JSON", { H1, B },
         { H2, B, "{\"b\":[" });
    CASE("r= duplicate key", NULL, "m=2 contains invalid JSON", { H1, B },
         { H2, B, "{\"b\":[],\"b\":null}" });
    CASE("m=1 Recipe is not applied", NULL, "PASS",
         { H1, B, "{\"b\":[{\"c\":[1,99]}]}" }, { H2, B, "{" RSUB "}" });
}

static void header_cases(void) {
    const char *B = "one\r\ntwo\r\n";
    CASE("subject tag removed", NULL, "PASS", { H1, B }, { H2, B, "{" RSUB "}" });
    CASE("fields removed", NULL, "PASS", { H1, B },
         { H1 "List-Id: <l.example.org>\r\nList-Post: x\r\n", B,
           "{\"h\":{\"list-id\":[],\"list-post\":[]}}" });
    CASE("repeated fields, copies + literals", NULL, "PASS",
         { H1 "Comments: a\r\nComments: q\r\nComments: c\r\n", B },
         { H1 "Comments: a\r\nComments: b\r\nComments: c\r\n", B,
           "{\"h\":{\"comments\":[{\"c\":[1,1]},{\"d\":[\"q\"]},{\"c\":[3,3]}]}}" });
    CASE("a field added", NULL, "PASS",
         { H1 "Cc: x@example.org\r\n", B }, { H1, B, "{\"h\":{\"cc\":[{\"d\":[\"x@example.org\"]}]}}" });
    CASE("3 levels of headers", NULL, "PASS", { H1, B }, { H2, B, "{" RSUB "}" },
         { H3 "List-Id: x\r\n", B, "{\"h\":{\"subject\":[{\"d\":[\"[L] hi\"]}],\"list-id\":[]}}" });
    CASE("folded values", NULL, "PASS",
         { "From: a@example.com\r\nSubject: hi\r\n  there\r\n", B },
         { "From: a@example.com\r\nSubject: [L] hi\r\n\tthere\r\n", B,
           "{\"h\":{\"subject\":[{\"d\":[\"hi there\"]}]}}" });
    CASE("mixed-case names", NULL, "PASS",
         { "FROM: a@example.com\r\nsubject: hi\r\n", B },
         { "FROM: a@example.com\r\nSUBJECT: [L] hi\r\n", B, "{" RSUB "}" });
    CASE("mixed-case Recipe key", NULL, NULL, { H1, B },
         { H2, B, "{\"h\":{\"Subject\":[{\"d\":[\"hi\"]}]}}" });
    CASE("keys differing in case, in turn", NULL, NULL, { H1, B },
         { H2, B, "{\"h\":{\"Subject\":[{\"d\":[\"hi\"]}],\"subject\":[{\"c\":[1,1]}]}}" });
    CASE("keys differing in case, other order", NULL, NULL, { H1, B },
         { H2, B, "{\"h\":{\"subject\":[{\"c\":[1,1]}],\"SUBJECT\":[{\"d\":[\"hi\"]}]}}" });
    CASE("key with a colon", NULL, NULL, { H1, B },
         { H2, B, "{\"h\":{\"x:y\":[{\"d\":[\"v\"]}],\"subject\":[{\"d\":[\"hi\"]}]}}" });
    CASE("skipped fields with Recipes", "Received: one\r\nReceived: two\r\n", "PASS",
         { H1 "X-Foo: 1\r\n", B },
         { H2 "X-Foo: 2\r\n", B,
           "{\"h\":{\"received\":[{\"c\":[1,1]}],\"x-foo\":[{\"d\":[\"1\"]}],\"subject\":[{\"d\":[\"hi\"]}]}}" });
    CASE("skipped field copy past end", "Received: one\r\n", "contains invalid JSON",
         { H1, B }, { H2, B, "{\"h\":{\"received\":[{\"c\":[1,2]}]}}" });
    CASE("header copy past end", NULL, "m=2 contains invalid JSON", { H1, B },
         { H2, B, "{\"h\":{\"subject\":[{\"c\":[1,2]}]}}" });
    CASE("missing field", NULL, "contains invalid JSON", { H1, B },
         { H2, B, "{\"h\":{\"cc\":[{\"c\":[1,1]}]}}" });
    CASE("header copies out of order", NULL, "contains invalid JSON",
         { H1 "Comments: a\r\nComments: b\r\n", B },
         { H1 "Comments: a\r\nComments: b\r\n", B,
           "{\"h\":{\"comments\":[{\"c\":[2,2]},{\"c\":[1,1]}]}}" });
    CASE("first bad name in key order", NULL, "contains invalid JSON", { H1, B },
         { H2, B, "{\"h\":{\"zz\":[{\"c\":[1,1]}],\"aa\":[{\"c\":[1,1]}],\"subject\":[{\"d\":[\"hi\"]}]}}" });
    CASE("body error before header error", NULL, "m=2 contains invalid JSON",
         { H1, B }, { H2, B, "{\"b\":[{\"c\":[1,99]}],\"h\":{\"cc\":[{\"c\":[1,1]}]}}" });
    CASE("header Recipes below a null", NULL, "m=2 contains invalid JSON",
         { H1, B }, { H2, "two\r\n", "{\"h\":{\"cc\":[{\"c\":[1,1]}]}}" },
         { H3, "new\r\n", "{" RSUB3 ",\"b\":null}" });
    CASE("header hash mismatch below a null", NULL, "m=1 header hash sha256 mismatch",
         { H1, B, NULL, NULL, "From: other\r\n" }, { H2, "new\r\n", "{" RSUB ",\"b\":null}" });
    CASE("h is null", NULL, "contains invalid JSON", { H1, B },
         { H2, B, "{\"h\":null}" });
    CASE("h is an array", NULL, "contains invalid JSON", { H1, B },
         { H2, B, "{\"h\":[]}" });
    CASE("non-array field / unknown step", NULL, "contains invalid JSON", { H1, B },
         { H2, B, "{\"h\":{\"to\":5,\"subject\":[{\"x\":1},{\"d\":[\"hi\",7]}]}}" });
    CASE("message-instance key, literal", NULL, "PASS", { H1, B },
         { H2, B, "{\"h\":{\"message-instance\":[{\"d\":[\"m=9\"]}]," "\"subject\":[{\"d\":[\"hi\"]}]}}" });
    CASE("message-instance key, copy", NULL, "contains invalid JSON", { H1, B },
         { H2, B, "{\"h\":{\"message-instance\":[{\"c\":[1,1]}]}}" });
    CASE("u literal header", NULL, "PASS",
         { "From: a@example.com\r\nSubject: caf\xc3\xa9\r\n", B },
         { "From: a@example.com\r\nSubject: x\r\n", B, "{\"h\":{\"subject\":[{\"u\":[\"Y2Fmw6k=\"]}]}}" });
    CASE("NUL in a u header literal", NULL, "contains invalid JSON", { H1, B },
         { H2, B, "{\"h\":{\"subject\":[{\"u\":[\"aABp\"]}]}}" });
    CASE("CR in a d literal", NULL, "contains invalid JSON", { H1, B },
         { H2, B, "{\"h\":{\"subject\":[{\"d\":[\"a\\rb\"]}]}}" });
    CASE("long field name", NULL, NULL,
         { H1 "Xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-a: 1\r\n", B },
         { H1 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: 2\r\n", B,
           "{\"h\":{\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\":[]}}" });
}

/* As eml_parse normalises: CRLF stays, a bare CR or LF becomes CRLF. */
static char *norm(const char *s) {
    size_t n = strlen(s), o = 0;
    char *out = malloc(n * 2 + 1);
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '\r' && s[i + 1] == '\n') { out[o++] = '\r'; out[o++] = '\n'; i++; }
        else if (s[i] == '\r' || s[i] == '\n') { out[o++] = '\r'; out[o++] = '\n'; }
        else out[o++] = s[i];
    }
    out[o] = '\0';
    return out;
}

/* The milter feeds raw SMTP body bytes (normalise = 1): every split of the
   raw body must give what the plan gives on the normalised bytes. */
static void normalise_cases(void) {
    static const char *raws[] = {
        "a\nb\n\nfoot\n", "a\r\nb\rc\r\r\n\n", "x\r", "\r\n\n\r", "q\r\nr", "",
    };
    for (size_t k = 0; k < sizeof raws / sizeof raws[0]; k++) {
        n_cases++;
        const char *raw = raws[k];
        char *nb = norm(raw);
        lvl_t lv[2] = { { H1, "pre\r\n" }, { H2, nb } };
        lv[1].r = "{" RSUB ",\"b\":[{\"d\":[\"pre\"]},{\"c\":[1,1]}]}";
        dkim2_mi_t *mis[2] = { mkmi(1, &lv[0]), mkmi(2, &lv[1]) };
        char *f[MAXF];
        int nf = split_fields(H2, f), bad = 0;
        dkim2_plan_t *ref = plan_fed(mis, 2, f, nf, nb, NULL, 0);
        size_t len = strlen(raw);
        for (size_t c = 0; c <= len; c++) {
            dkim2_plan_t *q = dkim2_plan_new(mis, 2, f, nf, 1, 1);
            assert(dkim2_plan_body_update(q, raw, c) == 0);
            assert(dkim2_plan_body_update(q, raw + c, len - c) == 0);
            assert(dkim2_plan_body_final(q) == 0);
            char e1[256] = "", e2[256] = "";
            int c1 = dkim2_plan_check(ref, e1, sizeof e1);
            int c2 = dkim2_plan_check(q, e2, sizeof e2);
            for (int vi = 0; vi < 2; vi++) {
                dkim2_plan_level_t x, y;
                dkim2_plan_level(ref, vi, &x);
                dkim2_plan_level(q, vi, &y);
                bad |= lvl_cmp("normalise", vi, &x, &y);
            }
            if (c1 != c2 || strcmp(e1, e2)) bad = 1;
            dkim2_plan_free(q);
        }
        printf("  raw body %-35zu %s\n", k, bad ? "FAIL" : "ok");
        if (bad) n_fail++;
        dkim2_plan_free(ref);
        free_fields(f, nf);
        dkim2_mi_free(mis[0]);
        dkim2_mi_free(mis[1]);
        free(nb);
    }
}

int main(void) {
    printf("body cases:\n");
    body_cases();
    printf("header cases:\n");
    header_cases();
    printf("normalised (milter) feeding:\n");
    normalise_cases();
    printf("test_plan: %d cases, %d failed\n", n_cases, n_fail);
    return n_fail ? 1 : 0;
}
