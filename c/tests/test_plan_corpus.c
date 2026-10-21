/* Planned chain walk against the undo walk on real mail.

   Usage: test_plan_corpus <keys.json> <dir> [<keys.json> <dir>]...

   For every *.eml in each dir, and for a copy with one body byte changed
   and a copy with the Subject changed:
     - per instance: header hash, body hash, Recipe errors (the undo walk's
       trace against the plan, fed the body in chunks of an odd size);
     - the same plan fed the RAW body bytes (normalise = 1, the milter path);
     - the full verdict text of dkim2_verify_message_opts, both walks.
   A dir that does not exist is skipped (the corpus is not in every
   checkout). Prints how long the chain walk alone took each way; nothing is
   asserted about time. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include "../dkim2_internal.h"
#include "../dkim2_verify.h"
#include "../dkim2_header.h"
#include "../dkim2_plan.h"
#include "../dkim2_message.h"
#include "../dkim2_dnsjson.h"
#include "../eml_parse.h"

static int n_files, n_compared, n_fail, n_fallback, n_pass;
static double t_undo, t_plan, tv_undo, tv_plan;

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

static char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    char *b = malloc((size_t)n + 1);
    *len = fread(b, 1, (size_t)n, f);
    b[*len] = '\0';
    fclose(f);
    return b;
}

/* Where the raw body starts: after the first empty line (any line ending). */
static size_t raw_body_start(const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (b[i] != '\n' && b[i] != '\r') continue;
        size_t j = i + (b[i] == '\r' && i + 1 < n && b[i + 1] == '\n' ? 2 : 1);
        if (j < n && b[j] == '\n') return j + 1;
        if (j < n && b[j] == '\r') return j + (j + 1 < n && b[j + 1] == '\n' ? 2 : 1);
        i = j - 1;
    }
    return n;
}

static int lvl_eq(const dkim2_plan_level_t *a, const dkim2_plan_level_t *b) {
    if (a->reached != b->reached) return 0;
    if (!a->reached) return 1;
    return a->have_body == b->have_body &&
           (!a->have_body || memcmp(&a->body, &b->body, sizeof a->body) == 0) &&
           memcmp(&a->hdr, &b->hdr, sizeof a->hdr) == 0 &&
           a->r_err == b->r_err && a->body_err == b->body_err && a->hdr_err == b->hdr_err;
}

/* The chain walk alone (outbound, signatures set aside), one way. */
static void walk_only(dkim2_ctx_t *ctx, int undo, char *out, size_t outsz) {
    dkim2_sig_t *sigs = ctx->sig_list;
    ctx->sig_list = NULL;
    ctx->outbound = 1;
    ctx->undo_walk = undo;
    dkim2_verify_result_t r;
    dkim2_do_verify(ctx, &r);
    snprintf(out, outsz, "%d %s", (int)r.status, r.message);
    ctx->sig_list = sigs;
    ctx->outbound = 0;
}

static void check_file(const char *path, const char *label) {
    n_files++;
    int bad = 0;
    char **h = NULL;
    int nh = 0;
    dkim2_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    if (eml_parse_with_body(path, &h, &nh, &ctx.body_digests, &ctx.body, &ctx.body_len) < 0) {
        fprintf(stderr, "  %s: cannot parse\n", label);
        n_fail++;
        return;
    }
    ctx.headers = h;
    ctx.n_headers = nh;
    dkim2_ctx_collect(&ctx);
    dkim2_mi_t *mis[64];
    int n = dkim2_mi_sorted(ctx.mi_list, mis, 64);

    /* Per instance. */
    dkim2_plan_level_t *tr = calloc((size_t)(n ? n : 1), sizeof *tr);
    char terr[512];
    dkim2_undo_walk_trace(mis, n, h, nh, ctx.body, ctx.body_len, tr, terr, sizeof terr);
    size_t step = 1 + (ctx.body_len * 7 + (size_t)n_files) % 997;
    dkim2_plan_t *p = dkim2_plan_new(mis, n, h, nh, 0, 1);
    for (size_t at = 0; at < ctx.body_len; at += step)
        dkim2_plan_body_update(p, ctx.body + at,
                               ctx.body_len - at < step ? ctx.body_len - at : step);
    dkim2_plan_body_final(p);
    char perr[512];
    int fb = dkim2_plan_check(p, perr, sizeof perr) == 1;
    if (fb) n_fallback++;
    for (int vi = 0; vi < n && !fb; vi++) {
        dkim2_plan_level_t x;
        dkim2_plan_level(p, vi, &x);
        if (!lvl_eq(&tr[vi], &x)) {
            fprintf(stderr, "  %s: instance m=%d differs from the undo walk\n", label, mis[vi]->m);
            bad = 1;
        }
    }

    /* The milter path: raw body bytes, normalised by the plan. */
    size_t rawlen;
    char *raw = slurp(path, &rawlen);
    size_t bs = raw_body_start(raw, rawlen);
    dkim2_plan_t *q = dkim2_plan_new(mis, n, h, nh, 1, 1);
    for (size_t at = bs; at < rawlen; at += step)
        dkim2_plan_body_update(q, raw + at, rawlen - at < step ? rawlen - at : step);
    dkim2_plan_body_final(q);
    for (int vi = 0; vi < n; vi++) {
        dkim2_plan_level_t x, y;
        dkim2_plan_level(p, vi, &x);
        dkim2_plan_level(q, vi, &y);
        if (!lvl_eq(&x, &y)) {
            fprintf(stderr, "  %s: raw-fed instance m=%d differs\n", label, mis[vi]->m);
            bad = 1;
        }
    }
    free(raw);
    dkim2_plan_free(q);
    dkim2_plan_free(p);
    free(tr);

    /* The chain walk alone, timed each way. */
    char wu[600], wp[600];
    double t0 = now();
    walk_only(&ctx, 1, wu, sizeof wu);
    double t1 = now();
    walk_only(&ctx, 0, wp, sizeof wp);
    double t2 = now();
    t_undo += t1 - t0;
    t_plan += t2 - t1;
    if (strcmp(wu, wp) != 0) {
        fprintf(stderr, "  %s: walks differ:\n    undo: %s\n    plan: %s\n", label, wu, wp);
        bad = 1;
    }

    /* The full verdict. */
    dkim2_verify_opts_t ou = { 1, 1, 0 }, op = { 0, 1, step };
    t0 = now();
    dkim2_verify_result_t ru = dkim2_verify_message_opts(path, NULL, NULL, 1, &ou);
    t1 = now();
    dkim2_verify_result_t rp = dkim2_verify_message_opts(path, NULL, NULL, 1, &op);
    t2 = now();
    tv_undo += t1 - t0;
    tv_plan += t2 - t1;
    if (ru.status != rp.status || strcmp(ru.message, rp.message) != 0) {
        fprintf(stderr, "  %s: verdicts differ:\n    undo: %s\n    plan: %s\n",
                label, ru.message, rp.message);
        bad = 1;
    }
    if (rp.status == DKIM2_OK) n_pass++;

    n_compared++;
    if (bad) n_fail++;
    dkim2_mi_free(ctx.mi_list);
    dkim2_sig_free(ctx.sig_list);
    dkim2_badfield_free(ctx.bad_list);
    free(ctx.body);
    eml_free(h, nh);
}

/* path with one change: a body byte (letter to the next letter), or the
   first character of the Subject value. 0 if there was nothing to change. */
static int mutate(const char *path, const char *tmp, int what) {
    size_t n;
    char *b = slurp(path, &n);
    if (!b) return 0;
    int done = 0;
    if (what == 0) {
        size_t bs = raw_body_start(b, n);
        for (size_t i = bs + (n - bs) / 2; i < n && !done; i++)
            if ((b[i] >= 'a' && b[i] < 'z') || (b[i] >= 'A' && b[i] < 'Z')) { b[i]++; done = 1; }
    } else {
        for (size_t i = 0; i + 9 < n && !done; i++)
            if ((i == 0 || b[i - 1] == '\n') && strncasecmp(b + i, "subject:", 8) == 0) {
                size_t j = i + 8;
                while (j < n && b[j] == ' ') j++;
                if (j < n && b[j] != '\r' && b[j] != '\n') { b[j] = b[j] == 'X' ? 'Y' : 'X'; done = 1; }
            }
    }
    if (done) {
        FILE *f = fopen(tmp, "wb");
        fwrite(b, 1, n, f);
        fclose(f);
    }
    free(b);
    return done;
}

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

int main(int argc, char **argv) {
    char tmp[] = "/tmp/dkim2-plan-corpus-XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) { perror("mkstemp"); return 1; }
    close(fd);
    for (int a = 1; a + 1 < argc; a += 2) {
        DIR *d = opendir(argv[a + 1]);
        if (!d) { printf("  %s: not here, skipped\n", argv[a + 1]); continue; }
        char jerr[256];
        if (dkim2_dns_json_load(argv[a], jerr, sizeof jerr) < 0) {
            fprintf(stderr, "%s\n", jerr);
            return 1;
        }
        char **names = NULL;
        int nn = 0;
        struct dirent *de;
        while ((de = readdir(d))) {
            size_t l = strlen(de->d_name);
            if (l > 4 && strcmp(de->d_name + l - 4, ".eml") == 0) {
                names = realloc(names, (size_t)(nn + 1) * sizeof *names);
                names[nn++] = strdup(de->d_name);
            }
        }
        closedir(d);
        qsort(names, (size_t)nn, sizeof *names, cmp_str);
        int f0 = n_files, fail0 = n_fail;
        for (int i = 0; i < nn; i++) {
            char path[4096], label[4200];
            snprintf(path, sizeof path, "%s/%s", argv[a + 1], names[i]);
            check_file(path, names[i]);
            for (int w = 0; w < 2; w++)
                if (mutate(path, tmp, w)) {
                    snprintf(label, sizeof label, "%s (%s changed)", names[i], w ? "Subject" : "body");
                    check_file(tmp, label);
                }
            free(names[i]);
        }
        free(names);
        printf("  %s: %d messages (%d originals + changed copies), %d differ\n",
               argv[a + 1], n_files - f0, nn, n_fail - fail0);
        dkim2_dns_json_free();
    }
    unlink(tmp);
    printf("test_plan_corpus: %d compared, %d differ, %d verified, %d via undo-walk fallback\n",
           n_compared, n_fail, n_pass, n_fallback);
    printf("  chain walk alone: undo %.3fs, planned %.3fs\n", t_undo, t_plan);
    printf("  whole verify (parse, signatures, walk): undo %.3fs, planned %.3fs\n",
           tv_undo, tv_plan);
    return n_fail ? 1 : 0;
}
