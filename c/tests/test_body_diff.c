/* Capped Myers body diff: the shared vectors (vectors/body-diff.json) plus
   timing and cap checks. Usage: test_body_diff [path-to-body-diff.json] */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <cjson/cJSON.h>
#include "../dkim2_recipe.h"

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    if (buf && fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); buf = NULL; }
    if (buf) buf[sz] = '\0';
    fclose(f);
    return buf;
}

static dkim2_line_t *to_lines(const cJSON *arr, int *n) {
    *n = cJSON_GetArraySize(arr);
    dkim2_line_t *ls = malloc(((size_t)*n + 1) * sizeof *ls);
    int i = 0;
    const cJSON *it;
    cJSON_ArrayForEach(it, arr) {
        assert(cJSON_IsString(it));
        ls[i].ptr = it->valuestring;
        ls[i].len = strlen(it->valuestring);
        i++;
    }
    return ls;
}

/* Compare the step list with the vector's flat recipe. */
static int steps_match(const dkim2_diff_step_t *st, int ns,
                       const dkim2_line_t *prev, const cJSON *expect) {
    if (cJSON_GetArraySize(expect) != ns) return 0;
    int s = 0;
    const cJSON *e;
    cJSON_ArrayForEach(e, expect) {
        if (cJSON_IsArray(e)) {
            if (st[s].lit) return 0;
            if (cJSON_GetArrayItem(e, 0)->valueint != st[s].from) return 0;
            if (cJSON_GetArrayItem(e, 1)->valueint != st[s].to) return 0;
        } else {
            if (!st[s].lit) return 0;
            const dkim2_line_t *l = &prev[st[s].from];
            if (strlen(e->valuestring) != l->len ||
                memcmp(e->valuestring, l->ptr, l->len) != 0) return 0;
        }
        s++;
    }
    return 1;
}

static int run_vectors(const char *path) {
    char *text = slurp(path);
    if (!text) { fprintf(stderr, "cannot read %s\n", path); return 1; }
    cJSON *root = cJSON_Parse(text);
    free(text);
    assert(root);
    int failures = 0, count = 0;
    const cJSON *c;
    cJSON_ArrayForEach(c, cJSON_GetObjectItem(root, "cases")) {
        const char *name = cJSON_GetObjectItem(c, "name")->valuestring;
        const cJSON *ml = cJSON_GetObjectItem(c, "max_literals");
        int L = ml ? ml->valueint : DKIM2_MAX_RECIPE_LITERALS;
        int nc, np;
        dkim2_line_t *cur = to_lines(cJSON_GetObjectItem(c, "cur"), &nc);
        dkim2_line_t *prev = to_lines(cJSON_GetObjectItem(c, "prev"), &np);
        const cJSON *expect = cJSON_GetObjectItem(c, "expect");
        dkim2_diff_step_t *st = NULL;
        int ns = 0;
        int rc = dkim2_body_diff(cur, nc, prev, np, L, &st, &ns);
        int ok;
        if (cJSON_IsString(expect) && strcmp(expect->valuestring, "identical") == 0)
            ok = rc == DKIM2_DIFF_IDENTICAL;
        else if (cJSON_IsString(expect) && strcmp(expect->valuestring, "too_big") == 0)
            ok = rc == DKIM2_DIFF_TOO_BIG;
        else
            ok = rc == DKIM2_DIFF_OK && steps_match(st, ns, prev, expect);
        if (!ok) { fprintf(stderr, "FAIL vector '%s' (rc=%d)\n", name, rc); failures++; }
        count++;
        if (rc == DKIM2_DIFF_OK) free(st);
        free(cur); free(prev);
    }
    cJSON_Delete(root);
    printf("body-diff vectors: %d/%d passed\n", count - failures, count);
    return failures;
}

static dkim2_line_t mk(const char *s) { return (dkim2_line_t){ s, strlen(s) }; }

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "../vectors/body-diff.json";
    if (run_vectors(path) != 0) return 1;

    dkim2_diff_step_t *st;
    int ns;

    /* a,b,a,b... vs b,a,b,a... at 4000 lines: fast, at most one literal. */
    {
        enum { NL = 4000 };
        dkim2_line_t *cur = malloc(NL * sizeof *cur), *prev = malloc(NL * sizeof *prev);
        for (int i = 0; i < NL; i++) {
            cur[i] = mk(i % 2 ? "b\r\n" : "a\r\n");
            prev[i] = mk(i % 2 ? "a\r\n" : "b\r\n");
        }
        double t0 = now_ms();
        int rc = dkim2_body_diff(cur, NL, prev, NL, DKIM2_MAX_RECIPE_LITERALS, &st, &ns);
        double dt = now_ms() - t0;
        assert(rc == DKIM2_DIFF_OK);
        int lits = 0;
        for (int s = 0; s < ns; s++) lits += st[s].lit;
        printf("alternating 4000: %d literal(s), %.2f ms\n", lits, dt);
        assert(lits <= 1);
        assert(dt < 100.0);
        free(st); free(cur); free(prev);
    }

    /* (30000+extra) x then 30000 y vs 30000 y then 30000 x: TOO_BIG, quickly.
       With extra = 0 the search stops at Dmax = 2000 (about 2.0M work);
       with extra = 5000, Dmax = 7000 is loose and the MAX_DIFF_WORK budget
       stops it (at d = 2827). */
    for (int extra = 0; extra <= 5000; extra += 5000) {
        enum { H = 30000 };
        int nc = 2 * H + extra;
        dkim2_line_t *cur = malloc((size_t)nc * sizeof *cur), *prev = malloc(2 * H * sizeof *prev);
        for (int i = 0; i < nc; i++) cur[i] = mk(i < H + extra ? "x\r\n" : "y\r\n");
        for (int i = 0; i < 2 * H; i++) prev[i] = mk(i < H ? "y\r\n" : "x\r\n");
        double t0 = now_ms();
        int rc = dkim2_body_diff(cur, nc, prev, 2 * H, DKIM2_MAX_RECIPE_LITERALS, &st, &ns);
        double dt = now_ms() - t0;
        printf("x/y swap, %d+%d vs %d+%d lines: rc=%d (TOO_BIG=%d), %.2f ms\n",
               H + extra, H, H, H, rc, DKIM2_DIFF_TOO_BIG, dt);
        assert(rc == DKIM2_DIFF_TOO_BIG);
        assert(dt < 1000.0);
        free(cur); free(prev);
    }

    /* 1000 literals OK, 1001 TOO_BIG (distinct new lines prepended). */
    {
        enum { E = 1001 };
        static char buf[E][16];
        dkim2_line_t cur[3], prev[E + 3];
        cur[0] = mk("keep1"); cur[1] = mk("keep2"); cur[2] = mk("keep3");
        for (int i = 0; i < E; i++) { snprintf(buf[i], sizeof buf[i], "new%d", i); prev[i] = mk(buf[i]); }
        for (int nlit = 1000; nlit <= 1001; nlit++) {
            for (int i = 0; i < 3; i++) prev[nlit + i] = cur[i];
            int rc = dkim2_body_diff(cur, 3, prev, nlit + 3, DKIM2_MAX_RECIPE_LITERALS, &st, &ns);
            if (nlit == 1000) {
                assert(rc == DKIM2_DIFF_OK);
                assert(ns == 1001 && !st[1000].lit && st[1000].from == 1 && st[1000].to == 3);
                free(st);
            } else {
                assert(rc == DKIM2_DIFF_TOO_BIG);
            }
        }
        /* and through the JSON generator: null body Recipe + *impossible */
        char *curb = "keep\r\n";
        size_t cap = E * 16 + 16, pos = 0;
        char *prevb = malloc(cap);
        for (int i = 0; i < E; i++) pos += (size_t)snprintf(prevb + pos, cap - pos, "new%d\r\n", i);
        pos += (size_t)snprintf(prevb + pos, cap - pos, "keep\r\n");
        int imp = 0;
        char *rj = dkim2_gen_body_recipe(curb, strlen(curb), prevb, pos, &imp);
        assert(rj && imp == 1 && strcmp(rj, "{\"b\":null}") == 0);
        free(rj); free(prevb);
    }

    /* A configurable cap through the public generator: 3 changed lines
       pass with max_literals 3 (and round-trip), fail with 2; 0 = default. */
    {
        const char *curb  = "a\r\nB\r\nc\r\nD\r\ne\r\nF\r\ng\r\n";
        const char *prevb = "a\r\nb\r\nc\r\nd\r\ne\r\nf\r\ng\r\n";
        int imp = -1;
        char *rj = dkim2_gen_body_recipe_ex(curb, strlen(curb), prevb, strlen(prevb), 3, &imp);
        assert(rj && imp == 0);
        assert(strcmp(rj, "{\"b\":[{\"c\":[1,1]},{\"d\":[\"b\"]},{\"c\":[3,3]},"
                          "{\"d\":[\"d\"]},{\"c\":[5,5]},{\"d\":[\"f\"]},{\"c\":[7,7]}]}") == 0);
        size_t n;
        char *r = dkim2_apply_body_recipe(rj, curb, strlen(curb), &n);
        assert(r && n == strlen(prevb) && memcmp(r, prevb, n) == 0);
        free(r); free(rj);
        rj = dkim2_gen_body_recipe_ex(curb, strlen(curb), prevb, strlen(prevb), 2, &imp);
        assert(rj && imp == 1 && strcmp(rj, "{\"b\":null}") == 0);
        free(rj);
        rj = dkim2_gen_body_recipe_ex(curb, strlen(curb), prevb, strlen(prevb), 0, &imp);
        assert(rj && imp == 0 && strncmp(rj, "{\"b\":[", 6) == 0);
        free(rj);
    }

    puts("body_diff: all tests passed");
    return 0;
}
