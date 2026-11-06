/* The library is called from the milter's per-connection threads: parsing
   a list tag and planning a chain walk must not share state between calls.
   Several threads parse and plan at once and check each result against
   the single-threaded one. A shared qsort context shows up here as a wrong
   answer or a crash, and reliably under -fsanitize=thread or address. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include "../dkim2_header.h"
#include "../dkim2_plan.h"

#define N_THREADS 8
#define N_ITERS   300
#define N_HDRS    64

static char *g_hdrs[N_HDRS];

/* An h= list with distinct names (none repeat), so it parses -- or, when
   dup, ends with a repeat of the first name, so it must not. */
static char *mk_hlist(int tid, int dup) {
    size_t cap = 64 * 40;
    char *s = malloc(cap), *p = s;
    p += sprintf(p, "m=1; h=");
    for (int i = 0; i < 40; i++)
        p += sprintf(p, "%sx%d-%d:AAAA:BBBB", i ? "," : "", tid, 40 - i);
    if (dup) p += sprintf(p, ",X%d-40:AAAA:BBBB", tid);
    return s;
}

static void *worker(void *arg) {
    int tid = (int)(long)arg;
    char *ok = mk_hlist(tid, 0), *bad = mk_hlist(tid, 1);
    for (int it = 0; it < N_ITERS; it++) {
        dkim2_mi_t *mi = dkim2_mi_parse(ok);
        assert(mi && mi->n_hsets == 40);
        dkim2_mi_free(mi);
        assert(dkim2_mi_parse(bad) == NULL);

        mi = dkim2_mi_parse("m=1; h=sha256:AAAA:BBBB");
        assert(mi);
        dkim2_plan_t *p = dkim2_plan_new(&mi, 1, g_hdrs, N_HDRS, 0, 1);
        assert(p);
        dkim2_plan_free(p);
        dkim2_mi_free(mi);
    }
    free(ok);
    free(bad);
    return NULL;
}

int main(void) {
    for (int i = 0; i < N_HDRS; i++) {
        g_hdrs[i] = malloc(48);
        snprintf(g_hdrs[i], 48, "X-H%02d: v\r\n", N_HDRS - i);
    }
    pthread_t th[N_THREADS];
    for (long t = 0; t < N_THREADS; t++)
        assert(pthread_create(&th[t], NULL, worker, (void *)t) == 0);
    for (int t = 0; t < N_THREADS; t++) pthread_join(th[t], NULL);
    for (int i = 0; i < N_HDRS; i++) free(g_hdrs[i]);
    printf("test_threads: %d threads x %d iterations OK\n", N_THREADS, N_ITERS);
    return 0;
}
