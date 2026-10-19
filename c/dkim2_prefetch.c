#include "dkim2_prefetch.h"
#include "dkim2_dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

int (*dkim2_prefetch_query_hook)(const char *qname, unsigned char *answer,
                                 int anslen, int *herr) = NULL;
int dkim2_prefetch_timeout_ms = 5000;

/* One lookup. Shared by the verifier and the thread doing the query: the
   last of the two to let go frees it, so a lookup that is not answered in
   time is simply left to finish (the thread is detached). */
typedef struct {
    char qname[512];
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int refs;
    int done;           /* the thread has stored its answer */
    int given_up;       /* not answered in time: synchronous from now on */
    struct timespec deadline;
    int anslen, herr;
    unsigned char answer[4096];
} pf_entry_t;

struct dkim2_prefetch {
    pf_entry_t **e;
    int n;
};

static void entry_release(pf_entry_t *e) {
    pthread_mutex_lock(&e->mu);
    int last = --e->refs == 0;
    pthread_mutex_unlock(&e->mu);
    if (last) {
        pthread_mutex_destroy(&e->mu);
        pthread_cond_destroy(&e->cv);
        free(e);
    }
}

/* res_query() shares one resolver state between threads; each lookup
   thread gets its own. */
static int default_query(const char *qname, unsigned char *answer, int anslen, int *herr) {
    struct __res_state st;
    memset(&st, 0, sizeof st);
    if (res_ninit(&st) != 0) { *herr = NO_RECOVERY; return -1; }
    int n = res_nquery(&st, qname, ns_c_in, ns_t_txt, answer, anslen);
    *herr = st.res_h_errno;
#ifdef __APPLE__
    res_ndestroy(&st);
#else
    res_nclose(&st);
#endif
    return n;
}

static void *lookup_thread(void *arg) {
    pf_entry_t *e = arg;
    unsigned char *ans = malloc(sizeof e->answer);
    int herr = NO_RECOVERY, n = -1;
    if (ans) {
        n = dkim2_prefetch_query_hook
            ? dkim2_prefetch_query_hook(e->qname, ans, (int)sizeof e->answer, &herr)
            : default_query(e->qname, ans, (int)sizeof e->answer, &herr);
        if (n > (int)sizeof e->answer) n = -1;
    }
    pthread_mutex_lock(&e->mu);
    e->anslen = n;
    e->herr = herr;
    if (n > 0) memcpy(e->answer, ans, (size_t)n);
    e->done = 1;
    pthread_cond_broadcast(&e->cv);
    pthread_mutex_unlock(&e->mu);
    free(ans);
    entry_release(e);
    return NULL;
}

static int known_alg(const char *alg) {
    return strcmp(alg, "rsa-sha256") == 0 || strcmp(alg, "ed25519-sha256") == 0;
}

static int add_name(dkim2_prefetch_t *pf, const char *qname) {
    for (int i = 0; i < pf->n; i++)
        if (strcasecmp(pf->e[i]->qname, qname) == 0) return 0;
    pf_entry_t **ne = realloc(pf->e, (size_t)(pf->n + 1) * sizeof *ne);
    if (!ne) return -1;
    pf->e = ne;
    pf_entry_t *e = calloc(1, sizeof *e);
    if (!e) return -1;
    snprintf(e->qname, sizeof e->qname, "%s", qname);
    pthread_mutex_init(&e->mu, NULL);
    pthread_cond_init(&e->cv, NULL);
    e->refs = 2;                        /* the verifier and the thread */
    clock_gettime(CLOCK_REALTIME, &e->deadline);
    long ms = dkim2_prefetch_timeout_ms;
    e->deadline.tv_sec += ms / 1000;
    e->deadline.tv_nsec += (ms % 1000) * 1000000L;
    if (e->deadline.tv_nsec >= 1000000000L) {
        e->deadline.tv_sec++;
        e->deadline.tv_nsec -= 1000000000L;
    }
    pf->e[pf->n++] = e;

    pthread_attr_t at;
    pthread_t tid;
    int rc = pthread_attr_init(&at);
    if (rc == 0) {
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        rc = pthread_create(&tid, &at, lookup_thread, e);
        pthread_attr_destroy(&at);
    }
    if (rc != 0) {                      /* no thread: the lookup is synchronous */
        e->given_up = 1;
        e->refs = 1;
    }
    return 0;
}

dkim2_prefetch_t *dkim2_prefetch_start(const dkim2_ctx_t *ctx) {
    /* Keys from dns.json or a test seam are not DNS: nothing to overlap. */
    if (dkim2_dns_override || (dkim2_dns_query_hook && !dkim2_prefetch_query_hook))
        return NULL;
    dkim2_prefetch_t *pf = calloc(1, sizeof *pf);
    if (!pf) return NULL;
    for (const dkim2_sig_t *s = ctx->sig_list; s; s = s->next) {
        if (!s->d) continue;
        for (int j = 0; j < s->n_ssets; j++) {
            if (!known_alg(s->ssets[j].alg)) continue;
            char q[512];
            snprintf(q, sizeof q, "%s._domainkey.%s", s->ssets[j].selector, s->d);
            if (add_name(pf, q) < 0) { dkim2_prefetch_free(pf); return NULL; }
        }
    }
    if (pf->n == 0) { dkim2_prefetch_free(pf); return NULL; }
    return pf;
}

int dkim2_prefetch_count(const dkim2_prefetch_t *pf) { return pf ? pf->n : 0; }

const char *dkim2_prefetch_name(const dkim2_prefetch_t *pf, int i) {
    return pf && i >= 0 && i < pf->n ? pf->e[i]->qname : NULL;
}

dkim2_pubkey_t *dkim2_prefetch_getkey(dkim2_prefetch_t *pf, const char *selector,
    const char *domain, dkim2_status_t *statusp, const char **errp) {
    char q[512];
    snprintf(q, sizeof q, "%s._domainkey.%s", selector, domain);
    pf_entry_t *e = NULL;
    for (int i = 0; pf && i < pf->n && !e; i++)
        if (strcasecmp(pf->e[i]->qname, q) == 0) e = pf->e[i];
    if (e) {
        unsigned char *ans = NULL;
        int anslen = -1, herr = 0, use = 0;
        pthread_mutex_lock(&e->mu);
        while (!e->done && !e->given_up)
            if (pthread_cond_timedwait(&e->cv, &e->mu, &e->deadline) == ETIMEDOUT &&
                !e->done)
                e->given_up = 1;
        if (e->done && !e->given_up &&
            dkim2_dns_answer_settles(e->answer, e->anslen, e->herr)) {
            anslen = e->anslen;
            herr = e->herr;
            ans = malloc(sizeof e->answer);
            if (ans) {
                if (anslen > 0) memcpy(ans, e->answer, (size_t)anslen);
                use = 1;
            }
        }
        pthread_mutex_unlock(&e->mu);
        if (use) {
            dkim2_pubkey_t *k = dkim2_dns_key_from_answer(ans, anslen, herr, statusp, errp);
            free(ans);
            return k;
        }
    }
    return dkim2_dns_getkey(selector, domain, statusp, errp);
}

void dkim2_prefetch_free(dkim2_prefetch_t *pf) {
    if (!pf) return;
    for (int i = 0; i < pf->n; i++) entry_release(pf->e[i]);
    free(pf->e);
    free(pf);
}
