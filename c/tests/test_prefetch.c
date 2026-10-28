/* Public-key prefetch (dkim2_prefetch.c): every key a message's
   DKIM2-Signatures name is looked up from the end of the headers, once;
   a definitive answer (records, NXDOMAIN, NOERROR with no TXT) is used as
   is; anything else -- no reply in time, SERVFAIL, any failure -- is
   redone the ordinary synchronous way, so every verdict (temperror text
   included) is the one the synchronous lookups give. Never prefetched when
   keys come from an override (dns.json).

   Both resolvers are fakes answering from dns.json in wire format: the
   prefetch one through dkim2_prefetch_query_hook, the synchronous one
   through dkim2_dns_query_hook. No wall-clock assertions: a "late" answer
   is one held back until the verifier has given up on it. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <pthread.h>
#include <netdb.h>
#include <cjson/cJSON.h>
#include "../dkim2_internal.h"
#include "../dkim2_dns.h"
#include "../dkim2_header.h"
#include "../dkim2_dnsjson.h"
#include "../dkim2_message.h"
#include "../dkim2_prefetch.h"
#include "../eml_parse.h"

static const char *EML = "../perl/tests/expected/chain-hop6-unchanged-re-sign.eml";
static cJSON *g_dns;

/* TXT record text for qname from dns.json, or NULL. */
static const char *zone_txt(const char *qname) {
    const char *m = strstr(qname, "._domainkey.");
    if (!m) return NULL;
    char key[256];
    snprintf(key, sizeof key, "%.*s._domainkey", (int)(m - qname), qname);
    cJSON *dom = cJSON_GetObjectItemCaseSensitive(g_dns, m + 12);
    cJSON *recs = dom ? cJSON_GetObjectItemCaseSensitive(dom, key) : NULL;
    cJSON *rec = recs ? cJSON_GetArrayItem(recs, 0) : NULL;
    cJSON *s = rec ? cJSON_GetArrayItem(rec, 1) : NULL;
    return s && cJSON_IsString(s) ? s->valuestring : NULL;
}

/* A NOERROR answer for qname holding txt (NULL: no records). */
static int wire(const char *qname, const char *txt, unsigned char *ans, int anslen) {
    int pos = 0;
    unsigned char hdr[12] = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, txt ? 1 : 0, 0, 0, 0, 0};
    memcpy(ans, hdr, 12); pos = 12;
    for (const char *l = qname; *l; ) {
        const char *dot = strchr(l, '.');
        size_t n = dot ? (size_t)(dot - l) : strlen(l);
        ans[pos++] = (unsigned char)n; memcpy(ans + pos, l, n); pos += (int)n;
        l += n; if (*l == '.') l++;
    }
    ans[pos++] = 0;
    ans[pos++] = 0; ans[pos++] = 16; ans[pos++] = 0; ans[pos++] = 1;
    if (txt) {
        ans[pos++] = 0xC0; ans[pos++] = 0x0C;
        ans[pos++] = 0; ans[pos++] = 16; ans[pos++] = 0; ans[pos++] = 1;
        ans[pos++] = 0; ans[pos++] = 0; ans[pos++] = 1; ans[pos++] = 0x2C;
        int rdlen_at = pos; pos += 2;
        int start = pos;
        for (size_t o = 0, n = strlen(txt); o < n || o == 0; ) {
            size_t k = n - o > 255 ? 255 : n - o;
            ans[pos++] = (unsigned char)k; memcpy(ans + pos, txt + o, k); pos += (int)k;
            o += k;
            if (k == 0) break;
        }
        ans[rdlen_at] = (unsigned char)((pos - start) >> 8);
        ans[rdlen_at + 1] = (unsigned char)((pos - start) & 0xff);
    }
    assert(pos <= anslen);
    return pos;
}

/* ---- the fakes ---- */

enum { ANSWER, SERVFAIL, NXDOMAIN, NODATA, HOLD };

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
static int g_pf_mode = ANSWER, g_sync_mode = ANSWER;
static const char *g_pf_only;       /* g_pf_mode applies to this name only (NULL: all) */
static int g_pf_calls, g_sync_calls, g_released;
static char g_pf_names[16][256];

static int pf_fake(const char *qname, unsigned char *ans, int anslen, int *herr) {
    pthread_mutex_lock(&g_mu);
    if (g_pf_calls < 16) snprintf(g_pf_names[g_pf_calls], 256, "%s", qname);
    g_pf_calls++;
    pthread_cond_broadcast(&g_cv);
    int mode = (!g_pf_only || strcasecmp(g_pf_only, qname) == 0) ? g_pf_mode : ANSWER;
    if (mode == HOLD)
        while (!g_released) pthread_cond_wait(&g_cv, &g_mu);
    pthread_mutex_unlock(&g_mu);
    switch (mode) {
    case SERVFAIL: *herr = TRY_AGAIN;      return -1;
    case NXDOMAIN: *herr = HOST_NOT_FOUND; return -1;
    case NODATA:   return wire(qname, NULL, ans, anslen);
    default:       return wire(qname, zone_txt(qname), ans, anslen);
    }
}

static int sync_fake(const char *qname, unsigned char *ans, int anslen) {
    pthread_mutex_lock(&g_mu);
    g_sync_calls++;
    pthread_mutex_unlock(&g_mu);
    if (g_sync_mode == SERVFAIL) { h_errno = TRY_AGAIN; return -1; }
    const char *t = zone_txt(qname);
    if (!t) { h_errno = HOST_NOT_FOUND; return -1; }
    return wire(qname, t, ans, anslen);
}

/* Each case starts once the lookups of the one before have all finished:
   a case that stops at its first bad key leaves the others to run on, and
   they would be counted here. */
static void release(void);

static void reset(int pf_mode, const char *only, int sync_mode) {
    release();
    dkim2_prefetch_drain();
    pthread_mutex_lock(&g_mu);
    g_pf_mode = pf_mode; g_pf_only = only; g_sync_mode = sync_mode;
    g_pf_calls = g_sync_calls = 0;
    g_released = 0;
    pthread_mutex_unlock(&g_mu);
    dkim2_prefetch_query_hook = pf_fake;
    dkim2_dns_query_hook = sync_fake;
    dkim2_dns_override = NULL;
}

static void release(void) {
    pthread_mutex_lock(&g_mu);
    g_released = 1;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
}

static dkim2_verify_result_t run(int prefetch) {
    dkim2_verify_opts_t o = { 0 };
    o.no_prefetch = !prefetch;
    return dkim2_verify_message_opts(EML, NULL, NULL, 1, &o);
}

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; fprintf(stderr, "FAIL: " __VA_ARGS__); fprintf(stderr, "\n"); } } while (0)

/* The five distinct keys hop 6 is signed with. */
static int distinct_keys(char names[][256]) {
    char **h = NULL;
    int nh = 0;
    dkim2_digests_t d;
    assert(eml_parse(EML, &h, &nh, &d) == 0);
    dkim2_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.headers = h;
    ctx.n_headers = nh;
    dkim2_ctx_collect(&ctx);
    int n = 0;
    for (dkim2_sig_t *s = ctx.sig_list; s; s = s->next)
        for (int j = 0; j < s->n_ssets; j++) {
            char q[256];
            snprintf(q, sizeof q, "%s._domainkey.%s", s->ssets[j].selector, s->d);
            int seen = 0;
            for (int k = 0; k < n; k++) if (strcasecmp(names[k], q) == 0) seen = 1;
            if (!seen) snprintf(names[n++], 256, "%s", q);
        }
    dkim2_mi_free(ctx.mi_list);
    dkim2_sig_free(ctx.sig_list);
    dkim2_badfield_free(ctx.bad_list);
    eml_free(h, nh);
    return n;
}

int main(void) {
    char jerr[256];
    FILE *jf = fopen("../dns.json", "r");
    assert(jf);
    static char jbuf[1 << 20];
    size_t jl = fread(jbuf, 1, sizeof jbuf - 1, jf);
    fclose(jf);
    jbuf[jl] = '\0';
    g_dns = cJSON_Parse(jbuf);
    assert(g_dns);

    char want[16][256];
    int nwant = distinct_keys(want);
    printf("  hop 6 names %d distinct keys\n", nwant);
    CHECK(nwant == 5, "expected 5 distinct keys, got %d", nwant);

    /* The reference: synchronous lookups only. */
    reset(ANSWER, NULL, ANSWER);
    dkim2_verify_result_t ref = run(0);
    CHECK(ref.status == DKIM2_OK, "sync verify: %s", ref.message);
    CHECK(g_pf_calls == 0, "no prefetch asked for, yet %d prefetches", g_pf_calls);
    int sync_ref = g_sync_calls;
    printf("  sync: %s (%d lookups)\n", ref.message, sync_ref);

    /* All keys requested by the end of the headers, once each. */
    {
        reset(HOLD, NULL, ANSWER);
        char **h = NULL;
        int nh = 0;
        dkim2_digests_t d;
        assert(eml_parse(EML, &h, &nh, &d) == 0);
        dkim2_ctx_t ctx;
        memset(&ctx, 0, sizeof ctx);
        ctx.headers = h;
        ctx.n_headers = nh;
        dkim2_ctx_collect(&ctx);
        dkim2_prefetch_t *pf = dkim2_prefetch_start(&ctx);
        CHECK(pf != NULL, "no prefetch started");
        CHECK(pf && dkim2_prefetch_count(pf) == nwant, "prefetch names %d keys",
              pf ? dkim2_prefetch_count(pf) : -1);
        for (int k = 0; pf && k < nwant; k++) {
            int found = 0;
            for (int i = 0; i < dkim2_prefetch_count(pf); i++)
                if (strcasecmp(dkim2_prefetch_name(pf, i), want[k]) == 0) found++;
            CHECK(found == 1, "%s requested %d times", want[k], found);
        }
        /* Every lookup is under way while nothing has been verified. */
        pthread_mutex_lock(&g_mu);
        while (pf && g_pf_calls < nwant) pthread_cond_wait(&g_cv, &g_mu);
        pthread_mutex_unlock(&g_mu);
        CHECK(g_pf_calls == nwant, "%d resolver calls for %d keys", g_pf_calls, nwant);
        release();
        dkim2_prefetch_free(pf);
        dkim2_mi_free(ctx.mi_list);
        dkim2_sig_free(ctx.sig_list);
        dkim2_badfield_free(ctx.bad_list);
        eml_free(h, nh);
        printf("  ok: %d keys requested at end of headers, once each\n", nwant);
    }

    /* Bounded: at most DKIM2_PREFETCH_MAX keys, top signature first,
       implemented algorithms only, de-duplicated -- signatures of 8
       selectors each (the most an s= may hold, -08 contract D3) cannot
       drive 8 queries each, and an s= of 50 does not parse at all. */
    {
        reset(ANSWER, NULL, ANSWER);
        dkim2_ctx_t ctx;
        memset(&ctx, 0, sizeof ctx);
        size_t cap = 50 * 40 + 256, len;
        char *v = malloc(cap);
        assert(v);
        len = (size_t)snprintf(v, cap, "i=1; m=1; t=1; d=one.example; mf=PGE+; rt=PGE+; s=");
        for (int k = 0; k < 8; k++)
            len += (size_t)snprintf(v + len, cap - len, "%ss%d:ed25519-sha256:AAAA", k ? "," : "", k);
        assert(dkim2_ctx_add_field(&ctx, 1, v) == 0);
        assert(dkim2_ctx_add_field(&ctx, 1,
            "i=2; m=1; t=1; d=two.example; mf=PGE+; rt=PGE+; "
            "s=x:future-alg:AAAA,a:ed25519-sha256:AAAA|y:mldsa44:AAAA,b:rsa-sha256:AAAA") == 0);
        assert(ctx.sig_list && ctx.sig_list->next && !ctx.bad_list);
        dkim2_prefetch_t *pf = dkim2_prefetch_start(&ctx);
        int n = dkim2_prefetch_count(pf);
        CHECK(n == DKIM2_PREFETCH_MAX, "8 + 4 selectors: %d names prefetched", n);
        CHECK(n > 1 && strcmp(dkim2_prefetch_name(pf, 0), "a._domainkey.two.example") == 0 &&
              strcmp(dkim2_prefetch_name(pf, 1), "b._domainkey.two.example") == 0 &&
              strcmp(dkim2_prefetch_name(pf, 2), "s0._domainkey.one.example") == 0,
              "not top signature first, de-duplicated: %s", n ? dkim2_prefetch_name(pf, 0) : "");
        dkim2_prefetch_free(pf);
        dkim2_prefetch_drain();
        CHECK(g_pf_calls == DKIM2_PREFETCH_MAX, "8 + 4 selectors: %d queries", g_pf_calls);
        dkim2_sig_free(ctx.sig_list);
        dkim2_badfield_free(ctx.bad_list);

        reset(ANSWER, NULL, ANSWER);
        memset(&ctx, 0, sizeof ctx);
        free(v);
        cap = 500 * 32 + 256;
        v = malloc(cap);
        assert(v);
        len = (size_t)snprintf(v, cap, "i=1; m=1; t=1; d=one.example; mf=PGE+; rt=PGE+; s=");
        for (int k = 0; k < 500; k++)
            len += (size_t)snprintf(v + len, cap - len, "%ss%d:rsa-sha256:AAAA", k ? "|" : "", k);
        assert(dkim2_ctx_add_field(&ctx, 1, v) == 0);
        assert(dkim2_ctx_add_field(&ctx, 1,
            "i=2; m=1; t=1; d=one.example; mf=PGE+; rt=PGE+; s=s:rsa-sha256:AAAA") == 0);
        assert(dkim2_ctx_add_field(&ctx, 1,
            "i=3; m=1; t=1; d=One.example; mf=PGE+; rt=PGE+; s=S:ed25519-sha256:AAAA") == 0);
        pf = dkim2_prefetch_start(&ctx);
        CHECK(dkim2_prefetch_count(pf) == 1, "500 items, then one key twice: %d names", dkim2_prefetch_count(pf));
        dkim2_prefetch_free(pf);
        dkim2_prefetch_drain();
        CHECK(g_pf_calls == 1, "500 items, then one key twice: %d queries", g_pf_calls);
        dkim2_sig_free(ctx.sig_list);
        dkim2_badfield_free(ctx.bad_list);
        free(v);
        printf("  ok: prefetch bounded to %d keys, top signature first\n", DKIM2_PREFETCH_MAX);
    }

    /* Good answers: no synchronous lookup at all. */
    reset(ANSWER, NULL, ANSWER);
    dkim2_verify_result_t r = run(1);
    CHECK(r.status == ref.status && strcmp(r.message, ref.message) == 0,
          "prefetch verdict '%s' != '%s'", r.message, ref.message);
    CHECK(g_pf_calls == nwant, "%d prefetches for %d keys", g_pf_calls, nwant);
    CHECK(g_sync_calls == 0, "%d synchronous lookups with good answers", g_sync_calls);
    printf("  ok: good answers used, %d prefetches, 0 sync\n", g_pf_calls);

    /* SERVFAIL: redone synchronously, same verdict. */
    reset(SERVFAIL, NULL, ANSWER);
    r = run(1);
    CHECK(r.status == ref.status && strcmp(r.message, ref.message) == 0,
          "SERVFAIL verdict '%s'", r.message);
    CHECK(g_sync_calls == sync_ref, "SERVFAIL: %d sync lookups, want %d", g_sync_calls, sync_ref);
    printf("  ok: SERVFAIL falls back (%d sync)\n", g_sync_calls);

    /* No reply in time (held past the timeout, answered later). */
    int saved = dkim2_prefetch_timeout_ms;
    dkim2_prefetch_timeout_ms = 0;
    reset(HOLD, NULL, ANSWER);
    r = run(1);
    release();
    CHECK(r.status == ref.status && strcmp(r.message, ref.message) == 0,
          "timeout verdict '%s'", r.message);
    CHECK(g_sync_calls == sync_ref, "timeout: %d sync lookups, want %d", g_sync_calls, sync_ref);
    printf("  ok: no reply in time falls back (%d sync)\n", g_sync_calls);

    /* Still pending for one key only. */
    reset(HOLD, want[2], ANSWER);
    r = run(1);
    release();
    CHECK(r.status == ref.status && strcmp(r.message, ref.message) == 0,
          "pending verdict '%s'", r.message);
    CHECK(g_sync_calls >= 1 && g_sync_calls < sync_ref,
          "one pending key: %d sync lookups", g_sync_calls);
    printf("  ok: one pending key falls back alone (%d sync)\n", g_sync_calls);
    dkim2_prefetch_timeout_ms = saved;

    /* SERVFAIL both ways: the synchronous TEMPERROR text, exactly. */
    reset(ANSWER, NULL, SERVFAIL);
    dkim2_verify_result_t tref = run(0);
    reset(SERVFAIL, NULL, SERVFAIL);
    r = run(1);
    CHECK(tref.status == DKIM2_TEMPERROR, "sync SERVFAIL gave '%s'", tref.message);
    CHECK(r.status == tref.status && strcmp(r.message, tref.message) == 0,
          "temperror '%s' != '%s'", r.message, tref.message);
    printf("  ok: temperror identical: %s\n", r.message);

    /* NXDOMAIN is definitive: used, never redone (the synchronous fake would
       have answered). */
    reset(NXDOMAIN, want[0], ANSWER);
    r = run(1);
    CHECK(r.status == DKIM2_PERMERROR && strstr(r.message, "does not exist"),
          "NXDOMAIN verdict '%s'", r.message);
    CHECK(g_sync_calls == 0, "NXDOMAIN redone: %d sync lookups", g_sync_calls);
    printf("  ok: NXDOMAIN used: %s\n", r.message);

    /* NOERROR with no TXT likewise. */
    reset(NODATA, want[0], ANSWER);
    r = run(1);
    CHECK(r.status == DKIM2_PERMERROR && strstr(r.message, "does not exist"),
          "NODATA verdict '%s'", r.message);
    CHECK(g_sync_calls == 0, "NODATA redone: %d sync lookups", g_sync_calls);
    printf("  ok: NOERROR/no TXT used: %s\n", r.message);

    /* Keys from dns.json: no prefetch. */
    reset(ANSWER, NULL, ANSWER);
    assert(dkim2_dns_json_load("../dns.json", jerr, sizeof jerr) == 0);
    r = run(1);
    CHECK(r.status == DKIM2_OK, "dns.json verify '%s'", r.message);
    CHECK(g_pf_calls == 0, "%d prefetches with dns.json keys", g_pf_calls);
    dkim2_dns_json_free();
    printf("  ok: no prefetch with an override key source\n");

    /* A synchronous test seam without a prefetch one: no prefetch either. */
    reset(ANSWER, NULL, ANSWER);
    dkim2_prefetch_query_hook = NULL;
    r = run(1);
    CHECK(r.status == DKIM2_OK && g_sync_calls == sync_ref,
          "query hook only: '%s', %d sync", r.message, g_sync_calls);
    printf("  ok: no prefetch with only the synchronous test seam\n");

    cJSON_Delete(g_dns);
    printf(fails ? "test_prefetch: %d FAILED\n" : "test_prefetch: all passed\n", fails);
    return fails ? 1 : 0;
}
