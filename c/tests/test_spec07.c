/* draft-ietf-dkim-dkim2-spec-07: the shared behaviour tests (U1-U5, K1-K2,
   F1-F2, C1-C6, A1-A4, T1) and the Review Focus items, plus the C6 error
   strings, the "none" result and the Tag=Value list grammar (§8).

   D1 (DSN) does not apply: the C implementation has no DSN code
   (c/TODO-dsn.md).

   Messages are built in memory: every signature is made here over the
   Message-Instance and DKIM2-Signature fields (-07 §12.8) with one Ed25519
   key, which the fake DNS serves for selectors "sel" and "sel2" under any
   domain, so the test domains are the ones the shared table names
   (example.com, example.org, lists.example.org, other.net, ...). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <cjson/cJSON.h>
#include "../dkim2_internal.h"
#include "../dkim2_sign.h"
#include "../dkim2_verify.h"
#include "../dkim2_header.h"
#include "../dkim2_dns.h"
#include "../dkim2_crypto.h"
#include "../dkim2_hash.h"
#include "../dkim2_message.h"
#include "../dkim2_recipe.h"
#include "../tagparse.h"
#include "../base64.h"

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)
#define CHECK_MSG(res, want) do { \
    if (strcmp((res).message, (want)) != 0) { \
        printf("FAIL %s:%d: got \"%s\", want \"%s\"\n", __FILE__, __LINE__, (res).message, (want)); \
        g_fail++; } } while (0)
#define CHECK_PASS(res) do { \
    if ((res).status != DKIM2_OK) { \
        printf("FAIL %s:%d: want PASS, got %d \"%s\"\n", __FILE__, __LINE__, (int)(res).status, (res).message); \
        g_fail++; } } while (0)

static EVP_PKEY *g_priv;
static char g_dns_txt[256];
static const char *KEY_PATH = "/tmp/dkim2_test_spec07.pem";

static char *dns_override(const char *qname, int *n_records) {
    (void)n_records;
    if (strncmp(qname, "sel._domainkey.", 15) == 0 || strncmp(qname, "sel2._domainkey.", 16) == 0)
        return strdup(g_dns_txt);
    return NULL;
}

/* ---- in-memory messages ---- */

#define MAXH 64
typedef struct {
    char *h[MAXH];      /* "Name: value\r\n", top-down */
    int n;
    char body[4096];
} msg_t;

static void msg_add_bottom(msg_t *m, const char *name, const char *value) {
    char buf[2048];
    snprintf(buf, sizeof buf, "%s: %s\r\n", name, value);
    m->h[m->n++] = strdup(buf);
}

static void msg_add_top(msg_t *m, const char *name, const char *value) {
    char buf[8192];
    snprintf(buf, sizeof buf, "%s: %s\r\n", name, value);
    memmove(m->h + 1, m->h, (size_t)m->n * sizeof m->h[0]);
    m->h[0] = strdup(buf);
    m->n++;
}

static void msg_init(msg_t *m, const char *from, const char *subject, const char *body) {
    memset(m, 0, sizeof *m);
    msg_add_bottom(m, "From", from);
    msg_add_bottom(m, "To", "list@lists.example.org");
    msg_add_bottom(m, "Subject", subject);
    msg_add_bottom(m, "Message-ID", "<spec07@example.com>");
    snprintf(m->body, sizeof m->body, "%s", body);
}

static void msg_free(msg_t *m) {
    for (int i = 0; i < m->n; i++) free(m->h[i]);
    m->n = 0;
}

static void msg_copy(msg_t *dst, const msg_t *src) {
    *dst = *src;
    for (int i = 0; i < src->n; i++) dst->h[i] = strdup(src->h[i]);
}

/* Replace the (first) field with this name. */
static void msg_set(msg_t *m, const char *name, const char *value) {
    size_t nl = strlen(name);
    for (int i = 0; i < m->n; i++)
        if (strncasecmp(m->h[i], name, nl) == 0 && m->h[i][nl] == ':') {
            char buf[2048];
            snprintf(buf, sizeof buf, "%s: %s\r\n", name, value);
            free(m->h[i]);
            m->h[i] = strdup(buf);
            return;
        }
}

static int count_fields(const msg_t *m, const char *name) {
    size_t nl = strlen(name);
    int c = 0;
    for (int i = 0; i < m->n; i++)
        if (strncasecmp(m->h[i], name, nl) == 0 && m->h[i][nl] == ':') c++;
    return c;
}

static char *b64(const char *s) {
    size_t n = strlen(s), cap = (n + 2) / 3 * 4 + 1;
    char *o = malloc(cap);
    b64_encode((const unsigned char *)s, n, o, cap);
    return o;
}

/* Add Message-Instance m=<next> over the message as it is now, with the
   Recipe JSON (NULL: none). */
static void add_mi(msg_t *m, const char *recipe) {
    int next = count_fields(m, "Message-Instance") + 1;
    unsigned char hh[DKIM2_MAX_HASH_LEN], bh[DKIM2_MAX_HASH_LEN];
    dkim2_header_hash_raw((const char **)m->h, m->n, hh);
    dkim2_body_hash_raw(m->body, strlen(m->body), bh);
    char hh64[128], bh64[128];
    b64_encode(hh, 32, hh64, sizeof hh64);
    b64_encode(bh, 32, bh64, sizeof bh64);
    char val[4096];
    if (recipe) {
        char *r = b64(recipe);
        snprintf(val, sizeof val, "m=%d; h=sha256:%s:%s; r=%s;", next, hh64, bh64, r);
        free(r);
    } else {
        snprintf(val, sizeof val, "m=%d; h=sha256:%s:%s;", next, hh64, bh64);
    }
    msg_add_top(m, "Message-Instance", val);
}

static void canon_append(char *buf, size_t *pos, const char *name, const char *value) {
    for (const char *h = name; *h; h++) buf[(*pos)++] = (char)tolower((unsigned char)*h);
    buf[(*pos)++] = ':';
    for (const char *h = value; *h; h++) {
        if (*h == ' ' || *h == '\t' || *h == '\r' || *h == '\n') continue;
        buf[(*pos)++] = *h;
    }
    buf[(*pos)++] = '\r';
    buf[(*pos)++] = '\n';
}

/* The value (after "Name: ", without CRLF) of field i, malloc'd. */
static char *field_value(const char *f) {
    const char *v = strchr(f, ':') + 1;
    while (*v == ' ') v++;
    size_t n = strlen(v);
    while (n && (v[n - 1] == '\r' || v[n - 1] == '\n')) n--;
    char *o = malloc(n + 1);
    memcpy(o, v, n);
    o[n] = '\0';
    return o;
}

/* The canonical Message-Instance fields (ascending m=) and DKIM2-Signature
   fields (ascending i=) of the message, appended to buf. */
static void canon_chain(const msg_t *m, char *buf, size_t *pos) {
    for (int want = 1; want <= MAXH; want++)
        for (int i = 0; i < m->n; i++)
            if (strncasecmp(m->h[i], "Message-Instance:", 17) == 0) {
                char *v = field_value(m->h[i]);
                dkim2_mi_t *mi = dkim2_mi_parse(v);
                if (mi && mi->m == want) canon_append(buf, pos, "message-instance", v);
                dkim2_mi_free(mi);
                free(v);
            }
    for (int want = 1; want <= MAXH; want++)
        for (int i = 0; i < m->n; i++)
            if (strncasecmp(m->h[i], "DKIM2-Signature:", 16) == 0) {
                char *v = field_value(m->h[i]);
                const char *ip = strstr(v, "i=");
                if (ip && atoi(ip + 2) == want) canon_append(buf, pos, "dkim2-signature", v);
                free(v);
            }
}

/* Add a DKIM2-Signature. tags: everything before s= (e.g. "i=1; m=1; t=..;
   d=..; mf=..; rt=.."). n_sel selectors "sel", "sel2"; bit k of bad corrupts
   selector k's signature value. */
static void add_sig_raw(msg_t *m, const char *tags, int n_sel, unsigned bad) {
    static const char *sels[] = { "sel", "sel2" };
    char tmpl[4096];
    size_t tl = (size_t)snprintf(tmpl, sizeof tmpl, "%s; s=", tags);
    for (int k = 0; k < n_sel; k++)
        tl += (size_t)snprintf(tmpl + tl, sizeof tmpl - tl, "%s%s:ed25519-sha256:", k ? "," : "", sels[k]);
    snprintf(tmpl + tl, sizeof tmpl - tl, ";");

    char *in = malloc(65536);
    size_t pos = 0;
    canon_chain(m, in, &pos);
    canon_append(in, &pos, "dkim2-signature", tmpl);
    char *sig = dkim2_sign(g_priv, "ed25519-sha256", (unsigned char *)in, pos);
    free(in);

    char val[4096];
    size_t vl = (size_t)snprintf(val, sizeof val, "%s; s=", tags);
    for (int k = 0; k < n_sel; k++) {
        char s[256];
        snprintf(s, sizeof s, "%s", sig);
        if (bad & (1u << k)) s[0] = (s[0] == 'A') ? 'B' : 'A';
        vl += (size_t)snprintf(val + vl, sizeof val - vl, "%s%s:ed25519-sha256:%s", k ? "," : "", sels[k], s);
    }
    snprintf(val + vl, sizeof val - vl, ";");
    free(sig);
    msg_add_top(m, "DKIM2-Signature", val);
}

/* The usual signature: mf (raw path, NULL with nd) and rt (raw paths,
   comma-separated), base64-encoded here. */
static void add_sig_t(msg_t *m, int i, int mi_m, unsigned long long t, const char *d,
                      const char *mf, const char *rt, const char *nd, const char *f) {
    char tags[2048];
    size_t n = (size_t)snprintf(tags, sizeof tags, "i=%d; m=%d; t=%llu; d=%s", i, mi_m, t, d);
    if (nd) n += (size_t)snprintf(tags + n, sizeof tags - n, "; nd=%s", nd);
    if (mf) {
        char *e = b64(mf);
        n += (size_t)snprintf(tags + n, sizeof tags - n, "; mf=%s", e);
        free(e);
    }
    if (rt) {
        n += (size_t)snprintf(tags + n, sizeof tags - n, "; rt=");
        char *copy = strdup(rt), *save = NULL;
        int first = 1;
        for (char *tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
            char *e = b64(tok);
            n += (size_t)snprintf(tags + n, sizeof tags - n, "%s%s", first ? "" : ",", e);
            free(e);
            first = 0;
        }
        free(copy);
    }
    if (f) snprintf(tags + n, sizeof tags - n, "; f=%s", f);
    add_sig_raw(m, tags, 1, 0);
}

static unsigned long long now(void) { return (unsigned long long)time(NULL); }

static void add_sig(msg_t *m, int i, int mi_m, const char *d,
                    const char *mf, const char *rt, const char *nd) {
    add_sig_t(m, i, mi_m, now(), d, mf, rt, nd, NULL);
}

/* Verify inbound (outbound=0) or as the signer gate would (1). Both walks
   (planned and undo) must give the same verdict. Envelope not checked. */
static dkim2_verify_result_t verify_mode(const msg_t *m, int outbound) {
    dkim2_verify_result_t res[2];
    for (int walk = 0; walk < 2; walk++) {
        dkim2_ctx_t ctx;
        memset(&ctx, 0, sizeof ctx);
        ctx.headers = (char **)m->h;
        ctx.n_headers = m->n;
        ctx.body = (char *)m->body;
        ctx.body_len = strlen(m->body);
        ctx.outbound = outbound;
        ctx.undo_walk = walk;
        dkim2_ctx_collect(&ctx);
        dkim2_do_verify(&ctx, &res[walk]);
        dkim2_mi_free(ctx.mi_list);
        dkim2_sig_free(ctx.sig_list);
    }
    if (res[0].status != res[1].status || strcmp(res[0].message, res[1].message) != 0) {
        printf("FAIL: walks disagree: planned \"%s\" undo \"%s\"\n", res[0].message, res[1].message);
        g_fail++;
    }
    return res[0];
}

static dkim2_verify_result_t verify(const msg_t *m) { return verify_mode(m, 0); }

/* Sign with the library (signer gate included). On success adds the new
   fields to m and returns 0; else -1 with err set. sig_out (optional) gets
   the new DKIM2-Signature value. */
static int lib_sign(msg_t *m, const char *d, const char *mail_from, char **rcpts,
                    int exploded, char *err, size_t errsz, char *sig_out, size_t sigsz) {
    dkim2_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.headers = m->h;
    ctx.n_headers = m->n;
    ctx.body = m->body;
    ctx.body_len = strlen(m->body);
    dkim2_body_hash_raw_alg(m->body, ctx.body_len, 0, ctx.body_digests.d[0]);
    dkim2_body_hash_raw_alg(m->body, ctx.body_len, 1, ctx.body_digests.d[1]);
    ctx.mail_from = (char *)mail_from;
    ctx.rcpt_to = rcpts;
    dkim2_ctx_collect(&ctx);
    dkim2_sign_config_t cfg = {
        .domain = (char *)d, .selector = "sel", .privkey_path = (char *)KEY_PATH,
        .alg = "ed25519-sha256", .exploded = exploded,
    };
    char *mi = NULL, *sig = NULL;
    int rc = dkim2_do_sign(&ctx, &cfg, &mi, &sig);
    if (err) snprintf(err, errsz, "%s", rc ? ctx.errmsg : "");
    dkim2_mi_free(ctx.mi_list);
    dkim2_sig_free(ctx.sig_list);
    if (rc == 0) {
        if (mi) msg_add_top(m, "Message-Instance", mi);
        msg_add_top(m, "DKIM2-Signature", sig);
        if (sig_out) snprintf(sig_out, sigsz, "%s", sig);
    }
    free(mi);
    free(sig);
    return rc;
}

/* The decoded mf= of a signature value. */
static void sig_mf(const char *sig, char *out, size_t outsz) {
    dkim2_sig_t *s = dkim2_sig_parse(sig);
    snprintf(out, outsz, "%s", s && s->mf ? s->mf : "");
    dkim2_sig_free(s);
}

static int sig_has_flag(const char *sig, const char *flag) {
    dkim2_sig_t *s = dkim2_sig_parse(sig);
    int has = 0;
    for (int k = 0; s && s->flags && s->flags[k]; k++)
        if (strcmp(s->flags[k], flag) == 0) has = 1;
    dkim2_sig_free(s);
    return has;
}

/* i=1 by example.com over m=1, From a@example.com, rt the list. */
static void base_signed(msg_t *m, const char *from) {
    msg_init(m, from, "test", "Hello\r\nworld\r\n");
    add_mi(m, NULL);
    add_sig(m, 1, 1, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
}

/* base_signed, then a reviser's m=2 with this Recipe and i=2 by example.org. */
static dkim2_verify_result_t recipe_at_m2(const char *recipe) {
    msg_t m;
    base_signed(&m, "a@example.com");
    add_mi(&m, recipe);
    add_sig(&m, 2, 2, "example.org", "<list-bounces@lists.example.org>", "<r@dest.example>", NULL);
    dkim2_verify_result_t r = verify(&m);
    msg_free(&m);
    return r;
}

static const char *INVALID_JSON_M2 = "PERMERROR: Message-Instance m=2 contains invalid JSON";

static void test_u_steps(void) {
    /* U1: a UTF-8 header value is a "d" step */
    {
        char *cur[] = { "Subject: x\r\n" };
        char *prev[] = { "Subject: caf\xc3\xa9\r\n" };
        char *r = dkim2_gen_header_recipe("Subject", cur, 1, prev, 1);
        CHECK(r && strstr(r, "{\"d\":[\"caf\xc3\xa9\"]}") != NULL);
        CHECK(r && strstr(r, "\"u\"") == NULL);
        free(r);

        msg_t m;
        msg_init(&m, "a@example.com", "caf\xc3\xa9", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
        msg_set(&m, "Subject", "x");
        add_mi(&m, "{\"h\":{\"subject\":[{\"d\":[\"caf\xc3\xa9\"]}]}}");
        add_sig(&m, 2, 2, "example.org", "<l@lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    /* U2: a non-UTF-8 body line is a "u" step, and the chain verifies */
    {
        const char *prev = "Hello\r\ncaf\xe9\r\n";
        const char *cur = "Hello\r\nchanged\r\n";
        int imp = 0;
        char *r = dkim2_gen_body_recipe(cur, strlen(cur), prev, strlen(prev), &imp);
        CHECK(r && strstr(r, "{\"u\":[\"Y2Fm6Q==\"]}") != NULL);

        msg_t m;
        msg_init(&m, "a@example.com", "test", prev);
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
        snprintf(m.body, sizeof m.body, "%s", cur);
        add_mi(&m, r);
        add_sig(&m, 2, 2, "example.org", "<l@lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
        free(r);
    }
    /* U2, body variant of the review item: valid UTF-8 non-ASCII stays "d"
       and undoes byte-exactly */
    {
        const char *prev = "Hello\r\nna\xc3\xafve\r\n";
        const char *cur = "Hello\r\nplain\r\n";
        int imp = 0;
        char *r = dkim2_gen_body_recipe(cur, strlen(cur), prev, strlen(prev), &imp);
        CHECK(r && strstr(r, "{\"d\":[\"na\xc3\xafve\"]}") != NULL);
        size_t n = 0;
        char *back = r ? dkim2_apply_body_recipe(r, cur, strlen(cur), &n) : NULL;
        CHECK(back && n == strlen(prev) && memcmp(back, prev, n) == 0);
        free(back);

        msg_t m;
        msg_init(&m, "a@example.com", "test", prev);
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
        snprintf(m.body, sizeof m.body, "%s", cur);
        add_mi(&m, r);
        add_sig(&m, 2, 2, "example.org", "<l@lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
        free(r);
    }
    /* U3: non-zero pad bits */
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{\"u\":[\"QR==\"]}]}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{\"u\":[\"QUJ=\"]}]}"); CHECK_MSG(r, INVALID_JSON_M2); }
    /* U4: the old "b" step key, two keys in a step, no key */
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{\"b\":[\"eA==\"]}]}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,1],\"d\":[\"x\"]}]}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{}]}"); CHECK_MSG(r, INVALID_JSON_M2); }
    /* U5: decoded CR; "h":{}; neither h nor b */
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{\"u\":[\"YQ1i\"]}]}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"h\":{}}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"x\":1}"); CHECK_MSG(r, INVALID_JSON_M2); }
    /* and other schema violations: a non-UTF-8 "d" string, an empty array,
       a non-string literal, a non-array header Recipe, a non-object step */
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{\"d\":[\"caf\xe9\"]}]}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{\"d\":[]}]}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{\"d\":[1]}]}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"h\":{\"subject\":null}}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[[1,2]]}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("[1]"); CHECK_MSG(r, INVALID_JSON_M2); }
    /* a valid "u" (canonical, zero pad bits) still applies: a no-op body
       change whose literal is the same line keeps the hash */
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"u\":[\"SGVsbG8=\"]},{\"c\":[2,2]}]}"); CHECK_PASS(r); }
}

static void test_json_keys(void) {
    /* K1: uppercase keys at every level match case-insensitively */
    { dkim2_verify_result_t r = recipe_at_m2("{\"H\":{\"Subject\":[{\"C\":[1,1]}]}}"); CHECK_PASS(r); }
    {
        msg_t m;
        base_signed(&m, "a@example.com");
        msg_set(&m, "Subject", "[list] test");
        add_mi(&m, "{\"H\":{\"SUBJECT\":[{\"D\":[\"test\"]}]},\"B\":[{\"C\":[1,2]}]}");
        add_sig(&m, 2, 2, "example.org", "<l@lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    {   /* and the keys are honoured, not ignored: a wrong literal fails */
        msg_t m;
        base_signed(&m, "a@example.com");
        msg_set(&m, "Subject", "[list] test");
        add_mi(&m, "{\"H\":{\"Subject\":[{\"D\":[\"wrong\"]}]}}");
        add_sig(&m, 2, 2, "example.org", "<l@lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "FAIL: Message-Instance m=1 header hash sha256 mismatch");
        msg_free(&m);
    }
    /* K2: keys equal ignoring case are duplicates, at every level */
    { dkim2_verify_result_t r = recipe_at_m2("{\"h\":{\"Subject\":[],\"subject\":[]}}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"h\":{\"subject\":[{\"c\":[1,1]}]},\"H\":{\"to\":[{\"c\":[1,1]}]}}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,1],\"C\":[2,2]}]}"); CHECK_MSG(r, INVALID_JSON_M2); }
    /* the signer emits lowercase keys */
    {
        char *cur[] = { "Subject: x\r\n" };
        char *prev[] = { "Subject: y\r\n" };
        char *r = dkim2_gen_header_recipe("SUBJECT", cur, 1, prev, 1);
        CHECK(r && strstr(r, "\"subject\"") != NULL && strstr(r, "SUBJECT") == NULL);
        free(r);
    }
}

static void test_flags(void) {
    /* F1: donotmodify is just a flag now */
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\nworld\r\n");
        add_mi(&m, NULL);
        add_sig_t(&m, 1, 1, now(), "example.com", "<a@example.com>", "<list@lists.example.org>", NULL, "donotmodify");
        msg_set(&m, "Subject", "[list] test");
        add_mi(&m, "{\"h\":{\"subject\":[{\"d\":[\"test\"]}]}}");
        add_sig(&m, 2, 2, "example.org", "<l@lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    /* F2: exploded */
    {
        char err[512], sig[4096];
        char *one[] = { "<list@lists.example.org>", NULL };
        char *two[] = { "<r1@dest.example>", "<r2@dest.example>", NULL };
        char *dest[] = { "<r1@dest.example>", NULL };
        msg_t m, m2, m3;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        CHECK(lib_sign(&m, "example.com", "<a@example.com>", one, 1, err, sizeof err, sig, sizeof sig) == 0);
        CHECK(!sig_has_flag(sig, "exploded"));          /* never at i=1 */
        CHECK(strstr(sig, "exploded") == NULL);
        msg_copy(&m2, &m);
        msg_copy(&m3, &m);
        CHECK(lib_sign(&m, "example.org", "<l@lists.example.org>", dest, 1, err, sizeof err, sig, sizeof sig) == 0);
        CHECK(sig_has_flag(sig, "exploded"));           /* requested at i=2 */
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        CHECK(lib_sign(&m2, "example.org", "<l@lists.example.org>", two, 0, err, sizeof err, sig, sizeof sig) == 0);
        CHECK(sig_has_flag(sig, "exploded"));           /* two rt= addresses */
        CHECK(lib_sign(&m3, "example.org", "<l@lists.example.org>", dest, 0, err, sizeof err, sig, sizeof sig) == 0);
        CHECK(!sig_has_flag(sig, "exploded"));          /* one address, no request */
        msg_free(&m); msg_free(&m2); msg_free(&m3);
    }
}

static void test_custody(void) {
    /* C1: a null-sender hop from the rt= domain's parent */
    {
        msg_t m;
        base_signed(&m, "a@example.com");
        add_sig(&m, 2, 1, "example.org", "<>", "<a@example.com>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    /* C1 with a Postfix-style rt= (uppercase, trailing dot) */
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "<A@Example.COM.>", "<List@Lists.Example.ORG.>", NULL);
        add_sig(&m, 2, 1, "example.org", "<>", "<a@example.com>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    /* C2 */
    {
        msg_t m;
        base_signed(&m, "a@example.com");
        add_sig(&m, 2, 1, "other.net", "<>", "<a@example.com>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=2 d= does not match the rt= of i=1");
        CHECK(res.status == DKIM2_PERMERROR);
        msg_free(&m);
    }
    /* C3: an nd= bridge */
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<x@mail.example.org>", NULL);
        add_sig(&m, 2, 1, "example.org", NULL, NULL, "fwd.example.net");
        add_sig(&m, 3, 1, "fwd.example.net", "<b@fwd.example.net>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    /* C3 swapped: Parameter1 is the rt= domain, so the direction matters */
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<x@example.org>", NULL);
        add_sig(&m, 2, 1, "mail.example.org", NULL, NULL, "fwd.example.net");
        add_sig(&m, 3, 1, "fwd.example.net", "<b@fwd.example.net>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=2 d= does not match the rt= of i=1");
        msg_free(&m);
    }
    /* C4 */
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<x@mail.example.org>", NULL);
        add_sig(&m, 2, 1, "example.org", NULL, NULL, "fwd.example.net");
        add_sig(&m, 3, 1, "other.example", "<b@other.example>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=2 nd= does not match");
        msg_free(&m);
    }
    /* C5: a domain literal never matches */
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<x@[192.0.2.1]>", NULL);
        add_sig(&m, 2, 1, "example.org", "<y@[192.0.2.1]>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=2 mf= does not match the rt= of i=1");
        msg_free(&m);
    }
    /* C6: MAIL FROM and d= on every signature (here i=1) */
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "<a@example.net>", "<list@lists.example.org>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 MAIL FROM and d= do not match");
        CHECK(res.status == DKIM2_PERMERROR);
        msg_free(&m);
    }
    /* mf= domain a subdomain of d= (and of the previous rt= domain) */
    {
        msg_t m;
        base_signed(&m, "a@example.com");
        add_sig(&m, 2, 1, "lists.example.org", "<bounce@x.lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    /* nd= with mf= is "tag=mf was unexpected" */
    {
        msg_t m;
        base_signed(&m, "a@example.com");
        char *mf = b64("<l@example.org>");
        char tags[512];
        snprintf(tags, sizeof tags, "i=2; m=1; t=%llu; d=example.org; nd=fwd.example.net; mf=%s", now(), mf);
        free(mf);
        add_sig_raw(&m, tags, 1, 0);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=2 tag=mf was unexpected");
        msg_free(&m);
    }
    /* top nd= inbound */
    {
        msg_t m;
        base_signed(&m, "a@example.com");
        add_sig(&m, 2, 1, "example.org", NULL, NULL, "fwd.example.net");
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=2 unexpected nd= tag");
        msg_free(&m);
    }
}

static void test_from_authentic(void) {
    /* A1 */
    {
        msg_t m;
        base_signed(&m, "A <a@example.com>");
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    {
        msg_t m;
        msg_init(&m, "A <a@example.com>", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.net", "<a@example.net>", "<list@lists.example.org>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 matching From is not authentic");
        msg_free(&m);
    }
    {
        msg_t m;
        base_signed(&m, "a@sub.example.com");
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    {
        msg_t m;
        base_signed(&m, "a@example.com, b@example.com");
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 matching From is not authentic");
        msg_free(&m);
    }
    {
        msg_t m;
        base_signed(&m, "a@[192.0.2.1]");
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 matching From is not authentic");
        msg_free(&m);
    }
    {   /* folded, RFC 2047 display name, angle-addr: one mailbox */
        msg_t m;
        base_signed(&m, "=?utf-8?q?Caf=C3=A9?=\r\n <a@example.com>");
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    {   /* two From fields are never Authentic */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        msg_add_bottom(&m, "From", "b@example.com");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 matching From is not authentic");
        msg_free(&m);
    }
    /* A2: a list rewrites From into its own domain */
    {
        msg_t m;
        base_signed(&m, "a@example.com");
        msg_set(&m, "From", "list@lists.example.org");
        add_mi(&m, "{\"h\":{\"from\":[{\"d\":[\"a@example.com\"]}]}}");
        add_sig(&m, 2, 2, "example.org", "<list-bounces@lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    {
        msg_t m;
        base_signed(&m, "a@example.com");
        msg_set(&m, "From", "x@elsewhere.net");
        add_mi(&m, "{\"h\":{\"from\":[{\"d\":[\"a@example.com\"]}]}}");
        add_sig(&m, 2, 2, "example.org", "<list-bounces@lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=2 matching From is not authentic");
        msg_free(&m);
    }
    {   /* the earlier From is checked too: i=1 is not Authentic for it */
        msg_t m;
        msg_init(&m, "a@elsewhere.net", "test", "Hello\r\nworld\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
        msg_set(&m, "From", "list@lists.example.org");
        add_mi(&m, "{\"h\":{\"From\":[{\"d\":[\"a@elsewhere.net\"]}]}}");
        add_sig(&m, 2, 2, "example.org", "<list-bounces@lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 matching From is not authentic");
        msg_free(&m);
    }
    {   /* From changed at m=2, which i=2 covers via m=3: i=2 is relevant */
        msg_t m;
        base_signed(&m, "a@example.com");
        msg_set(&m, "From", "list@lists.example.org");
        add_mi(&m, "{\"h\":{\"from\":[{\"d\":[\"a@example.com\"]}]}}");
        msg_set(&m, "Subject", "[list] test");
        add_mi(&m, "{\"h\":{\"subject\":[{\"d\":[\"test\"]}]}}");
        add_sig(&m, 2, 3, "example.org", "<list-bounces@lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    /* A3: the signer refuses */
    {
        char err[512];
        char *rc[] = { "<list@lists.example.org>", NULL };
        msg_t m;
        msg_init(&m, "a@example.net", "test", "Hello\r\n");
        CHECK(lib_sign(&m, "example.com", "<a@example.com>", rc, 0, err, sizeof err, NULL, 0) != 0);
        CHECK(strstr(err, "From header field is not Authentic for d=example.com") != NULL);
        msg_free(&m);
        msg_init(&m, "a@mail.example.com", "test", "Hello\r\n");
        CHECK(lib_sign(&m, "example.com", "<a@example.com>", rc, 0, err, sizeof err, NULL, 0) == 0);
        msg_free(&m);
    }
    /* A4: U-label From, A-label d= */
    {
        msg_t m;
        msg_init(&m, "u@b\xc3\xbc" "cher.example", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "xn--bcher-kva.example", "<u@xn--bcher-kva.example>", "<list@lists.example.org>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    /* §18: the signer records mf=/rt= domains as A-labels */
    {
        char err[512], sig[4096], mf[256];
        char *rc[] = { "<r@M\xc3\x9cNCHEN.example>", NULL };
        msg_t m;
        msg_init(&m, "u@b\xc3\xbc" "cher.example", "test", "Hello\r\n");
        CHECK(lib_sign(&m, "xn--bcher-kva.example", "<u@b\xc3\xbc" "cher.example>", rc, 0,
                       err, sizeof err, sig, sizeof sig) == 0);
        sig_mf(sig, mf, sizeof mf);
        CHECK(strcmp(mf, "<u@xn--bcher-kva.example>") == 0);
        dkim2_sig_t *s = dkim2_sig_parse(sig);
        CHECK(s && s->rt && s->rt[0] && strcmp(s->rt[0], "<r@xn--mnchen-3ya.example>") == 0);
        dkim2_sig_free(s);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
}

static void test_signer_gate(void) {
    char err[512];
    /* nd= on the top signature naming us: the gate signs */
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<x@example.org>", NULL);
        add_sig(&m, 2, 1, "example.org", NULL, NULL, "fwd.example.net");
        dkim2_verify_result_t in = verify(&m);
        CHECK_MSG(in, "PERMERROR: DKIM2-Signature i=2 unexpected nd= tag");
        char *rc[] = { "<r@dest.example>", NULL };
        CHECK(lib_sign(&m, "fwd.example.net", "<b@fwd.example.net>", rc, 0, err, sizeof err, NULL, 0) == 0);
        if (err[0]) printf("  gate said: %s\n", err);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    /* From changed in an unsigned top MI: matching D signs, other refused */
    {
        msg_t m, m2;
        base_signed(&m, "a@example.com");
        msg_set(&m, "From", "list@lists.example.org");
        add_mi(&m, "{\"h\":{\"from\":[{\"d\":[\"a@example.com\"]}]}}");
        dkim2_verify_result_t out = verify_mode(&m, 1);
        CHECK_PASS(out);
        msg_copy(&m2, &m);
        char *rc[] = { "<r@dest.example>", NULL };
        CHECK(lib_sign(&m, "example.org", "<list-bounces@lists.example.org>", rc, 0, err, sizeof err, NULL, 0) == 0);
        if (err[0]) printf("  gate said: %s\n", err);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        CHECK(lib_sign(&m2, "other.net", "<x@other.net>", rc, 0, err, sizeof err, NULL, 0) != 0);
        CHECK(strstr(err, "From header field is not Authentic for d=other.net") != NULL);
        msg_free(&m); msg_free(&m2);
    }
    /* an unchanged From is not re-checked when extending a chain */
    {
        msg_t m;
        base_signed(&m, "a@example.com");
        char *rc[] = { "<r@dest.example>", NULL };
        CHECK(lib_sign(&m, "example.org", "<l@lists.example.org>", rc, 0, err, sizeof err, NULL, 0) == 0);
        msg_free(&m);
    }
}

static void test_timestamps(void) {
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig_t(&m, 1, 1, now() + 7200, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL, NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig_t(&m, 1, 1, now() + 172800, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL, NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 signature is from the future");
        msg_free(&m);
    }
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig_t(&m, 1, 1, now() - 1209600 - 3600, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL, NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 signature expired");
        msg_free(&m);
    }
}

static void test_error_strings(void) {
    /* no DKIM2 header fields at all: "none", no error string */
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        dkim2_verify_result_t res = verify(&m);
        CHECK(res.status == DKIM2_NONE);
        CHECK(res.message[0] == '\0');
        msg_free(&m);
    }
    /* Message-Instance fields but no signature */
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: Message-Instance m=1 is not signed");
        msg_free(&m);
    }
    /* an unsigned top instance */
    {
        msg_t m;
        base_signed(&m, "a@example.com");
        add_mi(&m, NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: Message-Instance m=2 is not signed");
        msg_free(&m);
    }
    /* a missing instance, a missing signature */
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        msg_add_top(&m, "Message-Instance", "m=3; h=sha256:AAAA:AAAA;");
        add_sig(&m, 1, 3, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: Message-Instance m=2 missing");
        msg_free(&m);
    }
    {
        msg_t m;
        base_signed(&m, "a@example.com");
        add_sig(&m, 3, 1, "example.org", "<>", "<a@example.com>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=2 missing");
        msg_free(&m);
    }
    /* the signature names an instance that is not there */
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 1, 2, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: Message-Instance m=2 missing");
        msg_free(&m);
    }
    /* hash mismatches name the algorithm */
    {
        msg_t m;
        base_signed(&m, "a@example.com");
        snprintf(m.body, sizeof m.body, "tampered\r\n");
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "FAIL: Message-Instance m=1 body hash sha256 mismatch");
        msg_free(&m);
    }
    {
        msg_t m;
        base_signed(&m, "a@example.com");
        msg_set(&m, "Subject", "tampered");
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "FAIL: Message-Instance m=1 header hash sha256 mismatch");
        msg_free(&m);
    }
    /* signatures: all fail; one passes and one fails */
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        char *mf = b64("<a@example.com>"), *rt = b64("<list@lists.example.org>");
        char tags[512];
        snprintf(tags, sizeof tags, "i=1; m=1; t=%llu; d=example.com; mf=%s; rt=%s", now(), mf, rt);
        msg_t m2;
        msg_copy(&m2, &m);
        add_sig_raw(&m, tags, 2, 3);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "FAIL: DKIM2-Signature i=1 selector sel incorrect signature");
        add_sig_raw(&m2, tags, 2, 2);
        res = verify(&m2);
        CHECK_MSG(res, "FAIL: DKIM2-Signature i=1 signature sel signature sel2 failed");
        CHECK(res.status == DKIM2_FAIL);
        free(mf); free(rt);
        msg_free(&m); msg_free(&m2);
    }
    /* missing tags, unbracketed paths */
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        char *mf = b64("<a@example.com>");
        char tags[512];
        snprintf(tags, sizeof tags, "i=1; m=1; t=%llu; d=example.com; mf=%s", now(), mf);
        add_sig_raw(&m, tags, 1, 0);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 tag=rt missing");
        free(mf);
        msg_free(&m);
    }
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "a@example.com", "<list@lists.example.org>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 syntax error");
        msg_free(&m);
    }
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        msg_add_top(&m, "Message-Instance", "m=1; r=e30=;");
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: Message-Instance m=1 tag=h missing");
        msg_free(&m);
    }
    /* every error carries "STATE: " */
    {
        dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,9]}]}");
        CHECK(strncmp(r.message, "PERMERROR: ", 11) == 0);
    }
}

static void test_tag_lists(void) {
    taglist_t *tl;
    tl = tagparse("m=1; h=x;", NULL);
    CHECK(tl && !tl->syntax_error);
    taglist_free(tl);
    tl = tagparse("m=1; h=x; ", NULL);
    CHECK(tl && !tl->syntax_error);
    taglist_free(tl);
    tl = tagparse("m=1;; h=x", NULL);                  /* empty tag-spec in the middle */
    CHECK(tl && tl->syntax_error);
    taglist_free(tl);
    tl = tagparse("; m=1; h=x", NULL);                 /* leading empty tag-spec */
    CHECK(tl && tl->syntax_error);
    taglist_free(tl);
    tl = tagparse("m=1; h=x;;", NULL);                 /* two trailing semicolons */
    CHECK(tl && tl->syntax_error);
    taglist_free(tl);
    tl = tagparse("M=1; H=x", NULL);                   /* any case accepted */
    CHECK(tl && !tl->syntax_error && !tl->duplicate && tag_get(tl, "m"));
    taglist_free(tl);
    tl = tagparse("m=1; M=2", NULL);                   /* duplicate ignoring case */
    CHECK(tl && tl->duplicate);
    taglist_free(tl);
    CHECK(dkim2_mi_parse("m=1;; h=sha256:AAAA:AAAA") == NULL);
}

int main(void) {
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_keygen(kctx, &g_priv);
    EVP_PKEY_CTX_free(kctx);
    FILE *f = fopen(KEY_PATH, "w");
    PEM_write_PrivateKey(f, g_priv, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    unsigned char pub[32];
    size_t publen = sizeof pub;
    EVP_PKEY_get_raw_public_key(g_priv, pub, &publen);
    char pub64[64];
    b64_encode(pub, publen, pub64, sizeof pub64);
    snprintf(g_dns_txt, sizeof g_dns_txt, "v=DKIM1; k=ed25519; p=%s", pub64);
    dkim2_dns_override = dns_override;

    test_u_steps();
    test_json_keys();
    test_flags();
    test_custody();
    test_from_authentic();
    test_signer_gate();
    test_timestamps();
    test_error_strings();
    test_tag_lists();

    EVP_PKEY_free(g_priv);
    remove(KEY_PATH);
    if (g_fail) { printf("test_spec07: %d failure(s)\n", g_fail); return 1; }
    printf("test_spec07: all passed\n");
    return 0;
}
