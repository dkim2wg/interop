/* The in-memory message harness shared by test_spec07.c and
   test_spec08.c: messages built and signed here over the
   Message-Instance and DKIM2-Signature fields (§12.8) with one Ed25519
   key, which the fake DNS serves for selectors "sel" and "sel2" under any
   domain. Include once, from a test file, after the system headers. */
#pragma once
#pragma GCC diagnostic ignored "-Wunused-function"

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
#ifndef HARNESS_KEY_PATH
#define HARNESS_KEY_PATH "/tmp/dkim2_test_spec07.pem"
#endif
static const char *KEY_PATH = HARNESS_KEY_PATH;

static char *dns_override(const char *qname, int *n_records) {
    (void)n_records;
    if (strncmp(qname, "sel._domainkey.", 15) == 0 || strncmp(qname, "sel2._domainkey.", 16) == 0)
        return strdup(g_dns_txt);
    return NULL;
}

/* ---- in-memory messages ---- */

#define MAXH 128
typedef struct {
    char *h[MAXH];      /* "Name: value\r\n", top-down */
    int n;
    char body[4096];
} msg_t;

/* "Name: value\r\n", malloc'd to fit (a signature with many rt= values
   is long). */
static char *field_line(const char *name, const char *value) {
    size_t n = strlen(name) + strlen(value) + 5;
    char *buf = malloc(n);
    if (buf) snprintf(buf, n, "%s: %s\r\n", name, value);
    return buf;
}

static void msg_add_bottom(msg_t *m, const char *name, const char *value) {
    m->h[m->n++] = field_line(name, value);
}

static void msg_add_top(msg_t *m, const char *name, const char *value) {
    memmove(m->h + 1, m->h, (size_t)m->n * sizeof m->h[0]);
    m->h[0] = field_line(name, value);
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
        dkim2_badfield_free(ctx.bad_list);
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
    dkim2_badfield_free(ctx.bad_list);
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

/* Make the key, write it for the library signer, serve it from DNS. */
static void harness_init(void) {
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
}

static void harness_done(void) {
    EVP_PKEY_free(g_priv);
    remove(KEY_PATH);
}
