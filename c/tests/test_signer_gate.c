/* Signer gate: dkim2_sign_message / dkim2_do_sign must verify an existing
   DKIM2 chain (outbound mode: the unsigned top Message-Instance is the one
   being signed) before extending it, and refuse a null body Recipe on an
   UNSIGNED top instance (no DKIM2-Signature has its m=) unless
   allow_null_body_recipe is set; a null top already signed upstream signs.

   Usage: test_signer_gate <fixture-dir> <dns.json> <key.pem>
   Fixtures come from util/build-signer-gate-fixtures.py. */
#include "../dkim2_message.h"
#include "../dkim2_dnsjson.h"
#include "../eml_parse.h"
#include "../dkim2_header.h"
#include "../dkim2_crypto.h"
#include "../dkim2_hash.h"
#include <strings.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *g_dir, *g_key;
static int g_fail;

static int max_i(const char *s) {
    int m = 0;
    for (const char *p = s; (p = strstr(p, "DKIM2-Signature:")); p++) {
        const char *e = strchr(p, '\n');
        const char *i = strstr(p, " i=");
        if (i && (!e || i < e) && atoi(i + 3) > m) m = atoi(i + 3);
    }
    return m;
}

/* returns 0 = signed (new i = chain+1), -1 = refused; *err filled */
static int sign_fixture(const char *name, int allow_null, char *err, size_t errsz,
                        int *new_i) {
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", g_dir, name);
    FILE *out = tmpfile();
    assert(out);
    dkim2_sign_config_t cfg = {
        .domain = "test3.dkim2.com", .selector = "sel1",
        .privkey_path = (char *)g_key,
        .allow_null_body_recipe = allow_null,
        .skip_timestamp_check = 1,
    };
    char *rcpt[] = { "<subscriber@test4.dkim2.com>", NULL };
    err[0] = '\0';
    int r = dkim2_sign_message(path, out, &cfg, "<list@test3.dkim2.com>", rcpt, err, errsz);
    long n = ftell(out);
    rewind(out);
    char *buf = calloc(1, (size_t)n + 1);
    size_t got = fread(buf, 1, (size_t)n, out);
    (void)got;
    fclose(out);
    *new_i = max_i(buf);
    free(buf);
    return r;
}

static void expect(const char *name, int allow_null, int want_sign, const char *want_err) {
    char err[512];
    int ni = 0;
    int r = sign_fixture(name, allow_null, err, sizeof err, &ni);
    int ok = want_sign ? (r == 0 && ni >= 1) : (r != 0 && ni == 0);
    if (ok && want_err && !strstr(err, want_err)) ok = 0;
    printf("  %-22s allow_null=%d want %-6s: %s%s%s\n", name, allow_null,
           want_sign ? "sign" : "refuse", ok ? "ok" : "FAIL",
           err[0] ? " : " : "", err);
    if (!ok) g_fail = 1;
}


static int count_str(const char *s, const char *needle) {
    int n = 0;
    for (const char *p = s; (p = strstr(p, needle)); p++) n++;
    return n;
}

/* Sign a fixture and hand back the output text (caller frees), or NULL when
   the signer refused (err filled). */
static char *sign_to_text(const char *name, char *err, size_t errsz) {
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", g_dir, name);
    FILE *out = tmpfile();
    assert(out);
    dkim2_sign_config_t cfg = {
        .domain = "test3.dkim2.com", .selector = "sel1",
        .privkey_path = (char *)g_key, .skip_timestamp_check = 1,
    };
    char *rcpt[] = { "<subscriber@test4.dkim2.com>", NULL };
    err[0] = '\0';
    int r = dkim2_sign_message(path, out, &cfg, "<list@test3.dkim2.com>", rcpt, err, errsz);
    long n = ftell(out);
    rewind(out);
    char *buf = calloc(1, (size_t)n + 1);
    size_t got = fread(buf, 1, (size_t)n, out);
    (void)got;
    fclose(out);
    if (r != 0) { free(buf); return NULL; }
    return buf;
}

/* Reuse of the HIGHEST-m Message-Instance: when the message already matches
   its top MI, no redundant m=3 is added and the new signature covers m=2. */
static void expect_reuse_top_mi(const char *name) {
    char err[512];
    char *t = sign_to_text(name, err, sizeof err);
    int ok = t != NULL;
    int mis = 0, m2 = 0;
    if (t) {
        mis = count_str(t, "Message-Instance:");
        const char *sg = strstr(t, "DKIM2-Signature:");
        m2 = sg && strstr(sg, " m=2;") && strstr(sg, " m=2;") < strchr(sg, '\n');
        ok = mis == 2 && m2;
    }
    printf("  %-22s reuse highest-m MI (MIs=%d, sig m=2:%d): %s%s%s\n", name, mis, m2,
           ok ? "ok" : "FAIL", err[0] ? " : " : "", err);
    if (!ok) g_fail = 1;
    free(t);
}

/* A message whose only signature is i=1 by test1.dkim2.com carrying
   nd=<nd> (hand-signed: the C signer never emits nd=). Written to g_dir/name. */
static void build_nd_fixture(const char *name, const char *nd) {
    static const char *hdrs[] = {
        "From: alice@test1.dkim2.com\r\n", "To: list@test3.dkim2.com\r\n",
        "Subject: nd bridge\r\n", "Date: Mon, 01 Jan 2026 00:00:00 +0000\r\n",
        "Message-ID: <nd@test1.dkim2.com>\r\n",
    };
    const int nh = (int)(sizeof hdrs / sizeof *hdrs);
    const char *body = "hello\r\n";
    const char *k1 = "../keys/sel1._domainkey.test1.dkim2.com.pem";

    dkim2_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.headers = (char **)hdrs; ctx.n_headers = nh;
    dkim2_body_hash_raw(body, strlen(body), ctx.body_digests.d[0]);
    dkim2_body_hash_raw_alg(body, strlen(body), 1, ctx.body_digests.d[1]);
    char *rcpt[] = { "<list@test3.dkim2.com>", NULL };
    ctx.mail_from = "<alice@test1.dkim2.com>"; ctx.rcpt_to = rcpt;
    dkim2_sign_config_t cfg = { .domain = "test1.dkim2.com", .selector = "sel1",
        .privkey_path = (char *)k1, .skip_chain_check = 1 };
    char *mi = NULL, *sig = NULL;
    assert(dkim2_do_sign(&ctx, &cfg, &mi, &sig) == 0 && mi);
    free(sig);

    char inc[512];
    snprintf(inc, sizeof inc, "i=1; m=1; t=1740000000; d=test1.dkim2.com; nd=%s; "
             "s=sel1:rsa-sha256:;", nd);
    char in[8192]; size_t pos = 0;
    const char *vals[2] = { mi, inc };
    const char *nms[2] = { "message-instance", "dkim2-signature" };
    for (int k = 0; k < 2; k++) {
        for (const char *h = nms[k]; *h; h++) in[pos++] = *h;
        in[pos++] = ':';
        for (const char *h = vals[k]; *h; h++)
            if (*h != ' ' && *h != '\t' && *h != '\r' && *h != '\n') in[pos++] = *h;
        in[pos++] = '\r'; in[pos++] = '\n';
    }
    EVP_PKEY *pk = dkim2_load_privkey(k1);
    assert(pk);
    char *b = dkim2_sign(pk, "rsa-sha256", (unsigned char *)in, pos);
    EVP_PKEY_free(pk);
    assert(b);

    char path[1024];
    snprintf(path, sizeof path, "%s/%s", g_dir, name);
    FILE *f = fopen(path, "wb");
    assert(f);
    fprintf(f, "Message-Instance: %s\r\n", mi);
    fprintf(f, "DKIM2-Signature: i=1; m=1; t=1740000000; d=test1.dkim2.com; nd=%s; "
               "s=sel1:rsa-sha256:%s;\r\n", nd, b);
    for (int i = 0; i < nh; i++) fputs(hdrs[i], f);
    fprintf(f, "\r\n%s", body);
    fclose(f);
    free(b); free(mi);
}

/* nd= bridge: we (test3.dkim2.com) may extend a chain whose top signature
   carries nd=<us>, and must refuse nd=<anyone else> (case-insensitively
   matched). */
static void expect_nd(void) {
    build_nd_fixture("nd-to-us.eml", "test3.dkim2.com");
    build_nd_fixture("nd-to-us-case.eml", "TEST3.dkim2.COM");
    build_nd_fixture("nd-to-other.eml", "test4.dkim2.com");
    expect("nd-to-us.eml",      0, 1, NULL);
    expect("nd-to-us-case.eml", 0, 1, NULL);
    expect("nd-to-other.eml",   0, 0, "top signature nd=test4.dkim2.com names another domain");
}

/* The milter path: dkim2_do_sign on a ctx that has only the body DIGEST
       (ctx.body == NULL). Top-instance gating must still work. */
static void expect_digest_only(const char *name, int allow_null, int want_sign) {
    {
        char path[1024];
        snprintf(path, sizeof path, "%s/%s", g_dir, name);
        char **h = NULL; int nh = 0;
        dkim2_ctx_t ctx = {0};
        assert(eml_parse(path, &h, &nh, &ctx.body_digests) == 0);
        ctx.headers = h; ctx.n_headers = nh;
        ctx.mail_from = "<list@test3.dkim2.com>";
        char *rcpt[] = { "<subscriber@test4.dkim2.com>", NULL };
        ctx.rcpt_to = rcpt;
        /* collect headers the way the milter does */
        for (int i = 0; i < nh; i++) {
            const char *c = strchr(h[i], ':');
            char *v = strdup(c + 2);
            v[strcspn(v, "\r\n")] = 0;
            if (!strncasecmp(h[i], "Message-Instance", 16)) {
                dkim2_mi_t *mi = dkim2_mi_parse(v);
                dkim2_mi_t **t = &ctx.mi_list; while (*t) t = &(*t)->next; *t = mi;
            } else if (!strncasecmp(h[i], "DKIM2-Signature", 15)) {
                char eb[256];
                dkim2_sig_t *s = dkim2_sig_parse_err(v, eb, sizeof eb);
                if (s) {
                    dkim2_sig_t **t = &ctx.sig_list; while (*t) t = &(*t)->next; *t = s;
                } else if (!ctx.sig_error[0]) {
                    snprintf(ctx.sig_error, sizeof ctx.sig_error, "%s", eb);
                }
            }
            free(v);
        }
        dkim2_sign_config_t cfg = { .domain = "test3.dkim2.com", .selector = "sel1",
            .privkey_path = (char *)g_key, .skip_timestamp_check = 1,
            .allow_null_body_recipe = allow_null };
        char *mi = NULL, *sig = NULL;
        int r = dkim2_do_sign(&ctx, &cfg, &mi, &sig);
        int ok = want_sign ? r == 0 : r != 0;
        printf("  digest-only %-12s allow_null=%d want %-6s: %s%s%s\n", name, allow_null,
               want_sign ? "sign" : "refuse", ok ? "ok" : "FAIL",
               r ? " : " : "", r ? ctx.errmsg : "");
        if (!ok) g_fail = 1;
        free(mi); free(sig);
        dkim2_mi_free(ctx.mi_list); dkim2_sig_free(ctx.sig_list);
        eml_free(h, nh);
    }
}

int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr, "usage: %s fixtures dns.json key\n", argv[0]); return 2; }
    g_dir = argv[1]; g_key = argv[3];
    char err[256];
    if (dkim2_dns_json_load(argv[2], err, sizeof err) < 0) { fprintf(stderr, "%s\n", err); return 2; }

    expect("fresh.eml",            0, 1, NULL);
    expect("fresh.eml",            1, 1, NULL);
    expect("valid-chain.eml",      0, 1, NULL);
    expect("valid-chain.eml",      1, 1, NULL);
    expect("broken-signature.eml", 0, 0, "not signing: upstream DKIM2 chain");
    expect("broken-signature.eml", 1, 0, "not signing: upstream DKIM2 chain");
    expect("broken-mi-chain.eml",  0, 0, "not signing: Message-Instance chain");
    expect("broken-mi-chain.eml",  1, 0, "not signing: Message-Instance chain");
    expect("null-top.eml",         0, 0, "unsigned top Message-Instance m=2 has a null body Recipe");
    expect("null-top.eml",         1, 1, NULL);
    expect("null-top-forged.eml",  0, 0, "not signing");
    expect("null-top-forged.eml",  1, 0, "not signing");
    /* the null m=2 is already signed i=2/m=2 upstream: no option needed */
    expect("null-top-signed.eml",  0, 1, NULL);
    expect("null-top-signed.eml",  1, 1, NULL);

    /* A DKIM2-Signature naming m=2 that cannot be keyed is not coverage:
       the verifier PERMERRORs on it, so these are refused with or without
       the option. */
    {
        static const char *fake[] = {
            "fake-cover-no-i.eml", "fake-cover-i0.eml", "fake-cover-i-abc.eml",
            "fake-cover-m-rewritten.eml", "fake-cover-unparseable.eml", NULL };
        for (int k = 0; fake[k]; k++) {
            expect(fake[k], 0, 0, "result=permerror (PERMERROR DKIM2-Signature");
            expect(fake[k], 1, 0, "result=permerror (PERMERROR DKIM2-Signature");
            expect_digest_only(fake[k], 1, 0);
        }
    }

    expect_digest_only("valid-chain.eml", 0, 1);
    expect_digest_only("broken-mi-chain.eml", 0, 0);
    expect_digest_only("null-top.eml", 0, 0);
    expect_digest_only("null-top.eml", 1, 1);
    expect_digest_only("null-top-forged.eml", 1, 0);
    expect_digest_only("null-top-signed.eml", 0, 1);

    expect_reuse_top_mi("valid-chain.eml");
    expect_reuse_top_mi("mi-only.eml");
    expect_nd();

    dkim2_dns_json_free();
    printf(g_fail ? "FAILED\n" : "all signer-gate checks passed\n");
    return g_fail;
}
