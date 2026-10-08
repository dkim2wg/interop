/* Signer gate: dkim2_sign_message / dkim2_do_sign must verify an existing
   DKIM2 chain (outbound mode: the unsigned top Message-Instance is the one
   being signed) before extending it, and refuse a null body Recipe on top
   unless allow_null_body_recipe is set.

   Usage: test_signer_gate <fixture-dir> <dns.json> <key.pem>
   Fixtures come from util/build-signer-gate-fixtures.py. */
#include "../dkim2_message.h"
#include "../dkim2_dnsjson.h"
#include "../eml_parse.h"
#include "../dkim2_header.h"
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
                dkim2_sig_t *s = dkim2_sig_parse(v);
                dkim2_sig_t **t = &ctx.sig_list; while (*t) t = &(*t)->next; *t = s;
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
    expect("null-top.eml",         0, 0, "null body Recipe");
    expect("null-top.eml",         1, 1, NULL);
    expect("null-top-forged.eml",  0, 0, "not signing");
    expect("null-top-forged.eml",  1, 0, "not signing");

    expect_digest_only("valid-chain.eml", 0, 1);
    expect_digest_only("broken-mi-chain.eml", 0, 0);
    expect_digest_only("null-top.eml", 0, 0);
    expect_digest_only("null-top.eml", 1, 1);
    expect_digest_only("null-top-forged.eml", 1, 0);

    dkim2_dns_json_free();
    printf(g_fail ? "FAILED\n" : "all signer-gate checks passed\n");
    return g_fail;
}
