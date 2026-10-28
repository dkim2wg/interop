/* draft-ietf-dkim-dkim2-spec-08: the implementation contract's D1-D10
   (docs/superpowers/specs/2026-10-28-dkim2-spec-08-design.md), on
   messages built and signed in memory (spec_harness.h).

   D11 (DSN generation) and D12 (Provisionally Verified) do not apply: the C
   implementation has neither (c/TODO-dsn.md). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
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

#define HARNESS_KEY_PATH "/tmp/dkim2_test_spec08.pem"
#include "spec_harness.h"

/* D1: Auto-Submitted and VBR-Info are hashed (-08 §4). */
static void test_hashed_fields(void) {
    CHECK(!dkim2_hdr_ignored("auto-submitted", 14));
    CHECK(!dkim2_hdr_ignored("vbr-info", 8));
    CHECK(dkim2_hdr_ignored("received", 8));
    CHECK(dkim2_hdr_ignored("x-anything", 10));
    static const char *fields[] = { "Auto-Submitted", "VBR-Info" };
    for (int k = 0; k < 2; k++) {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        msg_add_bottom(&m, fields[k], "auto-generated");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
        CHECK_PASS(verify(&m));
        msg_set(&m, fields[k], "no");
        CHECK_MSG(verify(&m), "FAIL: Message-Instance m=1 header hash sha256 mismatch");
        msg_free(&m);
    }
}

static const char *INVALID_JSON_M2 = "PERMERROR: Message-Instance m=2 contains invalid JSON";

/* D10: tag names are strictly lowercase (an uppercase one is an unknown
   tag), and so are Recipe JSON keys (an uppercase one is invalid JSON). */
static void test_strict_lowercase(void) {
    taglist_t *tl = tagparse("M=1; H=x", NULL);
    CHECK(tl && !tl->syntax_error && !tl->duplicate);
    CHECK(tl && !tag_get(tl, "m") && !tag_get(tl, "h"));
    CHECK(tl && tag_get(tl, "M") && strcmp(tag_get(tl, "M"), "1") == 0);
    taglist_free(tl);
    tl = tagparse("m=1; M=2", NULL);                   /* not a duplicate */
    CHECK(tl && !tl->duplicate && strcmp(tag_get(tl, "m"), "1") == 0);
    taglist_free(tl);

    {   /* M=1 alone: m= is missing */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        msg_add_top(&m, "Message-Instance", "M=1; h=sha256:AAAA:AAAA;");
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
        CHECK_MSG(verify(&m), "PERMERROR: Message-Instance m= tag=m missing");
        msg_free(&m);
    }
    {   /* m=1; M=2: the M= is ignored, the instance verifies */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        char *v = field_value(m.h[0]);
        char nv[1024];
        snprintf(nv, sizeof nv, "%s M=2;", v);
        free(v);
        msg_set(&m, "Message-Instance", nv);
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
        CHECK_PASS(verify(&m));
        msg_free(&m);
    }
    {   /* D= is not d= */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        char tags[512], *mf = b64("<a@example.com>"), *rt = b64("<l@lists.example.org>");
        snprintf(tags, sizeof tags, "i=1; m=1; t=%llu; D=example.com; mf=%s; rt=%s", now(), mf, rt);
        free(mf); free(rt);
        add_sig_raw(&m, tags, 1, 0);
        CHECK_MSG(verify(&m), "PERMERROR: DKIM2-Signature i=1 tag=d missing");
        msg_free(&m);
    }

    /* JSON keys: any ASCII capital, at any level, after unescaping */
    static const char *upper[] = {
        "{\"H\":{\"subject\":[{\"c\":[1,1]}]}}",
        "{\"h\":{\"Subject\":[{\"c\":[1,1]}]}}",
        "{\"h\":{\"subject\":[{\"C\":[1,1]}]}}",
        "{\"b\":[{\"C\":[1,2]}]}",
        "{\"h\":{\"\\u0053ubject\":[{\"c\":[1,1]}]}}",
        "{\"b\":[{\"c\":[1,2]}],\"X\":1}",
    };
    for (size_t k = 0; k < sizeof upper / sizeof upper[0]; k++) {
        dkim2_verify_result_t r = recipe_at_m2(upper[k]);
        CHECK_MSG(r, INVALID_JSON_M2);
    }
    /* duplicates are compared exactly, after unescaping */
    {
        dkim2_verify_result_t r = recipe_at_m2(
            "{\"h\":{\"subject\":[{\"c\":[1,1]}],\"subj\\u0065ct\":[{\"c\":[1,1]}]}}");
        CHECK_MSG(r, INVALID_JSON_M2);
    }
    /* a non-ASCII letter is not judged */
    {
        dkim2_verify_result_t r = recipe_at_m2(
            "{\"h\":{\"subject\":[{\"c\":[1,1]}],\"x-\xc3\x89\":[{\"d\":[\"v\"]}]}}");
        CHECK(strcmp(r.message, INVALID_JSON_M2) != 0);
    }
}

/* D6: one bad step is "Recipe <path> is invalid"; a fault in the whole
   document is "contains invalid JSON", and is found first. */
static void test_recipe_paths(void) {
    static const struct { const char *json, *path; } steps[] = {
        { "{\"b\":[{\"c\":[2,2]},{\"c\":[1,1]}]}",          "b[1]" },   /* out of order */
        { "{\"b\":[{\"c\":[1,2]},{\"c\":[2,2]}]}",          "b[1]" },   /* overlap */
        { "{\"b\":[{\"x\":[1]}]}",                          "b[0]" },
        { "{\"b\":[{\"c\":[1,1],\"d\":[\"x\"]}]}",          "b[0]" },
        { "{\"b\":[{}]}",                                   "b[0]" },
        { "{\"b\":[\"x\"]}",                                "b[0]" },
        { "{\"b\":[{\"d\":[]}]}",                           "b[0]" },
        { "{\"b\":[{\"d\":[1]}]}",                          "b[0]" },
        { "{\"b\":[{\"d\":\"x\"}]}",                        "b[0]" },
        { "{\"b\":[{\"d\":[\"a\\nb\"]}]}",                  "b[0]" },
        { "{\"b\":[{\"u\":[\"QR==\"]}]}",                   "b[0]" },
        { "{\"b\":[{\"u\":[\"DQo=\"]}]}",                   "b[0]" },   /* decodes to CRLF */
        { "{\"b\":[{\"c\":[0,1]}]}",                        "b[0]" },
        { "{\"b\":[{\"c\":[2,1]}]}",                        "b[0]" },
        { "{\"b\":[{\"c\":[1]}]}",                          "b[0]" },
        { "{\"b\":[{\"c\":[\"1\",1]}]}",                    "b[0]" },
        { "{\"b\":[{\"c\":[1,2]},{\"d\":[\"x\"]},{\"q\":1}]}", "b[2]" },
        { "{\"h\":{\"subject\":{\"c\":[1,1]}}}",            "h.subject" },
        { "{\"h\":{\"subject\":[{\"c\":[1,1]},{\"x\":1}]}}", "h.subject[1]" },
        { "{\"h\":{\"x caf\\u00e9\":[{\"q\":1}]}}",         "h.x\\x20caf\\xC3\\xA9[0]" },
        { "{\"h\":{\"x\\u0001\":[{\"q\":1}]}}",             "h.x\\x01[0]" },
        /* b first, then h names in byte order, then steps in order */
        { "{\"h\":{\"a\":[{\"q\":1}]},\"b\":[{\"c\":[1,1]},{\"q\":1}]}", "b[1]" },
        { "{\"h\":{\"z\":[{\"q\":1}],\"a\":[{\"c\":[1,1]},{\"q\":1}]}}", "h.a[1]" },
        { "{\"h\":{\"to\":[{\"q\":1}],\"subject\":7}}",     "h.subject" },
    };
    for (size_t k = 0; k < sizeof steps / sizeof steps[0]; k++) {
        char want[256];
        snprintf(want, sizeof want, "PERMERROR: Message-Instance m=2 Recipe %s is invalid", steps[k].path);
        dkim2_verify_result_t r = recipe_at_m2(steps[k].json);
        if (strcmp(r.message, want) != 0)
            printf("  (Recipe %s)\n", steps[k].json);
        CHECK_MSG(r, want);
    }
    static const char *whole[] = {
        "{\"b\":[{\"x\":1}],\"h\":[]}",             /* whole-document fault first */
        "{\"b\":[{\"c\":[1e0,1]}]}",                /* exponent */
        "{\"b\":[{\"c\":[1,2E0]}]}",
        "{\"b\":[{\"c\":[1.0,2]}]}",                /* fraction */
        "{\"b\":[{\"c\":[1,2]}],\"x\":1.5}",        /* wherever it is */
        "{\"b\":[{\"c\":[1,2]}],\"x\":[-0.5]}",
        "{\"b\":[{\"d\":[\"\\udc80\"]}]}",          /* lone surrogates */
        "{\"b\":[{\"d\":[\"\\ud800x\"]}]}",
        "{\"b\":[{\"d\":[\"\\ud800\"]}]}",
        "{\"b\":[{\"c\":[1,2]}],\"x\":\"\\udfff\"}",
        "{\"b\":[{\"d\":[\"caf\xff\"]}]}",          /* not UTF-8 */
        "{\"b\":[{\"c\":[1,2]}],\"x\":\"\xed\xa0\x80\"}",  /* encoded surrogate */
        "{\"b\":{}}",
        "{\"b\":7}",
        "{\"h\":{}}",
        "{\"h\":null}",
        "{\"h\":[]}",
        "{}",
        "[]",
        "{\"b\":null} x",                          /* trailing text */
        "{\"b\":[{\"c\":[1,99]}]}",                 /* past the end: found by the walk */
    };
    for (size_t k = 0; k < sizeof whole / sizeof whole[0]; k++) {
        dkim2_verify_result_t r = recipe_at_m2(whole[k]);
        if (strcmp(r.message, INVALID_JSON_M2) != 0)
            printf("  (Recipe %s)\n", whole[k]);
        CHECK_MSG(r, INVALID_JSON_M2);
    }
    /* a string holding a number-like text, and a valid surrogate pair */
    CHECK_PASS(recipe_at_m2("{\"b\":[{\"c\":[1,2]}],\"x\":\"1.5e3\"}"));
    CHECK_PASS(recipe_at_m2("{\"b\":[{\"c\":[1,2]}],\"x\":\"\\ud83d\\ude00\"}"));
    CHECK_PASS(recipe_at_m2("{\"b\":[{\"c\":[1,2]}],\"x\":[-5,0,10]}"));
}

/* Verify with an envelope (undo and planned walks agree on these). */
static dkim2_verify_result_t verify_env(const msg_t *m, const char *mail_from, const char *rcpt) {
    dkim2_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    char *rcpts[2] = { (char *)rcpt, NULL };
    ctx.headers = (char **)m->h;
    ctx.n_headers = m->n;
    ctx.body = (char *)m->body;
    ctx.body_len = strlen(m->body);
    ctx.mail_from = (char *)mail_from;
    ctx.rcpt_to = rcpt ? rcpts : NULL;
    dkim2_ctx_collect(&ctx);
    dkim2_verify_result_t res;
    dkim2_do_verify(&ctx, &res);
    dkim2_mi_free(ctx.mi_list);
    dkim2_sig_free(ctx.sig_list);
    dkim2_badfield_free(ctx.bad_list);
    return res;
}

#define CHECK_STATE(res, st, want) do { CHECK((res).status == (st)); CHECK_MSG(res, want); } while (0)

/* D5: timestamps, Chain of Custody and From Authentic are FAIL. */
static void test_fail_states(void) {
    msg_t m;
    msg_init(&m, "a@example.com", "test", "Hello\r\n");
    add_mi(&m, NULL);
    add_sig_t(&m, 1, 1, now() - 15 * 86400, "example.com", "<a@example.com>", "<l@lists.example.org>", NULL, NULL);
    CHECK_STATE(verify(&m), DKIM2_FAIL, "FAIL: DKIM2-Signature i=1 signature expired");
    msg_free(&m);

    msg_init(&m, "a@example.com", "test", "Hello\r\n");
    add_mi(&m, NULL);
    add_sig_t(&m, 1, 1, now() + 2 * 86400, "example.com", "<a@example.com>", "<l@lists.example.org>", NULL, NULL);
    CHECK_STATE(verify(&m), DKIM2_FAIL, "FAIL: DKIM2-Signature i=1 signature is from the future");
    msg_free(&m);

    /* custody: the envelope, then the tags */
    base_signed(&m, "a@example.com");
    CHECK_STATE(verify_env(&m, "<b@example.com>", NULL), DKIM2_FAIL,
                "FAIL: DKIM2-Signature i=1 MAIL FROM <b@example.com> did not match");
    CHECK_STATE(verify_env(&m, "<a@example.com>", "<x@example.net>"), DKIM2_FAIL,
                "FAIL: DKIM2-Signature i=1 RCPT TO <x@example.net> did not match");
    CHECK_PASS(verify_env(&m, "<a@example.com>", "<list@lists.example.org>"));
    msg_free(&m);

    msg_init(&m, "a@example.com", "test", "Hello\r\n");
    add_mi(&m, NULL);
    add_sig(&m, 1, 1, "example.com", "<a@example.net>", "<l@lists.example.org>", NULL);
    CHECK_STATE(verify(&m), DKIM2_FAIL, "FAIL: DKIM2-Signature i=1 MAIL FROM and d= do not match");
    msg_free(&m);

    msg_init(&m, "a@example.com", "test", "Hello\r\n");
    add_mi(&m, NULL);
    add_sig(&m, 1, 1, "example.com", NULL, NULL, "example.org");
    CHECK_STATE(verify(&m), DKIM2_FAIL, "FAIL: DKIM2-Signature i=1 unexpected nd= tag");
    msg_free(&m);

    base_signed(&m, "a@example.com");
    add_sig(&m, 2, 1, "example.org", "<x@example.org>", "<r@dest.example>", NULL);
    CHECK_STATE(verify(&m), DKIM2_FAIL, "FAIL: DKIM2-Signature i=2 mf= does not match the rt= of i=1");
    msg_free(&m);

    base_signed(&m, "a@example.com");
    add_sig(&m, 2, 1, "other.net", "<>", "<r@dest.example>", NULL);
    CHECK_STATE(verify(&m), DKIM2_FAIL, "FAIL: DKIM2-Signature i=2 d= does not match the rt= of i=1");
    msg_free(&m);

    msg_init(&m, "a@example.com", "test", "Hello\r\n");
    add_mi(&m, NULL);
    add_sig(&m, 1, 1, "example.com", NULL, NULL, "example.org");
    add_sig(&m, 2, 1, "example.net", "<a@example.net>", "<r@dest.example>", NULL);
    CHECK_STATE(verify(&m), DKIM2_FAIL, "FAIL: DKIM2-Signature i=1 nd= does not match");
    msg_free(&m);

    base_signed(&m, "a@elsewhere.net");
    CHECK_STATE(verify(&m), DKIM2_FAIL, "FAIL: DKIM2-Signature i=1 matching From is not authentic");
    msg_free(&m);
}

/* D7: "public key <s> is malformed" (-08 §3.2, §14.5). */
static char g_key_txt[4096];
static char *key_override(const char *qname, int *n_records) {
    (void)qname; (void)n_records;
    return strdup(g_key_txt);
}

static const char *key_error(const char *fmt, const unsigned char *der, size_t len) {
    char b[3072];
    b64_encode(der, len, b, sizeof b);
    snprintf(g_key_txt, sizeof g_key_txt, fmt, b);
    char *(*saved)(const char *, int *) = dkim2_dns_override;
    dkim2_dns_override = key_override;
    dkim2_status_t st;
    const char *err = NULL;
    dkim2_pubkey_t *k = dkim2_dns_getkey("x", "example.com", &st, &err);
    dkim2_dns_override = saved;
    if (k && !k->revoked) { dkim2_pubkey_free(k); return "OK"; }
    dkim2_pubkey_free(k);
    return err ? err : "?";
}

static void test_malformed_keys(void) {
    unsigned char raw[64];
    for (size_t i = 0; i < sizeof raw; i++) raw[i] = (unsigned char)(i * 7 + 1);
    CHECK(strcmp(key_error("v=DKIM1; k=ed25519; p=%s", raw, 32), "OK") == 0);
    CHECK(strcmp(key_error("v=DKIM1; k=ed25519; p=%s", raw, 31), "is malformed") == 0);
    CHECK(strcmp(key_error("v=DKIM1; k=ed25519; p=%s", raw, 33), "is malformed") == 0);
    /* an Ed25519 key published as a DER SubjectPublicKeyInfo */
    {
        unsigned char *der = NULL;
        int n = i2d_PUBKEY(g_priv, &der);
        CHECK(n == 44);
        CHECK(strcmp(key_error("v=DKIM1; k=ed25519; p=%s", der, (size_t)n), "is malformed") == 0);
        OPENSSL_free(der);
    }
    /* RSA: base64 that is no key; a key under 1024 bits; 1024 is fine */
    CHECK(strcmp(key_error("v=DKIM1; k=rsa; p=%s", raw, 48), "is malformed") == 0);
    static const int bits[] = { 512, 1023, 1024, 2048 };
    for (int k = 0; k < 4; k++) {
        EVP_PKEY *rsa = EVP_RSA_gen((unsigned)bits[k]);
        CHECK(rsa != NULL);
        unsigned char *der = NULL;
        int n = i2d_PUBKEY(rsa, &der);
        const char *e = key_error("v=DKIM1; k=rsa; p=%s", der, (size_t)n);
        if (bits[k] < 1024) CHECK(strcmp(e, "is malformed") == 0);
        else CHECK(strcmp(e, "OK") == 0);
        OPENSSL_free(der);
        EVP_PKEY_free(rsa);
    }
    /* p= that is not base64 at all is still a syntax error */
    snprintf(g_key_txt, sizeof g_key_txt, "v=DKIM1; k=ed25519; p=!!!!");
    {
        char *(*saved)(const char *, int *) = dkim2_dns_override;
        dkim2_dns_override = key_override;
        dkim2_status_t st;
        const char *err = NULL;
        dkim2_pubkey_t *k = dkim2_dns_getkey("x", "example.com", &st, &err);
        dkim2_dns_override = saved;
        CHECK(!k && err && strcmp(err, "has a syntax error") == 0);
    }
}

/* The error dkim2_sig_parse_err gives for "<prefix> s=<s>", or "" when it
   parses (sig: the parse, freed by the caller). */
static const char *SIG_PREFIX = "i=1; m=1; t=1; d=ex.example; "
    "mf=PHVzZXJAZXhhbXBsZS5jb20+; rt=PGFAZXhhbXBsZS5jb20+; s=";
static void sig_err(const char *s, char *err, size_t errsz, dkim2_sig_t **sig) {
    char v[16384];
    snprintf(v, sizeof v, "%s%s", SIG_PREFIX, s);
    dkim2_sig_t *p = dkim2_sig_parse_err(v, err, errsz);
    if (p) err[0] = '\0';
    if (sig) *sig = p; else dkim2_sig_free(p);
}

static void mi_err(const char *h, char *err, size_t errsz, dkim2_mi_t **mi) {
    char v[16384];
    snprintf(v, sizeof v, "m=1; h=%s;", h);
    dkim2_mi_t *p = dkim2_mi_parse_err(v, err, errsz);
    if (p) err[0] = '\0';
    if (mi) *mi = p; else dkim2_mi_free(p);
}

/* D2: "|" groups of "," lists in s= and h= (-08 §9.3, §10.9). */
static void test_groups_parse(void) {
    char err[256];
    dkim2_sig_t *sig;
    sig_err("a:ed25519-sha256:AAAA|b:ed25519-sha256:BBBB,c:rsa-sha256:CCCC", err, sizeof err, &sig);
    CHECK(err[0] == '\0' && sig && sig->n_ssets == 3 && sig->n_groups == 2);
    if (sig && sig->n_ssets == 3) {
        CHECK(sig->ssets[0].group == 0 && sig->ssets[1].group == 1 && sig->ssets[2].group == 1);
        CHECK(strcmp(sig->ssets[2].selector, "c") == 0 && strcmp(sig->ssets[2].sig_b64, "CCCC") == 0);
    }
    dkim2_sig_free(sig);
    /* FWS on either side of "|" and "," and inside the value */
    sig_err("a:ed25519-sha256:AA\r\n AA \r\n | b : ed25519-sha256 : BBBB ,\tc:x:CC CC", err, sizeof err, &sig);
    CHECK(err[0] == '\0' && sig && sig->n_ssets == 3 && sig->n_groups == 2);
    if (sig && sig->n_ssets == 3) CHECK(strcmp(sig->ssets[0].sig_b64, "AAAA") == 0 &&
                                        strcmp(sig->ssets[1].selector, "b") == 0);
    dkim2_sig_free(sig);
    /* an empty member, anywhere; a value that is not base64, any algorithm;
       FWS inside a name */
    static const char *bad_s[] = {
        "a:x:AAAA||b:x:AAAA", "|a:x:AAAA", "a:x:AAAA|", "a:x:AAAA,,b:x:AAAA",
        "a:x:AAAA,|b:x:AAAA", ",a:x:AAAA", "a:x:AAAA,", "a:x:", "a:x:!!!!",
        "a:x:AAA", "a:ed25519-sha256:", "a:x:AAAA| ", "a b:x:AAAA", "a:x y:AAAA",
        "a:x:AAAA:BBBB",
    };
    for (size_t k = 0; k < sizeof bad_s / sizeof bad_s[0]; k++) {
        sig_err(bad_s[k], err, sizeof err, NULL);
        if (strcmp(err, "PERMERROR: DKIM2-Signature i=1 syntax error") != 0)
            printf("  (s=%s)\n", bad_s[k]);
        CHECK(strcmp(err, "PERMERROR: DKIM2-Signature i=1 syntax error") == 0);
    }
    /* duplicates across the whole tag, any case */
    sig_err("a:x:AAAA|b:y:AAAA,A:z:AAAA", err, sizeof err, NULL);
    CHECK(strcmp(err, "PERMERROR: DKIM2-Signature i=1 has a duplicate selector") == 0);
    /* any number of one algorithm, up to the local limit of 8 items */
    sig_err("a:x:AAAA,b:x:AAAA,c:x:AAAA,d:x:AAAA|e:x:AAAA,f:x:AAAA,g:x:AAAA,h:x:AAAA", err, sizeof err, NULL);
    CHECK(err[0] == '\0');
    sig_err("a:x:AAAA,b:x:AAAA,c:x:AAAA,d:x:AAAA|e:x:AAAA,f:x:AAAA,g:x:AAAA,h:x:AAAA|i:x:AAAA", err, sizeof err, NULL);
    CHECK(strcmp(err, "PERMERROR: DKIM2-Signature i=1 has more than 8 signatures") == 0);
    /* syntax before duplicate before the limit */
    sig_err("a:x:AAAA,a:x:AAAA,c:x:AAAA,d:x:AAAA,e:x:AAAA,f:x:AAAA,g:x:AAAA,h:x:AAAA,i:x:AAAA", err, sizeof err, NULL);
    CHECK(strcmp(err, "PERMERROR: DKIM2-Signature i=1 has a duplicate selector") == 0);
    sig_err("a:x:AAAA,a:x:AAAA,c:x:AAAA,d:x:AAAA,e:x:AAAA,f:x:AAAA,g:x:AAAA,h:x:AAAA,i:x:", err, sizeof err, NULL);
    CHECK(strcmp(err, "PERMERROR: DKIM2-Signature i=1 syntax error") == 0);
    /* thousands of groups: still one answer, and a bounded one */
    {
        size_t cap = 200000, n = 0;
        char *big = malloc(cap);
        for (int k = 0; k < 5000; k++)
            n += (size_t)snprintf(big + n, cap - n, "%ss%d:x:AAAA", k ? "|" : "", k);
        char *v = malloc(cap + 256);
        snprintf(v, cap + 256, "%s%s", SIG_PREFIX, big);
        dkim2_sig_t *p = dkim2_sig_parse_err(v, err, sizeof err);
        CHECK(!p && strcmp(err, "PERMERROR: DKIM2-Signature i=1 has more than 8 signatures") == 0);
        dkim2_sig_free(p);
        free(v);
        free(big);
    }

    dkim2_mi_t *mi;
    mi_err("sha256:AAAA:BBBB|sha512:CCCC:DDDD,x-hash:EEEE:FFFF", err, sizeof err, &mi);
    CHECK(err[0] == '\0' && mi && mi->n_hsets == 3 && mi->n_groups == 2);
    if (mi && mi->n_hsets == 3)
        CHECK(mi->hsets[0].group == 0 && mi->hsets[1].group == 1 && mi->hsets[2].group == 1 &&
              strcmp(mi->hsets[2].alg, "x-hash") == 0 && strcmp(mi->hsets[2].body_hash, "FFFF") == 0);
    dkim2_mi_free(mi);
    mi_err("sha256:AA\r\n AA:BBBB \r\n |\r\n sha512 :CCCC:DD DD", err, sizeof err, &mi);
    CHECK(err[0] == '\0' && mi && mi->n_hsets == 2 &&
          strcmp(mi->hsets[0].hdr_hash, "AAAA") == 0 && strcmp(mi->hsets[1].body_hash, "DDDD") == 0);
    dkim2_mi_free(mi);
    static const char *bad_h[] = {
        "sha256:AAAA:BBBB||sha512:AAAA:BBBB", "|sha256:AAAA:BBBB", "sha256:AAAA:BBBB,",
        "sha256:AAAA:BBBB,|sha512:AAAA:BBBB", "x-hash:AAAA:", "x-hash::AAAA",
        "x-hash:!!!!:AAAA", "sha256:AAAA:BBB", "sha 256:AAAA:BBBB",
    };
    for (size_t k = 0; k < sizeof bad_h / sizeof bad_h[0]; k++) {
        mi_err(bad_h[k], err, sizeof err, NULL);
        if (strcmp(err, "PERMERROR: Message-Instance m=1 syntax error") != 0)
            printf("  (h=%s)\n", bad_h[k]);
        CHECK(strcmp(err, "PERMERROR: Message-Instance m=1 syntax error") == 0);
    }
    mi_err("sha256:AAAA:BBBB|sha512:AAAA:BBBB,SHA256:AAAA:BBBB", err, sizeof err, NULL);
    CHECK(strcmp(err, "PERMERROR: Message-Instance m=1 has a duplicate hash algorithm") == 0);

    /* formatting keeps the groups */
    sig_err("a:x:AAAA|b:y:BBBB,c:z:CCCC", err, sizeof err, &sig);
    if (sig) {
        char *f = dkim2_sig_format(sig, 1);
        CHECK(f && strstr(f, "s=a:x:|b:y:,c:z:") != NULL);
        free(f);
        f = dkim2_sig_format(sig, 0);
        CHECK(f && strstr(f, "s=a:x:AAAA|b:y:BBBB,c:z:CCCC") != NULL);
        free(f);
    }
    dkim2_sig_free(sig);
    mi_err("sha256:AAAA:BBBB|sha512:CCCC:DDDD,x-hash:EEEE:FFFF", err, sizeof err, &mi);
    if (mi) {
        char *f = dkim2_mi_format(mi);
        CHECK(f && strstr(f, "h=sha256:AAAA:BBBB|sha512:CCCC:DDDD,x-hash:EEEE:FFFF;") != NULL);
        free(f);
    }
    dkim2_mi_free(mi);
}

/* Add a DKIM2-Signature whose s= is spec, written as it goes on the wire
   except that a value "G" is a good Ed25519 signature and "B" a bad one;
   any other value is kept. The signing input blanks every value and keeps
   the rest of s= byte for byte (-08 §12.8). tags: everything before s=. */
static void add_sig_spec(msg_t *m, const char *tags, const char *spec) {
    char tmpl[4096], val[8192];
    size_t tl = (size_t)snprintf(tmpl, sizeof tmpl, "%s; s=", tags);
    int colons = 0;
    for (const char *p = spec; *p && tl < sizeof tmpl - 2; p++) {
        if (*p == ',' || *p == '|') colons = 0;
        else if (*p == ':') colons++;
        else if (colons >= 2) continue;
        tmpl[tl++] = *p;
    }
    tmpl[tl++] = ';';
    tmpl[tl] = '\0';
    char *in = malloc(65536);
    size_t pos = 0;
    canon_chain(m, in, &pos);
    canon_append(in, &pos, "dkim2-signature", tmpl);
    char *good = dkim2_sign(g_priv, "ed25519-sha256", (unsigned char *)in, pos);
    free(in);
    char bad[256];
    snprintf(bad, sizeof bad, "%s", good);
    bad[0] = bad[0] == 'A' ? 'B' : 'A';
    size_t vl = (size_t)snprintf(val, sizeof val, "%s; s=", tags);
    colons = 0;
    for (const char *p = spec; *p; ) {
        if (colons >= 2 && strchr(" \t\r\n", *p)) { val[vl++] = *p++; continue; }
        if (colons >= 2 && *p != ',' && *p != '|') {
            size_t n = strcspn(p, ",|"), core = n;
            while (core && strchr(" \t\r\n", p[core - 1])) core--;
            if (core == 1 && *p == 'G') vl += (size_t)snprintf(val + vl, sizeof val - vl, "%s", good);
            else if (core == 1 && *p == 'B') vl += (size_t)snprintf(val + vl, sizeof val - vl, "%s", bad);
            else vl += (size_t)snprintf(val + vl, sizeof val - vl, "%.*s", (int)core, p);
            vl += (size_t)snprintf(val + vl, sizeof val - vl, "%.*s", (int)(n - core), p + core);
            p += n;
            colons = 0;
            continue;
        }
        if (*p == ',' || *p == '|') colons = 0;
        else if (*p == ':') colons++;
        val[vl++] = *p++;
    }
    snprintf(val + vl, sizeof val - vl, ";");
    free(good);
    msg_add_top(m, "DKIM2-Signature", val);
}

/* i=1 by example.com over m=1 with this s= (add_sig_spec). */
static void signed_with(msg_t *m, const char *spec) {
    msg_init(m, "a@example.com", "test", "Hello\r\nworld\r\n");
    add_mi(m, NULL);
    char tags[512], *mf = b64("<a@example.com>"), *rt = b64("<list@lists.example.org>");
    snprintf(tags, sizeof tags, "i=1; m=1; t=%llu; d=example.com; mf=%s; rt=%s", now(), mf, rt);
    free(mf); free(rt);
    add_sig_spec(m, tags, spec);
}

/* D2: the signing input keeps every "|" and "," (-08 §12.8). */
static void test_groups_signing_input(void) {
    static const char *ok[] = {
        "sel:ed25519-sha256:G",
        "sel:ed25519-sha256:G|sel2:ed25519-sha256:G",
        "sel:ed25519-sha256:G,sel2:ed25519-sha256:G",
        "sel:ed25519-sha256:G \r\n | \r\n sel2 : ed25519-sha256 : G",
    };
    for (size_t k = 0; k < sizeof ok / sizeof ok[0]; k++) {
        msg_t m;
        signed_with(&m, ok[k]);
        dkim2_verify_result_t r = verify(&m);
        if (r.status != DKIM2_OK) printf("  (%s)\n", m.h[0]);
        CHECK_PASS(r);
        msg_free(&m);
    }
}

int main(void) {
    harness_init();

    test_hashed_fields();
    test_strict_lowercase();
    test_recipe_paths();
    test_fail_states();
    test_malformed_keys();
    test_groups_parse();
    test_groups_signing_input();

    harness_done();
    if (g_fail) { printf("test_spec08: %d failure(s)\n", g_fail); return 1; }
    printf("test_spec08: all passed\n");
    return 0;
}
