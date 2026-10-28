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

int main(void) {
    harness_init();

    test_hashed_fields();
    test_strict_lowercase();
    test_recipe_paths();

    harness_done();
    if (g_fail) { printf("test_spec08: %d failure(s)\n", g_fail); return 1; }
    printf("test_spec08: all passed\n");
    return 0;
}
