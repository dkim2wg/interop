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

#include "spec_harness.h"

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
    /* -08 (contract D6): one bad step is "Recipe <path> is invalid" */
    /* U3: non-zero pad bits */
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{\"u\":[\"QR==\"]}]}"); CHECK_MSG(r, "PERMERROR: Message-Instance m=2 Recipe b[1] is invalid"); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{\"u\":[\"QUJ=\"]}]}"); CHECK_MSG(r, "PERMERROR: Message-Instance m=2 Recipe b[1] is invalid"); }
    /* U4: the old "b" step key, two keys in a step, no key */
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{\"b\":[\"eA==\"]}]}"); CHECK_MSG(r, "PERMERROR: Message-Instance m=2 Recipe b[1] is invalid"); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,1],\"d\":[\"x\"]}]}"); CHECK_MSG(r, "PERMERROR: Message-Instance m=2 Recipe b[0] is invalid"); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{}]}"); CHECK_MSG(r, "PERMERROR: Message-Instance m=2 Recipe b[1] is invalid"); }
    /* U5: decoded CR; "h":{}; neither h nor b */
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{\"u\":[\"YQ1i\"]}]}"); CHECK_MSG(r, "PERMERROR: Message-Instance m=2 Recipe b[1] is invalid"); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"h\":{}}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"x\":1}"); CHECK_MSG(r, INVALID_JSON_M2); }
    /* and other schema violations: a non-UTF-8 "d" string, an empty array,
       a non-string literal, a non-array header Recipe, a non-object step */
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{\"d\":[\"caf\xe9\"]}]}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{\"d\":[]}]}"); CHECK_MSG(r, "PERMERROR: Message-Instance m=2 Recipe b[1] is invalid"); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,2]},{\"d\":[1]}]}"); CHECK_MSG(r, "PERMERROR: Message-Instance m=2 Recipe b[1] is invalid"); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"h\":{\"subject\":null}}"); CHECK_MSG(r, "PERMERROR: Message-Instance m=2 Recipe h.subject is invalid"); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[[1,2]]}"); CHECK_MSG(r, "PERMERROR: Message-Instance m=2 Recipe b[0] is invalid"); }
    { dkim2_verify_result_t r = recipe_at_m2("[1]"); CHECK_MSG(r, INVALID_JSON_M2); }
    /* a valid "u" (canonical, zero pad bits) still applies: a no-op body
       change whose literal is the same line keeps the hash */
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"u\":[\"SGVsbG8=\"]},{\"c\":[2,2]}]}"); CHECK_PASS(r); }
}

static void test_json_keys(void) {
    /* K1/K2 (-07 decision 2, any case) are reversed by -08 (contract D10):
       keys are strictly lowercase; see test_spec08.c. */
    /* the signer emits lowercase keys */
    {
        char *cur[] = { "Subject: x\r\n" };
        char *prev[] = { "Subject: y\r\n" };
        char *r = dkim2_gen_header_recipe("SUBJECT", cur, 1, prev, 1);
        CHECK(r && strstr(r, "\"subject\"") != NULL && strstr(r, "SUBJECT") == NULL);
        free(r);
    }
}

/* An instance with no r= (-07 §9: r= is optional; §12.1) records no
   change: the state below it is the same message. */
static void test_no_recipe(void) {
    {
        msg_t m;
        base_signed(&m, "a@example.com");
        add_mi(&m, NULL);
        add_sig(&m, 2, 2, "example.org", "<l@lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    {   /* a change the missing Recipe does not record: a hash mismatch */
        msg_t m;
        base_signed(&m, "a@example.com");
        msg_set(&m, "Subject", "[list] test");
        add_mi(&m, NULL);
        add_sig(&m, 2, 2, "example.org", "<l@lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "FAIL: Message-Instance m=1 header hash sha256 mismatch");
        msg_free(&m);
    }
    {
        msg_t m;
        base_signed(&m, "a@example.com");
        snprintf(m.body, sizeof m.body, "Hello\r\nworld\r\nfooter\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 2, 2, "example.org", "<l@lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "FAIL: Message-Instance m=1 body hash sha256 mismatch");
        msg_free(&m);
    }
}

/* The signer, chained and with many recipients. */
static void test_sign_chain(void) {
    char err[512], sig[4096];
    /* A third hop signed over two instances and two signatures verifies:
       the signing input takes the existing fields in ascending m= and i=
       order (-07 §12.8), which the signer once got backwards. */
    {
        char *r1[] = { "<list@lists.example.org>", NULL };
        char *r2[] = { "<b@example.net>", NULL };
        char *r3[] = { "<c@dest.example>", NULL };
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        CHECK(lib_sign(&m, "example.com", "<a@example.com>", r1, 0, err, sizeof err, NULL, 0) == 0);
        msg_set(&m, "Subject", "[list] test");
        add_mi(&m, "{\"h\":{\"subject\":[{\"d\":[\"test\"]}]}}");
        CHECK(lib_sign(&m, "example.org", "<l@lists.example.org>", r2, 0, err, sizeof err, NULL, 0) == 0);
        msg_set(&m, "Subject", "Fwd: [list] test");
        add_mi(&m, "{\"h\":{\"subject\":[{\"d\":[\"[list] test\"]}]}}");
        CHECK(lib_sign(&m, "example.net", "<f@example.net>", r3, 0, err, sizeof err, NULL, 0) == 0);
        if (err[0]) fprintf(stderr, "  sign: %s\n", err);
        CHECK(count_fields(&m, "Message-Instance") == 3);
        CHECK(count_fields(&m, "DKIM2-Signature") == 3);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    /* 300 recipients with long addresses: rt= holds every one (it used to
       be built in a fixed 4096-byte buffer with no bounds check). 900 takes
       the signing input past 64KB, where build_sign_input used to drop the
       new signature's own field and sign without it. */
    for (int round = 0; round < 2; round++) {
        const int N = round ? 900 : 300;
        static char addrs[900][96];
        static char *rcpts[901];
        for (int i = 0; i < N; i++) {
            snprintf(addrs[i], sizeof addrs[i],
                     "<recipient-%03d-with-a-rather-long-local-part@dest.example>", i);
            rcpts[i] = addrs[i];
        }
        rcpts[N] = NULL;
        static char bigsig[262144];
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        CHECK(lib_sign(&m, "example.com", "<a@example.com>", rcpts, 0, err, sizeof err,
                       bigsig, sizeof bigsig) == 0);
        dkim2_sig_t *s = dkim2_sig_parse(bigsig);
        int n = 0;
        for (; s && s->rt && s->rt[n]; n++) ;
        CHECK(n == N);
        CHECK(s && s->rt && strcmp(s->rt[N - 1], addrs[N - 1]) == 0);
        dkim2_sig_free(s);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
        (void)sig;
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
    {   /* display text with no angle brackets is not one mailbox (final
           review T3): all five implementations agree */
        msg_t m;
        base_signed(&m, "A a@example.com");
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
        add_mi(&m, "{\"h\":{\"from\":[{\"d\":[\"a@elsewhere.net\"]}]}}");
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
    /* Ruling 19: an author's From in an unsigned ingress m=1, rewritten by
       the list in m=2 before it signed i=1 over m=2, is never checked */
    {
        msg_t m;
        msg_init(&m, "a@elsewhere.net", "test", "Hello\r\nworld\r\n");
        add_mi(&m, NULL);
        msg_set(&m, "From", "list@lists.example.org");
        add_mi(&m, "{\"h\":{\"from\":[{\"d\":[\"a@elsewhere.net\"]}]}}");
        add_sig(&m, 1, 2, "example.org", "<list-bounces@lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_PASS(res);
        msg_free(&m);
    }
    {   /* ... but the From at state m(i=1) is */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\nworld\r\n");
        add_mi(&m, NULL);
        msg_set(&m, "Subject", "[list] test");
        add_mi(&m, "{\"h\":{\"subject\":[{\"d\":[\"test\"]}]}}");
        add_sig(&m, 1, 2, "example.org", "<list-bounces@lists.example.org>", "<r@dest.example>", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 matching From is not authentic");
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

/* i=<i> over m=<mi_m> by d, mf/rt raw paths, made at t; bad corrupts the
   signature value. */
static void add_sig_bad(msg_t *m, int i, int mi_m, unsigned long long t, const char *d,
                        const char *mf, const char *rt, unsigned bad) {
    char *emf = b64(mf), *ert = b64(rt), tags[2048];
    snprintf(tags, sizeof tags, "i=%d; m=%d; t=%llu; d=%s; mf=%s; rt=%s", i, mi_m, t, d, emf, ert);
    free(emf);
    free(ert);
    add_sig_raw(m, tags, 1, bad);
}

/* Contract C9: the primary error is the first in -07 §14 section order,
   the lowest i= first within a section. */
static void test_check_order(void) {
    unsigned long long old = now() - 15 * 86400;
    {   /* §14.7 before §14.8: From changed after signing */
        msg_t m;
        base_signed(&m, "A <a@example.com>");
        msg_set(&m, "From", "a@evil.example");
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "FAIL: Message-Instance m=1 header hash sha256 mismatch");
        CHECK(res.status == DKIM2_FAIL);
        msg_free(&m);
    }
    {   /* within §14.7: header hash before body hash, as the other four do */
        msg_t m;
        base_signed(&m, "A <a@example.com>");
        msg_set(&m, "Subject", "tampered");
        snprintf(m.body, sizeof m.body, "tampered body\r\n");
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "FAIL: Message-Instance m=1 header hash sha256 mismatch");
        CHECK(res.status == DKIM2_FAIL);
        msg_free(&m);
    }
    {   /* §14.3 before §14.4: expired, and mf= not under d= */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig_t(&m, 1, 1, old, "example.com", "<a@example.net>", "<list@lists.example.org>", NULL, NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 signature expired");
        msg_free(&m);
    }
    {   /* §14.3 before §14.4: expired, and a top nd= */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig_t(&m, 1, 1, old, "example.com", NULL, NULL, "fwd.example.net", NULL);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 signature expired");
        msg_free(&m);
    }
    {   /* §14.4 before §14.6: mf= not under d=, and a bad signature */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig_bad(&m, 1, 1, now(), "example.com", "<a@example.net>", "<list@lists.example.org>", 1);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 MAIL FROM and d= do not match");
        msg_free(&m);
    }
    {   /* §14.7 before §14.6: Subject changed, and a bad signature (a
           failing walk is primary whatever is wrong with the signatures) */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig_bad(&m, 1, 1, now(), "example.com", "<a@example.com>", "<list@lists.example.org>", 1);
        msg_set(&m, "Subject", "tampered");
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "FAIL: Message-Instance m=1 header hash sha256 mismatch");
        CHECK(res.status == DKIM2_FAIL);
        msg_free(&m);
    }
    {   /* lowest i= first within §14.6: both signatures bad */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig_bad(&m, 1, 1, now(), "example.com", "<a@example.com>", "<list@lists.example.org>", 1);
        add_sig_bad(&m, 2, 1, now(), "example.org", "<list@lists.example.org>", "<b@example.net>", 1);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "FAIL: DKIM2-Signature i=1 selector sel incorrect signature");
        msg_free(&m);
    }

    /* §14.2 structure, a..h, before any content (contract C9). */
    static const char MI1[] = "m=1; h=sha256:AAAA:AAAA", MI2[] = "m=2; h=sha256:AAAA:AAAA";
    static const char SIG1[] = "i=1; m=1; t=1; d=example.com; mf=PGE+; rt=PGE+; s=sel:ed25519-sha256:AAAA";
    static const char SIG2[] = "i=2; m=1; t=1; d=example.com; mf=PGE+; rt=PGE+; s=sel:ed25519-sha256:AAAA";
    {   /* c: a number given twice is reported by its lowest value */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        msg_add_top(&m, "Message-Instance", MI2);
        msg_add_top(&m, "Message-Instance", MI2);
        msg_add_top(&m, "Message-Instance", MI1);
        msg_add_top(&m, "Message-Instance", MI1);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: Message-Instance m=1 appears more than once");
        /* b before c: an instance with no m= at all */
        msg_add_top(&m, "Message-Instance", "h=sha256:AAAA:AAAA");
        res = verify(&m);
        CHECK_MSG(res, "PERMERROR: Message-Instance m= tag=m missing");
        msg_free(&m);
    }
    {   /* c before d, d before e, e before f..h */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        msg_add_top(&m, "DKIM2-Signature", SIG2);
        msg_add_top(&m, "DKIM2-Signature", SIG2);
        msg_add_top(&m, "DKIM2-Signature", SIG1);
        msg_add_top(&m, "DKIM2-Signature", SIG1);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 appears more than once");
        msg_add_top(&m, "DKIM2-Signature", "m=1; t=1; d=example.com");
        res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i= tag=i missing");
        msg_add_top(&m, "Message-Instance", MI1);
        msg_add_top(&m, "Message-Instance", MI1);
        res = verify(&m);
        CHECK_MSG(res, "PERMERROR: Message-Instance m=1 appears more than once");
        msg_free(&m);
    }
    {   /* f before g before h: m=1 missing under a signed m=2 with i= gaps;
           then the top instance unsigned; then the lowest i= gap */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        msg_add_top(&m, "Message-Instance", MI2);
        msg_add_top(&m, "DKIM2-Signature", SIG2);
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: Message-Instance m=1 missing");
        msg_add_top(&m, "Message-Instance", MI1);
        res = verify(&m);
        CHECK_MSG(res, "PERMERROR: Message-Instance m=2 is not signed");
        msg_free(&m);
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        msg_add_top(&m, "Message-Instance", MI1);
        msg_add_top(&m, "DKIM2-Signature", SIG2);
        res = verify(&m);
        CHECK_MSG(res, "PERMERROR: DKIM2-Signature i=1 missing");
        msg_free(&m);
    }
    {   /* a: more than 32 fields of a kind, parsed or not, before all
           else; Message-Instance first */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        for (int k = 0; k < 33; k++) {
            msg_add_top(&m, "DKIM2-Signature", k ? SIG1 : "junk");
            msg_add_top(&m, "Message-Instance", k ? MI1 : "junk");
        }
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: more than 32 Message-Instance fields");
        msg_free(&m);
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        msg_add_top(&m, "Message-Instance", MI1);
        for (int k = 0; k < 33; k++) msg_add_top(&m, "DKIM2-Signature", SIG1);
        res = verify(&m);
        CHECK_MSG(res, "PERMERROR: more than 32 DKIM2-Signature fields");
        msg_free(&m);
    }
    {   /* g: signed means covered by any signature's m=, not only the top
           one's: i=1 m=1, i=2 m=2, i=3 m=1 leaves m=2 signed */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        msg_add_top(&m, "Message-Instance", MI1);
        msg_add_top(&m, "Message-Instance", MI2);
        msg_add_top(&m, "DKIM2-Signature", SIG1);
        msg_add_top(&m, "DKIM2-Signature",
            "i=2; m=2; t=1; d=example.com; mf=PGE+; rt=PGE+; s=sel:ed25519-sha256:AAAA");
        msg_add_top(&m, "DKIM2-Signature",
            "i=3; m=1; t=1; d=example.com; mf=PGE+; rt=PGE+; s=sel:ed25519-sha256:AAAA");
        dkim2_verify_result_t res = verify(&m);
        CHECK(strstr(res.message, "is not signed") == NULL);
        CHECK_MSG(res, "FAIL: Message-Instance m=2 header hash sha256 mismatch");
        msg_free(&m);
    }
    {   /* content: Message-Instances by ascending m=, whatever the order
           of the fields; then the walk, then the signatures' content */
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        msg_add_top(&m, "Message-Instance", "m=1; h=sha256:AAAA:AAAA; h=sha256:AAAA:AAAA");
        msg_add_top(&m, "Message-Instance", "m=2; h=sha256:AAAA:AAAA,sha256:BBBB:BBBB");
        msg_add_top(&m, "DKIM2-Signature",
            "i=1; m=2; t=1; d=example.com; mf=PGE+; rt=PGE+; s=sel:ed25519-sha256:AAAA,sel:ed25519-sha256:AAAA");
        dkim2_verify_result_t res = verify(&m);
        CHECK_MSG(res, "PERMERROR: Message-Instance m=1 syntax error");
        msg_free(&m);
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        msg_add_top(&m, "Message-Instance", MI1);
        msg_add_top(&m, "DKIM2-Signature",
            "i=1; m=1; t=1; d=example.com; mf=PGE+; rt=PGE+; s=sel:ed25519-sha256:AAAA,sel:ed25519-sha256:AAAA");
        res = verify(&m);
        CHECK_MSG(res, "FAIL: Message-Instance m=1 header hash sha256 mismatch");
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
        /* Structure before content (contract C9): unsigned first... */
        CHECK_MSG(res, "PERMERROR: Message-Instance m=1 is not signed");
        /* ...and once signed, the instance's own content. */
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
        res = verify(&m);
        CHECK_MSG(res, "PERMERROR: Message-Instance m=1 tag=h missing");
        msg_free(&m);
    }
    /* every Recipe error is "contains invalid JSON", including a copy past
       the end of the body or of a header field's instances */
    { dkim2_verify_result_t r = recipe_at_m2("{\"b\":[{\"c\":[1,9]}]}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"h\":{\"subject\":[{\"c\":[1,2]}]}}"); CHECK_MSG(r, INVALID_JSON_M2); }
    { dkim2_verify_result_t r = recipe_at_m2("{\"h\":{\"cc\":[{\"c\":[1,1]}]}}"); CHECK_MSG(r, INVALID_JSON_M2); }
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
    /* tag-name case: -08 reverses -07 decision 2 (test_spec08.c) */
    CHECK(dkim2_mi_parse("m=1;; h=sha256:AAAA:AAAA") == NULL);
}

int main(void) {
    harness_init();

    test_u_steps();
    test_json_keys();
    test_no_recipe();
    test_sign_chain();
    test_flags();
    test_custody();
    test_from_authentic();
    test_signer_gate();
    test_timestamps();
    test_error_strings();
    test_check_order();
    test_tag_lists();

    harness_done();
    if (g_fail) { printf("test_spec07: %d failure(s)\n", g_fail); return 1; }
    printf("test_spec07: all passed\n");
    return 0;
}
