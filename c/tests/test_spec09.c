/* draft-ietf-dkim-dkim2-spec-09: the implementation contract's E1-E6 and
   E3.4 (docs/superpowers/specs/2026-11-03-dkim2-spec-09-design.md), on
   messages built and signed in memory (spec_harness.h). Domain Policy
   Records come from a dkim2_dns_txt_hook table here, which counts the
   lookups; keys still come from the harness override. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include "../dkim2_internal.h"
#include "../dkim2_sign.h"
#include "../dkim2_verify.h"
#include "../dkim2_header.h"
#include "../dkim2_dns.h"
#include "../dkim2_domain.h"
#include "../dkim2_crypto.h"
#include "../dkim2_hash.h"
#include "../dkim2_message.h"
#include "../base64.h"

#define HARNESS_KEY_PATH "/tmp/dkim2_test_spec09.pem"
#include "spec_harness.h"

/* ---- the record table ---- */

#define MAXREC 4
static struct {
    const char *qname;
    const char *rec[MAXREC];
    int n;
    int temp;               /* answer a temporary failure */
} g_zone[8];
static int g_nzone;
static int g_policy_lookups;
static char *g_big;         /* a record too big for a literal */

static void zone_clear(void) { g_nzone = 0; g_policy_lookups = 0; }

static void zone_add(const char *qname, int temp, const char *r0, const char *r1) {
    g_zone[g_nzone].qname = qname;
    g_zone[g_nzone].temp = temp;
    g_zone[g_nzone].n = 0;
    if (r0) g_zone[g_nzone].rec[g_zone[g_nzone].n++] = r0;
    if (r1) g_zone[g_nzone].rec[g_zone[g_nzone].n++] = r1;
    g_nzone++;
}

/* Policy names: the table is the whole zone (absent: no record). Key
   names: the table if it has them, else on to the harness override. */
static int zone_hook(const char *qname, dkim2_txt_t *out) {
    int policy = strncmp(qname, "_domainkey.", 11) == 0;
    if (policy) g_policy_lookups++;
    for (int i = 0; i < g_nzone; i++) {
        if (strcmp(g_zone[i].qname, qname) != 0) continue;
        if (g_zone[i].temp) return -1;
        for (int k = 0; k < g_zone[i].n; k++)
            if (dkim2_txt_push(out, g_zone[i].rec[k], strlen(g_zone[i].rec[k])) < 0) return -1;
        return 0;
    }
    return policy ? 0 : 1;
}

/* ---- E1 ---- */

static void test_none(void) {
    msg_t m;
    msg_init(&m, "a@example.com", "test", "Hello\r\n");
    dkim2_verify_result_t r = verify(&m);
    CHECK(r.status == DKIM2_NONE);
    CHECK_MSG(r, "NONE: No DKIM2 header fields found");
    CHECK(r.fully_verified == 0);
    msg_free(&m);
}

/* ---- E2 ---- */

/* i=1 by example.com over m=1, then m=2 with this Recipe (and a changed
   body), signed i=2 by example.org. */
static void two_hops(msg_t *m, const char *recipe) {
    base_signed(m, "a@example.com");
    snprintf(m->body, sizeof m->body, "Something else\r\n");
    add_mi(m, recipe);
    add_sig(m, 2, 2, "example.org", "<list-bounces@lists.example.org>", "<r@dest.example>", NULL);
}

static void test_null_recipe(void) {
    msg_t m;
    dkim2_verify_result_t r;

    base_signed(&m, "a@example.com");
    r = verify(&m);
    CHECK_PASS(r);
    CHECK(r.fully_verified == 1);           /* deprecated: true exactly for PASS */
    msg_free(&m);

    two_hops(&m, "{\"b\":null}");
    r = verify(&m);
    CHECK(r.status == DKIM2_PERMERROR);
    CHECK_MSG(r, "PERMERROR: Message-Instance m=2 has a null recipe");
    CHECK(r.fully_verified == 0);
    /* an instance above changes nothing */
    add_mi(&m, NULL);
    add_sig(&m, 3, 3, "dest.example", "<x@dest.example>", "<y@final.example>", NULL);
    CHECK_MSG(verify(&m), "PERMERROR: Message-Instance m=2 has a null recipe");
    msg_free(&m);

    /* at m=1, with nothing below it to check: still a PERMERROR */
    msg_init(&m, "a@example.com", "test", "Hello\r\n");
    add_mi(&m, "{\"b\":null}");
    add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
    CHECK_MSG(verify(&m), "PERMERROR: Message-Instance m=1 has a null recipe");
    msg_free(&m);

    /* two nulls: the lowest m= */
    two_hops(&m, "{\"b\":null}");
    snprintf(m.body, sizeof m.body, "Third body\r\n");
    add_mi(&m, "{\"b\":null}");
    add_sig(&m, 3, 3, "dest.example", "<x@dest.example>", "<y@final.example>", NULL);
    CHECK_MSG(verify(&m), "PERMERROR: Message-Instance m=2 has a null recipe");
    msg_free(&m);

    /* a lower instance's own Recipe fault beats a higher null */
    two_hops(&m, "{\"b\":[{\"c\":[2,1]}]}");
    snprintf(m.body, sizeof m.body, "Third body\r\n");
    add_mi(&m, "{\"b\":null}");
    add_sig(&m, 3, 3, "dest.example", "<x@dest.example>", "<y@final.example>", NULL);
    CHECK_MSG(verify(&m), "PERMERROR: Message-Instance m=2 recipe b[0] is invalid");
    msg_free(&m);

    /* ...and a structure error beats any null */
    two_hops(&m, "{\"b\":null}");
    add_mi(&m, NULL);
    CHECK_MSG(verify(&m), "PERMERROR: Message-Instance m=3 is not signed");
    msg_free(&m);

    /* the signer's own view: an unsigned null above every signature is
       not an error; a signed one still is */
    base_signed(&m, "a@example.com");
    snprintf(m.body, sizeof m.body, "Something else\r\n");
    add_mi(&m, "{\"b\":null}");
    CHECK_PASS(verify_mode(&m, 1));
    {
        char err[512];
        CHECK(lib_sign(&m, "example.com", "<a@example.com>", (char *[]){ "<r@dest.example>", NULL },
                       0, err, sizeof err, NULL, 0) == 0);
        /* once signed, everyone downstream sees the null */
        CHECK_MSG(verify(&m), "PERMERROR: Message-Instance m=2 has a null recipe");
        /* and the next signer refuses it */
        int rc = lib_sign(&m, "dest.example", "<x@dest.example>", (char *[]){ "<y@final.example>", NULL },
                          0, err, sizeof err, NULL, 0);
        CHECK(rc != 0 && strstr(err, "has a null recipe"));
    }
    msg_free(&m);

    /* the deprecated option changes nothing */
    two_hops(&m, "{\"b\":null}");
    {
        dkim2_ctx_t ctx;
        memset(&ctx, 0, sizeof ctx);
        ctx.headers = m.h; ctx.n_headers = m.n;
        ctx.body = m.body; ctx.body_len = strlen(m.body);
        dkim2_body_hash_raw_alg(m.body, ctx.body_len, 0, ctx.body_digests.d[0]);
        dkim2_body_hash_raw_alg(m.body, ctx.body_len, 1, ctx.body_digests.d[1]);
        ctx.mail_from = "<r@dest.example>";
        ctx.rcpt_to = (char *[]){ "<y@final.example>", NULL };
        dkim2_ctx_collect(&ctx);
        dkim2_sign_config_t cfg = { .domain = "dest.example", .selector = "sel",
            .privkey_path = (char *)KEY_PATH, .alg = "ed25519-sha256",
            .allow_null_body_recipe = 1 };
        char *mi = NULL, *sig = NULL;
        CHECK(dkim2_do_sign(&ctx, &cfg, &mi, &sig) != 0);
        CHECK(strstr(ctx.errmsg, "has a null recipe") != NULL);
        free(mi); free(sig);
        dkim2_mi_free(ctx.mi_list); dkim2_sig_free(ctx.sig_list); dkim2_badfield_free(ctx.bad_list);
    }
    msg_free(&m);
}

/* ---- E3 ---- */

/* From a@<from>, signed i=1 by d over m=1 (mf in d). */
static dkim2_verify_result_t from_vs_d(const char *from, const char *d) {
    msg_t m;
    char mf[512];
    snprintf(mf, sizeof mf, "<a@%s>", d);
    msg_init(&m, from, "test", "Hello\r\n");
    add_mi(&m, NULL);
    add_sig(&m, 1, 1, d, mf, "<list@lists.example.org>", NULL);
    dkim2_verify_result_t r = verify(&m);
    msg_free(&m);
    return r;
}

static dkim2_verify_result_t subdomain_with(const char *r0, const char *r1) {
    zone_clear();
    zone_add("_domainkey.parent.example", 0, r0, r1);
    return from_vs_d("a@parent.example", "mail.parent.example");
}

static void test_from_classes(void) {
    zone_clear();
    CHECK_MSG(from_vs_d("a@example.com, b@example.com", "example.com"),
              "FAIL: DKIM2-Signature i=1 From has more than one address");
    CHECK_MSG(from_vs_d("g: a@example.com, b@example.com;", "example.com"),
              "FAIL: DKIM2-Signature i=1 From has more than one address");
    /* a ',' inside a quoted string or a comment is not a list */
    CHECK_PASS(from_vs_d("\"Doe, J\" <a@example.com>", "example.com"));
    CHECK_PASS(from_vs_d("a@example.com (Doe, J)", "example.com"));
    CHECK_MSG(from_vs_d("a@[192.0.2.1]", "example.com"),
              "FAIL: DKIM2-Signature i=1 From uses a domain literal");
    CHECK_MSG(from_vs_d("undisclosed-recipients:;", "example.com"),
              "FAIL: DKIM2-Signature i=1 matching From is not authentic");
    CHECK_MSG(from_vs_d("g: a@example.com;", "example.com"),
              "FAIL: DKIM2-Signature i=1 matching From is not authentic");
    CHECK_MSG(from_vs_d("nobody", "example.com"),
              "FAIL: DKIM2-Signature i=1 matching From is not authentic");
    /* sibling: neither way, no lookup */
    CHECK_MSG(from_vs_d("a@other.parent.example", "mail.parent.example"),
              "FAIL: DKIM2-Signature i=1 matching From is not authentic");
    CHECK(g_policy_lookups == 0);
    /* downward: no lookup */
    CHECK_PASS(from_vs_d("a@sub.example.com", "example.com"));
    CHECK(g_policy_lookups == 0);
    /* two From fields */
    {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        msg_add_bottom(&m, "From", "a@example.com");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
        CHECK_MSG(verify(&m), "FAIL: DKIM2-Signature i=1 From has more than one address");
        msg_free(&m);
    }
    /* classification of a single value */
    char dom[256];
    CHECK(dkim2_from_classify("Bron <brong@Test1.DKIM2.com.>", dom, sizeof dom) == DKIM2_FROM_OK);
    CHECK(strcmp(dom, "test1.dkim2.com") == 0);
    CHECK(dkim2_from_classify("a@b.example, c@d.example", dom, sizeof dom) == DKIM2_FROM_MULTI);
    CHECK(dkim2_from_classify("a@[IPv6:2001:db8::1]", dom, sizeof dom) == DKIM2_FROM_LITERAL);
    CHECK(dkim2_from_classify("g:;", dom, sizeof dom) == DKIM2_FROM_NOT_MAILBOX);
}

static void test_policy(void) {
    static const char *STRICT = "FAIL: DKIM2-Signature i=1 From parent.example forbids subdomain signing";
    /* subdomains authorized */
    CHECK_PASS(subdomain_with(NULL, NULL));
    CHECK(g_policy_lookups == 2);           /* verify() runs both walks */
    CHECK_PASS(subdomain_with("v=DKIM1", NULL));
    CHECK_PASS(subdomain_with("v=DKIM1; f=", NULL));
    CHECK_PASS(subdomain_with("v=DKIM1; f=foo", NULL));
    CHECK_PASS(subdomain_with("v=DKIM1; f=foo-bar:x2", NULL));
    CHECK_PASS(subdomain_with("v=DKIM1; f=Strict", NULL));       /* case-sensitive */
    CHECK_PASS(subdomain_with("v=DKIM1; f=strictly", NULL));
    CHECK_PASS(subdomain_with("v=DKIM1; x=strict; zz=whatever", NULL));
    CHECK_PASS(subdomain_with("v=spf1 -all", "f=strict"));       /* neither starts v=DKIM1 */
    CHECK_PASS(subdomain_with("v=dkim1; f=strict", NULL));
    CHECK_PASS(subdomain_with("f=strict; v=DKIM1", NULL));
    CHECK_PASS(subdomain_with("v=DKIM1 x; f=strict", NULL));
    CHECK_PASS(subdomain_with("v=DKIM1", "v=spf1 -all"));
    /* strict */
    CHECK_MSG(subdomain_with("v=DKIM1; f=strict", NULL), STRICT);
    CHECK(subdomain_with("v=DKIM1; f=strict", NULL).status == DKIM2_FAIL);
    CHECK_MSG(subdomain_with("v=DKIM1; f=foo : strict", NULL), STRICT);
    CHECK_MSG(subdomain_with(" v = DKIM1 ;f=strict\t", NULL), STRICT);
    CHECK_MSG(subdomain_with("v=DKIM1; f=strict:foo;", NULL), STRICT);
    CHECK_MSG(subdomain_with("v=DKIM1; f=strict", "v=spf1 -all"), STRICT);
    /* malformed: fail closed */
    CHECK_MSG(subdomain_with("v=DKIM1; f=foo:", NULL), STRICT);
    CHECK_MSG(subdomain_with("v=DKIM1; f=a::b", NULL), STRICT);
    CHECK_MSG(subdomain_with("v=DKIM1; f=-x", NULL), STRICT);
    CHECK_MSG(subdomain_with("v=DKIM1; f=x-", NULL), STRICT);
    CHECK_MSG(subdomain_with("v=DKIM1; f=a_b", NULL), STRICT);
    CHECK_MSG(subdomain_with("v=DKIM1; f=foo; f=bar", NULL), STRICT);   /* repeated tag */
    CHECK_MSG(subdomain_with("v=DKIM1; garbage", NULL), STRICT);
    CHECK_MSG(subdomain_with("v=DKIM1; n=caf\xc3\xa9", NULL), STRICT);
    /* multiple */
    {
        dkim2_verify_result_t r = subdomain_with("v=DKIM1", "v=DKIM1; f=strict");
        CHECK(r.status == DKIM2_PERMERROR);
        CHECK_MSG(r, "PERMERROR: DKIM2-Signature i=1 multiple records for parent.example policy");
    }
    /* temporary failure */
    zone_clear();
    zone_add("_domainkey.parent.example", 1, NULL, NULL);
    {
        dkim2_verify_result_t r = from_vs_d("a@parent.example", "mail.parent.example");
        CHECK(r.status == DKIM2_TEMPERROR);
        CHECK_MSG(r, "TEMPERROR: DKIM2-Signature i=1 policy for parent.example unavailable");
    }
    /* the name is the A-label, lowercased, no trailing dot */
    zone_clear();
    zone_add("_domainkey.xn--caf-dma.example", 0, "v=DKIM1; f=strict", NULL);
    CHECK_MSG(from_vs_d("a@Caf\xc3\xa9.EXAMPLE.", "mail.xn--caf-dma.example"),
              "FAIL: DKIM2-Signature i=1 From xn--caf-dma.example forbids subdomain signing");
    /* no lookup for a message that already has an error */
    zone_clear();
    zone_add("_domainkey.parent.example", 0, "v=DKIM1; f=strict", NULL);
    {
        msg_t m;
        msg_init(&m, "a@parent.example", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "mail.parent.example", "<a@parent.example.net>", "<l@lists.example.org>", NULL);
        dkim2_verify_result_t r = verify(&m);
        CHECK(r.status == DKIM2_FAIL && strstr(r.message, "mf= and d= do not match"));
        CHECK(g_policy_lookups == 0);
        msg_free(&m);
    }
    /* one lookup per domain per verification: i=1 and i=2 (whose m=2
       names From) both judged against parent.example */
    zone_clear();
    {
        msg_t m;
        msg_init(&m, "a@parent.example", "test", "Hello\r\n");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "mail.parent.example", "<a@mail.parent.example>",
                "<list@lists.parent.example>", NULL);
        add_mi(&m, "{\"h\":{\"from\":[{\"c\":[1,1]}]}}");
        add_sig(&m, 2, 2, "lists.parent.example", "<list@lists.parent.example>",
                "<r@dest.example>", NULL);
        dkim2_verify_result_t r = verify(&m);   /* two walks, so two verifications */
        CHECK_PASS(r);
        CHECK(g_policy_lookups == 2);
        msg_free(&m);
    }
}

/* Linear-time trimming and no fixed buffers: a 60000-byte record. */
static void test_big_records(void) {
    size_t n = 60000;
    g_big = malloc(n + 128);
    int k = snprintf(g_big, 64, "v=DKIM1 ");
    memset(g_big + k, ' ', n);
    snprintf(g_big + k + n, 64, "; f=strict");
    CHECK_MSG(subdomain_with(g_big, NULL),
              "FAIL: DKIM2-Signature i=1 From parent.example forbids subdomain signing");
    snprintf(g_big + k + n, 64, "\t");
    CHECK_PASS(subdomain_with(g_big, NULL));
    CHECK(dkim2_txt_first_tag(g_big, strlen(g_big)) == 1);
    free(g_big);
    g_big = NULL;

    /* many tags: repeats found by sorting, not by a fixed table */
    size_t cap = 200000;
    char *r = malloc(cap);
    size_t pos = (size_t)snprintf(r, cap, "v=DKIM1");
    for (int i = 0; i < 9000; i++) pos += (size_t)snprintf(r + pos, cap - pos, "; t%d=x", i);
    CHECK_PASS(subdomain_with(r, NULL));
    pos += (size_t)snprintf(r + pos, cap - pos, "; t17=y");
    CHECK_MSG(subdomain_with(r, NULL),
              "FAIL: DKIM2-Signature i=1 From parent.example forbids subdomain signing");
    free(r);
}

static void test_first_tag(void) {
    CHECK(dkim2_txt_first_tag("v=DKIM1", 7) == 1);
    CHECK(dkim2_txt_first_tag(" v = DKIM1 ; p=", 15) == 1);
    CHECK(dkim2_txt_first_tag("v=DKIM2; p=x", 12) == 2);
    CHECK(dkim2_txt_first_tag("v=spf1 -all", 11) == 2);
    CHECK(dkim2_txt_first_tag("v=", 2) == 2);
    CHECK(dkim2_txt_first_tag("p=abc; v=DKIM1", 14) == 0);
    CHECK(dkim2_txt_first_tag("vv=DKIM1", 8) == 0);
    CHECK(dkim2_txt_first_tag("garbage", 7) == 0);
    CHECK(dkim2_txt_first_tag("", 0) == 0);
}

/* E3.4: the signer accepts the upward match the policy allows. */
static void test_signer_policy(void) {
    char err[512];
    static char *rcpt[] = { "<r@dest.example>", NULL };
    msg_t m;

    zone_clear();
    msg_init(&m, "a@parent.example", "test", "Hello\r\n");
    CHECK(lib_sign(&m, "mail.parent.example", "<a@mail.parent.example>", rcpt, 0,
                   err, sizeof err, NULL, 0) == 0);
    CHECK(g_policy_lookups == 1);
    msg_free(&m);

    zone_clear();
    msg_init(&m, "a@sub.example.com", "test", "Hello\r\n");
    CHECK(lib_sign(&m, "example.com", "<a@example.com>", rcpt, 0, err, sizeof err, NULL, 0) == 0);
    CHECK(g_policy_lookups == 0);                       /* downward: no lookup */
    msg_free(&m);

    static const struct { const char *r0, *r1; int temp; const char *why; } refuse[] = {
        { "v=DKIM1; f=strict", NULL, 0, ": From parent.example forbids subdomain signing" },
        { "v=DKIM1; f=a::b", NULL, 0, ": From parent.example forbids subdomain signing" },
        { "v=DKIM1", "v=DKIM1", 0, ": multiple records for parent.example policy" },
        { NULL, NULL, 1, ": policy for parent.example unavailable" },
    };
    for (size_t k = 0; k < sizeof refuse / sizeof *refuse; k++) {
        zone_clear();
        zone_add("_domainkey.parent.example", refuse[k].temp, refuse[k].r0, refuse[k].r1);
        msg_init(&m, "a@parent.example", "test", "Hello\r\n");
        int rc = lib_sign(&m, "mail.parent.example", "<a@mail.parent.example>", rcpt, 0,
                          err, sizeof err, NULL, 0);
        char want[256];
        snprintf(want, sizeof want,
                 "not signing: From header field is not Authentic for d=mail.parent.example%s",
                 refuse[k].why);
        CHECK(rc != 0);
        if (strcmp(err, want) != 0) {
            printf("FAIL %s:%d: got \"%s\", want \"%s\"\n", __FILE__, __LINE__, err, want);
            g_fail++;
        }
        msg_free(&m);
    }

    /* anything else keeps the old text, with no reason after it */
    zone_clear();
    msg_init(&m, "a@other.example", "test", "Hello\r\n");
    CHECK(lib_sign(&m, "mail.parent.example", "<a@mail.parent.example>", rcpt, 0,
                   err, sizeof err, NULL, 0) != 0);
    CHECK(strcmp(err, "not signing: From header field is not Authentic for d=mail.parent.example") == 0);
    CHECK(g_policy_lookups == 0);
    msg_free(&m);
}

/* ---- E4 ---- */

static const char *key_err(const char *r0, const char *r1) {
    zone_clear();
    zone_add("k._domainkey.keys.example", 0, r0, r1);
    dkim2_status_t st = DKIM2_OK;
    const char *err = NULL;
    dkim2_pubkey_t *k = dkim2_dns_getkey("k", "keys.example", &st, &err);
    const char *out = k && st == DKIM2_OK ? "OK" : err ? err : "?";
    dkim2_pubkey_free(k);
    return out;
}

static void test_key_records(void) {
    static const char *good = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    static const char *bare = "k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    CHECK(strcmp(key_err(good, NULL), "OK") == 0);
    CHECK(strcmp(key_err(good, "v=spf1 -all"), "OK") == 0);
    CHECK(strcmp(key_err("v=DKIM2; p=abcd", good), "OK") == 0);
    CHECK(strcmp(key_err(bare, "v=spf1 -all"), "OK") == 0);        /* no v= is kept */
    CHECK(strcmp(key_err(good, good), "has multiple records") == 0);
    CHECK(strcmp(key_err(good, bare), "has multiple records") == 0);
    CHECK(strcmp(key_err(good, "garbage"), "has multiple records") == 0);  /* unparseable is kept */
    CHECK(strcmp(key_err("garbage", "v=spf1"), "has a syntax error") == 0);
    CHECK(strcmp(key_err("v=spf1 -all", NULL), "does not exist") == 0);
    CHECK(strcmp(key_err(NULL, NULL), "does not exist") == 0);
}

/* ---- E5 ---- */

static void test_rsa_short(void) {
    EVP_PKEY *rsa = EVP_RSA_gen(768);
    unsigned char *der = NULL;
    int n = i2d_PUBKEY(rsa, &der);
    char b[2048], rec[2100];
    b64_encode(der, (size_t)n, b, sizeof b);
    snprintf(rec, sizeof rec, "v=DKIM1; k=rsa; p=%s", b);
    CHECK(strcmp(key_err(rec, NULL), "too short") == 0);
    OPENSSL_free(der);
    EVP_PKEY_free(rsa);
}

/* ---- E6 ---- */

static void test_strings(void) {
    msg_t m;
    zone_clear();

    /* i=1 with "exploded" in f= */
    msg_init(&m, "a@example.com", "test", "Hello\r\n");
    add_mi(&m, NULL);
    add_sig_t(&m, 1, 1, now(), "example.com", "<a@example.com>", "<l@lists.example.org>", NULL,
              "exploded");
    CHECK_MSG(verify(&m), "PERMERROR: DKIM2-Signature i=1 has an exploded flag");
    msg_free(&m);
    msg_init(&m, "a@example.com", "test", "Hello\r\n");
    add_mi(&m, NULL);
    add_sig_t(&m, 1, 1, now(), "example.com", "<a@example.com>", "<l@lists.example.org>", NULL,
              "feedback , exploded");
    CHECK_MSG(verify(&m), "PERMERROR: DKIM2-Signature i=1 has an exploded flag");
    msg_free(&m);
    /* a flag that only looks like it */
    msg_init(&m, "a@example.com", "test", "Hello\r\n");
    add_mi(&m, NULL);
    add_sig_t(&m, 1, 1, now(), "example.com", "<a@example.com>", "<l@lists.example.org>", NULL,
              "exploded2");
    CHECK_PASS(verify(&m));
    /* above i=1 it is fine */
    add_mi(&m, NULL);
    add_sig_t(&m, 2, 2, now(), "lists.example.org", "<l@lists.example.org>", "<r@dest.example>",
              NULL, "exploded");
    CHECK_PASS(verify(&m));
    msg_free(&m);

    /* order: after the tag checks, before the duplicate Selector */
    char err[256];
    dkim2_sig_t *s = dkim2_sig_parse_err("i=1; m=1; t=1; d=e.example; mf=PGFAZS5leGFtcGxlPg==; "
        "rt=PGJAZS5leGFtcGxlPg==; f=exploded; s=a:ed25519-sha256:AA==,a:ed25519-sha256:AA==;",
        err, sizeof err);
    CHECK(!s && strcmp(err, "PERMERROR: DKIM2-Signature i=1 has an exploded flag") == 0);
    s = dkim2_sig_parse_err("i=1; m=1; t=1; d=e.example; mf=PGFAZS5leGFtcGxlPg==; "
        "f=exploded; s=a:ed25519-sha256:AA==;", err, sizeof err);
    CHECK(!s && strcmp(err, "PERMERROR: DKIM2-Signature i=1 tag=rt missing") == 0);

    /* duplicates */
    msg_init(&m, "a@example.com", "test", "Hello\r\n");
    add_mi(&m, NULL);
    msg_add_top(&m, "Message-Instance", "m=1; h=sha256:AA==:AA==;");
    add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<l@lists.example.org>", NULL);
    CHECK_MSG(verify(&m), "PERMERROR: Message-Instance m=1 is duplicated");
    msg_free(&m);
    base_signed(&m, "a@example.com");
    add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<l@lists.example.org>", NULL);
    CHECK_MSG(verify(&m), "PERMERROR: DKIM2-Signature i=1 is duplicated");
    msg_free(&m);

    /* recipe, lower case; mf= */
    CHECK_MSG(recipe_at_m2("{\"b\":[{\"c\":[1,1]},{\"c\":[1,1]}]}"),
              "PERMERROR: Message-Instance m=2 recipe b[1] is invalid");
    msg_init(&m, "a@example.com", "test", "Hello\r\n");
    add_mi(&m, NULL);
    add_sig(&m, 1, 1, "example.com", "<a@example.net>", "<l@lists.example.org>", NULL);
    CHECK_MSG(verify(&m), "FAIL: DKIM2-Signature i=1 mf= and d= do not match");
    msg_free(&m);
}

int main(void) {
    harness_init();
    dkim2_dns_txt_hook = zone_hook;

    test_none();
    test_null_recipe();
    test_from_classes();
    test_policy();
    test_big_records();
    test_first_tag();
    test_signer_policy();
    test_key_records();
    test_rsa_short();
    test_strings();

    dkim2_dns_txt_hook = NULL;
    harness_done();
    if (g_fail) { printf("test_spec09: %d failure(s)\n", g_fail); return 1; }
    printf("test_spec09: all passed\n");
    return 0;
}
