/* Verifier strictness (docs/superpowers/specs/2026-10-09-verifier-strictness-
 * review-fixes.md), end to end through dkim2_verify_message():
 *   A. signature algorithms  (spec-06 §3.4, §8.9)
 *   B. key-record errors as reported by the verifier (spec-06 §11.5)
 *   C. Message-Instance tag case and repeats (spec-06 §7)
 *   D. t= syntax (spec-06 §8.4, §11.2)
 * Key-record parsing itself is covered in test_dns.c.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "../dkim2_internal.h"
#include "../dkim2_sign.h"
#include "../dkim2_verify.h"
#include "../dkim2_header.h"
#include "../dkim2_dns.h"
#include "../dkim2_crypto.h"
#include "../dkim2_message.h"
#include "../base64.h"

#define ED_PEM  "/tmp/dkim2_strict_ed.pem"
#define RSA_PEM "/tmp/dkim2_strict_rsa.pem"
#define EML     "/tmp/dkim2_strict.eml"
/* Two 40-character labels + .example.com (behaviour spec F.5). */
#define LONG_DOMAIN "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.example.com"

static const char *MAIL_FROM = "<sender@example.com>";
static char *RCPTS[] = { "<rcpt@example.org>", NULL };
static const char *HEADERS[] = {
    "From: sender@example.com\r\n",
    "To: rcpt@example.org\r\n",
    "Subject: strictness\r\n",
};
static const char *BODY = "Hello, strict world!\r\n";

/* ---- DNS: a small table of selector -> TXT, counting every lookup ---- */
static struct { const char *sel; char txt[2048]; } g_keys[8];
static int g_nkeys;
static int g_lookups;

static void set_key(const char *sel, const char *fmt, const char *b64) {
    for (int i = 0; i < g_nkeys; i++)
        if (strcmp(g_keys[i].sel, sel) == 0) {
            snprintf(g_keys[i].txt, sizeof g_keys[i].txt, fmt, b64);
            return;
        }
    g_keys[g_nkeys].sel = sel;
    snprintf(g_keys[g_nkeys].txt, sizeof g_keys[g_nkeys].txt, fmt, b64);
    g_nkeys++;
}

static char *fake_dns(const char *qname, int *n_records) {
    g_lookups++;
    if (strncmp(qname, "tempfail.", 9) == 0) { *n_records = -1; return NULL; }
    char want[256];
    for (int i = 0; i < g_nkeys; i++) {
        snprintf(want, sizeof want, "%s._domainkey.example.com", g_keys[i].sel);
        if (strcmp(qname, want) == 0) return strdup(g_keys[i].txt);
        snprintf(want, sizeof want, "%s._domainkey.%s", g_keys[i].sel, LONG_DOMAIN);
        if (strcmp(qname, want) == 0) return strdup(g_keys[i].txt);
    }
    /* Never fall through to live DNS from a unit test: anything else is
       absent (NXDOMAIN). */
    *n_records = 0;
    return NULL;
}

static char g_ed_b64[128], g_rsa_b64[1024];
static EVP_PKEY *g_ed, *g_rsa;

static void make_keys(void) {
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    assert(c && EVP_PKEY_keygen_init(c) == 1 && EVP_PKEY_keygen(c, &g_ed) == 1);
    EVP_PKEY_CTX_free(c);
    unsigned char raw[32]; size_t rl = sizeof raw;
    EVP_PKEY_get_raw_public_key(g_ed, raw, &rl);
    b64_encode(raw, rl, g_ed_b64, sizeof g_ed_b64);

    c = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    assert(c && EVP_PKEY_keygen_init(c) == 1);
    EVP_PKEY_CTX_set_rsa_keygen_bits(c, 2048);
    assert(EVP_PKEY_keygen(c, &g_rsa) == 1);
    EVP_PKEY_CTX_free(c);
    unsigned char *der = NULL;
    int dl = i2d_PUBKEY(g_rsa, &der);
    b64_encode(der, (size_t)dl, g_rsa_b64, sizeof g_rsa_b64);
    OPENSSL_free(der);

    FILE *f = fopen(ED_PEM, "w");  PEM_write_PrivateKey(f, g_ed, NULL, NULL, 0, NULL, NULL);  fclose(f);
    f = fopen(RSA_PEM, "w");       PEM_write_PrivateKey(f, g_rsa, NULL, NULL, 0, NULL, NULL); fclose(f);
}

/* A correctly hashed, signer-made Message-Instance value for the message. */
static char *good_mi(void) {
    dkim2_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.headers = (char **)HEADERS;
    ctx.n_headers = 3;
    dkim2_body_hash_raw(BODY, strlen(BODY), ctx.body_digests.d[0]);
    ctx.mail_from = (char *)MAIL_FROM;
    ctx.rcpt_to = RCPTS;
    dkim2_sign_config_t cfg = { .domain = "example.com", .selector = "ed",
        .privkey_path = ED_PEM, .alg = "ed25519-sha256" };
    char *mi = NULL, *sig = NULL;
    assert(dkim2_do_sign(&ctx, &cfg, &mi, &sig) == 0);
    free(sig);
    return mi;
}

/* The verifier's §9.6 canonicalization: lowercase name, value with all WSP
   removed, CRLF. */
static void canon_append(char *buf, size_t *pos, const char *name, const char *value) {
    for (const char *h = name; *h; h++) buf[(*pos)++] = (char)tolower((unsigned char)*h);
    buf[(*pos)++] = ':';
    for (const char *h = value; *h; h++)
        if (!(*h == ' ' || *h == '\t' || *h == '\r' || *h == '\n')) buf[(*pos)++] = *h;
    buf[(*pos)++] = '\r'; buf[(*pos)++] = '\n';
}

/* One s= item: sel:alg:<value>. key != NULL: the value is a real signature
   over the signing input made with key (sign_alg names how to sign);
   otherwise lit is written verbatim. */
typedef struct { const char *sel, *alg; EVP_PKEY *key; const char *sign_alg; const char *lit; } item_t;

/* Build and sign "i=1; m=1; t=<t>; d=example.com; mf=..; rt=..; <g_sig_extra>s=<items>;"
   over mi_val. Returns a malloc'd header value. */
static const char *g_sig_extra = "";
static char *make_sig(const char *mi_val, const char *t, const item_t *items, int n) {
    char mf[128], rt[128];
    b64_encode((const unsigned char *)MAIL_FROM, strlen(MAIL_FROM), mf, sizeof mf);
    b64_encode((const unsigned char *)RCPTS[0], strlen(RCPTS[0]), rt, sizeof rt);
    size_t cap = 256 + strlen(g_sig_extra) + (size_t)n * 64;
    for (int i = 0; i < n; i++) cap += strlen(items[i].sel) + strlen(items[i].alg) + 800
                                       + (items[i].lit ? strlen(items[i].lit) : 0);
    char *inc = malloc(cap), *fin = malloc(cap);
    int ip = snprintf(inc, cap, "i=1; m=1; t=%s; d=example.com; mf=%s; rt=%s; %ss=", t, mf, rt, g_sig_extra);
    for (int i = 0; i < n; i++)
        ip += snprintf(inc + ip, cap - (size_t)ip, "%s%s:%s:", i ? "," : "", items[i].sel, items[i].alg);
    snprintf(inc + ip, cap - (size_t)ip, ";");

    char *input = malloc(cap + 4096);
    size_t pos = 0;
    canon_append(input, &pos, "message-instance", mi_val);
    canon_append(input, &pos, "dkim2-signature", inc);

    int fp = snprintf(fin, cap, "i=1; m=1; t=%s; d=example.com; mf=%s; rt=%s; %ss=", t, mf, rt, g_sig_extra);
    for (int i = 0; i < n; i++) {
        char *v = items[i].key
            ? dkim2_sign(items[i].key, items[i].sign_alg, (unsigned char *)input, pos)
            : strdup(items[i].lit);
        assert(v);
        fp += snprintf(fin + fp, cap - (size_t)fp, "%s%s:%s:%s", i ? "," : "",
                       items[i].sel, items[i].alg, v);
        free(v);
    }
    snprintf(fin + fp, cap - (size_t)fp, ";");
    free(inc); free(input);
    return fin;
}

static char g_now[32];

static char *sig1(const char *mi, const char *sel, const char *alg, EVP_PKEY *key, const char *sign_alg) {
    item_t it = { sel, alg, key, sign_alg, NULL };
    return make_sig(mi, g_now, &it, 1);
}

static dkim2_verify_result_t verify(const char *mi_val, const char *sig_val, int skip_ts) {
    FILE *f = fopen(EML, "wb");
    assert(f);
    fprintf(f, "DKIM2-Signature: %s\r\nMessage-Instance: %s\r\n", sig_val, mi_val);
    for (int i = 0; i < 3; i++) fputs(HEADERS[i], f);
    fprintf(f, "\r\n%s", BODY);
    fclose(f);
    g_lookups = 0;
    return dkim2_verify_message(EML, MAIL_FROM, RCPTS, skip_ts);
}

static int g_failures;

static void expect(const char *what, dkim2_verify_result_t r, dkim2_status_t st,
                   const char *msg, int lookups) {
    int ok = r.status == st && (!msg || strcmp(r.message, msg) == 0) &&
             (lookups < 0 || g_lookups == lookups);
    printf("  %s: %s [%d] %s (lookups %d)\n", ok ? "ok" : "FAIL", what,
           (int)r.status, r.message, g_lookups);
    if (!ok) {
        printf("        want [%d] %s", (int)st, msg ? msg : "(any message)");
        if (lookups >= 0) printf(" (lookups %d)", lookups);
        printf("\n");
        g_failures++;
    }
}

/* Replace the first occurrence of from with to (malloc'd). */
static char *subst(const char *s, const char *from, const char *to) {
    const char *at = strstr(s, from);
    assert(at);
    size_t n = strlen(s) - strlen(from) + strlen(to);
    char *out = malloc(n + 1);
    size_t pre = (size_t)(at - s);
    memcpy(out, s, pre);
    strcpy(out + pre, to);
    strcat(out, at + strlen(from));
    return out;
}

static void test_algorithms(const char *mi) {
    printf("A. signature algorithms\n");
    char *s;

    s = sig1(mi, "sel1", "rsa-sha256", g_rsa, "rsa-sha256");
    expect("good rsa-sha256 passes with one lookup", verify(mi, s, 0), DKIM2_OK, NULL, 1);
    free(s);
    s = sig1(mi, "ed", "ed25519-sha256", g_ed, "ed25519-sha256");
    expect("good ed25519-sha256 passes", verify(mi, s, 0), DKIM2_OK, NULL, 1);
    free(s);

    /* A message correctly RSA-signed but declaring future-alg. */
    s = sig1(mi, "sel1", "future-alg", g_rsa, "rsa-sha256");
    expect("RSA signature declared future-alg is ignored, no lookup",
        verify(mi, s, 0), DKIM2_FAIL,
        "FAIL DKIM2-Signature i=1 has no signature with a supported algorithm", 0);
    free(s);
    s = sig1(mi, "sel1", "RSA-SHA256", g_rsa, "rsa-sha256");
    expect("RSA-SHA256 (case differs) is unknown",
        verify(mi, s, 0), DKIM2_FAIL,
        "FAIL DKIM2-Signature i=1 has no signature with a supported algorithm", 0);
    free(s);
    s = sig1(mi, "sel1", "rsa-sha256x", g_rsa, "rsa-sha256");
    expect("rsa-sha256x is unknown", verify(mi, s, 0), DKIM2_FAIL,
        "FAIL DKIM2-Signature i=1 has no signature with a supported algorithm", 0);
    free(s);

    {
        item_t it[2] = { { "sel2", "future-alg", NULL, NULL, "AAAA" },
                         { "sel1", "rsa-sha256", g_rsa, "rsa-sha256", NULL } };
        s = make_sig(mi, g_now, it, 2);
        expect("sel2:future-alg:AAAA,sel1:rsa-sha256:<good> passes, one lookup",
            verify(mi, s, 0), DKIM2_OK, NULL, 1);
        free(s);
    }

    {
        enum { N = 4000 };
        item_t *it = calloc(N + 1, sizeof *it);
        char (*sels)[16] = calloc(N, 16), (*algs)[24] = calloc(N, 24);
        for (int i = 0; i < N; i++) {
            snprintf(sels[i], 16, "u%d", i);
            snprintf(algs[i], 24, "future-alg-%d", i);
            it[i] = (item_t){ sels[i], algs[i], NULL, NULL, "AAAA" };
        }
        it[N] = (item_t){ "sel1", "rsa-sha256", g_rsa, "rsa-sha256", NULL };
        s = make_sig(mi, g_now, it, N + 1);
        dkim2_verify_result_t r = verify(mi, s, 0);
        expect("4000 unknown items + one good item pass, one lookup", r, DKIM2_OK, NULL, 1);
        free(s); free(it); free(sels); free(algs);
    }

    item_t bad[] = {
        { "sel1", "rsa-sha256", NULL, NULL, "" },
        { "sel1", "rsa-sha256", NULL, NULL, "!!!!" },
        { "sel1", "rsa-sha256", NULL, NULL, "AAA" },
        { "sel1", "ed25519-sha256", NULL, NULL, "AA=A" },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char what[96];
        snprintf(what, sizeof what, "%s value '%s' is a syntax error, no lookup", bad[i].alg, bad[i].lit);
        s = make_sig(mi, g_now, &bad[i], 1);
        expect(what, verify(mi, s, 0), DKIM2_PERMERROR,
            "PERMERROR DKIM2-Signature i=1 syntax error", 0);
        free(s);
    }

    /* Key of the wrong type for the algorithm. */
    s = sig1(mi, "ed", "rsa-sha256", g_rsa, "rsa-sha256");
    expect("rsa-sha256 item with an Ed25519 key: algorithm mismatch",
        verify(mi, s, 0), DKIM2_PERMERROR,
        "PERMERROR DKIM2-Signature i=1 public key ed algorithm mismatch", 1);
    free(s);
    s = sig1(mi, "sel1", "ed25519-sha256", g_ed, "ed25519-sha256");
    expect("ed25519-sha256 item with an RSA key: algorithm mismatch",
        verify(mi, s, 0), DKIM2_PERMERROR,
        "PERMERROR DKIM2-Signature i=1 public key sel1 algorithm mismatch", 1);
    free(s);
    set_key("ednok", "v=DKIM1; p=%s", g_ed_b64);   /* k= defaults to rsa */
    s = sig1(mi, "ednok", "ed25519-sha256", g_ed, "ed25519-sha256");
    expect("Ed25519 p= without k=ed25519 is not an RSA key",
        verify(mi, s, 0), DKIM2_PERMERROR,
        "PERMERROR DKIM2-Signature i=1 public key ednok has a syntax error", 1);
    free(s);
}

static void test_key_errors(const char *mi) {
    printf("B. key-record errors\n");
    struct { const char *fmt, *msg; } cases[] = {
        { "v=DKIM1; p=; p=%s",          "has a syntax error" },
        { "v=garbage; p=%s",            "has a syntax error" },
        { "k=rsa; v=DKIM1; p=%s",       "has a syntax error" },
        { "v=DKIM1; k=unknown; p=%s",   "algorithm mismatch" },
        { "v=DKIM1; k=rsa; p=%.0s",     "has been revoked" },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        set_key("kx", cases[i].fmt, g_rsa_b64);
        char *s = sig1(mi, "kx", "rsa-sha256", g_rsa, "rsa-sha256");
        char want[160], what[96];
        snprintf(want, sizeof want, "PERMERROR DKIM2-Signature i=1 public key kx %s", cases[i].msg);
        snprintf(what, sizeof what, "record '%.30s'", g_keys[g_nkeys - 1].txt);
        expect(what, verify(mi, s, 0), DKIM2_PERMERROR, want, 1);
        free(s);
    }
}

static void test_outcome(const char *mi) {
    printf("E. outcome of a signature's items\n");
    char *s;
    set_key("kx", "v=DKIM1; k=rsa; p=%.0s", g_rsa_b64);          /* revoked */
    set_key("sel2", "v=DKIM1; k=rsa; p=%s", g_rsa_b64);
    set_key("edbad", "v=DKIM1; k=ed25519; p=%s", g_ed_b64);

    item_t rev_last[2] = { { "sel1", "rsa-sha256", g_rsa, "rsa-sha256", NULL },
                           { "kx", "ed25519-sha256", g_ed, "ed25519-sha256", NULL } };
    s = make_sig(mi, g_now, rev_last, 2);
    expect("good item + revoked item: PERMERROR for the signature",
        verify(mi, s, 0), DKIM2_PERMERROR,
        "PERMERROR DKIM2-Signature i=1 public key kx has been revoked", -1);
    free(s);
    item_t rev_first[2] = { { "kx", "ed25519-sha256", g_ed, "ed25519-sha256", NULL },
                            { "sel1", "rsa-sha256", g_rsa, "rsa-sha256", NULL } };
    s = make_sig(mi, g_now, rev_first, 2);
    expect("revoked item + good item: PERMERROR for the signature",
        verify(mi, s, 0), DKIM2_PERMERROR,
        "PERMERROR DKIM2-Signature i=1 public key kx has been revoked", -1);
    free(s);
    item_t mism[2] = { { "sel1", "rsa-sha256", g_rsa, "rsa-sha256", NULL },
                       { "sel2", "ed25519-sha256", g_ed, "ed25519-sha256", NULL } };
    s = make_sig(mi, g_now, mism, 2);
    expect("good item + algorithm-mismatch item: PERMERROR",
        verify(mi, s, 0), DKIM2_PERMERROR,
        "PERMERROR DKIM2-Signature i=1 public key sel2 algorithm mismatch", -1);
    free(s);

    item_t absent1[2] = { { "nosel", "ed25519-sha256", g_ed, "ed25519-sha256", NULL },
                          { "sel1", "rsa-sha256", g_rsa, "rsa-sha256", NULL } };
    s = make_sig(mi, g_now, absent1, 2);
    expect("absent item + good item: absent skipped, pass",
        verify(mi, s, 0), DKIM2_OK, NULL, 2);
    free(s);
    s = sig1(mi, "nosel", "rsa-sha256", g_rsa, "rsa-sha256");
    expect("only item absent: PERMERROR does not exist", verify(mi, s, 0), DKIM2_PERMERROR,
        "PERMERROR DKIM2-Signature i=1 public key nosel does not exist", 1);
    free(s);
    item_t absent2[3] = { { "nosel1", "rsa-sha256", g_rsa, "rsa-sha256", NULL },
                          { "zz", "future-alg", NULL, NULL, "AAAA" },
                          { "nosel2", "ed25519-sha256", g_ed, "ed25519-sha256", NULL } };
    s = make_sig(mi, g_now, absent2, 3);
    expect("every implemented item absent: names the first", verify(mi, s, 0), DKIM2_PERMERROR,
        "PERMERROR DKIM2-Signature i=1 public key nosel1 does not exist", 2);
    free(s);

    s = sig1(mi, "tempfail", "rsa-sha256", g_rsa, "rsa-sha256");
    expect("DNS failure: TEMPERROR could not be fetched", verify(mi, s, 0), DKIM2_TEMPERROR,
        "TEMPERROR DKIM2-Signature i=1 public key tempfail could not be fetched", 1);
    free(s);

    item_t onebad[2] = { { "sel1", "rsa-sha256", g_rsa, "rsa-sha256", NULL },
                         { "ed", "ed25519-sha256", NULL, NULL,
                           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" } };
    s = make_sig(mi, g_now, onebad, 2);
    expect("good item + bad signature: FAIL naming the selector", verify(mi, s, 0), DKIM2_FAIL,
        "FAIL DKIM2-Signature i=1 ed incorrect signature", 2);
    free(s);
    {   /* §3.2: an RSA key under 1024 bits is present but unusable. */
        EVP_PKEY *weak = NULL;
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        assert(c && EVP_PKEY_keygen_init(c) == 1);
        EVP_PKEY_CTX_set_rsa_keygen_bits(c, 768);
        assert(EVP_PKEY_keygen(c, &weak) == 1);
        EVP_PKEY_CTX_free(c);
        unsigned char *der = NULL;
        int dl = i2d_PUBKEY(weak, &der);
        char wb64[1024];
        b64_encode(der, (size_t)dl, wb64, sizeof wb64);
        OPENSSL_free(der);
        set_key("weak", "v=DKIM1; k=rsa; p=%s", wb64);
        s = sig1(mi, "weak", "rsa-sha256", weak, "rsa-sha256");
        expect("only item has a 768-bit RSA key: PERMERROR", verify(mi, s, 0), DKIM2_PERMERROR,
            "PERMERROR DKIM2-Signature i=1 public key weak is shorter than 1024 bits", 1);
        free(s);
        item_t wk[2] = { { "ed", "ed25519-sha256", g_ed, "ed25519-sha256", NULL },
                         { "weak", "rsa-sha256", weak, "rsa-sha256", NULL } };
        s = make_sig(mi, g_now, wk, 2);
        expect("good item + 768-bit RSA item: PERMERROR for the signature",
            verify(mi, s, 0), DKIM2_PERMERROR,
            "PERMERROR DKIM2-Signature i=1 public key weak is shorter than 1024 bits", 2);
        free(s);
        EVP_PKEY_free(weak);
    }
    item_t twogood[2] = { { "sel1", "rsa-sha256", g_rsa, "rsa-sha256", NULL },
                          { "ed", "ed25519-sha256", g_ed, "ed25519-sha256", NULL } };
    s = make_sig(mi, g_now, twogood, 2);
    expect("two good items pass", verify(mi, s, 0), DKIM2_OK, NULL, 2);
    free(s);
}

static void test_mi_tags(const char *mi) {
    printf("C. Message-Instance tags\n");
    char *m2, *s;

    m2 = subst(mi, "h=", "H=");
    s = sig1(m2, "sel1", "rsa-sha256", g_rsa, "rsa-sha256");
    expect("signed instance written with H= passes", verify(m2, s, 0), DKIM2_OK, NULL, 1);
    free(s); free(m2);

    m2 = subst(mi, "m=", "M=");
    s = sig1(m2, "sel1", "rsa-sha256", g_rsa, "rsa-sha256");
    expect("signed instance written with M= passes", verify(m2, s, 0), DKIM2_OK, NULL, 1);
    free(s); free(m2);

    const char *h = strstr(mi, "h=");
    char good_h[512];
    snprintf(good_h, sizeof good_h, "%.*s", (int)(strchr(h, ';') - h), h);
    char *variants[4];
    char buf[1024];
    snprintf(buf, sizeof buf, "m=1; h=sha256:AAAA:AAAA; %s;", good_h);   variants[0] = strdup(buf);
    snprintf(buf, sizeof buf, "m=1; %s; h=sha256:AAAA:AAAA;", good_h);   variants[1] = strdup(buf);
    snprintf(buf, sizeof buf, "m=1; H=sha256:AAAA:AAAA; %s;", good_h);   variants[2] = strdup(buf);
    snprintf(buf, sizeof buf, "m=1; %s; M=1;", good_h);                  variants[3] = strdup(buf);
    for (int i = 0; i < 4; i++) {
        s = sig1(variants[i], "sel1", "rsa-sha256", g_rsa, "rsa-sha256");
        char what[128];
        snprintf(what, sizeof what, "repeated tag (signed) '%.40s...' is a syntax error", variants[i]);
        expect(what, verify(variants[i], s, 0), DKIM2_PERMERROR,
            "PERMERROR Message-Instance m=1 syntax error", -1);
        free(s); free(variants[i]);
    }
}

static void test_timestamps(const char *mi) {
    printf("D. t= syntax\n");
    const char *bad[] = { "garbage", "-5", "1e9", "0x10", "12 34", "+5", "" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        item_t it = { "sel1", "rsa-sha256", g_rsa, "rsa-sha256", NULL };
        char *s = make_sig(mi, bad[i], &it, 1);
        char what[96];
        for (int skip = 0; skip < 2; skip++) {
            snprintf(what, sizeof what, "t=%s is a syntax error (skip age check: %d)", bad[i], skip);
            expect(what, verify(mi, s, skip), DKIM2_PERMERROR,
                "PERMERROR DKIM2-Signature i=1 syntax error", 0);
        }
        free(s);
    }
    item_t it = { "sel1", "rsa-sha256", g_rsa, "rsa-sha256", NULL };
    char *s = make_sig(mi, "0", &it, 1);
    dkim2_verify_result_t r = verify(mi, s, 0);
    expect("t=0 is valid syntax but expired", r, DKIM2_PERMERROR, NULL, -1);
    if (!strstr(r.message, "expired")) { printf("  FAIL: t=0 not reported expired\n"); g_failures++; }
    expect("t=0 passes with the age check skipped", verify(mi, s, 1), DKIM2_OK, NULL, 1);
    free(s);
    s = make_sig(mi, " 1000000000000 ", &it, 1);
    expect("t=10^12 does not overflow (future, skipped)", verify(mi, s, 1), DKIM2_OK, NULL, 1);
    r = verify(mi, s, 0);
    expect("t=10^12 is in the future", r, DKIM2_PERMERROR, NULL, -1);
    if (!strstr(r.message, "future")) { printf("  FAIL: t=10^12 not reported future\n"); g_failures++; }
    free(s);
    s = make_sig(mi, "99999999999999999999999999", &it, 1);
    r = verify(mi, s, 0);
    expect("t= past 2^64 is digits, saturates to the future", r, DKIM2_PERMERROR, NULL, -1);
    if (!strstr(r.message, "future")) { printf("  FAIL: huge t= not reported future\n"); g_failures++; }
    free(s);
}

/* Insert ins into s at byte offset at (malloc'd). */
static char *insert_at(const char *s, size_t at, const char *ins) {
    size_t n = strlen(s), k = strlen(ins);
    char *out = malloc(n + k + 1);
    memcpy(out, s, at); memcpy(out + at, ins, k); strcpy(out + at + k, s + at);
    return out;
}

static void test_field_syntax(const char *mi) {
    printf("F.1 tag-list syntax\n");
    const char *SIG_SYNTAX = "PERMERROR DKIM2-Signature i=1 syntax error";
    const char *MI_SYNTAX = "PERMERROR Message-Instance m=1 syntax error";
    const char *bad[] = { "junk; ", "9bad=foo; ", "=v; ", "x=a\x7f" "b; ", "x=caf\xc3\xa9; ",
                          "n=\x80; ", "x=a\x01; ", "x y=1; ", NULL };
    const char *good[] = { "x=unknown value; ", ";; ", "x=; ", " X_9 = a=b ; ", NULL };
    char *s, *m2, what[128];
    for (int i = 0; bad[i]; i++) {
        g_sig_extra = bad[i];
        s = sig1(mi, "sel1", "rsa-sha256", g_rsa, "rsa-sha256");
        snprintf(what, sizeof what, "DKIM2-Signature fragment '%.20s' is a syntax error", bad[i]);
        expect(what, verify(mi, s, 0), DKIM2_PERMERROR, SIG_SYNTAX, 0);
        free(s);
    }
    for (int i = 0; good[i]; i++) {
        g_sig_extra = good[i];
        s = sig1(mi, "sel1", "rsa-sha256", g_rsa, "rsa-sha256");
        snprintf(what, sizeof what, "DKIM2-Signature fragment '%.20s' is fine", good[i]);
        expect(what, verify(mi, s, 0), DKIM2_OK, NULL, 1);
        free(s);
    }
    g_sig_extra = "";
    for (int i = 0; bad[i]; i++) {
        char frag[64];
        snprintf(frag, sizeof frag, "%sh=", bad[i]);
        m2 = subst(mi, "h=", frag);
        s = sig1(m2, "sel1", "rsa-sha256", g_rsa, "rsa-sha256");
        snprintf(what, sizeof what, "Message-Instance fragment '%.20s' is a syntax error", bad[i]);
        expect(what, verify(m2, s, 0), DKIM2_PERMERROR, MI_SYNTAX, -1);
        free(s); free(m2);
    }
    for (int i = 0; good[i]; i++) {
        char frag[64];
        snprintf(frag, sizeof frag, "%sh=", good[i]);
        m2 = subst(mi, "h=", frag);
        s = sig1(m2, "sel1", "rsa-sha256", g_rsa, "rsa-sha256");
        snprintf(what, sizeof what, "Message-Instance fragment '%.20s' is fine", good[i]);
        expect(what, verify(m2, s, 0), DKIM2_OK, NULL, 1);
        free(s); free(m2);
    }

    printf("F.2 s= items\n");
    struct { const char *sel, *alg; int ok; } items[] = {
        { "sel1", "rsa- sha256", 0 },
        { "sel1", "rsa-\r\n\tsha256", 0 },
        { "se l1", "rsa-sha256", 0 },
        { "se\r\n l1", "rsa-sha256", 0 },
        { "a..b", "rsa-sha256", 0 },
        { ".sel1", "rsa-sha256", 0 },
        { "sel1.", "rsa-sha256", 0 },
        { "sel!", "rsa-sha256", 0 },
        { "sel1", "rsa+sha256", 0 },
        { "sel1", "", 0 },
        { "", "rsa-sha256", 0 },
        { " sel1 ", " rsa-sha256\r\n\t", 1 },
        { "\r\n sel1", "rsa-sha256 ", 1 },
    };
    for (size_t i = 0; i < sizeof items / sizeof items[0]; i++) {
        s = sig1(mi, items[i].sel, items[i].alg, g_rsa, "rsa-sha256");
        snprintf(what, sizeof what, "s= item sel '%s' alg '%s' %s", items[i].sel, items[i].alg,
                 items[i].ok ? "passes" : "is a syntax error");
        if (items[i].ok) expect(what, verify(mi, s, 0), DKIM2_OK, NULL, 1);
        else expect(what, verify(mi, s, 0), DKIM2_PERMERROR, SIG_SYNTAX, 0);
        free(s);
    }
    {   /* FWS around the comma, after a colon and inside the base64 value */
        item_t two[2] = { { "zz", "future-alg", NULL, NULL, "AAAA" },
                          { "sel1", "rsa-sha256", g_rsa, "rsa-sha256", NULL } };
        s = make_sig(mi, g_now, two, 2);
        char *s2 = subst(s, ",sel1:rsa-sha256:", " \r\n\t, sel1 :\r\n rsa-sha256 : ");
        const char *v = strstr(s2, "rsa-sha256 : ") + 13;
        char *s3 = insert_at(s2, (size_t)(v - s2) + 20, "\r\n\t");
        char *s4 = insert_at(s3, strlen(s3) - 30, " ");   /* and a space */
        expect("FWS around , and : and inside base64 is fine", verify(mi, s4, 0), DKIM2_OK, NULL, 1);
        free(s2); free(s3); free(s4);
        s2 = subst(s, "zz:future-alg:AAAA", "zz:future-alg");
        expect("an item with two parts is a syntax error", verify(mi, s2, 0), DKIM2_PERMERROR, SIG_SYNTAX, 0);
        free(s2);
        s2 = subst(s, "zz:future-alg:AAAA", "zz:future-alg:AA:AA");
        expect("an item with four parts is a syntax error", verify(mi, s2, 0), DKIM2_PERMERROR, SIG_SYNTAX, 0);
        free(s2);
        s2 = subst(s, "zz:future-alg:AAAA,", "zz:future-alg:AAAA,,");
        expect("an empty item is a syntax error", verify(mi, s2, 0), DKIM2_PERMERROR, SIG_SYNTAX, 0);
        free(s2);
        free(s);
    }

    printf("F.3 h= hash-sets\n");
    struct { const char *from, *to; int ok; } hs[] = {
        { "h=sha256:", "h=sha 256:", 0 },
        { "h=sha256:", "h=sha\r\n 256:", 0 },
        { "h=sha256:", "h=sha512:AAAA:,sha256:", 0 },
        { "h=sha256:", "h=sha512::AAAA,sha256:", 0 },
        { "h=sha256:", "h=sha512:AAAA,sha256:", 0 },
        { "h=sha256:", "h=,sha256:", 0 },
        { "h=sha256:", "h=sh+a:AAAA:AAAA,sha256:", 0 },
        { "h=sha256:", "h= \r\n sha256 :\r\n ", 1 },
        { "h=sha256:", "h=future-hash:AAAA:AAAA , sha256: ", 1 },
    };
    for (size_t i = 0; i < sizeof hs / sizeof hs[0]; i++) {
        m2 = subst(mi, hs[i].from, hs[i].to);
        if (hs[i].ok) {   /* also fold inside the first digest's base64 */
            const char *d = strstr(m2, "sha256");
            d = strchr(d, ':') + 1;
            while (*d == ' ' || *d == '\r' || *d == '\n') d++;
            char *m3 = insert_at(m2, (size_t)(d - m2) + 10, "\r\n\t");
            free(m2); m2 = m3;
        }
        s = sig1(m2, "sel1", "rsa-sha256", g_rsa, "rsa-sha256");
        snprintf(what, sizeof what, "h= '%s' %s", hs[i].to, hs[i].ok ? "passes" : "is a syntax error");
        if (hs[i].ok) expect(what, verify(m2, s, 0), DKIM2_OK, NULL, 1);
        else expect(what, verify(m2, s, 0), DKIM2_PERMERROR, MI_SYNTAX, -1);
        free(s); free(m2);
    }
}

/* F.5: the C signer never folds, so a long Domain stays whole; it must sign
   and verify with mf= in that domain. */
static void test_long_domain(void) {
    printf("F.5 long d=\n");
    const char *mf = "<sender@" LONG_DOMAIN ">";
    dkim2_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.headers = (char **)HEADERS;
    ctx.n_headers = 3;
    dkim2_body_hash_raw(BODY, strlen(BODY), ctx.body_digests.d[0]);
    ctx.mail_from = (char *)mf;
    ctx.rcpt_to = RCPTS;
    dkim2_sign_config_t cfg = { .domain = LONG_DOMAIN, .selector = "ed",
        .privkey_path = ED_PEM, .alg = "ed25519-sha256" };
    char *mi = NULL, *sig = NULL;
    assert(dkim2_do_sign(&ctx, &cfg, &mi, &sig) == 0);
    int whole = strstr(sig, "d=" LONG_DOMAIN ";") != NULL && !strpbrk(sig, "\r\n");
    printf("  %s: d= of %zu chars is unbroken\n", whole ? "ok" : "FAIL", strlen(LONG_DOMAIN));
    if (!whole) g_failures++;
    FILE *f = fopen(EML, "wb");
    assert(f);
    fprintf(f, "DKIM2-Signature: %s\r\nMessage-Instance: %s\r\n", sig, mi);
    for (int i = 0; i < 3; i++) fputs(HEADERS[i], f);
    fprintf(f, "\r\n%s", BODY);
    fclose(f);
    g_lookups = 0;
    expect("signs and verifies", dkim2_verify_message(EML, mf, RCPTS, 0), DKIM2_OK, NULL, 1);
    free(mi); free(sig);
}

int main(void) {
    make_keys();
    set_key("sel1", "v=DKIM1; k=rsa; p=%s", g_rsa_b64);
    set_key("ed", "v=DKIM1; k=ed25519; p=%s", g_ed_b64);
    dkim2_dns_override = fake_dns;
    snprintf(g_now, sizeof g_now, "%llu", (unsigned long long)time(NULL));

    char *mi = good_mi();
    test_algorithms(mi);
    test_key_errors(mi);
    test_outcome(mi);
    test_mi_tags(mi);
    test_timestamps(mi);
    test_field_syntax(mi);
    test_long_domain();
    free(mi);

    EVP_PKEY_free(g_ed); EVP_PKEY_free(g_rsa);
    remove(EML); remove(ED_PEM); remove(RSA_PEM);
    if (g_failures) { printf("test_strictness: %d FAILED\n", g_failures); return 1; }
    puts("test_strictness: all passed");
    return 0;
}
