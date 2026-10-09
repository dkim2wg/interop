/* Key-record parsing tests for dkim2_dns.c.
 *
 * Pins the RFC 6376 erratum 3017 compatibility rule: a DKIM p= value may carry
 * an RSA key either as a full SubjectPublicKeyInfo (what `openssl rsa -pubout`
 * emits, and what every generator in this repo publishes) or as a bare PKCS#1
 * RSAPublicKey, which is what RFC 6376 §3.6.1 literally says. Verifiers must
 * accept both, so removing the PKCS#1 fallback in parse_key_record must fail
 * these tests.  See https://github.com/dkim2wg/interop/issues/9.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "../dkim2_dns.h"
#include "../dkim2_dnsjson.h"
#include "../base64.h"

/* TXT record handed back by the override hook for the next lookup. */
static char override_txt[2048];

static char *fake_dns(const char *qname, int *n_records) {
    (void)qname; (void)n_records;
    return strdup(override_txt);
}

static EVP_PKEY *gen_rsa(void) {
    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    assert(ctx != NULL);
    assert(EVP_PKEY_keygen_init(ctx) == 1);
    assert(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) == 1);
    assert(EVP_PKEY_keygen(ctx, &k) == 1);
    EVP_PKEY_CTX_free(ctx);
    assert(k != NULL);
    return k;
}

/* Build "v=DKIM1; k=rsa; p=<base64 of der>" in override_txt. */
static void set_key_record(const unsigned char *der, int derlen) {
    char b64[4096];
    assert(b64_encode(der, (size_t)derlen, b64, sizeof b64) > 0);
    int n = snprintf(override_txt, sizeof override_txt,
        "v=DKIM1; k=rsa; p=%s", b64);
    assert(n > 0 && (size_t)n < sizeof override_txt);
}

/* Fetch the key currently in override_txt and assert it imported cleanly. */
static void expect_key_accepted(const char *what) {
    dkim2_status_t status = DKIM2_PERMERROR;
    const char *err = NULL;
    dkim2_pubkey_t *k = dkim2_dns_getkey("sel1", "test1.dkim2.com", &status, &err);
    if (!k || status != DKIM2_OK || !k->pkey) {
        fprintf(stderr, "FAIL: %s key rejected: status=%d err=%s\n",
            what, (int)status, err ? err : "(none)");
        exit(1);
    }
    assert(strcmp(k->alg, "rsa") == 0);
    assert(EVP_PKEY_get_base_id(k->pkey) == EVP_PKEY_RSA);
    dkim2_pubkey_free(k);
    printf("  ok: %s accepted\n", what);
}

static void test_rsa_spki(EVP_PKEY *priv) {
    unsigned char *der = NULL;
    int derlen = i2d_PUBKEY(priv, &der); /* SubjectPublicKeyInfo */
    assert(derlen > 0);
    set_key_record(der, derlen);
    OPENSSL_free(der);
    expect_key_accepted("SubjectPublicKeyInfo");
}

static void test_rsa_pkcs1(EVP_PKEY *priv) {
    unsigned char *der = NULL;
    int derlen = i2d_PublicKey(priv, &der); /* bare PKCS#1 RSAPublicKey */
    assert(derlen > 0);
    set_key_record(der, derlen);
    OPENSSL_free(der);
    expect_key_accepted("bare PKCS#1 RSAPublicKey");
}

static void test_garbage_rejected(void) {
    snprintf(override_txt, sizeof override_txt, "v=DKIM1; k=rsa; p=bm90YWtleQ==");
    dkim2_status_t status = DKIM2_OK;
    const char *err = NULL;
    dkim2_pubkey_t *k = dkim2_dns_getkey("sel1", "test1.dkim2.com", &status, &err);
    assert(k == NULL);
    assert(status == DKIM2_PERMERROR);
    printf("  ok: non-key p= rejected (%s)\n", err ? err : "(no message)");
}

/* ---- Key-record validation (spec-06 §11.5; dns-00 §3.2, §3.4.1) ---- */

static char g_rsa_b64[2048];

static void expect_record(const char *txt, dkim2_status_t want_status,
                          const char *want_err, const char *what) {
    snprintf(override_txt, sizeof override_txt, "%s", txt);
    dkim2_status_t status = DKIM2_OK;
    const char *err = NULL;
    dkim2_pubkey_t *k = dkim2_dns_getkey("sel1", "test1.dkim2.com", &status, &err);
    int ok = (status == want_status) &&
             (want_err ? (err && strcmp(err, want_err) == 0) : (k && k->pkey != NULL));
    if (!ok) {
        fprintf(stderr, "FAIL: %s: status=%d err=%s (want %d %s)\n", what,
            (int)status, err ? err : "(none)", (int)want_status,
            want_err ? want_err : "a key");
        exit(1);
    }
    dkim2_pubkey_free(k);
    printf("  ok: %s\n", what);
}

static void test_key_records(void) {
    char rec[4096];
#define REC(...) (snprintf(rec, sizeof rec, __VA_ARGS__), rec)
    expect_record(REC("v=DKIM1; k=rsa; p=%s", g_rsa_b64), DKIM2_OK, NULL, "plain good record");
    expect_record(REC("v=DKIM1; k=rsa; p=%s;", g_rsa_b64), DKIM2_OK, NULL, "trailing ; is fine");
    expect_record(REC("p=%s", g_rsa_b64), DKIM2_OK, NULL, "v= and k= optional");
    expect_record(REC("v=DKIM1; h=sha1; n=note; s=email; t=y; x=1; p=%s", g_rsa_b64),
        DKIM2_OK, NULL, "retired and unknown tags ignored");
    expect_record(REC("v=DKIM1; p=%.20s \r\n\t%s", g_rsa_b64, g_rsa_b64 + 20),
        DKIM2_OK, NULL, "FWS inside p= removed");
    expect_record(REC("v=DKIM1; p=; p=%s", g_rsa_b64), DKIM2_PERMERROR,
        "has a syntax error", "repeated p= is a syntax error");
    expect_record(REC("v=garbage; p=%s", g_rsa_b64), DKIM2_PERMERROR,
        "has a syntax error", "bad v= is a syntax error");
    expect_record(REC("k=rsa; v=DKIM1; p=%s", g_rsa_b64), DKIM2_PERMERROR,
        "has a syntax error", "v= not first is a syntax error");
    expect_record(REC("v=DKIM1; k=rsa"), DKIM2_PERMERROR,
        "has a syntax error", "no p= is a syntax error");
    expect_record(REC("v=DKIM1; P=%s", g_rsa_b64), DKIM2_PERMERROR,
        "has a syntax error", "tag names are case sensitive (P= is not p=)");
    expect_record(REC("v=DKIM1; p=%s; garbage", g_rsa_b64), DKIM2_PERMERROR,
        "has a syntax error", "a spec with no = is a syntax error");
    expect_record(REC("v=DKIM1; 1k=rsa; p=%s", g_rsa_b64), DKIM2_PERMERROR,
        "has a syntax error", "a bad tag name is a syntax error");
    expect_record(REC("v=DKIM1; p=!!notbase64!!"), DKIM2_PERMERROR,
        "has a syntax error", "p= not base64 is a syntax error");
    expect_record(REC("v=DKIM1; k=rsa; p="), DKIM2_PERMERROR,
        "has been revoked", "empty p= is revoked");
    expect_record(REC("v=DKIM1; k=unknown; p=%s", g_rsa_b64), DKIM2_PERMERROR,
        "algorithm mismatch", "unknown k= is never read as RSA");
    expect_record(REC("v=DKIM1; k=ed25519; p=%s", g_rsa_b64), DKIM2_PERMERROR,
        "has a syntax error", "p= not a key of type k= is a syntax error");
    /* Behaviour spec F.4: every value, known or ignored, is VALCHARs with
       WSP/FWS only between them. */
    expect_record(REC("v=DKIM1; x=a\x7f" "b; p=%s", g_rsa_b64), DKIM2_PERMERROR,
        "has a syntax error", "DEL in an unknown tag is a syntax error");
    expect_record(REC("v=DKIM1; n=caf\xc3\xa9; p=%s", g_rsa_b64), DKIM2_PERMERROR,
        "has a syntax error", "8-bit byte in n= is a syntax error");
    expect_record(REC("v=DKIM1; k=rsa\x01; p=%s", g_rsa_b64), DKIM2_PERMERROR,
        "has a syntax error", "control byte in k= is a syntax error");
    expect_record(REC("v=DKIM1; p=%s\x80", g_rsa_b64), DKIM2_PERMERROR,
        "has a syntax error", "8-bit byte in p= is a syntax error");
    expect_record(REC("v=DKIM1; n=a b\r\n\tc; x=; p=%s", g_rsa_b64), DKIM2_OK, NULL,
        "WSP/FWS between VALCHARs and an empty value are fine");
#undef REC
}

/* Wire-format answers for the res_query seam: one TXT RR per entry of
   rrs[], each RR's strings separated by '|'. */
static const char **g_rrs;
static int g_nrrs;

static int fake_query(const char *qname, unsigned char *ans, int anslen) {
    int pos = 0;
    unsigned char hdr[12] = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0};
    hdr[7] = (unsigned char)g_nrrs;
    memcpy(ans, hdr, 12); pos = 12;
    for (const char *l = qname; *l; ) {
        const char *dot = strchr(l, '.');
        size_t n = dot ? (size_t)(dot - l) : strlen(l);
        ans[pos++] = (unsigned char)n; memcpy(ans + pos, l, n); pos += (int)n;
        l += n; if (*l == '.') l++;
    }
    ans[pos++] = 0;
    ans[pos++] = 0; ans[pos++] = 16; ans[pos++] = 0; ans[pos++] = 1;
    for (int r = 0; r < g_nrrs; r++) {
        ans[pos++] = 0xC0; ans[pos++] = 0x0C;
        ans[pos++] = 0; ans[pos++] = 16; ans[pos++] = 0; ans[pos++] = 1;
        ans[pos++] = 0; ans[pos++] = 0; ans[pos++] = 1; ans[pos++] = 0x2C;
        int rdlen_at = pos; pos += 2;
        int start = pos;
        for (const char *s = g_rrs[r]; ; ) {
            const char *bar = strchr(s, '|');
            size_t n = bar ? (size_t)(bar - s) : strlen(s);
            assert(n < 256);
            ans[pos++] = (unsigned char)n; memcpy(ans + pos, s, n);
            for (size_t j = 0; j < n; j++)         /* '\x02' stands for a NUL */
                if (ans[pos + j] == 0x02) ans[pos + j] = 0;
            pos += (int)n;
            if (!bar) break;
            s = bar + 1;
        }
        ans[rdlen_at] = (unsigned char)((pos - start) >> 8);
        ans[rdlen_at + 1] = (unsigned char)((pos - start) & 0xff);
    }
    assert(pos <= anslen);
    return pos;
}

static void expect_rrs(const char **rrs, int n, dkim2_status_t want_status,
                       const char *want_err, const char *what) {
    g_rrs = rrs; g_nrrs = n;
    dkim2_status_t status = DKIM2_OK;
    const char *err = NULL;
    dkim2_pubkey_t *k = dkim2_dns_getkey("sel1", "test1.dkim2.com", &status, &err);
    int ok = (status == want_status) &&
             (want_err ? (err && strcmp(err, want_err) == 0) : (k && k->pkey != NULL));
    if (!ok) {
        fprintf(stderr, "FAIL: %s: status=%d err=%s\n", what, (int)status, err ? err : "(none)");
        exit(1);
    }
    dkim2_pubkey_free(k);
    printf("  ok: %s\n", what);
}

static void test_txt_rrs(void) {
    dkim2_dns_override = NULL;
    dkim2_dns_query_hook = fake_query;
    char s1[1024], s2[1024], split[2100];
    /* A real 2048-bit p= is ~400 chars: two strings of one RR, split mid-p=. */
    snprintf(s1, sizeof s1, "v=DKIM1; k=rsa; p=%.200s", g_rsa_b64);
    snprintf(s2, sizeof s2, "%s", g_rsa_b64 + 200);
    snprintf(split, sizeof split, "%s|%s", s1, s2);
    const char *rr_split[] = { split };
    expect_rrs(rr_split, 1, DKIM2_OK, NULL, "one RR in two strings is concatenated");
    const char *rr_two[] = { split, split };
    expect_rrs(rr_two, 2, DKIM2_PERMERROR, "has multiple records",
        "two identical TXT RRs are multiple records");
    const char *rr_two_diff[] = { split, "v=DKIM1; p=" };
    expect_rrs(rr_two_diff, 2, DKIM2_PERMERROR, "has multiple records",
        "two different TXT RRs are multiple records");
    char nul[2100];
    /* NUL after a complete record: truncating there would leave a good key */
    snprintf(nul, sizeof nul, "v=DKIM1; k=rsa; p=%.200s|%s; n=a\x02" "b", g_rsa_b64, g_rsa_b64 + 200);
    const char *rr_nul[] = { nul };
    expect_rrs(rr_nul, 1, DKIM2_PERMERROR, "has a syntax error",
        "a NUL inside the record is a syntax error");
    dkim2_dns_query_hook = NULL;
    dkim2_dns_override = fake_dns;
}

/* dns.json: two records for one name are "multiple records", like DNS;
   one record given as several strings is concatenated. */
static void test_dns_json(void) {
    const char *path = "/tmp/dkim2_test_dns.json";
    char s1[256];
    snprintf(s1, sizeof s1, "v=DKIM1; k=rsa; p=%.100s", g_rsa_b64);
    FILE *f = fopen(path, "w");
    assert(f);
    fprintf(f, "{ \"test1.dkim2.com\": {\n"
               "  \"sel1._domainkey\": [[\"txt\", \"%s\", \"%s\"]],\n"
               "  \"two._domainkey\": [[\"txt\", \"v=DKIM1; p=%s\"], [\"txt\", \"v=DKIM1; p=%s\"]]\n"
               "} }\n", s1, g_rsa_b64 + 100, g_rsa_b64, g_rsa_b64);
    fclose(f);
    char err[256];
    assert(dkim2_dns_json_load(path, err, sizeof err) == 0);
    remove(path);
    dkim2_status_t status = DKIM2_OK;
    const char *e = NULL;
    dkim2_pubkey_t *k = dkim2_dns_getkey("sel1", "test1.dkim2.com", &status, &e);
    if (!k || status != DKIM2_OK) {
        fprintf(stderr, "FAIL: dns.json record in two strings: %s\n", e ? e : "-"); exit(1);
    }
    dkim2_pubkey_free(k);
    printf("  ok: dns.json record in two strings is concatenated\n");
    k = dkim2_dns_getkey("two", "test1.dkim2.com", &status, &e);
    if (k || status != DKIM2_PERMERROR || !e || strcmp(e, "has multiple records") != 0) {
        fprintf(stderr, "FAIL: dns.json two records: status=%d err=%s\n", (int)status, e ? e : "-");
        exit(1);
    }
    printf("  ok: dns.json two records are multiple records\n");
    dkim2_dns_json_free();
    dkim2_dns_override = fake_dns;
}

int main(void) {
    dkim2_dns_override = fake_dns;
    EVP_PKEY *priv = gen_rsa();

    printf("test_dns: RSA p= encodings\n");
    test_rsa_spki(priv);
    test_rsa_pkcs1(priv);
    test_garbage_rejected();

    {
        unsigned char *der = NULL;
        int derlen = i2d_PUBKEY(priv, &der);
        assert(derlen > 0);
        assert(b64_encode(der, (size_t)derlen, g_rsa_b64, sizeof g_rsa_b64) > 0);
        OPENSSL_free(der);
    }
    printf("test_dns: key-record validation\n");
    test_key_records();
    printf("test_dns: TXT RRsets\n");
    test_txt_rrs();
    printf("test_dns: dns.json\n");
    test_dns_json();

    EVP_PKEY_free(priv);
    printf("test_dns: all passed\n");
    return 0;
}
