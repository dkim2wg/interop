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
#include "../base64.h"

/* TXT record handed back by the override hook for the next lookup. */
static char override_txt[2048];

static char *fake_dns(const char *qname) {
    (void)qname;
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

int main(void) {
    dkim2_dns_override = fake_dns;
    EVP_PKEY *priv = gen_rsa();

    printf("test_dns: RSA p= encodings\n");
    test_rsa_spki(priv);
    test_rsa_pkcs1(priv);
    test_garbage_rejected();

    EVP_PKEY_free(priv);
    printf("test_dns: all passed\n");
    return 0;
}
