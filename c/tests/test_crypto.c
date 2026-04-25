#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "../dkim2_crypto.h"
#include "../base64.h"

static void test_ed25519(void) {
    EVP_PKEY *privkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    assert(ctx != NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &privkey);
    EVP_PKEY_CTX_free(ctx);
    assert(privkey != NULL);

    const unsigned char data[] = "test signing data for ed25519";
    char *sig = dkim2_sign(privkey, "ed25519-sha256", data, sizeof data - 1);
    assert(sig != NULL);

    /* Extract raw public key */
    size_t publen = 32;
    unsigned char pubbuf[32];
    EVP_PKEY_get_raw_public_key(privkey, pubbuf, &publen);
    EVP_PKEY *pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubbuf, publen);
    assert(pubkey != NULL);

    int r = dkim2_verify(pubkey, "ed25519-sha256", data, sizeof data - 1, sig);
    assert(r == 0);

    const unsigned char tampered[] = "test signing data for ed25520";
    int r2 = dkim2_verify(pubkey, "ed25519-sha256", tampered, sizeof tampered - 1, sig);
    assert(r2 != 0);

    free(sig);
    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);
}

static void test_rsa(void) {
    /* Generate RSA-2048 key */
    EVP_PKEY *privkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    assert(ctx != NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &privkey);
    EVP_PKEY_CTX_free(ctx);
    assert(privkey != NULL);

    const unsigned char data[] = "test signing data for rsa-sha256";
    char *sig = dkim2_sign(privkey, "rsa-sha256", data, sizeof data - 1);
    assert(sig != NULL);

    /* Get public key via PEM round-trip */
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, privkey);
    EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    assert(pubkey != NULL);

    int r = dkim2_verify(pubkey, "rsa-sha256", data, sizeof data - 1, sig);
    assert(r == 0);

    const unsigned char tampered[] = "test signing data for rsa-sha257";
    int r2 = dkim2_verify(pubkey, "rsa-sha256", tampered, sizeof tampered - 1, sig);
    assert(r2 != 0);

    free(sig);
    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);
}

static void test_load_privkey(void) {
    /* Generate and write an Ed25519 key to a temp PEM file */
    EVP_PKEY *privkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &privkey);
    EVP_PKEY_CTX_free(ctx);

    FILE *f = fopen("/tmp/dkim2_test_key.pem", "w");
    assert(f != NULL);
    PEM_write_PrivateKey(f, privkey, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    EVP_PKEY_free(privkey);

    EVP_PKEY *loaded = dkim2_load_privkey("/tmp/dkim2_test_key.pem");
    assert(loaded != NULL);
    EVP_PKEY_free(loaded);
}

int main(void) {
    test_ed25519();
    test_rsa();
    test_load_privkey();
    puts("crypto: all tests passed");
    return 0;
}
