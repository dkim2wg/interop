#include "dkim2_crypto.h"
#include "base64.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

/* ed25519-sha256: pre-hash signing input with SHA-256, then Ed25519-sign the digest.
   Both Python and Perl do this; it matches the algorithm name: SHA-256 first. */
static void sha256_of(const unsigned char *data, size_t len, unsigned char out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int dlen = 32;
    EVP_DigestFinal_ex(ctx, out, &dlen);
    EVP_MD_CTX_free(ctx);
}

char *dkim2_sign(EVP_PKEY *privkey, const char *alg,
    const unsigned char *data, size_t datalen) {
    int is_ed = (strcmp(alg, "ed25519-sha256") == 0);

    const unsigned char *to_sign = data;
    size_t to_sign_len = datalen;
    unsigned char digest[32];
    if (is_ed) {
        sha256_of(data, datalen, digest);
        to_sign = digest;
        to_sign_len = 32;
    }

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return NULL;

    const EVP_MD *md = is_ed ? NULL : EVP_sha256();
    if (EVP_DigestSignInit(mctx, NULL, md, NULL, privkey) <= 0) {
        EVP_MD_CTX_free(mctx); return NULL;
    }

    size_t siglen = 0;
    if (is_ed) {
        if (EVP_DigestSign(mctx, NULL, &siglen, to_sign, to_sign_len) <= 0) {
            EVP_MD_CTX_free(mctx); return NULL;
        }
        unsigned char *sigbuf = malloc(siglen);
        if (!sigbuf) { EVP_MD_CTX_free(mctx); return NULL; }
        if (EVP_DigestSign(mctx, sigbuf, &siglen, to_sign, to_sign_len) <= 0) {
            free(sigbuf); EVP_MD_CTX_free(mctx); return NULL;
        }
        EVP_MD_CTX_free(mctx);
        size_t b64len = ((siglen + 2) / 3) * 4 + 2;
        char *b64out = malloc(b64len);
        if (!b64out) { free(sigbuf); return NULL; }
        b64_encode(sigbuf, siglen, b64out, b64len);
        free(sigbuf);
        return b64out;
    } else {
        if (EVP_DigestSignUpdate(mctx, to_sign, to_sign_len) <= 0) {
            EVP_MD_CTX_free(mctx); return NULL;
        }
        if (EVP_DigestSignFinal(mctx, NULL, &siglen) <= 0) {
            EVP_MD_CTX_free(mctx); return NULL;
        }
        unsigned char *sigbuf = malloc(siglen);
        if (!sigbuf) { EVP_MD_CTX_free(mctx); return NULL; }
        if (EVP_DigestSignFinal(mctx, sigbuf, &siglen) <= 0) {
            free(sigbuf); EVP_MD_CTX_free(mctx); return NULL;
        }
        EVP_MD_CTX_free(mctx);
        size_t b64len = ((siglen + 2) / 3) * 4 + 2;
        char *b64out = malloc(b64len);
        if (!b64out) { free(sigbuf); return NULL; }
        b64_encode(sigbuf, siglen, b64out, b64len);
        free(sigbuf);
        return b64out;
    }
}

int dkim2_verify(EVP_PKEY *pubkey, const char *alg,
    const unsigned char *data, size_t datalen,
    const char *sig_b64) {
    unsigned char sigbuf[1024];
    int siglen = b64_decode(sig_b64, sigbuf, sizeof sigbuf);
    if (siglen < 0) return -1;

    int is_ed = (strcmp(alg, "ed25519-sha256") == 0);

    const unsigned char *to_verify = data;
    size_t to_verify_len = datalen;
    unsigned char digest[32];
    if (is_ed) {
        sha256_of(data, datalen, digest);
        to_verify = digest;
        to_verify_len = 32;
    }

    const EVP_MD *md = is_ed ? NULL : EVP_sha256();
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return -1;

    int ok = 0;
    if (EVP_DigestVerifyInit(mctx, NULL, md, NULL, pubkey) <= 0) goto done;

    if (is_ed) {
        ok = (EVP_DigestVerify(mctx, sigbuf, (size_t)siglen, to_verify, to_verify_len) == 1);
    } else {
        if (EVP_DigestVerifyUpdate(mctx, to_verify, to_verify_len) <= 0) goto done;
        ok = (EVP_DigestVerifyFinal(mctx, sigbuf, (size_t)siglen) == 1);
    }
done:
    EVP_MD_CTX_free(mctx);
    return ok ? 0 : -1;
}

EVP_PKEY *dkim2_load_privkey(const char *pem_path) {
    FILE *f = fopen(pem_path, "r");
    if (!f) return NULL;
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return k;
}
