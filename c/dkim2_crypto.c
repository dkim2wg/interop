#include "dkim2_crypto.h"
#include "base64.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

char *dkim2_sign(EVP_PKEY *privkey, const char *alg,
    const unsigned char *data, size_t datalen) {
    int is_ed = (strcmp(alg, "ed25519-sha256") == 0);
    const EVP_MD *md = is_ed ? NULL : EVP_sha256();

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return NULL;

    if (EVP_DigestSignInit(mctx, NULL, md, NULL, privkey) <= 0) {
        EVP_MD_CTX_free(mctx); return NULL;
    }

    /* Ed25519 uses one-shot EVP_DigestSign; RSA uses update+final */
    size_t siglen = 0;
    if (is_ed) {
        /* Determine output length */
        if (EVP_DigestSign(mctx, NULL, &siglen, data, datalen) <= 0) {
            EVP_MD_CTX_free(mctx); return NULL;
        }
        unsigned char *sigbuf = malloc(siglen);
        if (!sigbuf) { EVP_MD_CTX_free(mctx); return NULL; }
        if (EVP_DigestSign(mctx, sigbuf, &siglen, data, datalen) <= 0) {
            free(sigbuf); EVP_MD_CTX_free(mctx); return NULL;
        }
        EVP_MD_CTX_free(mctx);
        size_t b64len = ((siglen + 2) / 3) * 4 + 2;
        char *b64 = malloc(b64len);
        if (!b64) { free(sigbuf); return NULL; }
        b64_encode(sigbuf, siglen, b64, b64len);
        free(sigbuf);
        return b64;
    } else {
        if (EVP_DigestSignUpdate(mctx, data, datalen) <= 0) {
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
        char *b64 = malloc(b64len);
        if (!b64) { free(sigbuf); return NULL; }
        b64_encode(sigbuf, siglen, b64, b64len);
        free(sigbuf);
        return b64;
    }
}

int dkim2_verify(EVP_PKEY *pubkey, const char *alg,
    const unsigned char *data, size_t datalen,
    const char *sig_b64) {
    unsigned char sigbuf[1024];
    int siglen = b64_decode(sig_b64, sigbuf, sizeof sigbuf);
    if (siglen < 0) return -1;

    int is_ed = (strcmp(alg, "ed25519-sha256") == 0);
    const EVP_MD *md = is_ed ? NULL : EVP_sha256();

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return -1;

    int ok = 0;
    if (EVP_DigestVerifyInit(mctx, NULL, md, NULL, pubkey) <= 0) goto done;

    if (is_ed) {
        ok = (EVP_DigestVerify(mctx, sigbuf, (size_t)siglen, data, datalen) == 1);
    } else {
        if (EVP_DigestVerifyUpdate(mctx, data, datalen) <= 0) goto done;
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
