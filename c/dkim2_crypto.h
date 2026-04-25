#pragma once
#include <stddef.h>
#include <openssl/evp.h>

/* Sign data with private key.
   alg: "rsa-sha256" or "ed25519-sha256".
   Returns malloc'd base64-encoded signature string (caller frees), or NULL on error. */
char *dkim2_sign(EVP_PKEY *privkey, const char *alg,
    const unsigned char *data, size_t datalen);

/* Verify a base64-encoded signature against data.
   Returns 0 on success (PASS), -1 on failure (FAIL). */
int dkim2_verify(EVP_PKEY *pubkey, const char *alg,
    const unsigned char *data, size_t datalen,
    const char *sig_b64);

/* Load a private key from a PEM file. Returns EVP_PKEY (caller frees) or NULL. */
EVP_PKEY *dkim2_load_privkey(const char *pem_path);
