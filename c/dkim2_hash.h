#pragma once
#include <stddef.h>

#define DKIM2_HASH_LEN     32  /* SHA-256 output bytes (algorithm index 0) */
#define DKIM2_MAX_HASH_LEN 64  /* SHA-512 output bytes — sizes every buffer */
#define DKIM2_N_HASH_ALGS   2

/* spec-05 §3.1: sha256 (index 0) and sha512 (index 1). Verifiers MUST
   implement both. Lookup is case-insensitive per RFC 5234. */
int         dkim2_hash_alg_index(const char *name); /* -1 if unimplemented */
const char *dkim2_hash_alg_name(int idx);
size_t      dkim2_hash_alg_len(int idx);

/* Digests for every implemented algorithm, indexed as above. */
typedef struct {
    unsigned char d[DKIM2_N_HASH_ALGS][DKIM2_MAX_HASH_LEN];
} dkim2_digests_t;

/* ── Streaming body hasher ───────────────────────────────────────────────────
   Handles CRLF normalisation and trailing empty-line stripping on the fly.
   Memory profile matches OpenDKIM: body is never buffered, only hashed.
   One EVP context per implemented algorithm is fed from the single
   canonicalisation pass — canonicalisation output is identical across
   algorithms, only the digest sink differs. */
typedef struct dkim2_body_hasher dkim2_body_hasher_t;

dkim2_body_hasher_t *dkim2_body_hasher_new(void);
/* Feed a chunk (need not be CRLF-aligned; handles split boundaries). */
int dkim2_body_hasher_update(dkim2_body_hasher_t *bh,
                             const char *data, size_t len);
/* Finalise (sha256 only): strips trailing empty lines, appends one canonical CRLF. */
int dkim2_body_hasher_final(dkim2_body_hasher_t *bh,
                            unsigned char digest[DKIM2_HASH_LEN]);
/* Finalise every implemented algorithm in one pass. */
int dkim2_body_hasher_final_all(dkim2_body_hasher_t *bh, dkim2_digests_t *out);
void dkim2_body_hasher_free(dkim2_body_hasher_t *bh);

/* ── Batch body hash (legacy / signing convenience) ──────────────────────── */
int dkim2_body_hash_raw(const char *body, size_t bodylen,
                        unsigned char digest[DKIM2_HASH_LEN]);
int dkim2_body_hash_raw_alg(const char *body, size_t bodylen, int alg,
                            unsigned char *digest);
int dkim2_body_hash(const char *body, size_t bodylen, char *out, size_t outlen);

/* ── Header hash §5.2 ────────────────────────────────────────────────────── */
int dkim2_header_hash_raw(const char **headers, int n_headers,
                          unsigned char digest[DKIM2_HASH_LEN]);
int dkim2_header_hash_raw_alg(const char **headers, int n_headers, int alg,
                              unsigned char *digest);
int dkim2_header_hash(const char **headers, int n_headers, char *out, size_t outlen);
