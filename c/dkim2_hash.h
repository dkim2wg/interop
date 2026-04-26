#pragma once
#include <stddef.h>

#define DKIM2_HASH_LEN 32  /* SHA-256 output bytes */

/* ── Streaming body hasher ───────────────────────────────────────────────────
   Handles CRLF normalisation and trailing empty-line stripping on the fly.
   Memory profile matches OpenDKIM: body is never buffered, only hashed. */
typedef struct dkim2_body_hasher dkim2_body_hasher_t;

dkim2_body_hasher_t *dkim2_body_hasher_new(void);
/* Feed a chunk (need not be CRLF-aligned; handles split boundaries). */
int dkim2_body_hasher_update(dkim2_body_hasher_t *bh,
                             const char *data, size_t len);
/* Finalise: strips trailing empty lines, appends one canonical CRLF. */
int dkim2_body_hasher_final(dkim2_body_hasher_t *bh,
                            unsigned char digest[DKIM2_HASH_LEN]);
void dkim2_body_hasher_free(dkim2_body_hasher_t *bh);

/* ── Batch body hash (legacy / signing convenience) ──────────────────────── */
int dkim2_body_hash_raw(const char *body, size_t bodylen,
                        unsigned char digest[DKIM2_HASH_LEN]);
int dkim2_body_hash(const char *body, size_t bodylen, char *out, size_t outlen);

/* ── Header hash §5.2 ────────────────────────────────────────────────────── */
int dkim2_header_hash_raw(const char **headers, int n_headers,
                          unsigned char digest[DKIM2_HASH_LEN]);
int dkim2_header_hash(const char **headers, int n_headers, char *out, size_t outlen);
