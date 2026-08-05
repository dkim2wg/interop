#pragma once
#include <stddef.h>
#include <stdio.h>
#include "dkim2_hash.h"

/* Parse a raw .eml file.
   Headers are buffered (unavoidable); body is hashed streaming and discarded.

   *headers_out: array of malloc'd "Name: value\r\n" logical header strings.
   *n_headers_out: number of entries.
   body_digest_out: SHA-256 body digest per §5.1 (written on return).
   Returns 0 on success, -1 on error. Caller frees headers with eml_free(). */
int eml_parse(const char *path,
              char ***headers_out, int *n_headers_out,
              unsigned char body_digest_out[DKIM2_HASH_LEN]);

/* Like eml_parse but also returns the CRLF-normalised body bytes.
   *body_out is malloc'd; caller frees. body_len_out is the byte count. */
int eml_parse_with_body(const char *path,
                        char ***headers_out, int *n_headers_out,
                        unsigned char body_digest_out[DKIM2_HASH_LEN],
                        char **body_out, size_t *body_len_out);

/* Stream the body portion of path (CRLF-normalised) to out.
   Used by the signer after signing to re-emit the original body without
   ever holding the body bytes in memory alongside the signature data.
   Returns 0 on success, -1 on error. */
int eml_emit_body(const char *path, FILE *out);

void eml_free(char **headers, int n_headers);
