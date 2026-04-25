#pragma once
#include <stddef.h>

/* Compute body hash per §5.1 (simple scheme, SHA256, base64-encoded).
   outlen must be >= 45. Returns 0 on success, -1 on error. */
int dkim2_body_hash(const char *body, size_t bodylen, char *out, size_t outlen);

/* Compute header hash per §5.2 (SHA256, base64-encoded).
   headers: array of "Name: value\r\n" strings (as received from MTA).
   outlen must be >= 45. Returns 0 on success, -1 on error. */
int dkim2_header_hash(const char **headers, int n_headers, char *out, size_t outlen);
