#pragma once
#include <stddef.h>

/* Encode binary data to base64 string (NUL-terminated).
   outlen must be >= ((inlen+2)/3)*4 + 1.
   Returns number of base64 chars written (not counting NUL), or -1. */
int b64_encode(const unsigned char *in, size_t inlen, char *out, size_t outlen);

/* Decode base64 string, ignoring all whitespace per DKIM2 §2.14.
   Returns number of decoded bytes, or -1 on invalid input. */
int b64_decode(const char *in, unsigned char *out, size_t outlen);
