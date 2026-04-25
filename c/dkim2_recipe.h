#pragma once
#include <stddef.h>

/* Apply a body recipe (JSON string) to reconstruct the original body.
   body/bodylen: current (possibly modified) body.
   out_len: set to reconstructed body length.
   Returns malloc'd buffer (caller frees) or NULL on error. */
char *dkim2_apply_body_recipe(const char *r_json,
    const char *body, size_t bodylen, size_t *out_len);

/* Apply a header recipe (JSON string) to reconstruct original headers.
   headers[]: array of "Name: value\r\n" strings (n entries).
   n_out: set to number of resulting headers.
   Returns new malloc'd array of malloc'd strings (caller frees each + array).
   Returns NULL on error. */
char **dkim2_apply_header_recipe(const char *r_json,
    char **headers, int n, int *n_out);

/* Generate a body recipe JSON string (caller frees) that transforms
   old_body into new_body. Returns NULL on error.
   If the change cannot be expressed as a recipe, sets *impossible = 1. */
char *dkim2_gen_body_recipe(
    const char *old_body, size_t old_len,
    const char *new_body, size_t new_len,
    int *impossible);

/* Generate a header recipe JSON string (caller frees) expressing
   how to transform old_fields into new_fields for the named header. */
char *dkim2_gen_header_recipe(const char *field_name,
    char **old_fields, int n_old,
    char **new_fields, int n_new);
