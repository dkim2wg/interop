#pragma once
#include <stddef.h>

/* Recipe steps (spec-06 §5 plus the WG extension of 2026-10):
     {"c": [start, end]}  copy items start..end (1-based, inclusive); across
                          a list each start MUST exceed the previous end
     {"d": [str, ...]}    literal lines/values, ASCII/UTF-8 JSON strings
     {"b": [b64, ...]}    literal lines/values whose raw octets are base64
                          (RFC 4648 §4) -- used for any literal with a byte
                          >= 0x80; decoded octets MUST NOT contain CR or LF
   Any violation is a malformed Recipe: the apply_* functions return NULL and
   the verifier reports PERMERROR. The gen_* functions never emit a literal
   with 8-bit bytes as "d", nor a "c" range that breaks the ascending rule. */

/* cJSON_Parse() of a Recipe, refusing (NULL) one in which any object names
   a key twice: cJSON keeps the first of two equal keys and the other
   implementations' parsers the last, so {"b":[...],"b":null} would be a null
   body Recipe to some verifiers and signers and a real one to others. Every
   Recipe parse here goes through it. Free with dkim2_recipe_free(). */
struct cJSON *dkim2_recipe_parse(const char *r_json);
void dkim2_recipe_free(struct cJSON *root);

/* Structure-only validation of a body Recipe (same rules as apply, but no
   bounds check against a body, which may be unrecoverable below a null body
   Recipe). Returns 0 if well-formed (including null/absent "b"), -1 if not. */
int dkim2_validate_body_recipe(const char *r_json);

/* Apply a body Recipe (JSON string) to reconstruct the original body.
   body/bodylen: current (possibly modified) body.
   out_len: set to reconstructed body length.
   Returns malloc'd buffer (caller frees) or NULL on error. */
char *dkim2_apply_body_recipe(const char *r_json,
    const char *body, size_t bodylen, size_t *out_len);

/* Apply a header Recipe (JSON string) to reconstruct original headers.
   headers[]: array of "Name: value\r\n" strings (n entries).
   n_out: set to number of resulting headers.
   Returns new malloc'd array of malloc'd strings (caller frees each + array).
   Returns NULL on error. */
char **dkim2_apply_header_recipe(const char *r_json,
    char **headers, int n, int *n_out);

/* Generate a body Recipe JSON string (caller frees) that transforms
   old_body into new_body. Returns NULL on error.
   If the change cannot be expressed as a Recipe, sets *impossible = 1. */
char *dkim2_gen_body_recipe(
    const char *old_body, size_t old_len,
    const char *new_body, size_t new_len,
    int *impossible);

/* Generate a header Recipe JSON string (caller frees) expressing
   how to transform old_fields into new_fields for the named header. */
char *dkim2_gen_header_recipe(const char *field_name,
    char **old_fields, int n_old,
    char **new_fields, int n_new);
