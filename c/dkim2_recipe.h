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

/* ---- Capped Myers body diff (docs/superpowers/specs/
   2026-10-09-capped-myers-body-diff-design.md, "Exact pseudocode") ---- */

#define DKIM2_MAX_RECIPE_LITERALS 1000
#define DKIM2_MAX_DIFF_WORK       4000000

/* One line (compared as an exact byte string, terminator included if the
   caller's splitter keeps it). */
typedef struct { const char *ptr; size_t len; } dkim2_line_t;

/* A flat recipe step: lit == 0 is a copy of cur lines from..to (1-based,
   inclusive); lit == 1 is previous-body line `from` (0-based) as a literal. */
typedef struct { int lit; int from, to; } dkim2_diff_step_t;

enum {
    DKIM2_DIFF_ERROR     = -1,  /* allocation failure */
    DKIM2_DIFF_OK        = 0,   /* *steps / *n_steps set (caller frees *steps) */
    DKIM2_DIFF_IDENTICAL = 1,   /* cur == prev: no recipe */
    DKIM2_DIFF_TOO_BIG   = 2    /* over max_literals or DKIM2_MAX_DIFF_WORK */
};

/* Recipe rebuilding prev[] from cur[] with at most max_literals literal
   lines. *steps is only set (malloc'd, possibly with *n_steps == 0) on
   DKIM2_DIFF_OK. */
int dkim2_body_diff(const dkim2_line_t *cur, int n_cur,
                    const dkim2_line_t *prev, int n_prev, int max_literals,
                    dkim2_diff_step_t **steps, int *n_steps);

/* Generate a body Recipe JSON string (caller frees) that rebuilds new_body
   (the PREVIOUS body) from old_body (the CURRENT body). Lines keep their
   terminators for comparison; literal text drops trailing CR/LF. Identical
   bodies give "{}". When the diff needs more than DKIM2_MAX_RECIPE_LITERALS
   (see dkim2_gen_body_recipe_ex for another cap) literal lines or exceeds DKIM2_MAX_DIFF_WORK, returns the null body Recipe
   "{\"b\":null}" and sets *impossible = 1. Returns NULL (with
   *impossible = 1) on allocation failure. */
char *dkim2_gen_body_recipe(
    const char *old_body, size_t old_len,
    const char *new_body, size_t new_len,
    int *impossible);

/* As dkim2_gen_body_recipe, with the literal-line cap given explicitly;
   max_literals <= 0 means DKIM2_MAX_RECIPE_LITERALS. */
char *dkim2_gen_body_recipe_ex(
    const char *old_body, size_t old_len,
    const char *new_body, size_t new_len,
    int max_literals, int *impossible);

/* Generate a header Recipe JSON string (caller frees) expressing
   how to transform old_fields into new_fields for the named header. */
char *dkim2_gen_header_recipe(const char *field_name,
    char **old_fields, int n_old,
    char **new_fields, int n_new);
