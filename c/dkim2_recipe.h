#pragma once
#include <stddef.h>

/* Recipe steps (-08 §5, §5.1, §5.2); each step is an object with exactly
   one key:
     {"c": [start, end]}  copy items start..end (1-based, inclusive); across
                          a list each start MUST exceed the previous end
     {"d": [str, ...]}    literal lines/values: UTF-8 JSON strings, no CR/LF
     {"u": [b64, ...]}    literal lines/values whose raw octets are canonical
                          base64 (zero pad bits, no whitespace) -- used for a
                          literal that is not valid UTF-8; decoded octets
                          MUST NOT contain CR or LF
   Keys are strictly lowercase (-08, contract D10). A Recipe
   that breaks the schema is rejected by dkim2_recipe_parse() (the verifier's
   "contains invalid JSON" for the document as a whole, "Recipe <path> is
   invalid" for one step: dkim2_recipe_parse_ex); one that only fails against the message (a copy
   past the last item) makes the apply_* functions return NULL -- reported
   as "contains invalid JSON" as well. The gen_*
   functions emit "d" for every UTF-8 literal and "u" for the rest, and never
   a "c" range that breaks the ascending rule. */

/* cJSON_Parse() of a Recipe, refusing (NULL) one that is not valid -08 §5
   JSON: a key holding an ASCII capital (contract D10), or a key named
   twice in one object, compared exactly after unescaping (cJSON keeps the first of two equal keys and the other implementations'
   parsers the last, so {"b":[...],"b":null} would be a null body Recipe to
   some verifiers and signers and a real one to others), or anything the
   schema forbids -- not an object, neither "h" nor "b", an empty "h", a step
   without exactly one of "c"/"d"/"u", a malformed literal or copy range.
   Every Recipe parse here goes through it. Free with dkim2_recipe_free(). */
struct cJSON *dkim2_recipe_parse(const char *r_json);
/* As dkim2_recipe_parse, for len octets of JSON text (which may hold a
   NUL, which makes it invalid; r_json[len] must be the terminating NUL).
   On failure path (pathsz > 0) gets "" when
   the document as a whole is at fault -- "contains invalid JSON" -- or the
   first bad step's path, "b[<n>]", "h.<name>[<n>]" or "h.<name>" (a header
   entry that is not an array), name octets outside 0x21-0x7E written as
   \xHH: "Recipe <path> is invalid" (-08 §14.2, contract D6). Every
   whole-document check is made before any step check. */
struct cJSON *dkim2_recipe_parse_ex(const char *r_json, size_t len, char *path, size_t pathsz);
void dkim2_recipe_free(struct cJSON *root);

/* Structure-only validation of a body Recipe (same rules as apply, but no
   bounds check against a body, which may be unrecoverable below a null body
   Recipe). Returns 0 if well-formed (including null/absent "b"), -1 if not. */
int dkim2_validate_body_recipe(const char *r_json);

/* One step of a Recipe list, flattened: lit == 0 copies items from..to
   (1-based, inclusive) of the list it applies to; lit == 1 is one literal
   line/value (s, len: its octets, without CR/LF, NUL-terminated as well). */
typedef struct {
    int lit;
    int from, to;
    unsigned char *s;
    size_t len;
} dkim2_recipe_op_t;

/* Flatten one Recipe list -- the body ("b") array or one header field's array --
   exactly as the apply_* functions read it (same step classification, same
   literal and copy-range rules), but with no bounds check: the caller
   compares the last copy's end against the list the Recipe applies to.
   reject_nul: refuse a "u" literal with an embedded NUL (header values).
   Returns 0 with *ops (malloc'd, free with dkim2_recipe_ops_free) and
   *n_ops set, or -1 for a malformed list (*ops NULL). */
int dkim2_recipe_ops(const struct cJSON *list, int reject_nul,
                     dkim2_recipe_op_t **ops, int *n_ops);
void dkim2_recipe_ops_free(dkim2_recipe_op_t *ops, int n_ops);

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
