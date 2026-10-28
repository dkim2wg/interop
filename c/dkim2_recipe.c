#include "dkim2_recipe.h"
#include "base64.h"
#include <cjson/cJSON.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <strings.h>

typedef dkim2_line_t line_t;

static line_t *split_lines(const char *body, size_t bodylen, int *n_out) {
    int cnt = 0;
    for (size_t i = 0; i < bodylen; i++)
        if (body[i] == '\n') cnt++;
    if (bodylen > 0 && body[bodylen - 1] != '\n') cnt++;

    line_t *lines = malloc((size_t)(cnt + 1) * sizeof(line_t));
    if (!lines) return NULL;
    int idx = 0;
    const char *p = body;
    const char *end = body + bodylen;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t ll = nl ? (size_t)(nl - p + 1) : (size_t)(end - p);
        lines[idx].ptr = p;
        lines[idx].len = ll;
        idx++;
        p = nl ? nl + 1 : end;
    }
    *n_out = idx;
    return lines;
}

static int buf_append(char **buf, size_t *pos, size_t *cap,
                      const char *data, size_t len) {
    if (*pos + len > *cap) {
        size_t newcap = *cap ? *cap * 2 : 4096;
        while (newcap < *pos + len) newcap *= 2;
        char *nb = realloc(*buf, newcap);
        if (!nb) return -1;
        *buf = nb;
        *cap = newcap;
    }
    memcpy(*buf + *pos, data, len);
    *pos += len;
    return 0;
}

/* ---- Recipe step validation (shared by the body and header appliers) ---- */

/* A "c" step is exactly two integers with 1 <= start <= end <= n_items, and
   its start MUST be greater than the end of every preceding "c" step in the
   same list (-08 §5.1; the same ascending/non-overlapping rule is applied
   to body lists -- WG extension, 2026-10). `prev_end` is the end of the
   previous "c" step, 0 when there is none.

   Anything else -- the bounds as JSON strings, which one list manager
   emitted; zero; a fraction; a range past the last item; a range that goes
   backwards or overlaps an earlier one -- is a malformed Recipe: return -1
   so the caller rejects the instance. cJSON reports valueint 0 for a string,
   so reading it unchecked made start -1 and indexed lines[-1]: a segfault on
   every such message (2026-10-04, replaying Sympa output). An end past the
   last item used to be silently clamped, which let a Recipe that disagreed
   with the message it was attached to "apply" and then fail on the hash. */
static int copy_range(const cJSON *c, int n_items, int prev_end,
                      int *start, int *end) {
    if (!c || !cJSON_IsArray(c) || cJSON_GetArraySize(c) != 2) return -1;
    const cJSON *a = cJSON_GetArrayItem(c, 0), *b = cJSON_GetArrayItem(c, 1);
    if (!cJSON_IsNumber(a) || !cJSON_IsNumber(b)) return -1;
    if (a->valuedouble != (double)a->valueint || b->valuedouble != (double)b->valueint) return -1;
    if (a->valueint < 1 || b->valueint < a->valueint) return -1;
    if (n_items >= 0 && b->valueint > n_items) return -1;  /* <0: no body to bound against */
    if (a->valueint <= prev_end) return -1;
    *start = a->valueint;
    *end = b->valueint;
    return 0;
}

static int is_b64_char(char ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
           (ch >= '0' && ch <= '9') || ch == '+' || ch == '/';
}

/* Strict UTF-8 (RFC 3629): no overlong forms, no surrogates, nothing above
   U+10FFFF. JSON strings are UTF-8, and -08 §5.1/§5.2 make "u" the step
   for anything else. */
static int utf8_valid(const unsigned char *s, size_t n) {
    for (size_t i = 0; i < n; ) {
        unsigned char c = s[i];
        size_t len;
        unsigned cp;
        if (c < 0x80) { i++; continue; }
        else if (c >= 0xC2 && c <= 0xDF) { len = 2; cp = c & 0x1F; }
        else if (c >= 0xE0 && c <= 0xEF) { len = 3; cp = c & 0x0F; }
        else if (c >= 0xF0 && c <= 0xF4) { len = 4; cp = c & 0x07; }
        else return 0;
        if (i + len > n) return 0;
        for (size_t k = 1; k < len; k++) {
            if ((s[i + k] & 0xC0) != 0x80) return 0;
            cp = (cp << 6) | (s[i + k] & 0x3F);
        }
        if ((len == 3 && cp < 0x800) || (len == 4 && (cp < 0x10000 || cp > 0x10FFFF)) ||
            (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
        i += len;
    }
    return 1;
}

/* The -08 §5 "base64-line" patterns: ^[A-Za-z0-9+/]*={0,2}$, ^(.{4})*$
   and ^([^=]*|.*[AQgw]==|.*[AEIMQUYcgkosw048]=)$ -- the standard alphabet,
   padded to a multiple of four, no whitespace, and zero pad bits ("QR==" is
   not canonical: its pad bits are not zero). */
static int b64_canonical(const char *s) {
    size_t sl = strlen(s), i = 0, npad = 0;
    while (i < sl && is_b64_char(s[i])) i++;
    size_t ndata = i;
    while (i < sl && s[i] == '=') { i++; npad++; }
    if (i != sl || npad > 2 || sl % 4 != 0) return 0;
    if (npad == 2 && !strchr("AQgw", s[ndata - 1])) return 0;
    if (npad == 1 && !strchr("AEIMQUYcgkosw048", s[ndata - 1])) return 0;
    return 1;
}

/* A "u" item (-08 §5.1/§5.2) is a JSON string holding the literal's raw
   octets as canonical base64 (b64_canonical). It is applied exactly like a
   "d" item once decoded. Returns the malloc'd octets and their length, or
   NULL for anything that is not canonical base64 or whose decoded octets
   contain CR or LF (a literal is one line/value; a line break inside it
   would change the line numbering the rest of the Recipe depends on). The
   octets are otherwise arbitrary, so callers must carry `*len_out` and
   never strlen() the result. */
static unsigned char *decode_u_item(const cJSON *item, size_t *len_out) {
    if (!cJSON_IsString(item) || !item->valuestring) return NULL;
    const char *s = item->valuestring;
    if (!b64_canonical(s)) return NULL;
    size_t sl = strlen(s);
    size_t cap = sl / 4 * 3 + 3;
    unsigned char *out = malloc(cap);
    if (!out) return NULL;
    int n = b64_decode(s, out, cap);
    if (n < 0) { free(out); return NULL; }
    for (int k = 0; k < n; k++)
        if (out[k] == '\r' || out[k] == '\n') { free(out); return NULL; }
    *len_out = (size_t)n;
    return out;
}

/* Classify one Recipe step (-08 §5.1/§5.2: "a JSON object with exactly one
   key"): 'c', 'd' or 'u', with *arr the "c" value or the literal array; -1
   for anything else -- not an object, no key, two keys, any other key, a
   "d"/"u" that is not an array. dkim2_recipe_parse() has already refused
   any key that is not lowercase. */
static int step_kind(const cJSON *step, const cJSON **arr) {
    if (!cJSON_IsObject(step)) return -1;
    const cJSON *only = step->child;
    if (!only || only->next || !only->string || strlen(only->string) != 1) return -1;
    int k = (unsigned char)only->string[0];
    if (k != 'c' && k != 'd' && k != 'u') return -1;
    if (k != 'c' && !cJSON_IsArray(only)) return -1;
    *arr = only;
    return k;
}

/* Receives one literal's octets (not NUL-terminated for "u"); nonzero = fail. */
typedef int (*literal_fn)(void *ctx, const unsigned char *s, size_t len);

/* Validate every item of a "d" (kind 'd') or "u" (kind 'u') literal array
   and hand each to `fn` (NULL: validate only). Rejects (-1) an empty array
   (schema minItems 1), a "d" item that is not a string, is not valid UTF-8
   or contains CR/LF (§5.1/§5.2), a "u" item that is not canonical base64 or
   decodes to CR/LF, and -- if `reject_nul` -- a "u" item with an embedded
   NUL. */
static int walk_literals(const cJSON *arr, int kind, int reject_nul,
                         literal_fn fn, void *ctx) {
    if (cJSON_GetArraySize(arr) == 0) return -1;
    const cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        if (kind == 'd') {
            if (!cJSON_IsString(item) || !item->valuestring) return -1;
            const char *s = item->valuestring;
            size_t sl = strlen(s);
            if (strpbrk(s, "\r\n") || !utf8_valid((const unsigned char *)s, sl)) return -1;
            if (fn && fn(ctx, (const unsigned char *)s, sl) != 0) return -1;
        } else {
            size_t dl;
            unsigned char *dec = decode_u_item(item, &dl);
            if (!dec) return -1;
            if ((reject_nul && memchr(dec, '\0', dl)) ||
                (fn && fn(ctx, dec, dl) != 0)) { free(dec); return -1; }
            free(dec);
        }
    }
    return 0;
}

/* Non-zero if a key holds an ASCII capital (-08 §5, contract D10: keys
   are strictly lowercase; a non-ASCII letter is not judged), after cJSON's
   unescaping ("S" is "S"). */
static int key_not_lowercase(const char *k) {
    for (; *k; k++)
        if (*k >= 'A' && *k <= 'Z') return 1;
    return 0;
}

static int cmp_key(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Non-zero if any object in the tree names a key twice (compared exactly,
   after unescaping: "subject" is "subject") or a key that is not
   lowercase. An object's keys are sorted to find a repeat, so a Recipe
   with thousands of keys costs n log n, not n squared. -1 on OOM. */
static int bad_keys(const cJSON *node) {
    int n = 0;
    for (const cJSON *c = node ? node->child : NULL; c; c = c->next) {
        if (cJSON_IsObject(node) && c->string) {
            if (key_not_lowercase(c->string)) return 1;
            n++;
        }
        int r = bad_keys(c);
        if (r) return r;
    }
    if (n < 2) return 0;
    const char **keys = malloc((size_t)n * sizeof *keys);
    if (!keys) return -1;
    int k = 0;
    for (const cJSON *c = node->child; c; c = c->next)
        if (c->string) keys[k++] = c->string;
    qsort(keys, (size_t)k, sizeof *keys, cmp_key);
    int dup = 0;
    for (int i = 1; i < k && !dup; i++)
        dup = strcmp(keys[i - 1], keys[i]) == 0;
    free(keys);
    return dup;
}

/* The whole-document checks that are judged from the text (contract D6,
   D10): the octets are UTF-8 (RFC 3629, so no encoded surrogate) with no
   NUL; no JSON number has a fraction or an exponent, wherever it is (JSON
   libraries disagree on whether 1e0 is an integer); and no "\u" escape is
   an unpaired surrogate. Anything else wrong with the text is cJSON's to
   find. 0, or -1. */
static int text_ok(const char *s, size_t len) {
    if (memchr(s, '\0', len) || !utf8_valid((const unsigned char *)s, len)) return -1;
    for (size_t i = 0; i < len; ) {
        char c = s[i];
        if (c == '"') {
            for (i++; i < len && s[i] != '"'; ) {
                if (s[i] != '\\') { i++; continue; }
                if (i + 1 < len && s[i + 1] == 'u' && i + 6 <= len) {
                    unsigned v = 0;
                    if (sscanf(s + i + 2, "%4x", &v) != 1) return -1;
                    i += 6;
                    if (v >= 0xDC00 && v <= 0xDFFF) return -1;     /* lone low */
                    if (v >= 0xD800 && v <= 0xDBFF) {              /* needs a low */
                        unsigned w = 0;
                        if (i + 6 > len || s[i] != '\\' || s[i + 1] != 'u' ||
                            sscanf(s + i + 2, "%4x", &w) != 1 || w < 0xDC00 || w > 0xDFFF)
                            return -1;
                        i += 6;
                    }
                } else {
                    i += 2;
                }
            }
            i++;
        } else if (c == '-' || (c >= '0' && c <= '9')) {
            for (; i < len && (s[i] == '-' || s[i] == '+' || s[i] == '.' ||
                               s[i] == 'e' || s[i] == 'E' || (s[i] >= '0' && s[i] <= '9')); i++)
                if (s[i] == '.' || s[i] == 'e' || s[i] == 'E') return -1;
        } else {
            i++;
        }
    }
    return 0;
}

/* The index of the first step of a list (a "b" array or one header
   field's array) that the -08 §5 schema or §5.1/§5.2 rejects, as the
   appliers read it but with no bound against any message; -1 when every
   step is good. reject_nul: a header value's "u" literal may not hold a
   NUL. */
static int first_bad_step(const cJSON *list, int reject_nul) {
    int prev_end = 0, idx = 0;
    const cJSON *step;
    cJSON_ArrayForEach(step, list) {
        const cJSON *arr;
        int kind = step_kind(step, &arr);
        if (kind == 'c') {
            int st, en;
            if (copy_range(arr, -1, prev_end, &st, &en) != 0) return idx;
            prev_end = en;
        } else if (kind < 0 || walk_literals(arr, kind, reject_nul, NULL, NULL) != 0) {
            return idx;
        }
        idx++;
    }
    return -1;
}

/* path: "h.<name>" then, with idx >= 0, "[<idx>]"; every octet of the
   name outside 0x21-0x7E written as \xHH (contract D6). */
static void header_path(char *path, size_t pathsz, const char *name, int idx) {
    size_t n = 0;
#define PUT(...) do { if (n < pathsz) { int w_ = snprintf(path + n, pathsz - n, __VA_ARGS__); \
                      if (w_ > 0) n += (size_t)w_; } } while (0)
    PUT("h.");
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        if (*p >= 0x21 && *p <= 0x7E) PUT("%c", *p);
        else PUT("\\x%02X", *p);
    }
    if (idx >= 0) PUT("[%d]", idx);
#undef PUT
}

/* The -08 §5 schema (contract D6). Whole document: an object with "h"
   and/or "b"; "h" an object with at least one property; "b" an array or
   null (unknown top-level keys are ignored). Then each step: "b" first,
   then the "h" fields in byte order of their names, each a list of steps.
   0; 1 for a whole-document fault; 2 for a bad step, with its path. */
static int validate_schema(const cJSON *root, char *path, size_t pathsz) {
    if (!cJSON_IsObject(root)) return 1;
    const cJSON *h = cJSON_GetObjectItemCaseSensitive(root, "h");
    const cJSON *b = cJSON_GetObjectItemCaseSensitive(root, "b");
    if (!h && !b) return 1;
    if (h && (!cJSON_IsObject(h) || !h->child)) return 1;
    if (b && !cJSON_IsNull(b) && !cJSON_IsArray(b)) return 1;

    int bad = b && cJSON_IsArray(b) ? first_bad_step(b, 0) : -1;
    if (bad >= 0) {
        if (path && pathsz) snprintf(path, pathsz, "b[%d]", bad);
        return 2;
    }
    const cJSON *first = NULL;
    int first_idx = -1;
    for (const cJSON *f = h ? h->child : NULL; f; f = f->next) {
        if (!f->string) return 1;
        if (first && strcmp(f->string, first->string) > 0) continue;   /* a later name */
        int idx = cJSON_IsArray(f) ? first_bad_step(f, 1) : -2;
        if (idx == -1) continue;
        first = f;
        first_idx = idx;
    }
    if (first) {
        if (path && pathsz) header_path(path, pathsz, first->string, first_idx >= 0 ? first_idx : -1);
        return 2;
    }
    return 0;
}

cJSON *dkim2_recipe_parse_ex(const char *r_json, size_t len, char *path, size_t pathsz) {
    if (path && pathsz) path[0] = '\0';
    if (text_ok(r_json, len) != 0) return NULL;
    /* len + 1: cJSON wants the terminating NUL inside the length to know
       that nothing follows the value. */
    cJSON *root = cJSON_ParseWithLengthOpts(r_json, len + 1, NULL, 1);
    if (!root) return NULL;
    if (bad_keys(root) || validate_schema(root, path, pathsz) != 0) {
        cJSON_Delete(root);
        return NULL;
    }
    return root;
}

cJSON *dkim2_recipe_parse(const char *r_json) {
    return dkim2_recipe_parse_ex(r_json, strlen(r_json), NULL, 0);
}

void dkim2_recipe_free(cJSON *root) { cJSON_Delete(root); }

typedef struct { dkim2_recipe_op_t *ops; int n, cap; } ops_acc_t;

static int ops_push(ops_acc_t *a, dkim2_recipe_op_t op) {
    if (a->n >= a->cap) {
        int nc = a->cap ? a->cap * 2 : 8;
        dkim2_recipe_op_t *no = realloc(a->ops, (size_t)nc * sizeof *no);
        if (!no) return -1;
        a->ops = no;
        a->cap = nc;
    }
    a->ops[a->n++] = op;
    return 0;
}

static int ops_literal(void *ctx, const unsigned char *s, size_t len) {
    unsigned char *c = malloc(len + 1);
    if (!c) return -1;
    memcpy(c, s, len);
    c[len] = '\0';
    dkim2_recipe_op_t op = { 1, 0, 0, c, len };
    if (ops_push(ctx, op) != 0) { free(c); return -1; }
    return 0;
}

void dkim2_recipe_ops_free(dkim2_recipe_op_t *ops, int n_ops) {
    for (int i = 0; i < n_ops; i++) free(ops[i].s);
    free(ops);
}

int dkim2_recipe_ops(const cJSON *list, int reject_nul,
                     dkim2_recipe_op_t **ops, int *n_ops) {
    ops_acc_t a = { NULL, 0, 0 };
    int prev_end = 0;
    const cJSON *step;
    *ops = NULL;
    *n_ops = 0;
    cJSON_ArrayForEach(step, list) {
        const cJSON *arr;
        int kind = step_kind(step, &arr);
        if (kind == 'c') {
            int st, en;
            if (copy_range(arr, -1, prev_end, &st, &en) != 0) goto fail;
            dkim2_recipe_op_t op = { 0, st, en, NULL, 0 };
            if (ops_push(&a, op) != 0) goto fail;
            prev_end = en;
        } else if (kind < 0 || walk_literals(arr, kind, reject_nul, ops_literal, &a) != 0) {
            goto fail;
        }
    }
    *ops = a.ops;
    *n_ops = a.n;
    return 0;
fail:
    dkim2_recipe_ops_free(a.ops, a.n);
    return -1;
}

int dkim2_validate_body_recipe(const char *r_json) {
    cJSON *root = dkim2_recipe_parse(r_json);
    if (!root) return -1;
    cJSON *b = cJSON_GetObjectItemCaseSensitive(root, "b");
    if (!b || cJSON_IsNull(b)) { cJSON_Delete(root); return 0; }
    if (!cJSON_IsArray(b)) { cJSON_Delete(root); return -1; }
    int prev_end = 0, rc = 0;
    cJSON *step;
    cJSON_ArrayForEach(step, b) {
        const cJSON *arr;
        int kind = step_kind(step, &arr);
        if (kind == 'c') {
            int st, en;
            if (copy_range(arr, -1, prev_end, &st, &en) != 0) { rc = -1; break; }
            prev_end = en;
        } else if (kind < 0 || walk_literals(arr, kind, 0, NULL, NULL) != 0) {
            rc = -1; break;
        }
    }
    cJSON_Delete(root);
    return rc;
}

typedef struct { char *out; size_t pos, cap; } body_acc_t;

static int body_literal(void *ctx, const unsigned char *s, size_t len) {
    body_acc_t *a = ctx;
    if (buf_append(&a->out, &a->pos, &a->cap, (const char *)s, len) != 0) return -1;
    return buf_append(&a->out, &a->pos, &a->cap, "\r\n", 2);
}

char *dkim2_apply_body_recipe(const char *r_json,
    const char *body, size_t bodylen, size_t *out_len) {
    cJSON *root = dkim2_recipe_parse(r_json);
    if (!root) return NULL;

    cJSON *b = cJSON_GetObjectItemCaseSensitive(root, "b");
    if (!b || cJSON_IsNull(b)) {
        cJSON_Delete(root);
        char *copy = malloc(bodylen + 1);
        if (!copy) return NULL;
        memcpy(copy, body, bodylen);
        copy[bodylen] = '\0';
        *out_len = bodylen;
        return copy;
    }

    if (!cJSON_IsArray(b)) { cJSON_Delete(root); return NULL; }

    int n_lines = 0;
    line_t *lines = split_lines(body, bodylen, &n_lines);
    if (!lines) { cJSON_Delete(root); return NULL; }

    body_acc_t acc = {NULL, 0, 0};
    int ok = 1;
    int prev_end = 0;

    cJSON *step;
    cJSON_ArrayForEach(step, b) {
        const cJSON *arr;
        int kind = step_kind(step, &arr);
        if (kind == 'c') {
            int start, end_i;
            if (copy_range(arr, n_lines, prev_end, &start, &end_i) != 0) { ok = 0; break; }
            for (int i = start - 1; i <= end_i - 1 && ok; i++)
                ok = (buf_append(&acc.out, &acc.pos, &acc.cap, lines[i].ptr, lines[i].len) == 0);
            prev_end = end_i;
        } else {
            ok = kind > 0 && walk_literals(arr, kind, 0, body_literal, &acc) == 0;
        }
        if (!ok) break;
    }

    free(lines);
    cJSON_Delete(root);

    if (!ok) { free(acc.out); return NULL; }
    if (acc.out) acc.out[acc.pos] = '\0';
    *out_len = acc.pos;
    return acc.out ? acc.out : calloc(1, 1);
}

static char **headers_for_name(char **headers, int n, const char *lname,
                                int *n_out) {
    /* `headers` is the caller's working array, which carries NULL holes where
       an earlier Recipe field was removed (they are only compacted away once
       every field has been processed), so both passes must skip them. */
    int cnt = 0;
    for (int i = 0; i < n; i++) {
        if (!headers[i]) continue;
        const char *colon = strchr(headers[i], ':');
        if (!colon) continue;
        size_t nl = (size_t)(colon - headers[i]);
        char tmp[128];
        if (nl >= sizeof tmp) continue;
        for (size_t j = 0; j < nl; j++) tmp[j] = (char)tolower((unsigned char)headers[i][j]);
        tmp[nl] = '\0';
        if (strcmp(tmp, lname) == 0) cnt++;
    }
    char **out = malloc((size_t)(cnt + 1) * sizeof(char *));
    if (!out) { *n_out = 0; return NULL; }
    int idx = 0;
    for (int i = n - 1; i >= 0; i--) {
        if (!headers[i]) continue;
        const char *colon = strchr(headers[i], ':');
        if (!colon) continue;
        size_t nl = (size_t)(colon - headers[i]);
        char tmp[128];
        if (nl >= sizeof tmp) continue;
        for (size_t j = 0; j < nl; j++) tmp[j] = (char)tolower((unsigned char)headers[i][j]);
        tmp[nl] = '\0';
        if (strcmp(tmp, lname) == 0) out[idx++] = headers[i];
    }
    out[idx] = NULL;
    *n_out = idx;
    return out;
}

/* "Name: value\r\n" from an explicit-length value (which may hold 8-bit
   octets from a "u" item, so no printf-family formatting of the value). */
static char *make_field(const char *fname, const unsigned char *val, size_t vlen) {
    size_t nl = strlen(fname);
    char *hdr = malloc(nl + 2 + vlen + 3);
    if (!hdr) return NULL;
    memcpy(hdr, fname, nl);
    hdr[nl] = ':';
    hdr[nl + 1] = ' ';
    memcpy(hdr + nl + 2, val, vlen);
    memcpy(hdr + nl + 2 + vlen, "\r\n", 2);
    hdr[nl + 2 + vlen + 2] = '\0';
    return hdr;
}

static int push_val(char ***vals, int *n, int *cap, char *v) {
    if (!v) return -1;
    if (*n >= *cap) {
        int nc = *cap ? *cap * 2 : 8;
        char **nv = realloc(*vals, (size_t)nc * sizeof(char *));
        if (!nv) { free(v); return -1; }
        *vals = nv;
        *cap = nc;
    }
    (*vals)[(*n)++] = v;
    return 0;
}

typedef struct { const char *fname; char ***vals; int *n, *cap; } hdr_acc_t;

static int header_literal(void *ctx, const unsigned char *s, size_t len) {
    hdr_acc_t *a = ctx;
    return push_val(a->vals, a->n, a->cap, make_field(a->fname, s, len));
}

char **dkim2_apply_header_recipe(const char *r_json,
    char **headers, int n, int *n_out) {
    cJSON *root = dkim2_recipe_parse(r_json);
    if (!root) return NULL;

    cJSON *h = cJSON_GetObjectItemCaseSensitive(root, "h");
    if (h && cJSON_IsNull(h)) {
        /* -08 §5.1: a null header Recipe is no longer permitted. */
        cJSON_Delete(root);
        return NULL;
    }
    if (!h || !cJSON_IsObject(h)) {
        cJSON_Delete(root);
        char **out = malloc((size_t)(n + 1) * sizeof(char *));
        if (!out) return NULL;
        for (int i = 0; i < n; i++) out[i] = strdup(headers[i]);
        out[n] = NULL;
        *n_out = n;
        return out;
    }

    int working_cap = n + 64;
    char **working = malloc((size_t)working_cap * sizeof(char *));
    if (!working) { cJSON_Delete(root); return NULL; }
    int working_n = n;
    for (int i = 0; i < n; i++) working[i] = strdup(headers[i]);

    char **field_hdrs = NULL;
    char **new_vals = NULL;
    int n_new = 0, new_cap = 0;

    cJSON *field;
    cJSON_ArrayForEach(field, h) {
        const char *fname = field->string;
        if (!fname || !cJSON_IsArray(field)) continue;

        int n_field = 0;
        field_hdrs = headers_for_name(working, working_n, fname, &n_field);
        if (!field_hdrs) goto fail;

        new_vals = NULL;
        n_new = 0; new_cap = 0;
        int prev_end = 0;

        cJSON *step;
        cJSON_ArrayForEach(step, field) {
            const cJSON *arr;
            int kind = step_kind(step, &arr);
            if (kind == 'c') {
                int start, end_i;
                /* Malformed Recipe: reject the whole instance. */
                if (copy_range(arr, n_field, prev_end, &start, &end_i) != 0) goto fail;
                for (int i = start - 1; i <= end_i - 1; i++)
                    if (push_val(&new_vals, &n_new, &new_cap, strdup(field_hdrs[i])) != 0) goto fail;
                prev_end = end_i;
            } else {
                hdr_acc_t ha = { fname, &new_vals, &n_new, &new_cap };
                /* Header fields travel as NUL-terminated strings through this
                   API, so an embedded NUL in a "u" item cannot be represented. */
                if (kind < 0 || walk_literals(arr, kind, 1, header_literal, &ha) != 0) goto fail;
            }
        }
        free(field_hdrs);
        field_hdrs = NULL;

        /* Remove existing instances of fname */
        for (int i = 0; i < working_n; i++) {
            if (!working[i]) continue;
            const char *colon = strchr(working[i], ':');
            if (!colon) continue;
            size_t nl = (size_t)(colon - working[i]);
            char tmp[128];
            if (nl >= sizeof tmp) continue;
            for (size_t j = 0; j < nl; j++) tmp[j] = (char)tolower((unsigned char)working[i][j]);
            tmp[nl] = '\0';
            if (strcmp(tmp, fname) == 0) { free(working[i]); working[i] = NULL; }
        }

        /* Append new_vals in reverse (bottom-up → natural top-down order) */
        for (int i = n_new - 1; i >= 0; i--) {
            if (working_n >= working_cap) {
                working_cap *= 2;
                working = realloc(working, (size_t)working_cap * sizeof(char *));
            }
            working[working_n++] = new_vals[i];
        }
        free(new_vals);
        new_vals = NULL;
    }

    cJSON_Delete(root);

    int out_n = 0;
    for (int i = 0; i < working_n; i++)
        if (working[i]) working[out_n++] = working[i];
    working[out_n] = NULL;
    *n_out = out_n;
    return working;

fail:
    for (int i = 0; i < n_new; i++) free(new_vals[i]);
    free(new_vals);
    free(field_hdrs);
    for (int i = 0; i < working_n; i++) free(working[i]);
    free(working);
    cJSON_Delete(root);
    return NULL;
}

/* ---- Recipe generation ---- */

/* Append one literal (a body line or a header value, without its line
   terminator) to `steps`, coalescing with the previous step when that is a
   literal step of the same kind. A literal that is valid UTF-8 is a "d"
   item (-08 §5: "u" SHOULD NOT be used when "d" would suffice); anything
   else -- and a literal holding a NUL, which a cJSON string cannot carry --
   is a "u" item, the canonical base64 of the raw octets. `*cur` is the open
   literal array (NULL after a "c" step), `*cur_is_u` its kind. */
static void add_literal(cJSON *steps, cJSON **cur, int *cur_is_u,
                        const char *p, size_t l) {
    int is_u = !utf8_valid((const unsigned char *)p, l) || memchr(p, '\0', l) != NULL;

    if (!*cur || *cur_is_u != is_u) {
        cJSON *step = cJSON_CreateObject();
        *cur = cJSON_CreateArray();
        cJSON_AddItemToObject(step, is_u ? "u" : "d", *cur);
        cJSON_AddItemToArray(steps, step);
        *cur_is_u = is_u;
    }

    if (is_u) {
        size_t cap = (l + 2) / 3 * 4 + 1;
        char *enc = malloc(cap);
        if (!enc) return;
        if (b64_encode((const unsigned char *)p, l, enc, cap) >= 0)
            cJSON_AddItemToArray(*cur, cJSON_CreateString(enc));
        free(enc);
    } else {
        char *s = malloc(l + 1);
        if (!s) return;
        memcpy(s, p, l); s[l] = '\0';
        cJSON_AddItemToArray(*cur, cJSON_CreateString(s));
        free(s);
    }
}

static void add_copy(cJSON *steps, cJSON **cur, int start, int end) {
    cJSON *step = cJSON_CreateObject();
    cJSON *c = cJSON_CreateArray();
    cJSON_AddItemToArray(c, cJSON_CreateNumber(start));
    cJSON_AddItemToArray(c, cJSON_CreateNumber(end));
    cJSON_AddItemToObject(step, "c", c);
    cJSON_AddItemToArray(steps, step);
    *cur = NULL;
}

/* ---- Capped Myers body diff ----
   A direct port of "Exact pseudocode (normative for every port)" in
   docs/superpowers/specs/2026-10-09-capped-myers-body-diff-design.md; the
   comments name the pseudocode's variables. Every implementation must make
   the same tie-breaks so that all produce identical recipes
   (vectors/body-diff.json). */

static int line_eq(const line_t *x, const line_t *y) {
    return x->len == y->len && memcmp(x->ptr, y->ptr, x->len) == 0;
}

static uint64_t line_hash(const line_t *l) {
    uint64_t h = 1469598103934665603ULL;               /* FNV-1a */
    for (size_t i = 0; i < l->len; i++) {
        h ^= (unsigned char)l->ptr[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* Intern the n lines of `ls` into `ids` (equal lines, equal ids) using the
   open-addressed table `slot` (size mask+1, -1 = empty) whose entries index
   `rep`, the first line seen with each id. Returns the new id count. */
static int intern_lines(const line_t *ls, int n, int *ids, int *slot,
                        size_t mask, const line_t **rep, int nid) {
    for (int i = 0; i < n; i++) {
        size_t h = (size_t)line_hash(&ls[i]) & mask;
        for (;;) {
            int s = slot[h];
            if (s < 0) { slot[h] = nid; rep[nid] = &ls[i]; ids[i] = nid++; break; }
            if (line_eq(rep[s], &ls[i])) { ids[i] = s; break; }
            h = (h + 1) & mask;
        }
    }
    return nid;
}

int dkim2_body_diff(const line_t *cur, int C, const line_t *prev, int P,
                    int L, dkim2_diff_step_t **steps_out, int *n_steps_out) {
    int pre = 0;
    while (pre < C && pre < P && line_eq(&cur[pre], &prev[pre])) pre++;
    if (pre == C && pre == P) return DKIM2_DIFF_IDENTICAL;
    int suf = 0;
    while (suf < C - pre && suf < P - pre &&
           line_eq(&cur[C - 1 - suf], &prev[P - 1 - suf])) suf++;

    const line_t *a = cur + pre, *b = prev + pre;
    int n = C - pre - suf, m = P - pre - suf;

    int rc = DKIM2_DIFF_ERROR;
    int *ida = NULL, *idb = NULL, *slot = NULL, *cnt_a = NULL, *cnt_b = NULL;
    int *A = NULL, *ai = NULL, *B = NULL, *bj = NULL, *match = NULL;
    int *V = NULL, *trace = NULL, *src = NULL;
    size_t *trace_off = NULL;
    const line_t **rep = NULL;
    dkim2_diff_step_t *steps = NULL;

    /* Intern a and b to integer ids and count occurrences. */
    size_t tsize = 16;
    while (tsize < 2 * (size_t)(n + m) + 1) tsize <<= 1;
    ida = malloc(((size_t)n + 1) * sizeof *ida);
    idb = malloc(((size_t)m + 1) * sizeof *idb);
    slot = malloc(tsize * sizeof *slot);
    rep = malloc(((size_t)(n + m) + 1) * sizeof *rep);
    if (!ida || !idb || !slot || !rep) goto out;
    memset(slot, 0xff, tsize * sizeof *slot);
    int nid = intern_lines(a, n, ida, slot, tsize - 1, rep, 0);
    nid = intern_lines(b, m, idb, slot, tsize - 1, rep, nid);
    cnt_a = calloc((size_t)nid + 1, sizeof *cnt_a);
    cnt_b = calloc((size_t)nid + 1, sizeof *cnt_b);
    if (!cnt_a || !cnt_b) goto out;
    for (int i = 0; i < n; i++) cnt_a[ida[i]]++;
    for (int j = 0; j < m; j++) cnt_b[idb[j]]++;

    /* Discard lines that cannot be in the LCS. */
    A = malloc(((size_t)n + 1) * sizeof *A);
    ai = malloc(((size_t)n + 1) * sizeof *ai);
    B = malloc(((size_t)m + 1) * sizeof *B);
    bj = malloc(((size_t)m + 1) * sizeof *bj);
    match = malloc(((size_t)m + 1) * sizeof *match);
    if (!A || !ai || !B || !bj || !match) goto out;
    int N = 0, M = 0;
    for (int i = 0; i < n; i++)
        if (cnt_b[ida[i]] > 0) { A[N] = ida[i]; ai[N] = i; N++; }
    for (int j = 0; j < m; j++)
        if (cnt_a[idb[j]] > 0) { B[M] = idb[j]; bj[M] = j; M++; }
    long long u = m - M;
    long long floor_lits = u;
    for (int id = 0; id < nid; id++)
        if (cnt_a[id] > 0 && cnt_b[id] > cnt_a[id]) floor_lits += cnt_b[id] - cnt_a[id];
    if (floor_lits > L) { rc = DKIM2_DIFF_TOO_BIG; goto out; }

    for (int y = 0; y < M; y++) match[y] = -1;
    if (N > 0 && M > 0) {
        long long dmax_ll = (long long)N - M + 2 * ((long long)L - u);
        if (dmax_ll > (long long)N + M) dmax_ll = (long long)N + M;
        if (dmax_ll < 0) { rc = DKIM2_DIFF_TOO_BIG; goto out; }
        int dmax = (int)dmax_ll;
        /* V[k] for k in [-dmax-1, dmax+1]: stored at V[k + off]. */
        int off = dmax + 1;
        V = calloc(2 * (size_t)dmax + 3, sizeof *V);
        trace_off = malloc(((size_t)dmax + 1) * sizeof *trace_off);
        if (!V || !trace_off) goto out;
        /* trace[d] keeps only k in [-d-1, d+1] (2d+3 values), packed:
           trace[d][k] = trace[trace_off[d] + k + d + 1]. */
        size_t tlen = 0, tcap = 0;
        long long work = 0;
        int D = -1;
        for (int d = 0; d <= dmax && D < 0; d++) {
            size_t need = tlen + 2 * (size_t)d + 3;
            if (need > tcap) {
                size_t nc = tcap ? tcap : 1024;
                while (nc < need) nc *= 2;
                int *nt = realloc(trace, nc * sizeof *nt);
                if (!nt) goto out;
                trace = nt; tcap = nc;
            }
            trace_off[d] = tlen;
            memcpy(trace + tlen, V + off - d - 1, (2 * (size_t)d + 3) * sizeof *V);
            tlen = need;
            for (int k = -d; k <= d; k += 2) {
                int x;
                if (k == -d || (k != d && V[off + k - 1] < V[off + k + 1]))
                    x = V[off + k + 1];                 /* down */
                else
                    x = V[off + k - 1] + 1;             /* right */
                int y = x - k;
                while (x < N && y < M && A[x] == B[y]) { x++; y++; work++; }
                V[off + k] = x;
                if (++work > DKIM2_MAX_DIFF_WORK) { rc = DKIM2_DIFF_TOO_BIG; goto out; }
                if (x == N && y == M) { D = d; break; }
            }
        }
        if (D < 0) { rc = DKIM2_DIFF_TOO_BIG; goto out; }

        /* FOUND(D): backtrack. */
        int x = N, y = M;
        for (int d = D; d >= 1; d--) {
            const int *T = trace + trace_off[d] + d + 1;   /* T[k], k in [-d-1, d+1] */
            int k = x - y;
            int down = (k == -d || (k != d && T[k - 1] < T[k + 1]));
            int pk = down ? k + 1 : k - 1;
            int px = T[pk], py = px - pk;
            int sx = down ? px : px + 1;
            while (x > sx) { x--; y--; match[y] = x; }
            x = px; y = py;
        }
        while (x > 0) { x--; y--; match[y] = x; }
    }

    /* src[j]: the cur line (0-based) that previous line j copies, or -1. */
    src = malloc(((size_t)P + 1) * sizeof *src);
    steps = malloc(((size_t)P + 1) * sizeof *steps);
    if (!src || !steps) goto out;
    for (int j = 0; j < P; j++)
        src[j] = j < pre ? j : j >= P - suf ? j - P + C : -1;
    for (int y = 0; y < M; y++)
        if (match[y] >= 0) src[pre + bj[y]] = pre + ai[match[y]];

    int ns = 0, literals = 0;
    for (int j = 0; j < P; j++) {
        int i = src[j];
        if (i < 0) {
            steps[ns++] = (dkim2_diff_step_t){ 1, j, j };
            literals++;
        } else if (ns > 0 && !steps[ns - 1].lit && steps[ns - 1].to == i) {
            steps[ns - 1].to = i + 1;
        } else {
            steps[ns++] = (dkim2_diff_step_t){ 0, i + 1, i + 1 };
        }
    }
    if (literals > L) { rc = DKIM2_DIFF_TOO_BIG; goto out; }   /* cannot happen */

    *steps_out = steps; steps = NULL;
    *n_steps_out = ns;
    rc = DKIM2_DIFF_OK;

out:
    free(ida); free(idb); free(slot); free(rep); free(cnt_a); free(cnt_b);
    free(A); free(ai); free(B); free(bj); free(match);
    free(V); free(trace); free(trace_off); free(src); free(steps);
    return rc;
}

char *dkim2_gen_body_recipe(
    const char *old_body, size_t old_len,
    const char *new_body, size_t new_len,
    int *impossible) {
    return dkim2_gen_body_recipe_ex(old_body, old_len, new_body, new_len,
                                    DKIM2_MAX_RECIPE_LITERALS, impossible);
}

char *dkim2_gen_body_recipe_ex(
    const char *old_body, size_t old_len,
    const char *new_body, size_t new_len,
    int max_literals, int *impossible) {
    if (max_literals <= 0) max_literals = DKIM2_MAX_RECIPE_LITERALS;
    *impossible = 0;
    if (old_len == new_len && memcmp(old_body, new_body, old_len) == 0)
        return strdup("{}");

    /* old_body is the current body (the copy source); new_body is the
       previous body the Recipe rebuilds. */
    int n_old = 0, n_new = 0;
    line_t *old_lines = split_lines(old_body, old_len, &n_old);
    line_t *new_lines = split_lines(new_body, new_len, &n_new);
    dkim2_diff_step_t *ds = NULL;
    int nds = 0;
    int rc = (old_lines && new_lines)
        ? dkim2_body_diff(old_lines, n_old, new_lines, n_new,
                          max_literals, &ds, &nds)
        : DKIM2_DIFF_ERROR;

    char *json = NULL;
    if (rc == DKIM2_DIFF_IDENTICAL) {
        json = strdup("{}");
    } else if (rc == DKIM2_DIFF_TOO_BIG) {
        /* Too many literal lines (or too much work): the null body Recipe,
           body unrecoverable. */
        *impossible = 1;
        json = strdup("{\"b\":null}");
    } else if (rc == DKIM2_DIFF_OK) {
        cJSON *root = cJSON_CreateObject();
        cJSON *steps = cJSON_CreateArray();
        cJSON_AddItemToObject(root, "b", steps);
        cJSON *cur = NULL; int cur_is_u = 0;
        for (int s = 0; s < nds; s++) {
            if (!ds[s].lit) {
                add_copy(steps, &cur, ds[s].from, ds[s].to);
            } else {
                const char *p = new_lines[ds[s].from].ptr;
                size_t l = new_lines[ds[s].from].len;
                while (l > 0 && (p[l-1] == '\n' || p[l-1] == '\r')) l--;
                add_literal(steps, &cur, &cur_is_u, p, l);
            }
        }
        json = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
    }
    if (!json) *impossible = 1;
    free(ds); free(old_lines); free(new_lines);
    return json;
}

/* blk_end[i]: one past the last of the consecutive fields identical to f[i]. */
static int *blk_ends(char **f, int n) {
    int *e = n ? malloc((size_t)n * sizeof *e) : NULL;
    if (!e) return NULL;
    for (int i = n - 1; i >= 0; i--)
        e[i] = (i + 1 < n && strcmp(f[i], f[i + 1]) == 0) ? e[i + 1] : i + 1;
    return e;
}

/* Length of the match of new[ni..] against old[oi..], a run at a time. */
static int match_run(char **nf, int n_new, const int *nend, int ni,
                     char **of, int n_old, const int *oend, int oi) {
    int run = 0;
    while (ni + run < n_new && oi + run < n_old &&
           strcmp(nf[ni + run], of[oi + run]) == 0) {
        int a = nend[ni + run] - (ni + run), b = oend[oi + run] - (oi + run);
        run += a < b ? a : b;
    }
    return run;
}

char *dkim2_gen_header_recipe(const char *field_name,
    char **old_fields, int n_old,
    char **new_fields, int n_new) {
    cJSON *root = cJSON_CreateObject();
    cJSON *h = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "h", h);
    cJSON *steps = cJSON_CreateArray();
    char lname[128];
    size_t i;
    for (i = 0; field_name[i] && i < sizeof lname - 1; i++)
        lname[i] = (char)tolower((unsigned char)field_name[i]);
    lname[i] = '\0';
    cJSON_AddItemToObject(h, lname, steps);

    /* As for the body: a field instance that matches an old one at or below
       the previous copy range's end (reordered duplicates, say) is emitted as
       a literal rather than as a range that would go backwards. */
    /* Linear in repeated identical fields (16,000 identical Comments:, say):
       blk_end[i] is one past the run of fields identical to field i. Matching
       fields inside two such runs match for the shorter remaining run, so a
       match extends a whole run at a time; and within one run of old fields
       only two start points can give the first longest match -- the run's
       first field, and the one leaving exactly the new run's length (where
       the match can carry on past both runs). Same result as trying every
       start point. */
    int *oend = blk_ends(old_fields, n_old), *nend = blk_ends(new_fields, n_new);
    if ((n_old && !oend) || (n_new && !nend)) {
        free(oend); free(nend); cJSON_Delete(root); return NULL;
    }
    int ni = 0, prev_end = 0;
    cJSON *cur = NULL; int cur_is_u = 0;
    while (ni < n_new) {
        int best_old = -1, best_len_found = 0;
        for (int oi = prev_end; oi < n_old && best_len_found < n_new - ni; ) {
            int bend = oend[oi], cand[2] = { oi, -1 }, a = nend[ni] - ni;
            if (bend - a > oi) cand[1] = bend - a;
            for (int c = 0; c < 2 && cand[c] >= 0; c++) {
                int run = match_run(new_fields, n_new, nend, ni,
                                    old_fields, n_old, oend, cand[c]);
                if (run > best_len_found) { best_len_found = run; best_old = cand[c]; }
            }
            oi = bend;
        }

        if (best_len_found >= 1) {
            add_copy(steps, &cur, best_old + 1, best_old + best_len_found);
            prev_end = best_old + best_len_found;
            ni += best_len_found;
        } else {
            const char *val = strchr(new_fields[ni], ':');
            if (val) {
                val++;
                while (*val == ' ') val++;
                /* A literal is one unfolded value: drop every CR/LF (the
                   -08 §6.2 header hash unfolds and collapses WSP, so this is
                   hash-neutral) and the terminator with them. */
                size_t vl = strlen(val);
                char *s = malloc(vl + 1);
                if (s) {
                    size_t k = 0;
                    for (size_t j = 0; j < vl; j++)
                        if (val[j] != '\r' && val[j] != '\n') s[k++] = val[j];
                    add_literal(steps, &cur, &cur_is_u, s, k);
                    free(s);
                }
            }
            ni++;
        }
    }

    free(oend); free(nend);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}
