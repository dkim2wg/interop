#include "dkim2_recipe.h"
#include "base64.h"
#include <cjson/cJSON.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

typedef struct { const char *ptr; size_t len; } line_t;

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
   same list (spec-06 §5.1; the same ascending/non-overlapping rule is applied
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

/* A "b" item is a JSON string holding the literal's raw octets as standard
   alphabet base64 (RFC 4648 §4): alphabet characters followed by at most two
   '=' and nothing else (no whitespace, no URL-safe alphabet). It is applied
   exactly like a "d" item once decoded. Returns the malloc'd octets and their
   length, or NULL for anything that is not clean base64 or whose decoded
   octets contain CR or LF (a literal is one line/value; a line break inside
   it would change the line numbering the rest of the Recipe depends on).
   The octets are otherwise arbitrary, so callers must carry `*len_out` and
   never strlen() the result. */
static unsigned char *decode_b_item(const cJSON *item, size_t *len_out) {
    if (!cJSON_IsString(item) || !item->valuestring) return NULL;
    const char *s = item->valuestring;
    size_t sl = strlen(s), i = 0, npad = 0;
    while (i < sl && is_b64_char(s[i])) i++;
    while (i < sl && s[i] == '=') { i++; npad++; }
    /* Canonical §4 form only: padded to a multiple of four ("QUI" is
       rejected, "QUI=" accepted), so every verifier decodes the same set. */
    if (i != sl || npad > 2 || sl % 4 != 0) return NULL;

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

/* Classify one Recipe step the same way for every walker: a "c" member wins,
   then a "d" array, then a "b" array. Returns 'c', 'd', 'b', or 0 for a step
   that carries none of them (silently ignored). *arr is the "c" value or the
   literal array. */
static int step_kind(const cJSON *step, const cJSON **arr) {
    const cJSON *c = cJSON_GetObjectItemCaseSensitive(step, "c");
    const cJSON *d = cJSON_GetObjectItemCaseSensitive(step, "d");
    const cJSON *bl = cJSON_GetObjectItemCaseSensitive(step, "b");
    if (c) { *arr = c; return 'c'; }
    if (d && cJSON_IsArray(d)) { *arr = d; return 'd'; }
    if (bl && cJSON_IsArray(bl)) { *arr = bl; return 'b'; }
    return 0;
}

/* Receives one literal's octets (not NUL-terminated for "b"); nonzero = fail. */
typedef int (*literal_fn)(void *ctx, const unsigned char *s, size_t len);

/* Validate every item of a "d" (kind 'd') or "b" (kind 'b') literal array and
   hand each to `fn` (NULL: validate only). Rejects (-1) an empty array
   (schema minItems 1), a "d" string containing CR/LF (§5.1/§5.2), a "b" item
   that is not clean base64 or decodes to CR/LF, and -- if `reject_nul` -- a
   "b" item with an embedded NUL. Non-string "d" items are skipped. */
static int walk_literals(const cJSON *arr, int kind, int reject_nul,
                         literal_fn fn, void *ctx) {
    if (cJSON_GetArraySize(arr) == 0) return -1;
    const cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        if (kind == 'd') {
            if (!cJSON_IsString(item)) continue;
            const char *s = item->valuestring;
            if (strpbrk(s, "\r\n")) return -1;
            if (fn && fn(ctx, (const unsigned char *)s, strlen(s)) != 0) return -1;
        } else {
            size_t dl;
            unsigned char *dec = decode_b_item(item, &dl);
            if (!dec) return -1;
            if ((reject_nul && memchr(dec, '\0', dl)) ||
                (fn && fn(ctx, dec, dl) != 0)) { free(dec); return -1; }
            free(dec);
        }
    }
    return 0;
}

/* Non-zero if any object in the tree names a key twice (cJSON unescapes the
   keys, so "subj\u0065ct" and "subject" are the same key). */
static int has_duplicate_key(const cJSON *node) {
    for (const cJSON *c = node ? node->child : NULL; c; c = c->next) {
        if (cJSON_IsObject(node) && c->string)
            for (const cJSON *d = c->next; d; d = d->next)
                if (d->string && strcmp(c->string, d->string) == 0) return 1;
        if (has_duplicate_key(c)) return 1;
    }
    return 0;
}

cJSON *dkim2_recipe_parse(const char *r_json) {
    cJSON *root = cJSON_Parse(r_json);
    if (root && has_duplicate_key(root)) {
        cJSON_Delete(root);
        return NULL;
    }
    return root;
}

void dkim2_recipe_free(cJSON *root) { cJSON_Delete(root); }

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
        } else if (kind) {
            if (walk_literals(arr, kind, 0, NULL, NULL) != 0) { rc = -1; break; }
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
        } else if (kind) {
            ok = (walk_literals(arr, kind, 0, body_literal, &acc) == 0);
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
   octets from a "b" item, so no printf-family formatting of the value). */
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
        /* draft-06 §5.1: a null header Recipe is no longer permitted. */
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
            } else if (kind) {
                hdr_acc_t ha = { fname, &new_vals, &n_new, &new_cap };
                /* Header fields travel as NUL-terminated strings through this
                   API, so an embedded NUL in a "b" item cannot be represented. */
                if (walk_literals(arr, kind, 1, header_literal, &ha) != 0) goto fail;
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
   literal step of the same kind. Any byte >= 0x80 forces a "b" item (base64
   of the raw octets): cJSON would otherwise copy the bytes straight into the
   JSON text, which has to stay 7-bit clean. Pure-ASCII literals stay "d".
   `*cur` is the open literal array (NULL after a "c" step), `*cur_is_b` its
   kind. */
static void add_literal(cJSON *steps, cJSON **cur, int *cur_is_b,
                        const char *p, size_t l) {
    int is_b = 0;
    for (size_t i = 0; i < l; i++)
        if ((unsigned char)p[i] >= 0x80) { is_b = 1; break; }

    if (!*cur || *cur_is_b != is_b) {
        cJSON *step = cJSON_CreateObject();
        *cur = cJSON_CreateArray();
        cJSON_AddItemToObject(step, is_b ? "b" : "d", *cur);
        cJSON_AddItemToArray(steps, step);
        *cur_is_b = is_b;
    }

    if (is_b) {
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

static int body_run(const line_t *nw, int ni, int n_new,
                    const line_t *od, int oi, int n_old) {
    int run = 0;
    while (ni + run < n_new && oi + run < n_old &&
           nw[ni + run].len == od[oi + run].len &&
           memcmp(nw[ni + run].ptr, od[oi + run].ptr, nw[ni + run].len) == 0)
        run++;
    return run;
}

char *dkim2_gen_body_recipe(
    const char *old_body, size_t old_len,
    const char *new_body, size_t new_len,
    int *impossible) {
    if (old_len == new_len && memcmp(old_body, new_body, old_len) == 0) {
        *impossible = 0;
        return strdup("{}");
    }

    int n_old = 0, n_new = 0;
    line_t *old_lines = split_lines(old_body, old_len, &n_old);
    line_t *new_lines = split_lines(new_body, new_len, &n_new);

    if (!old_lines || !new_lines) {
        free(old_lines); free(new_lines);
        *impossible = 1; return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *steps = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "b", steps);

    /* Copy ranges must ascend without overlapping across the list, so only
       old lines after the previous range's end are candidates; anything
       earlier is emitted literally (it still round-trips, just less
       compactly). */
    int ni = 0, prev_end = 0;
    cJSON *cur = NULL; int cur_is_b = 0;
    while (ni < n_new) {
        int best_old = -1, best_len_found = 0;
        for (int oi = prev_end; oi < n_old; oi++) {
            int run = body_run(new_lines, ni, n_new, old_lines, oi, n_old);
            if (run > best_len_found) { best_len_found = run; best_old = oi; }
        }

        if (best_len_found >= 2) {
            add_copy(steps, &cur, best_old + 1, best_old + best_len_found);
            prev_end = best_old + best_len_found;
            ni += best_len_found;
        } else {
            const char *p = new_lines[ni].ptr;
            size_t l = new_lines[ni].len;
            while (l > 0 && (p[l-1] == '\n' || p[l-1] == '\r')) l--;
            add_literal(steps, &cur, &cur_is_b, p, l);
            ni++;
        }
    }

    free(old_lines); free(new_lines);
    *impossible = 0;
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
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
    int ni = 0, prev_end = 0;
    cJSON *cur = NULL; int cur_is_b = 0;
    while (ni < n_new) {
        int best_old = -1, best_len_found = 0;
        for (int oi = prev_end; oi < n_old; oi++) {
            int run = 0;
            while (ni + run < n_new && oi + run < n_old &&
                   strcmp(new_fields[ni + run], old_fields[oi + run]) == 0)
                run++;
            if (run > best_len_found) { best_len_found = run; best_old = oi; }
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
                   §6.2 header hash unfolds and collapses WSP, so this is
                   hash-neutral) and the terminator with them. */
                size_t vl = strlen(val);
                char *s = malloc(vl + 1);
                if (s) {
                    size_t k = 0;
                    for (size_t j = 0; j < vl; j++)
                        if (val[j] != '\r' && val[j] != '\n') s[k++] = val[j];
                    add_literal(steps, &cur, &cur_is_b, s, k);
                    free(s);
                }
            }
            ni++;
        }
    }

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}
