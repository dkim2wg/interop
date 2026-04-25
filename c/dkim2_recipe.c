#include "dkim2_recipe.h"
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

char *dkim2_apply_body_recipe(const char *r_json,
    const char *body, size_t bodylen, size_t *out_len) {
    cJSON *root = cJSON_Parse(r_json);
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

    char *out = NULL;
    size_t pos = 0, cap = 0;
    int ok = 1;

    cJSON *step;
    cJSON_ArrayForEach(step, b) {
        cJSON *c = cJSON_GetObjectItemCaseSensitive(step, "c");
        cJSON *d = cJSON_GetObjectItemCaseSensitive(step, "d");

        if (c && cJSON_IsArray(c) && cJSON_GetArraySize(c) == 2) {
            int start = cJSON_GetArrayItem(c, 0)->valueint - 1;
            int end_i = cJSON_GetArrayItem(c, 1)->valueint - 1;
            for (int i = start; i <= end_i && i < n_lines && ok; i++)
                ok = (buf_append(&out, &pos, &cap, lines[i].ptr, lines[i].len) == 0);
        } else if (d && cJSON_IsArray(d)) {
            cJSON *item;
            cJSON_ArrayForEach(item, d) {
                if (!cJSON_IsString(item)) continue;
                const char *s = item->valuestring;
                ok = ok && (buf_append(&out, &pos, &cap, s, strlen(s)) == 0);
                ok = ok && (buf_append(&out, &pos, &cap, "\r\n", 2) == 0);
            }
        }
    }

    free(lines);
    cJSON_Delete(root);

    if (!ok) { free(out); return NULL; }
    if (out) out[pos] = '\0';
    *out_len = pos;
    return out ? out : calloc(1, 1);
}

static char **headers_for_name(char **headers, int n, const char *lname,
                                int *n_out) {
    int cnt = 0;
    for (int i = 0; i < n; i++) {
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

char **dkim2_apply_header_recipe(const char *r_json,
    char **headers, int n, int *n_out) {
    cJSON *root = cJSON_Parse(r_json);
    if (!root) return NULL;

    cJSON *h = cJSON_GetObjectItemCaseSensitive(root, "h");
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

    cJSON *field;
    cJSON_ArrayForEach(field, h) {
        const char *fname = field->string;
        if (!fname || !cJSON_IsArray(field)) continue;

        int n_field = 0;
        char **field_hdrs = headers_for_name(working, working_n, fname, &n_field);

        char **new_vals = NULL;
        int n_new = 0, new_cap = 0;

        cJSON *step;
        cJSON_ArrayForEach(step, field) {
            cJSON *c = cJSON_GetObjectItemCaseSensitive(step, "c");
            cJSON *d = cJSON_GetObjectItemCaseSensitive(step, "d");

            if (c && cJSON_IsArray(c) && cJSON_GetArraySize(c) == 2) {
                int start = cJSON_GetArrayItem(c, 0)->valueint - 1;
                int end_i = cJSON_GetArrayItem(c, 1)->valueint - 1;
                for (int i = start; i <= end_i && i < n_field; i++) {
                    if (n_new >= new_cap) {
                        new_cap = new_cap ? new_cap * 2 : 8;
                        new_vals = realloc(new_vals, (size_t)new_cap * sizeof(char *));
                    }
                    new_vals[n_new++] = strdup(field_hdrs[i]);
                }
            } else if (d && cJSON_IsArray(d)) {
                cJSON *item;
                cJSON_ArrayForEach(item, d) {
                    if (!cJSON_IsString(item)) continue;
                    if (n_new >= new_cap) {
                        new_cap = new_cap ? new_cap * 2 : 8;
                        new_vals = realloc(new_vals, (size_t)new_cap * sizeof(char *));
                    }
                    size_t len = strlen(fname) + 2 + strlen(item->valuestring) + 3;
                    char *hdr = malloc(len);
                    snprintf(hdr, len, "%s: %s\r\n", fname, item->valuestring);
                    new_vals[n_new++] = hdr;
                }
            }
        }
        free(field_hdrs);

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
    }

    cJSON_Delete(root);

    int out_n = 0;
    for (int i = 0; i < working_n; i++)
        if (working[i]) working[out_n++] = working[i];
    working[out_n] = NULL;
    *n_out = out_n;
    return working;
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

    int ni = 0;
    while (ni < n_new) {
        int best_old = -1, best_len_found = 0;
        for (int oi = 0; oi < n_old; oi++) {
            int run = 0;
            while (ni + run < n_new && oi + run < n_old &&
                   new_lines[ni + run].len == old_lines[oi + run].len &&
                   memcmp(new_lines[ni + run].ptr, old_lines[oi + run].ptr,
                          new_lines[ni + run].len) == 0)
                run++;
            if (run > best_len_found) { best_len_found = run; best_old = oi; }
        }

        if (best_len_found >= 2) {
            cJSON *step = cJSON_CreateObject();
            cJSON *c = cJSON_CreateArray();
            cJSON_AddItemToArray(c, cJSON_CreateNumber(best_old + 1));
            cJSON_AddItemToArray(c, cJSON_CreateNumber(best_old + best_len_found));
            cJSON_AddItemToObject(step, "c", c);
            cJSON_AddItemToArray(steps, step);
            ni += best_len_found;
        } else {
            cJSON *step = cJSON_CreateObject();
            cJSON *d = cJSON_CreateArray();
            while (ni < n_new) {
                int found = 0;
                for (int oi = 0; oi < n_old && !found; oi++) {
                    int run = 0;
                    while (ni + run < n_new && oi + run < n_old &&
                           new_lines[ni + run].len == old_lines[oi + run].len &&
                           memcmp(new_lines[ni + run].ptr, old_lines[oi + run].ptr,
                                  new_lines[ni + run].len) == 0)
                        run++;
                    if (run >= 2) found = 1;
                }
                if (found) break;
                const char *p = new_lines[ni].ptr;
                size_t l = new_lines[ni].len;
                while (l > 0 && (p[l-1] == '\n' || p[l-1] == '\r')) l--;
                char *s = malloc(l + 1);
                memcpy(s, p, l); s[l] = '\0';
                cJSON_AddItemToArray(d, cJSON_CreateString(s));
                free(s);
                ni++;
            }
            cJSON_AddItemToObject(step, "d", d);
            cJSON_AddItemToArray(steps, step);
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

    int ni = 0;
    while (ni < n_new) {
        int best_old = -1, best_len_found = 0;
        for (int oi = 0; oi < n_old; oi++) {
            int run = 0;
            while (ni + run < n_new && oi + run < n_old &&
                   strcmp(new_fields[ni + run], old_fields[oi + run]) == 0)
                run++;
            if (run > best_len_found) { best_len_found = run; best_old = oi; }
        }

        if (best_len_found >= 1) {
            cJSON *step = cJSON_CreateObject();
            cJSON *c = cJSON_CreateArray();
            cJSON_AddItemToArray(c, cJSON_CreateNumber(best_old + 1));
            cJSON_AddItemToArray(c, cJSON_CreateNumber(best_old + best_len_found));
            cJSON_AddItemToObject(step, "c", c);
            cJSON_AddItemToArray(steps, step);
            ni += best_len_found;
        } else {
            cJSON *step = cJSON_CreateObject();
            cJSON *d = cJSON_CreateArray();
            while (ni < n_new) {
                int found = 0;
                for (int oi = 0; oi < n_old && !found; oi++)
                    if (strcmp(new_fields[ni], old_fields[oi]) == 0) found = 1;
                if (found) break;
                const char *val = strchr(new_fields[ni], ':');
                if (val) {
                    val++;
                    while (*val == ' ') val++;
                    size_t vl = strlen(val);
                    while (vl > 0 && (val[vl-1] == '\n' || val[vl-1] == '\r')) vl--;
                    char *s = malloc(vl + 1);
                    memcpy(s, val, vl); s[vl] = '\0';
                    cJSON_AddItemToArray(d, cJSON_CreateString(s));
                    free(s);
                }
                ni++;
            }
            cJSON_AddItemToObject(step, "d", d);
            cJSON_AddItemToArray(steps, step);
        }
    }

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}
