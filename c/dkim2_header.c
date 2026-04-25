#include "dkim2_header.h"
#include "tagparse.h"
#include "base64.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* Parse h= value: "sha256:hhash:bhash,sha256:hhash:bhash,..." */
static int parse_hsets(const char *h, dkim2_hashset_t **out, int *n) {
    int cnt = 1;
    for (const char *p = h; *p; p++) if (*p == ',') cnt++;
    *out = calloc((size_t)cnt, sizeof(dkim2_hashset_t));
    if (!*out) return -1;
    *n = 0;
    char *copy = strdup(h);
    if (!copy) { free(*out); *out = NULL; return -1; }
    char *saveptr = NULL, *tok = strtok_r(copy, ",", &saveptr);
    while (tok) {
        while (*tok == ' ' || *tok == '\t') tok++;
        char *c1 = strchr(tok, ':');
        if (!c1) { free(copy); return -1; }
        *c1++ = '\0';
        char *c2 = strchr(c1, ':');
        if (!c2) { free(copy); return -1; }
        *c2++ = '\0';
        (*out)[*n].alg       = strdup(tok);
        (*out)[*n].hdr_hash  = strdup(c1);
        (*out)[*n].body_hash = strdup(c2);
        (*n)++;
        tok = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);
    return 0;
}

dkim2_mi_t *dkim2_mi_parse(const char *value) {
    taglist_t *tl = tagparse(value, NULL);
    if (!tl) return NULL;
    dkim2_mi_t *mi = calloc(1, sizeof *mi);
    if (!mi) { taglist_free(tl); return NULL; }
    const char *v;
    v = tag_get(tl, "m");
    if (!v) goto err;
    mi->m = atoi(v);
    v = tag_get(tl, "h");
    if (!v) goto err;
    if (parse_hsets(v, &mi->hsets, &mi->n_hsets) < 0) goto err;
    v = tag_get(tl, "r");
    if (v) mi->r_raw = strdup(v);
    mi->raw_value = strdup(value);
    taglist_free(tl);
    return mi;
err:
    taglist_free(tl);
    dkim2_mi_free(mi);
    return NULL;
}

void dkim2_mi_free(dkim2_mi_t *mi) {
    if (!mi) return;
    dkim2_mi_free(mi->next);   /* recurse before freeing self */
    mi->next = NULL;
    for (int i = 0; i < mi->n_hsets; i++) {
        free(mi->hsets[i].alg);
        free(mi->hsets[i].hdr_hash);
        free(mi->hsets[i].body_hash);
    }
    free(mi->hsets);
    free(mi->r_raw);
    free(mi->raw_value);
    free(mi);
}

/* Decode comma-separated list of base64-encoded forward-paths from rt= */
static char **parse_rt(const char *rt_val, int *n_out) {
    int cnt = 1;
    for (const char *p = rt_val; *p; p++) if (*p == ',') cnt++;
    char **out = calloc((size_t)(cnt + 1), sizeof(char *));
    if (!out) return NULL;
    int n = 0;
    char *copy = strdup(rt_val), *saveptr = NULL, *tok;
    if (!copy) { free(out); return NULL; }
    tok = strtok_r(copy, ",", &saveptr);
    while (tok) {
        while (*tok == ' ' || *tok == '\t') tok++;
        unsigned char dec[512];
        int dlen = b64_decode(tok, dec, sizeof dec);
        if (dlen < 0) { free(copy); for (int i=0;i<n;i++) free(out[i]); free(out); return NULL; }
        out[n] = malloc((size_t)dlen + 1);
        if (!out[n]) { free(copy); for (int i=0;i<n;i++) free(out[i]); free(out); return NULL; }
        memcpy(out[n], dec, (size_t)dlen);
        out[n][dlen] = '\0';
        n++;
        tok = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);
    out[n] = NULL;
    *n_out = n;
    return out;
}

/* Parse s= value: comma-separated "selector:alg:sig" triples */
static int parse_ssets(const char *s, dkim2_sigset_t **out, int *n) {
    int cnt = 1;
    for (const char *p = s; *p; p++) if (*p == ',') cnt++;
    *out = calloc((size_t)cnt, sizeof(dkim2_sigset_t));
    if (!*out) return -1;
    *n = 0;
    char *copy = strdup(s), *saveptr = NULL, *tok;
    if (!copy) { free(*out); *out = NULL; return -1; }
    tok = strtok_r(copy, ",", &saveptr);
    while (tok) {
        while (*tok == ' ' || *tok == '\t') tok++;
        char *c1 = strchr(tok, ':');
        if (!c1) { free(copy); return -1; }
        *c1++ = '\0';
        char *c2 = strchr(c1, ':');
        if (!c2) { free(copy); return -1; }
        *c2++ = '\0';
        (*out)[*n].selector = strdup(tok);
        (*out)[*n].alg      = strdup(c1);
        (*out)[*n].sig_b64  = strdup(c2);
        (*n)++;
        tok = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);
    return 0;
}

dkim2_sig_t *dkim2_sig_parse(const char *value) {
    taglist_t *tl = tagparse(value, NULL);
    if (!tl) return NULL;
    dkim2_sig_t *sig = calloc(1, sizeof *sig);
    if (!sig) { taglist_free(tl); return NULL; }
    const char *v;
#define REQ(tag) do { v = tag_get(tl, tag); if (!v) goto err; } while(0)
    REQ("i"); sig->i = atoi(v);
    REQ("m"); sig->m = atoi(v);
    REQ("t"); sig->t = (uint64_t)strtoull(v, NULL, 10);
    REQ("d"); sig->d = strdup(v);
    REQ("mf");
    { unsigned char dec[512]; int n = b64_decode(v, dec, sizeof dec);
      if (n < 0) goto err;
      sig->mf = malloc((size_t)n + 1); memcpy(sig->mf, dec, (size_t)n); sig->mf[n] = '\0'; }
    REQ("rt");
    { int nrt = 0; sig->rt = parse_rt(v, &nrt); if (!sig->rt) goto err; }
    REQ("s");
    if (parse_ssets(v, &sig->ssets, &sig->n_ssets) < 0) goto err;
#undef REQ
    v = tag_get(tl, "n"); if (v) sig->n = strdup(v);
    sig->raw_value = strdup(value);
    taglist_free(tl);
    return sig;
err:
    taglist_free(tl);
    dkim2_sig_free(sig);
    return NULL;
}

void dkim2_sig_free(dkim2_sig_t *sig) {
    if (!sig) return;
    dkim2_sig_free(sig->next);
    sig->next = NULL;
    free(sig->n); free(sig->mf); free(sig->d); free(sig->raw_value);
    if (sig->rt) { for (int i = 0; sig->rt[i]; i++) free(sig->rt[i]); free(sig->rt); }
    for (int i = 0; i < sig->n_ssets; i++) {
        free(sig->ssets[i].selector);
        free(sig->ssets[i].alg);
        free(sig->ssets[i].sig_b64);
    }
    free(sig->ssets);
    if (sig->flags) { for (int i = 0; sig->flags[i]; i++) free(sig->flags[i]); free(sig->flags); }
    free(sig);
}

char *dkim2_mi_format(const dkim2_mi_t *mi) {
    char *buf = malloc(4096);
    if (!buf) return NULL;
    int pos = snprintf(buf, 4096, "m=%d; h=", mi->m);
    for (int i = 0; i < mi->n_hsets; i++) {
        if (i) buf[pos++] = ',';
        pos += snprintf(buf + pos, 4096 - pos, "%s:%s:%s",
            mi->hsets[i].alg, mi->hsets[i].hdr_hash, mi->hsets[i].body_hash);
    }
    if (mi->r_raw)
        pos += snprintf(buf + pos, 4096 - pos, "; r=%s", mi->r_raw);
    return buf;
}

char *dkim2_sig_format(const dkim2_sig_t *sig, int empty_sig) {
    char *buf = malloc(8192);
    if (!buf) return NULL;
    char mf_b64[512];
    b64_encode((const unsigned char *)sig->mf, strlen(sig->mf), mf_b64, sizeof mf_b64);
    int pos = snprintf(buf, 8192, "i=%d; m=%d; t=%llu; d=%s; mf=%s",
        sig->i, sig->m, (unsigned long long)sig->t, sig->d, mf_b64);
    /* rt= */
    pos += snprintf(buf + pos, 8192 - pos, "; rt=");
    for (int i = 0; sig->rt && sig->rt[i]; i++) {
        if (i) buf[pos++] = ',';
        char rt_b64[512];
        b64_encode((const unsigned char *)sig->rt[i], strlen(sig->rt[i]), rt_b64, sizeof rt_b64);
        pos += snprintf(buf + pos, 8192 - pos, "%s", rt_b64);
    }
    /* s= */
    pos += snprintf(buf + pos, 8192 - pos, "; s=");
    for (int i = 0; i < sig->n_ssets; i++) {
        if (i) buf[pos++] = ',';
        pos += snprintf(buf + pos, 8192 - pos, "%s:%s:%s",
            sig->ssets[i].selector, sig->ssets[i].alg,
            empty_sig ? "" : (sig->ssets[i].sig_b64 ? sig->ssets[i].sig_b64 : ""));
    }
    if (sig->n)
        pos += snprintf(buf + pos, 8192 - pos, "; n=%s", sig->n);
    return buf;
}
