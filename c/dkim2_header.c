#include "dkim2_header.h"
#include "tagparse.h"
#include "base64.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdint.h>

/* Strip all FWS (whitespace including CRLF) from a base64 string in-place. */
static void strip_fws(char *s) {
    char *r = s, *w = s;
    while (*r) {
        if (*r == ' ' || *r == '\t' || *r == '\r' || *r == '\n') { r++; continue; }
        *w++ = *r++;
    }
    *w = '\0';
}

/* Parse h= value: "sha256:hhash:bhash,sha256:hhash:bhash,..."
   Returns 0 on success, -1 on malloc/syntax failure, -2 if an algorithm
   name is present more than once (spec-05 §7.3; case-insensitive per
   RFC 5234, since ABNF quoted strings are case-insensitive). */
static int parse_hsets(const char *h, dkim2_hashset_t **out, int *n) {
    int cnt = 1;
    for (const char *p = h; *p; p++) if (*p == ',') cnt++;
    *out = calloc((size_t)cnt, sizeof(dkim2_hashset_t));
    if (!*out) return -1;
    *n = 0;
    char *copy = strdup(h);
    if (!copy) { free(*out); *out = NULL; return -1; }
    /* Strip all FWS from the copy so folded hashes parse correctly */
    strip_fws(copy);
    char *saveptr = NULL, *tok = strtok_r(copy, ",", &saveptr);
    int dup = 0;
    while (tok) {
        char *c1 = strchr(tok, ':');
        if (!c1) { free(copy); return -1; }
        *c1++ = '\0';
        char *c2 = strchr(c1, ':');
        if (!c2) { free(copy); return -1; }
        *c2++ = '\0';

        /* §7.3: an algorithm MUST NOT be present more than once. Check
           against every entry already stored -- this must run before any
           hash is computed or compared. */
        for (int i = 0; i < *n; i++) {
            if (strcasecmp((*out)[i].alg, tok) == 0) { dup = 1; break; }
        }
        if (dup) break;

        (*out)[*n].alg       = strdup(tok);
        (*out)[*n].hdr_hash  = strdup(c1);
        (*out)[*n].body_hash = strdup(c2);
        (*n)++;
        tok = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);
    return dup ? -2 : 0;
}

dkim2_mi_t *dkim2_mi_parse_err(const char *value, char *errbuf, size_t errbufsz) {
    if (errbuf && errbufsz) errbuf[0] = '\0';
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
    {
        int hr = parse_hsets(v, &mi->hsets, &mi->n_hsets);
        if (hr == -2) {
            /* spec-05 §7.3: duplicate hash algorithm -- a specific,
               reportable parse failure, not a plain "MI absent". mi->m is
               already populated at this point, so the message can name it. */
            if (errbuf && errbufsz)
                snprintf(errbuf, errbufsz,
                    "PERMERROR Message-Instance m=%d has a duplicate hash algorithm",
                    mi->m);
            goto err;
        }
        if (hr < 0) goto err;
    }
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

dkim2_mi_t *dkim2_mi_parse(const char *value) {
    return dkim2_mi_parse_err(value, NULL, 0);
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

/* Parse f= value: comma-separated plain flag tokens (draft-05 §8.10).
   Flags are an open list; tokens are stored verbatim with WSP trimmed. */
static char **parse_flags(const char *f_val, int *n_out) {
    int cnt = 1;
    for (const char *p = f_val; *p; p++) if (*p == ',') cnt++;
    char **out = calloc((size_t)(cnt + 1), sizeof(char *));
    if (!out) return NULL;
    int n = 0;
    char *copy = strdup(f_val), *saveptr = NULL, *tok;
    if (!copy) { free(out); return NULL; }
    tok = strtok_r(copy, ",", &saveptr);
    while (tok) {
        while (*tok == ' ' || *tok == '\t') tok++;
        size_t len = strlen(tok);
        while (len && (tok[len-1] == ' ' || tok[len-1] == '\t')) tok[--len] = '\0';
        if (len) { out[n] = strdup(tok); if (!out[n]) { free(copy); for (int i=0;i<n;i++) free(out[i]); free(out); return NULL; } n++; }
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
        /* Strip FWS before splitting: a fold may land between the Selector
           colon and the algorithm token, which would otherwise leave CRLF+WSP
           attached to the algorithm name. */
        strip_fws(tok);
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
    /* §8: "there MUST be only one of each kind" of tag. */
    if (tl->duplicate) { taglist_free(tl); return NULL; }
    dkim2_sig_t *sig = calloc(1, sizeof *sig);
    if (!sig) { taglist_free(tl); return NULL; }
    const char *v;
#define REQ(tag) do { v = tag_get(tl, tag); if (!v) goto err; } while(0)
    REQ("i"); sig->i = atoi(v);
    REQ("m"); sig->m = atoi(v);
    REQ("t"); sig->t = (uint64_t)strtoull(v, NULL, 10);
    REQ("d"); sig->d = strdup(v);
    /* draft-05 §8: either nd= or both mf=+rt=, never both forms. */
    {   const char *nd = tag_get(tl, "nd");
        const char *mf = tag_get(tl, "mf");
        const char *rt = tag_get(tl, "rt");
        if (nd && (mf || rt)) goto err;      /* nd= excludes mf=/rt= */
        if (!nd && !(mf && rt)) goto err;    /* need nd= or both mf=+rt= */
        if (nd) sig->nd = strdup(nd);
        if (mf) {
            unsigned char dec[512]; int n = b64_decode(mf, dec, sizeof dec);
            if (n < 0) goto err;
            sig->mf = malloc((size_t)n + 1); memcpy(sig->mf, dec, (size_t)n); sig->mf[n] = '\0';
        }
        if (rt) { int nrt = 0; sig->rt = parse_rt(rt, &nrt); if (!sig->rt) goto err; }
    }
    REQ("s");
    if (parse_ssets(v, &sig->ssets, &sig->n_ssets) < 0) goto err;
#undef REQ
    v = tag_get(tl, "n");
    if (v) {
        if (strlen(v) > 64) goto err;  /* §8.3: n= must not exceed 64 chars */
        sig->n = strdup(v);
    }
    v = tag_get(tl, "f");
    if (v) {
        int nf = 0;
        sig->flags = parse_flags(v, &nf);
        if (!sig->flags) goto err;
    }
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
    free(sig->n); free(sig->mf); free(sig->d); free(sig->nd); free(sig->raw_value);
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
    /* Trailing semicolon per spec ABNF tag-list grammar (matches Python/Perl) */
    pos += snprintf(buf + pos, 4096 - pos, ";");
    return buf;
}

char *dkim2_sig_format(const dkim2_sig_t *sig, int empty_sig) {
    char *buf = malloc(8192);
    if (!buf) return NULL;
    int pos = snprintf(buf, 8192, "i=%d; m=%d; t=%llu; d=%s",
        sig->i, sig->m, (unsigned long long)sig->t, sig->d);
    if (sig->nd) {
        /* draft-05 §9.3: imaginary hop carries nd= instead of mf=/rt= */
        pos += snprintf(buf + pos, 8192 - pos, "; nd=%s", sig->nd);
    } else {
        char mf_b64[512];
        b64_encode((const unsigned char *)sig->mf, strlen(sig->mf), mf_b64, sizeof mf_b64);
        pos += snprintf(buf + pos, 8192 - pos, "; mf=%s", mf_b64);
        pos += snprintf(buf + pos, 8192 - pos, "; rt=");
        for (int i = 0; sig->rt && sig->rt[i]; i++) {
            if (i) buf[pos++] = ',';
            char rt_b64[512];
            b64_encode((const unsigned char *)sig->rt[i], strlen(sig->rt[i]), rt_b64, sizeof rt_b64);
            pos += snprintf(buf + pos, 8192 - pos, "%s", rt_b64);
        }
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
    /* f= flags (draft-05 §8.10), e.g. feedback, feedhere — preserved verbatim */
    if (sig->flags && sig->flags[0]) {
        pos += snprintf(buf + pos, 8192 - pos, "; f=");
        for (int i = 0; sig->flags[i]; i++) {
            if (i) buf[pos++] = ',';
            pos += snprintf(buf + pos, 8192 - pos, "%s", sig->flags[i]);
        }
    }
    return buf;
}
