#include "dkim2_header.h"
#include "tagparse.h"
#include "base64.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

/* Strip all FWS (whitespace including CRLF) from a base64 string in-place. */
static void strip_fws(char *s) {
    char *r = s, *w = s;
    while (*r) {
        if (*r == ' ' || *r == '\t' || *r == '\r' || *r == '\n') { r++; continue; }
        *w++ = *r++;
    }
    *w = '\0';
}

static char *trim_fws(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    size_t n = strlen(s);
    while (n && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\r' || s[n-1] == '\n'))
        s[--n] = '\0';
    return s;
}

/* An algorithm or hash name: [A-Za-z0-9_-]+. With labels, a Selector:
   such labels joined by '.'. No FWS inside either. */
static int name_ok(const char *s, int labels) {
    int len = 0;
    for (; *s; s++) {
        if ((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') ||
            (*s >= '0' && *s <= '9') || *s == '_' || *s == '-') len++;
        else if (labels && *s == '.' && len) len = 0;
        else return 0;
    }
    return len > 0;
}

/* Split one s= or h= item into exactly three parts on ':' (-08 §9.3,
   §10.9). FWS is trimmed from around the first two (it may sit beside a
   colon or a list separator) and removed from inside the third (a base64
   value), and from inside the second too when strip2 (a hash value); a
   name with FWS inside it is left for name_ok() to reject. */
static int split3(char *item, char **p1, char **p2, char **p3, int strip2) {
    char *c1 = strchr(item, ':');
    if (!c1) return -1;
    *c1++ = '\0';
    char *c2 = strchr(c1, ':');
    if (!c2) return -1;
    *c2++ = '\0';
    if (strchr(c2, ':')) return -1;
    *p1 = trim_fws(item);
    *p2 = trim_fws(c1);
    if (strip2) strip_fws(*p2);
    strip_fws(c2);
    *p3 = c2;
    return 0;
}

/* One item of an h= or s= list, pointing into the list's buffer. */
typedef struct { char *p1, *p2, *p3; int group; } item3_t;

static const item3_t *g_cmp_items;   /* qsort context (single-threaded use) */
static int cmp_item_p1(const void *a, const void *b) {
    return strcasecmp(g_cmp_items[*(const int *)a].p1, g_cmp_items[*(const int *)b].p1);
}

/* Parse an h= (is_sig 0) or s= (is_sig 1) value (-08 §9.3, §10.9):
     any = all *([FWS] "|" [FWS] all), all = item *([FWS] "," [FWS] item)
   An h= item is hash-name ":" base64 ":" base64, an s= item selector ":"
   sig-name ":" base64, every base64 value non-empty and padded, whatever
   the algorithm (contract D3). The items point into one copy of v (*buf),
   so a list of any length costs three allocations; finding a repeated
   hash name or Selector (compared without regard to case, across the whole
   tag) sorts, so it costs n log n. Returns 0; -1 for a syntax error (an
   empty member: a leading, trailing or doubled "|" or ",") or OOM; -2 for
   a repeated name; -3 for more than DKIM2_MAX_SIGNATURES s= items -- each
   only when nothing before it in that order applies. */
static int parse_list(const char *v, int is_sig, char **buf, item3_t **items,
                      int *n, int *n_groups) {
    *buf = NULL; *items = NULL; *n = 0; *n_groups = 0;
    size_t cnt = 1;
    for (const char *p = v; *p; p++) if (*p == ',' || *p == '|') cnt++;
    char *copy = strdup(v);
    item3_t *it = calloc(cnt, sizeof *it);
    int *idx = calloc(cnt, sizeof *idx);
    int rc = 0, k = 0, group = 0;
    if (!copy || !it || !idx) { rc = -1; goto out; }
    for (char *tok = copy, *next; tok; tok = next) {
        size_t span = strcspn(tok, ",|");
        char sep = tok[span];
        tok[span] = '\0';
        next = sep ? tok + span + 1 : NULL;
        if (split3(tok, &it[k].p1, &it[k].p2, &it[k].p3, !is_sig) < 0 ||
            !name_ok(it[k].p1, is_sig) ||
            !(is_sig ? name_ok(it[k].p2, 0) : b64_is_strict(it[k].p2)) ||
            !b64_is_strict(it[k].p3)) { rc = -1; goto out; }
        it[k].group = group;
        idx[k] = k;
        k++;
        if (sep == '|') group++;
    }
    g_cmp_items = it;
    qsort(idx, (size_t)k, sizeof *idx, cmp_item_p1);
    g_cmp_items = NULL;
    for (int i = 1; i < k; i++)
        if (strcasecmp(it[idx[i - 1]].p1, it[idx[i]].p1) == 0) { rc = -2; goto out; }
    if (is_sig && k > DKIM2_MAX_SIGNATURES) { rc = -3; goto out; }
    *buf = copy; copy = NULL;
    *items = it; it = NULL;
    *n = k;
    *n_groups = group + 1;
out:
    free(copy);
    free(it);
    free(idx);
    return rc;
}

/* Parse h= into hsets (-08 §9.3): 0, -1 syntax error or OOM, -2 a hash
   name present more than once anywhere in the tag (case-insensitive per
   RFC 5234, since ABNF quoted strings are case-insensitive). */
static int parse_hsets(const char *h, dkim2_mi_t *mi) {
    item3_t *it;
    int n, ng;
    int rc = parse_list(h, 0, &mi->list_buf, &it, &n, &ng);
    if (rc < 0) return rc;
    mi->hsets = calloc((size_t)(n ? n : 1), sizeof *mi->hsets);
    if (!mi->hsets) { free(it); free(mi->list_buf); mi->list_buf = NULL; return -1; }
    for (int i = 0; i < n; i++) {
        mi->hsets[i].alg = it[i].p1;
        mi->hsets[i].hdr_hash = it[i].p2;
        mi->hsets[i].body_hash = it[i].p3;
        mi->hsets[i].group = it[i].group;
    }
    mi->n_hsets = n;
    mi->n_groups = ng;
    free(it);
    return 0;
}

dkim2_mi_t *dkim2_mi_parse_err(const char *value, char *errbuf, size_t errbufsz) {
    if (errbuf && errbufsz) errbuf[0] = '\0';
    taglist_t *tl = tagparse(value, NULL);
    if (!tl) {
        /* Malloc failure or syntax error inside tagparse() itself -- no
           tag, including m=, was ever read, so the instance number is
           genuinely unknowable. This is the surviving sibling of the
           silent-drop bug already fixed for the -07 §9.3 duplicate-hash (-2)
           case: before this, a -1 failure here vanished with no error at
           all. Report the same generic wording used below for the other
           unattributable case, without an m=N -- there is nothing more
           specific to name (compare dkim2_verify.c's own unattributable
           "PERMERROR: No DKIM2-Signature header"). */
        if (errbuf && errbufsz)
            snprintf(errbuf, errbufsz, "PERMERROR: Message-Instance syntax error");
        return NULL;
    }
    dkim2_mi_t *mi = calloc(1, sizeof *mi);
    if (!mi) {
        /* OOM allocating the MI struct itself -- same unattributable case. */
        if (errbuf && errbufsz)
            snprintf(errbuf, errbufsz, "PERMERROR: Message-Instance syntax error");
        taglist_free(tl);
        return NULL;
    }
    const char *v;
    v = tag_get(tl, "m");
    if (!v) {
        /* No m= tag at all (C6: tag=m missing, with no m= to name). */
        if (errbuf && errbufsz)
            snprintf(errbuf, errbufsz, "PERMERROR: Message-Instance m= tag=m missing");
        goto err;
    }
    if (dkim2_chain_number_error("Message-Instance", "m", v, v, errbuf, errbufsz))
        goto err;
    mi->m = atoi(v);   /* 1..DKIM2_MAX_CHAIN_LENGTH ASCII digits: exact */
    /* -08 §8: tag names are lowercase; any other is an unknown tag and is
       ignored (contract D10: "M=1" is not m=, and "m=1; M=2" is no
       duplicate). §8 forbids duplicates -- a repeated name is a syntax
       error, never first- or last-one-wins. */
    if (tl->duplicate || tl->syntax_error) {
        if (errbuf && errbufsz)
            snprintf(errbuf, errbufsz,
                "PERMERROR: Message-Instance m=%d syntax error", mi->m);
        goto err;
    }
    v = tag_get(tl, "h");
    if (!v) {
        /* mi->m is known from here on, so every remaining failure can
           name it. */
        if (errbuf && errbufsz)
            snprintf(errbuf, errbufsz,
                "PERMERROR: Message-Instance m=%d tag=h missing", mi->m);
        goto err;
    }
    {
        int hr = parse_hsets(v, mi);
        if (hr == -2) {
            /* -08 §9.3: duplicate hash algorithm -- a specific,
               reportable parse failure, not a plain "MI absent". mi->m is
               already populated at this point, so the message can name it. */
            if (errbuf && errbufsz)
                snprintf(errbuf, errbufsz,
                    "PERMERROR: Message-Instance m=%d has a duplicate hash algorithm",
                    mi->m);
            goto err;
        }
        if (hr < 0) {
            /* -1: either a malformed hash-set entry or a malloc/strdup
               failure inside parse_hsets(). Both are folded into the same
               "syntax error" wording (the -07 §14.2 precedent used for a bad
               r= payload elsewhere in this file/dkim2_verify.c) -- a
               permanent parse failure isn't usefully distinguished from an
               allocation failure to the remote party either way, and this
               is what "vanished with no error at all" must become. */
            if (errbuf && errbufsz)
                snprintf(errbuf, errbufsz,
                    "PERMERROR: Message-Instance m=%d syntax error", mi->m);
            goto err;
        }
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
    free(mi->hsets);           /* its strings are in list_buf */
    free(mi->list_buf);
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

/* Parse f= value: comma-separated plain flag tokens (-07 §10.10).
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

/* Parse s= into ssets (-08 §10.9; parse_list): 0, -1 syntax error or OOM,
   -2 a Selector present more than once anywhere in the tag (a Selector is
   a Domain, so without regard to case), -3 more than DKIM2_MAX_SIGNATURES
   items. */
static int parse_ssets(const char *s, dkim2_sig_t *sig) {
    item3_t *it;
    int n, ng;
    int rc = parse_list(s, 1, &sig->list_buf, &it, &n, &ng);
    if (rc < 0) return rc;
    sig->ssets = calloc((size_t)(n ? n : 1), sizeof *sig->ssets);
    if (!sig->ssets) { free(it); free(sig->list_buf); sig->list_buf = NULL; return -1; }
    for (int i = 0; i < n; i++) {
        sig->ssets[i].selector = it[i].p1;
        sig->ssets[i].alg = it[i].p2;
        sig->ssets[i].sig_b64 = it[i].p3;
        sig->ssets[i].group = it[i].group;
    }
    sig->n_ssets = n;
    sig->n_groups = ng;
    free(it);
    return 0;
}

int dkim2_chain_number_error(const char *field, const char *tag, const char *v,
                             const char *ident, char *errbuf, size_t errbufsz) {
    if (!v) return 0;
    if (!ident) ident = v;
    const char *ident_tag = strcmp(field, "Message-Instance") == 0 ? "m" : "i";
    char who[160];
    int digits = *v != '\0', nonzero = 0;
    for (const char *p = v; *p; p++) {
        if (*p < '0' || *p > '9') { digits = 0; break; }
        if (*p != '0') nonzero = 1;
    }
    snprintf(who, sizeof who, "%s %s=%.40s", field, ident_tag, ident);
    if (!digits || !nonzero) {
        if (errbuf && errbufsz)
            snprintf(errbuf, errbufsz, "PERMERROR: %s syntax error", who);
        return 1;
    }
    if (strcmp(tag, ident_tag) != 0) {
        size_t wl = strlen(who);
        snprintf(who + wl, sizeof who - wl, " %s=%.40s", tag, v);
    }
    if (strlen(v) > 3 || atoi(v) > DKIM2_MAX_CHAIN_NUMBER) {
        if (errbuf && errbufsz)
            snprintf(errbuf, errbufsz, "PERMERROR: %s exceeds the maximum chain number of %d",
                     who, DKIM2_MAX_CHAIN_NUMBER);
        return 1;
    }
    if (atoi(v) > DKIM2_MAX_CHAIN_LENGTH) {
        if (errbuf && errbufsz)
            snprintf(errbuf, errbufsz, "PERMERROR: %s exceeds the maximum chain length of %d",
                     who, DKIM2_MAX_CHAIN_LENGTH);
        return 1;
    }
    return 0;
}

/* i= must be a positive integer in ASCII digits: atoi() alone would take
   "abc" as 0 and "+1" or " 1x" as 1. Positive means not all zeros; the
   digits are not converted here (dkim2_chain_number_error bounds them), so
   a value too big for an int cannot overflow. */
static int valid_i(const char *v) {
    if (!v || !*v) return 0;
    int nonzero = 0;
    for (const char *p = v; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
        if (*p != '0') nonzero = 1;
    }
    return nonzero;
}

/* -07 §10.4: t= is 1*DIGIT (the value's surrounding WSP is already
   trimmed by tagparse()). Values beyond 2^64-1 saturate rather than wrap --
   they are far in the future either way. Returns 0, or -1 if not digits. */
static int parse_t(const char *v, uint64_t *out) {
    if (!v || !*v) return -1;
    uint64_t t = 0;
    for (const char *p = v; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
        unsigned d = (unsigned)(*p - '0');
        t = (t > (UINT64_MAX - d) / 10) ? UINT64_MAX : t * 10 + d;
    }
    *out = t;
    return 0;
}

/* parse_list's verdict on an s= value (0 when absent). */
static int s_list_error(const char *v) {
    if (!v) return 0;
    char *buf;
    item3_t *it;
    int n, ng, rc = parse_list(v, 1, &buf, &it, &n, &ng);
    if (rc == 0) { free(buf); free(it); }
    return rc;
}

/* An mf= or rt= value: comma-separated base64 items, each decoding to a
   bracketed RFC 5321 path (-07 §10.5/§10.6: "The angle brackets MUST be
   included"). */
static int paths_ok(const char *v) {
    char *copy = strdup(v), *save = NULL;
    int ok = copy != NULL, any = 0;
    for (char *tok = copy ? strtok_r(copy, ",", &save) : NULL; tok && ok;
         tok = strtok_r(NULL, ",", &save)) {
        unsigned char dec[512];
        int n = b64_decode(tok, dec, sizeof dec - 1);
        ok = n >= 2 && dec[0] == '<' && dec[n - 1] == '>';
        any = 1;
    }
    free(copy);
    return ok && any;
}

/* -07 §14.2: a required tag that is absent ("tag=<y> missing"), or mf=/rt=
   together with nd= ("tag=<y> was unexpected", §10.7). 1 with errbuf set,
   or 0. */
static int missing_tag(const taglist_t *tl, char *errbuf, size_t errbufsz, int i) {
    static const char *req[] = { "m", "t", "d", "s", NULL };
    for (int k = 0; req[k]; k++)
        if (!tag_get(tl, req[k])) {
            snprintf(errbuf, errbufsz, "PERMERROR: DKIM2-Signature i=%d tag=%s missing", i, req[k]);
            return 1;
        }
    int nd = tag_get(tl, "nd") != NULL;
    static const char *path[] = { "mf", "rt", NULL };
    for (int k = 0; path[k]; k++) {
        int has = tag_get(tl, path[k]) != NULL;
        if (nd && has) {
            snprintf(errbuf, errbufsz, "PERMERROR: DKIM2-Signature i=%d tag=%s was unexpected", i, path[k]);
            return 1;
        }
        if (!nd && !has) {
            snprintf(errbuf, errbufsz, "PERMERROR: DKIM2-Signature i=%d tag=%s missing", i, path[k]);
            return 1;
        }
    }
    return 0;
}

dkim2_sig_t *dkim2_sig_parse_err(const char *value, char *errbuf, size_t errbufsz) {
    if (errbuf && errbufsz) errbuf[0] = '\0';
    dkim2_sig_t *sig = dkim2_sig_parse(value);
    if (sig || !errbuf || !errbufsz) return sig;
    taglist_t *tl = tagparse(value, NULL);
    const char *iv = tl ? tag_get(tl, "i") : NULL;
    const char *mv = tl ? tag_get(tl, "m") : NULL;
    if (!iv)
        snprintf(errbuf, errbufsz, "PERMERROR: DKIM2-Signature i= tag=i missing");
    else if (!valid_i(iv))
        snprintf(errbuf, errbufsz, "PERMERROR: DKIM2-Signature i=%.40s syntax error", iv);
    else if (dkim2_chain_number_error("DKIM2-Signature", "i", iv, iv, errbuf, errbufsz))
        ;
    else if (dkim2_chain_number_error("DKIM2-Signature", "m", mv, iv, errbuf, errbufsz))
        ;
    else if (tl && (tl->syntax_error || tl->duplicate || s_list_error(tag_get(tl, "s")) == -1 ||
                    (tag_get(tl, "t") && parse_t(tag_get(tl, "t"), &(uint64_t){0}) < 0) ||
                    (tag_get(tl, "mf") && !paths_ok(tag_get(tl, "mf"))) ||
                    (tag_get(tl, "rt") && !paths_ok(tag_get(tl, "rt")))))
        snprintf(errbuf, errbufsz, "PERMERROR: DKIM2-Signature i=%d syntax error", atoi(iv));
    else if (tl && missing_tag(tl, errbuf, errbufsz, atoi(iv)))
        ;
    /* -08 §10.9: then a repeated Selector, then the local limit (D3). */
    else if (tl && s_list_error(tag_get(tl, "s")) == -2)
        snprintf(errbuf, errbufsz, "PERMERROR: DKIM2-Signature i=%d has a duplicate selector", atoi(iv));
    else if (tl && s_list_error(tag_get(tl, "s")) == -3)
        snprintf(errbuf, errbufsz, "PERMERROR: DKIM2-Signature i=%d has more than %d signatures",
                 atoi(iv), DKIM2_MAX_SIGNATURES);
    else
        snprintf(errbuf, errbufsz, "PERMERROR: DKIM2-Signature is malformed");
    if (tl) taglist_free(tl);
    return NULL;
}

dkim2_sig_t *dkim2_sig_parse(const char *value) {
    taglist_t *tl = tagparse(value, NULL);
    if (!tl) return NULL;
    /* -07 §8: "Tags with duplicate names MUST NOT occur". */
    if (tl->duplicate || tl->syntax_error) { taglist_free(tl); return NULL; }
    dkim2_sig_t *sig = calloc(1, sizeof *sig);
    if (!sig) { taglist_free(tl); return NULL; }
    const char *v;
#define REQ(tag) do { v = tag_get(tl, tag); if (!v) goto err; } while(0)
    /* Chain numbers only: atoi() of "4294967297x" would be 4294967297. */
    REQ("i"); if (!valid_i(v) || dkim2_chain_number_error("DKIM2-Signature", "i", v, NULL, NULL, 0)) goto err; sig->i = atoi(v);
    REQ("m"); if (dkim2_chain_number_error("DKIM2-Signature", "m", v, NULL, NULL, 0)) goto err; sig->m = atoi(v);
    REQ("t"); if (parse_t(v, &sig->t) < 0) goto err;
    REQ("d"); sig->d = strdup(v);
    /* -07 §10.7: either nd= or both mf=+rt=, never both forms. */
    {   const char *nd = tag_get(tl, "nd");
        const char *mf = tag_get(tl, "mf");
        const char *rt = tag_get(tl, "rt");
        if (nd && (mf || rt)) goto err;      /* nd= excludes mf=/rt= */
        if (!nd && !(mf && rt)) goto err;    /* need nd= or both mf=+rt= */
        if (nd) sig->nd = strdup(nd);
        /* Bracketed paths only (a syntax error otherwise). */
        if ((mf && !paths_ok(mf)) || (rt && !paths_ok(rt))) goto err;
        if (mf) {
            unsigned char dec[512]; int n = b64_decode(mf, dec, sizeof dec);
            if (n < 0) goto err;
            sig->mf = malloc((size_t)n + 1);
            if (!sig->mf) goto err;
            memcpy(sig->mf, dec, (size_t)n); sig->mf[n] = '\0';
        }
        if (rt) { int nrt = 0; sig->rt = parse_rt(rt, &nrt); if (!sig->rt) goto err; }
    }
    REQ("s");
    if (parse_ssets(v, sig) < 0) goto err;
#undef REQ
    v = tag_get(tl, "n");
    if (v) {
        if (strlen(v) > 64) goto err;  /* -07 §10.3: n= must not exceed 64 chars */
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
    free(sig->ssets);          /* its strings are in list_buf */
    free(sig->list_buf);
    if (sig->flags) { for (int i = 0; sig->flags[i]; i++) free(sig->flags[i]); free(sig->flags); }
    free(sig);
}

/* A string built to fit: every append grows it; any allocation failure
   makes sb_done() return NULL. */
typedef struct { char *s; size_t len, cap; int oom; } sbuf_t;

static void sb_printf(sbuf_t *b, const char *fmt, ...) {
    if (b->oom) return;
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) { b->oom = 1; va_end(ap2); return; }
    if (b->len + (size_t)n + 1 > b->cap) {
        size_t want = b->cap ? b->cap : 256;
        while (b->len + (size_t)n + 1 > want) want *= 2;
        char *g = realloc(b->s, want);
        if (!g) { b->oom = 1; va_end(ap2); return; }
        b->s = g;
        b->cap = want;
    }
    vsnprintf(b->s + b->len, b->cap - b->len, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)n;
}

/* Append the base64 of raw. */
static void sb_b64(sbuf_t *b, const char *raw) {
    size_t n = strlen(raw), el = ((n + 2) / 3) * 4 + 2;
    char *e = malloc(el);
    if (!e) { b->oom = 1; return; }
    b64_encode((const unsigned char *)raw, n, e, el);
    sb_printf(b, "%s", e);
    free(e);
}

static char *sb_done(sbuf_t *b) {
    if (b->oom) { free(b->s); return NULL; }
    return b->s ? b->s : strdup("");
}

/* What goes before item i of an h= or s= list: nothing, "," or "|". A
   struct built by hand (n_groups 0) is one group. */
static const char *list_sep(int i, int n_groups, int prev_group, int group) {
    if (!i) return "";
    return n_groups > 1 && group != prev_group ? "|" : ",";
}

char *dkim2_mi_format(const dkim2_mi_t *mi) {
    sbuf_t b = {0};
    sb_printf(&b, "m=%d; h=", mi->m);
    for (int i = 0; i < mi->n_hsets; i++)
        sb_printf(&b, "%s%s:%s:%s", list_sep(i, mi->n_groups, i ? mi->hsets[i - 1].group : 0,
                                             mi->hsets[i].group),
            mi->hsets[i].alg, mi->hsets[i].hdr_hash, mi->hsets[i].body_hash);
    if (mi->r_raw)
        sb_printf(&b, "; r=%s", mi->r_raw);
    /* Trailing semicolon per spec ABNF tag-list grammar (matches Python/Perl) */
    sb_printf(&b, ";");
    return sb_done(&b);
}

char *dkim2_sig_format(const dkim2_sig_t *sig, int empty_sig) {
    sbuf_t b = {0};
    sb_printf(&b, "i=%d; m=%d; t=%llu; d=%s",
        sig->i, sig->m, (unsigned long long)sig->t, sig->d);
    if (sig->nd) {
        /* -07 §12.3: imaginary hop carries nd= instead of mf=/rt= */
        sb_printf(&b, "; nd=%s", sig->nd);
    } else {
        sb_printf(&b, "; mf=");
        sb_b64(&b, sig->mf ? sig->mf : "");
        sb_printf(&b, "; rt=");
        for (int i = 0; sig->rt && sig->rt[i]; i++) {
            if (i) sb_printf(&b, ",");
            sb_b64(&b, sig->rt[i]);
        }
    }
    /* s= */
    sb_printf(&b, "; s=");
    for (int i = 0; i < sig->n_ssets; i++)
        sb_printf(&b, "%s%s:%s:%s", list_sep(i, sig->n_groups, i ? sig->ssets[i - 1].group : 0,
                                             sig->ssets[i].group),
            sig->ssets[i].selector, sig->ssets[i].alg,
            empty_sig ? "" : (sig->ssets[i].sig_b64 ? sig->ssets[i].sig_b64 : ""));
    if (sig->n)
        sb_printf(&b, "; n=%s", sig->n);
    /* f= flags (-07 §10.10), e.g. feedback, feedhere — preserved verbatim */
    if (sig->flags && sig->flags[0]) {
        sb_printf(&b, "; f=");
        for (int i = 0; sig->flags[i]; i++)
            sb_printf(&b, "%s%s", i ? "," : "", sig->flags[i]);
    }
    return sb_done(&b);
}

/* The chain number a field gives for tag, or 0 when it has none usable. */
static int usable_number(const taglist_t *tl, const char *field, const char *tag) {
    const char *v = tl ? tag_get(tl, tag) : NULL;
    if (!v || dkim2_chain_number_error(field, tag, v, NULL, NULL, 0)) return 0;
    return atoi(v);     /* 1..DKIM2_MAX_CHAIN_LENGTH ASCII digits: exact */
}

int dkim2_ctx_add_field(dkim2_ctx_t *ctx, int is_sig, const char *value) {
    char errbuf[256];
    /* Past the chain-length limit the message is rejected on the count
       alone (contract C9 step a): count, but keep no more fields. */
    int *count = is_sig ? &ctx->n_sig_fields : &ctx->n_mi_fields;
    if (++*count > DKIM2_MAX_CHAIN_LENGTH) return 0;
    if (!is_sig) {
        dkim2_mi_t *mi = dkim2_mi_parse_err(value, errbuf, sizeof errbuf);
        if (mi) {
            dkim2_mi_t **tail = &ctx->mi_list;
            while (*tail) tail = &(*tail)->next;
            *tail = mi;
            return 0;
        }
    } else {
        dkim2_sig_t *sig = dkim2_sig_parse_err(value, errbuf, sizeof errbuf);
        if (sig) {
            dkim2_sig_t **tail = &ctx->sig_list;
            while (*tail) tail = &(*tail)->next;
            *tail = sig;
            return 0;
        }
    }
    /* Keep the first error of each kind for the signer, which refuses on
       any (dkim2_sign.c). */
    char *first = is_sig ? ctx->sig_error : ctx->mi_error;
    if (!first[0])
        snprintf(first, is_sig ? sizeof ctx->sig_error : sizeof ctx->mi_error, "%s", errbuf);

    dkim2_badfield_t *b = calloc(1, sizeof *b);
    if (!b) return -1;
    b->is_sig = is_sig;
    if (!(b->err = strdup(errbuf))) { free(b); return -1; }
    taglist_t *tl = tagparse(value, NULL);
    if (!is_sig) {
        b->num = usable_number(tl, "Message-Instance", "m");
        b->structural = !b->num;
    } else {
        const char *iv = tl ? tag_get(tl, "i") : NULL;
        b->num = valid_i(iv) ? usable_number(tl, "DKIM2-Signature", "i") : 0;
        b->sig_m = usable_number(tl, "DKIM2-Signature", "m");
        b->structural = !b->num || (tl && tag_get(tl, "m") && !b->sig_m);
    }
    if (tl) taglist_free(tl);
    dkim2_badfield_t **tail = &ctx->bad_list;
    while (*tail) tail = &(*tail)->next;
    *tail = b;
    return 0;
}

void dkim2_badfield_free(dkim2_badfield_t *b) {
    while (b) {
        dkim2_badfield_t *next = b->next;
        free(b->err);
        free(b);
        b = next;
    }
}
