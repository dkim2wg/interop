#include "dkim2_verify.h"
#include "dkim2_hash.h"
#include "dkim2_header.h"
#include "dkim2_crypto.h"
#include "dkim2_dns.h"
#include "dkim2_recipe.h"
#include "dkim2_plan.h"
#include "dkim2_prefetch.h"
#include "dkim2_domain.h"
#include "base64.h"
#include <strings.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <cjson/cJSON.h>

#define SETSTATUS(s, fmt, ...) do { \
    result->status = (s); \
    snprintf(result->message, sizeof result->message, fmt, ##__VA_ARGS__); \
    return; } while(0)

/* -07 §12.8 canonicalization — same as in dkim2_sign.c.
   Forward-declare to avoid duplicating code; share via static inline or header.
   Here we duplicate for self-containment. */
static char *canon_for_sig(const char *hdr) {
    size_t len = strlen(hdr);
    char *out = malloc(len + 4);
    if (!out) return NULL;
    char *p = out;
    const char *h = hdr;
    const char *colon = strchr(h, ':');
    if (!colon) { free(out); return NULL; }
    for (; h < colon; h++) *p++ = (char)tolower((unsigned char)*h);
    *p++ = ':'; h++;
    while (*h) {
        if (h[0] == '\r' && h[1] == '\n') {
            h += 2;
            while (*h == ' ' || *h == '\t') h++;
            continue;
        }
        if (*h == ' ' || *h == '\t') { h++; continue; }
        *p++ = *h++;
    }
    if (p > out && p[-1] == '\n') {
        if (p > out + 1 && p[-2] == '\r') { /* ok */ }
        else { p[-1] = '\r'; *p++ = '\n'; }
    } else {
        *p++ = '\r'; *p++ = '\n';
    }
    *p = '\0';
    return out;
}


/* Strip optional RFC5321 angle brackets into out (NUL-terminated). */
static void unbracket(const char *s, char *out, size_t outsz) {
    if (*s == '<') s++;
    size_t n = strlen(s);
    if (n > 0 && s[n - 1] == '>') n--;
    if (n >= outsz) n = outsz - 1;
    memcpy(out, s, n);
    out[n] = '\0';
}

/* -07 §14.4 envelope comparison: local-part case-sensitive, domain
   case-insensitive, angle brackets ignored; two null senders (<>) are equal. */
static int env_addr_eq(const char *a, const char *b) {
    char ab[512], bb[512];
    unbracket(a, ab, sizeof ab);
    unbracket(b, bb, sizeof bb);
    if (ab[0] == '\0' && bb[0] == '\0') return 1; /* both null sender */
    const char *aat = strrchr(ab, '@');
    const char *bat = strrchr(bb, '@');
    if (!aat || !bat) return strcasecmp(ab, bb) == 0;
    size_t al = (size_t)(aat - ab), bl = (size_t)(bat - bb);
    if (al != bl || strncmp(ab, bb, al) != 0) return 0; /* local-part: exact */
    return strcasecmp(aat + 1, bat + 1) == 0;           /* domain: case-insensitive */
}

static int is_null_path(const char *path) { return path && strcmp(path, "<>") == 0; }

/* Some rt= address of p whose (A-label) domain relaxed-matches p2 as
   Parameter1 (-07 §7.2: a domain literal never matches). */
static int rt_matches(const dkim2_sig_t *p, const char *p2) {
    for (int j = 0; p->rt && p->rt[j]; j++) {
        char rd[512];
        if (dkim2_addr_alabel(p->rt[j], rd, sizeof rd, NULL) == 0 && dkim2_relaxed_match(rd, p2))
            return 1;
    }
    return 0;
}

/* Some rt= address of p whose domain is relaxed-matched by p1 (Parameter1). */
static int matches_rt(const char *p1, const dkim2_sig_t *p) {
    for (int j = 0; p->rt && p->rt[j]; j++) {
        char rd[512];
        if (dkim2_addr_alabel(p->rt[j], rd, sizeof rd, NULL) == 0 && dkim2_relaxed_match(p1, rd))
            return 1;
    }
    return 0;
}

/* -07 Chain of Custody (§7.1 items 1 and 2, §14.4; contract C4) over the
   signatures in ascending i= order. 0, or -1 with the PERMERROR in msg.
   Every signature after the first is checked against the one before it:
   after an nd= hop its d= must be that nd=; an nd= hop, or a null mf=, needs
   an rt= domain of the previous hop that relaxed-matches its d= (rt= is
   Parameter1); otherwise its mf= domain must relaxed-match an rt= domain of
   the previous hop (mf= is Parameter1). Then every signature with a
   non-null mf= (and so no nd=) needs its mf= domain to relaxed-match its d=.
   mf=/rt= domains are compared as A-labels (§18). */
static int check_custody(dkim2_sig_t **sig_arr, int n_sigs, char *msg, size_t msgsz);

/* ---- From Authentic (-07 §11, §14.8; contract C5) ---- */

/* The values of a message's From fields, bottom-up (v[0] is the last From
   field, as header Recipes number them). */
typedef struct { char **v; int n; } fromlist_t;

static void fromlist_free(fromlist_t *f) {
    for (int i = 0; i < f->n; i++) free(f->v[i]);
    free(f->v);
    f->v = NULL;
    f->n = 0;
}

static int fromlist_push(fromlist_t *f, const char *s, size_t len) {
    char **nv = realloc(f->v, (size_t)(f->n + 1) * sizeof *nv);
    if (!nv) return -1;
    f->v = nv;
    if (!(f->v[f->n] = malloc(len + 1))) return -1;
    memcpy(f->v[f->n], s, len);
    f->v[f->n][len] = '\0';
    f->n++;
    return 0;
}

static int fromlist_of(char **hdrs, int n, fromlist_t *out) {
    out->v = NULL;
    out->n = 0;
    for (int i = n - 1; i >= 0; i--) {
        if (!hdrs[i] || strncasecmp(hdrs[i], "from", 4) != 0) continue;
        const char *v = hdrs[i] + 4;
        while (*v == ' ' || *v == '\t') v++;
        if (*v != ':') continue;
        v++;
        size_t len = strlen(v);
        while (len && (v[len - 1] == '\r' || v[len - 1] == '\n')) len--;
        if (fromlist_push(out, v, len) < 0) { fromlist_free(out); return -1; }
    }
    return 0;
}

/* Exactly one From field, holding exactly one mailbox whose (A-label)
   domain is not a literal and relaxed-matches d (From is Parameter1). */
static int fromlist_authentic(const fromlist_t *f, const char *d) {
    char dom[512];
    return f->n == 1 && d && dkim2_from_domain(f->v[0], dom, sizeof dom) == 0 &&
           dkim2_relaxed_match(dom, d);
}

int dkim2_from_authentic(char **hdrs, int n_hdrs, const char *d) {
    fromlist_t f;
    if (fromlist_of(hdrs, n_hdrs, &f) < 0) return 0;
    int ok = fromlist_authentic(&f, d);
    fromlist_free(&f);
    return ok;
}

/* Undo MI's header Recipe for From (a "from" key, any case) on cur: 1 with
   *prev the From fields as they were before this instance, 0 when the
   Recipe does not name From, -1 when it cannot be read or does not fit. */
static int from_undo(const dkim2_mi_t *mi, const fromlist_t *cur, fromlist_t *prev) {
    prev->v = NULL;
    prev->n = 0;
    if (!mi->r_raw) return 0;
    size_t rl = strlen(mi->r_raw), dmax = rl * 3 / 4 + 4;
    unsigned char *rj = malloc(dmax + 1);
    if (!rj) return -1;
    int jl = b64_decode(mi->r_raw, rj, dmax);
    if (jl <= 0) { free(rj); return -1; }
    rj[jl] = '\0';
    cJSON *root = dkim2_recipe_parse((const char *)rj);
    free(rj);
    if (!root) return -1;
    const cJSON *h = cJSON_GetObjectItemCaseSensitive(root, "h");   /* keys lowercased */
    const cJSON *list = h ? cJSON_GetObjectItemCaseSensitive(h, "from") : NULL;
    if (!list) { cJSON_Delete(root); return 0; }
    dkim2_recipe_op_t *ops;
    int n_ops, rc = 1;
    if (dkim2_recipe_ops(list, 1, &ops, &n_ops) < 0) { cJSON_Delete(root); return -1; }
    for (int i = 0; i < n_ops && rc == 1; i++) {
        if (ops[i].lit) {
            if (fromlist_push(prev, (const char *)ops[i].s, ops[i].len) < 0) rc = -1;
            continue;
        }
        for (int k = ops[i].from; k <= ops[i].to && rc == 1; k++)
            if (k > cur->n || fromlist_push(prev, cur->v[k - 1], strlen(cur->v[k - 1])) < 0) rc = -1;
    }
    dkim2_recipe_ops_free(ops, n_ops);
    cJSON_Delete(root);
    if (rc < 0) fromlist_free(prev);
    return rc;
}

int dkim2_mi_changes_from(const dkim2_mi_t *mi) {
    fromlist_t none = { NULL, 0 }, prev;
    int rc = from_undo(mi, &none, &prev);
    fromlist_free(&prev);
    return rc != 0;     /* a Recipe naming From, or one we cannot read */
}

/* The pairs of -07 §11 (contract C5 as corrected by Ruling 19): the From in
   effect when each signature was made. State k is the message as it was when
   m=k was the highest instance. The From fields of state m(i=1) are checked
   with i=1, and for each i >= 2 where some instance k with m(i-1) < k <= m(i)
   has a header Recipe naming From, the From fields of state m(i) with i. A
   From replaced before any signature covered it is never checked, nor are
   instances above the top signature's m= (the signer gate leaves the
   unsigned top to the signer's own check). sig_arr is ascending i= from 1;
   the instances are contiguous 1..N (both checked already).
   0, or -1 with the PERMERROR in msg. */
static int check_from_authentic(const dkim2_ctx_t *ctx, dkim2_sig_t **sig_arr, int n_sigs,
                                char *msg, size_t msgsz) {
    enum { MAX_MI = 64 };
    dkim2_mi_t *mis[MAX_MI];
    int n_mi = dkim2_mi_sorted(ctx->mi_list, mis, MAX_MI);
    fromlist_t lists[MAX_MI + 1];   /* distinct From states, top first */
    int state_of[MAX_MI], changed[MAX_MI];
    int nl = 1, cur = 0, rc_out = 0;
    if (fromlist_of(ctx->headers, ctx->n_headers, &lists[0]) < 0) {
        snprintf(msg, msgsz, "PERMERROR: OOM");
        return -1;
    }
    for (int vi = 0; vi < n_mi; vi++) {
        state_of[vi] = -1;          /* not reached (yet) */
        changed[vi] = 0;
    }
    for (int vi = n_mi - 1; vi >= 0; vi--) {
        state_of[vi] = cur;
        if (vi == 0) break;
        fromlist_t prev;
        int rc = from_undo(mis[vi], &lists[cur], &prev);
        /* A From Recipe that cannot be undone leaves the states below it
           unreached: they are not checked here, and the Recipe is already
           the §14.2 error the chain walk reported (C9 runs this check
           last), as in the other implementations (final review M1). */
        if (rc < 0) { changed[vi] = 1; break; }
        if (rc == 0) continue;
        changed[vi] = 1;
        lists[nl] = prev;
        cur = nl++;
    }
    for (int k = 0, prev_m = 0; k < n_sigs; k++) {
        const dkim2_sig_t *s = sig_arr[k];
        int due = s->i == 1, at = -1;
        for (int vi = 0; vi < n_mi; vi++) {
            if (mis[vi]->m > prev_m && mis[vi]->m <= s->m && changed[vi]) due = 1;
            if (mis[vi]->m == s->m) at = vi;
        }
        prev_m = s->m;
        if (!due || at < 0 || state_of[at] < 0) continue;
        if (!fromlist_authentic(&lists[state_of[at]], s->d)) {
            snprintf(msg, msgsz, "PERMERROR: DKIM2-Signature i=%d matching From is not authentic", s->i);
            rc_out = -1;
            goto done;
        }
    }
done:
    for (int i = 0; i < nl; i++) fromlist_free(&lists[i]);
    return rc_out;
}

static int check_custody(dkim2_sig_t **sig_arr, int n_sigs, char *msg, size_t msgsz) {
    for (int k = 1; k < n_sigs; k++) {
        const dkim2_sig_t *s = sig_arr[k], *p = sig_arr[k - 1];
        if (p->nd) {
            if (!s->d || strcasecmp(p->nd, s->d) != 0) {
                snprintf(msg, msgsz, "PERMERROR: DKIM2-Signature i=%d nd= does not match", p->i);
                return -1;
            }
            continue;
        }
        if (s->nd || !s->mf || is_null_path(s->mf)) {
            if (!s->d || !rt_matches(p, s->d)) {
                snprintf(msg, msgsz,
                    "PERMERROR: DKIM2-Signature i=%d d= does not match the rt= of i=%d", s->i, p->i);
                return -1;
            }
            continue;
        }
        char md[512];
        if (dkim2_addr_alabel(s->mf, md, sizeof md, NULL) != 0 || !matches_rt(md, p)) {
            snprintf(msg, msgsz,
                "PERMERROR: DKIM2-Signature i=%d mf= does not match the rt= of i=%d", s->i, p->i);
            return -1;
        }
    }
    for (int k = 0; k < n_sigs; k++) {
        const dkim2_sig_t *s = sig_arr[k];
        if (s->nd || !s->mf || is_null_path(s->mf)) continue;
        char md[512];
        if (dkim2_addr_alabel(s->mf, md, sizeof md, NULL) != 0 || !s->d ||
            !dkim2_relaxed_match(md, s->d)) {
            snprintf(msg, msgsz, "PERMERROR: DKIM2-Signature i=%d MAIL FROM and d= do not match", s->i);
            return -1;
        }
    }
    return 0;
}

/* -07 §10.9: a Selector MUST NOT appear more than once within a single
   s= tag; the same signing algorithm MAY appear a second time, but only
   with a distinct Selector -- three or more occurrences of the same
   algorithm means "more selectors than allowed". The two checks are
   independent: two items sharing both algorithm and Selector are a
   duplicate-selector error, not a selector-count error (the count is 2,
   not 3+). Matching is
   case-insensitive for both: algorithm names are RFC 5234 ABNF quoted
   strings, and a Selector is a Domain (-07 §3.6) -- DNS names are
   case-insensitive. Returns 0 if clean, -1 with errbuf filled otherwise. */
static const dkim2_sigset_t *g_cmp_ssets; /* qsort context (single-threaded use) */

static int cmp_sel(const void *a, const void *b) {
    return strcasecmp(g_cmp_ssets[*(const int *)a].selector,
                      g_cmp_ssets[*(const int *)b].selector);
}
static int cmp_alg(const void *a, const void *b) {
    return strcasecmp(g_cmp_ssets[*(const int *)a].alg,
                      g_cmp_ssets[*(const int *)b].alg);
}

/* Sorted, not pairwise: an s= with thousands of items stays O(n log n). */
int dkim2_sig_check_duplicates(const dkim2_sig_t *sig, char *errbuf, size_t errbufsz) {
    int n = sig->n_ssets;
    if (n < 2) return 0;
    int *idx = malloc((size_t)n * sizeof *idx);
    if (!idx) {
        snprintf(errbuf, errbufsz, "PERMERROR: DKIM2-Signature i=%d syntax error", sig->i);
        return -1;
    }
    int rc = 0;
    for (int i = 0; i < n; i++) idx[i] = i;
    g_cmp_ssets = sig->ssets;
    qsort(idx, (size_t)n, sizeof *idx, cmp_sel);
    for (int i = 1; i < n; i++)
        if (strcasecmp(sig->ssets[idx[i - 1]].selector, sig->ssets[idx[i]].selector) == 0) {
            snprintf(errbuf, errbufsz,
                "PERMERROR: DKIM2-Signature i=%d has a duplicate selector", sig->i);
            rc = -1; goto out;
        }

    qsort(idx, (size_t)n, sizeof *idx, cmp_alg);
    for (int i = 0, run = 1; i < n; i++, run++) {
        if (i == 0 || strcasecmp(sig->ssets[idx[i - 1]].alg, sig->ssets[idx[i]].alg) != 0)
            run = 1;
        if (run > 2) {
            snprintf(errbuf, errbufsz,
                "PERMERROR: DKIM2-Signature i=%d has more selectors than allowed", sig->i);
            rc = -1; goto out;
        }
    }
out:
    g_cmp_ssets = NULL;
    free(idx);
    return rc;
}

/* -07 §3.5/§10.9: the signing algorithms we implement, by exact
   (case-significant) name. Anything else is ignored. */
static int known_sig_alg(const char *alg) {
    return strcmp(alg, "rsa-sha256") == 0 || strcmp(alg, "ed25519-sha256") == 0;
}

/* The key type an implemented algorithm needs (dkim2_pubkey_t.alg). */
static const char *sig_alg_key_type(const char *alg) {
    return strcmp(alg, "rsa-sha256") == 0 ? "rsa" : "ed25519";
}

/* Build signing input for the verifier — same structure as -07 §12.8 signing,
   but for the signature being verified, substitute empty string for its sig value.
   The sig_value_to_empty is the sig_b64 we want to blank out.
   We reconstruct an "incomplete" signature value by using dkim2_sig_format. */
/* Blank sig bytes in a raw DKIM2-Signature value, preserving trailing semicolon.
   Finds the s= tag and replaces each sel:alg:sigvalue with sel:alg: (empty).
   Returns malloc'd string. */
static char *blank_sig_values(const char *raw_val) {
    size_t rlen = strlen(raw_val);

    /* Find the s= tag at a tag boundary (start, or after ';'/FWS), matching
       the tag name case-insensitively per -07 §10.  FWS may sit between the
       tag name and '=' ("s = sel:alg:sig", Turscar tags_whitespace). */
    const char *s_tag = NULL, *s_eq = NULL;
    for (const char *p = raw_val; *p; p++) {
        if ((p[0] == 's' || p[0] == 'S')
            && (p == raw_val || p[-1] == ';' || p[-1] == ' ' || p[-1] == '\t'
                || p[-1] == '\n')) {
            const char *q = p + 1;
            while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
            if (*q == '=') {
                s_tag = p;
                s_eq = q;
                break;
            }
        }
    }
    if (!s_tag) return strdup(raw_val); /* no s= tag, return as-is */

    /* Output buffer: prefix + blanked ssets + optional trailing ";" */
    char *out = malloc(rlen + 32);
    if (!out) return NULL;
    size_t pos = 0;

    /* Copy prefix up to and including the "=" of s= */
    size_t prefix_len = (size_t)(s_eq - raw_val) + 1;
    memcpy(out, raw_val, prefix_len);
    pos = prefix_len;

    /* Parse comma-separated selector:alg:sigval entries */
    const char *p = s_eq + 1;
    int first = 1;
    while (*p && *p != ';') {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == ';') break;

        /* selector */
        const char *c1 = p;
        while (*c1 && *c1 != ':' && *c1 != ';' && *c1 != ',') c1++;
        if (*c1 != ':') break;
        size_t sel_len = (size_t)(c1 - p);

        /* alg */
        const char *c2 = c1 + 1;
        while (*c2 && *c2 != ':' && *c2 != ';' && *c2 != ',') c2++;
        if (*c2 != ':') break;
        size_t alg_len = (size_t)(c2 - c1 - 1);

        /* skip sig value to next comma or semicolon */
        const char *sig_end = c2 + 1;
        while (*sig_end && *sig_end != ',' && *sig_end != ';') sig_end++;

        if (!first) out[pos++] = ',';
        first = 0;
        memcpy(out + pos, p, sel_len); pos += sel_len;
        out[pos++] = ':';
        memcpy(out + pos, c1 + 1, alg_len); pos += alg_len;
        out[pos++] = ':';

        p = sig_end;
        if (*p == ',') p++;
    }

    /* Copy everything from the end of the s= value onward verbatim: a trailing
       ';' and/or any tags that follow s= when it is not the last tag (so the
       reconstruction is independent of tag order). */
    size_t rest_len = strlen(p);
    memcpy(out + pos, p, rest_len); pos += rest_len;
    out[pos] = '\0';
    return out;
}

/* Append the canonical form of "hdr_name: val" to *buf, growing it.
   Returns 0, or -1 on allocation failure. */
static int append_canon(char **buf, size_t *pos, size_t *bufsz,
                        const char *hdr_name, const char *val) {
    size_t vl = strlen(val);
    char *full = malloc(vl + strlen(hdr_name) + 5);
    if (!full) return -1;
    sprintf(full, "%s: %s\r\n", hdr_name, val);
    char *canon = canon_for_sig(full);
    free(full);
    if (!canon) return -1;
    size_t cl = strlen(canon);
    if (*pos + cl > *bufsz) {
        size_t nsz = (*pos + cl) * 2;
        char *nb = realloc(*buf, nsz);
        if (!nb) { free(canon); return -1; }
        *buf = nb; *bufsz = nsz;
    }
    memcpy(*buf + *pos, canon, cl);
    *pos += cl;
    free(canon);
    return 0;
}

static unsigned char *build_verify_input(
    dkim2_mi_t *mi_list, dkim2_sig_t *sig_list,
    dkim2_sig_t *target_sig, int target_sset_idx __attribute__((unused)),
    size_t *out_len) {
    /* Build signing input for target_sig: include only MI headers with m <=
       target_sig->m, and only DKIM2-Signature headers with i <= target_sig->i.
       The email stores them newest-first; -07 §12.8 requires ascending order. */
    const int MAX = 64;
    dkim2_mi_t *mi_arr[MAX]; int n_mi = 0;
    dkim2_sig_t *sig_arr[MAX]; int n_sig = 0;

    for (dkim2_mi_t *mi = mi_list; mi && n_mi < MAX; mi = mi->next)
        if (mi->raw_value && mi->m <= target_sig->m) mi_arr[n_mi++] = mi;
    for (dkim2_sig_t *s = sig_list; s && n_sig < MAX; s = s->next)
        if (s->raw_value && s->i <= target_sig->i) sig_arr[n_sig++] = s;

    /* Insertion sort MI by ascending m= */
    for (int i = 1; i < n_mi; i++) {
        dkim2_mi_t *key = mi_arr[i]; int j = i - 1;
        while (j >= 0 && mi_arr[j]->m > key->m) { mi_arr[j+1] = mi_arr[j]; j--; }
        mi_arr[j+1] = key;
    }
    /* Insertion sort sig by ascending i= */
    for (int i = 1; i < n_sig; i++) {
        dkim2_sig_t *key = sig_arr[i]; int j = i - 1;
        while (j >= 0 && sig_arr[j]->i > key->i) { sig_arr[j+1] = sig_arr[j]; j--; }
        sig_arr[j+1] = key;
    }

    size_t bufsz = 65536;
    char *buf = malloc(bufsz);
    if (!buf) return NULL;
    size_t pos = 0;

    /* MI headers ascending m= */
    for (int i = 0; i < n_mi; i++)
        if (append_canon(&buf, &pos, &bufsz, "message-instance", mi_arr[i]->raw_value) < 0) {
            free(buf); return NULL;
        }

    /* DKIM2-Signature headers ascending i= */
    for (int i = 0; i < n_sig; i++) {
        dkim2_sig_t *sig = sig_arr[i];
        char *to_use;
        if (sig->i == target_sig->i)
            to_use = blank_sig_values(sig->raw_value);
        else
            to_use = strdup(sig->raw_value);
        if (!to_use) { free(buf); return NULL; }
        int ar = append_canon(&buf, &pos, &bufsz, "dkim2-signature", to_use);
        free(to_use);
        if (ar < 0) { free(buf); return NULL; }
    }

    *out_len = pos;
    return (unsigned char *)buf;
}

/* The undo walk (the reference for the planned walk in dkim2_plan.c, which
   is the default; ctx->undo_walk selects this one): verify all MI
   body+header hashes, walking from highest to lowest version and applying
   Recipes to rebuild each earlier message. Returns 0 on success, sets errbuf
   on failure. With trace (n_mi entries) it records what each instance
   hashed to, every algorithm, and carries on past hash mismatches: only a
   Recipe error stops it (parity tests). */
static int undo_walk(
    dkim2_mi_t **mi_arr, int n_mi,
    char **all_hdrs, int n_all_hdrs,
    const char *initial_body, size_t initial_body_len,
    const dkim2_ctx_t *ctx,
    char *errbuf, size_t errbufsz, dkim2_plan_level_t *trace)
{
    /* Build content-headers array (exclude Message-Instance and DKIM2-Signature). */
    char **content = malloc((size_t)n_all_hdrs * sizeof(char *));
    if (!content) { snprintf(errbuf, errbufsz, "PERMERROR: OOM"); return -1; }
    int n_content = 0;
    for (int i = 0; i < n_all_hdrs; i++) {
        const char *colon = strchr(all_hdrs[i], ':');
        size_t nl = colon ? (size_t)(colon - all_hdrs[i]) : strlen(all_hdrs[i]);
        char lname[64] = {0};
        if (nl < sizeof lname) {
            for (size_t j = 0; j < nl; j++)
                lname[j] = (char)tolower((unsigned char)all_hdrs[i][j]);
            if (strcmp(lname, "message-instance") == 0 ||
                strcmp(lname, "dkim2-signature")  == 0) continue;
        }
        content[n_content++] = all_hdrs[i];
    }
    int content_owned = 0; /* initially points into all_hdrs, not owned */

    char *cur_body = NULL;
    size_t cur_body_len = 0;
    /* A non-NULL body of length 0 is a valid EMPTY body (still hashed and
       Recipe-undone like any other); only a NULL pointer means digest-only. */
    if (initial_body) {
        cur_body = malloc(initial_body_len + 1);
        if (!cur_body) {
            free(content);
            snprintf(errbuf, errbufsz, "PERMERROR: OOM");
            return -1;
        }
        memcpy(cur_body, initial_body, initial_body_len);
        cur_body[initial_body_len] = '\0';
        cur_body_len = initial_body_len;
    }

    int ret = 0;
    /* -07 §5.2: a null body Recipe means the previous body cannot be
       recreated -- but header Recipes are mandatory (-07 §5.1), so the header
       history can still be walked. Once set (sticky), every lower instance
       is checked on its header hashes only and body Recipes are not applied. */
    int body_gone = 0;
    for (int vi = n_mi - 1; vi >= 0; vi--) {
        dkim2_mi_t *mi = mi_arr[vi];

        if (trace) {
            dkim2_plan_level_t *t = &trace[vi];
            t->reached = 1;
            t->have_body = !body_gone && cur_body;
            for (int a = 0; a < DKIM2_N_HASH_ALGS; a++) {
                if (t->have_body)
                    dkim2_body_hash_raw_alg(cur_body, cur_body_len, a, t->body.d[a]);
                dkim2_header_hash_raw_alg((const char **)content, n_content, a, t->hdr.d[a]);
            }
        }
        int n_checked = 0;
        for (int hi = 0; !trace && hi < mi->n_hsets; hi++) {
            int alg = dkim2_hash_alg_index(mi->hsets[hi].alg);
            if (alg < 0) continue;          /* -07 §3.5: ignore what we don't implement */
            size_t alen = dkim2_hash_alg_len(alg);
            n_checked++;

            /* Header hash before body hash (contract C9: the same primary
               error as the other verifiers when both are wrong). */
            unsigned char computed_hh[DKIM2_MAX_HASH_LEN];
            if (dkim2_header_hash_raw_alg((const char **)content, n_content, alg, computed_hh) < 0) {
                snprintf(errbuf, errbufsz, "PERMERROR: header hash computation failed");
                ret = -1; goto done;
            }
            unsigned char stored_hh[DKIM2_MAX_HASH_LEN];
            int hh_len = (int)b64_decode(mi->hsets[hi].hdr_hash, stored_hh, sizeof stored_hh);
            if (hh_len != (int)alen || memcmp(computed_hh, stored_hh, alen) != 0) {
                snprintf(errbuf, errbufsz,
                    "FAIL: Message-Instance m=%d header hash %s mismatch", mi->m, dkim2_hash_alg_name(alg));
                ret = -1; goto done;
            }

            if (!body_gone) {
            unsigned char stored_bh[DKIM2_MAX_HASH_LEN];
            int bh_len = (int)b64_decode(mi->hsets[hi].body_hash, stored_bh, sizeof stored_bh);
            if (bh_len != (int)alen) {
                snprintf(errbuf, errbufsz, "PERMERROR: bad body hash in MI m=%d", mi->m);
                ret = -1; goto done;
            }
            unsigned char computed_bh[DKIM2_MAX_HASH_LEN];
            int have_body_hash = 1;
            if (cur_body) {
                dkim2_body_hash_raw_alg(cur_body, cur_body_len, alg, computed_bh);
            } else if (vi == n_mi - 1) {
                memcpy(computed_bh, ctx->body_digests.d[alg], alen);
            } else {
                have_body_hash = 0;          /* no body bytes for inner MIs */
            }
            /* Only the BODY comparison is skipped without body bytes; the
               header hash above is always checked (a digest-only caller
               still sees a bad inner header history). */
            if (have_body_hash && memcmp(computed_bh, stored_bh, alen) != 0) {
                snprintf(errbuf, errbufsz,
                    "FAIL: Message-Instance m=%d body hash %s mismatch", mi->m, dkim2_hash_alg_name(alg));
                ret = -1; goto done;
            }
            }
        }
        /* Fail closed: an MI naming no implemented algorithm is unverifiable. */
        if (n_checked == 0 && !trace) {
            snprintf(errbuf, errbufsz,
                "PERMERROR: Message-Instance m=%d no supported hash algorithm", mi->m);
            ret = -1; goto done;
        }

        /* -07 §12.1: even the bottom (m=1) instance MAY carry Recipes
           ("if it is wished to record any changes made to a message as it
           enters the DKIM2 ecosystem"), so a malformed r= there must be
           reported exactly like on any other instance -- this check is NOT
           gated on vi > 0. Only the UNDO step below (reconstructing the
           prior hop's state) is skipped at vi == 0: there is no earlier
           state to undo to. */
        if (mi->r_raw) {
            size_t rraw_len = strlen(mi->r_raw);
            size_t decoded_max = rraw_len * 3 / 4 + 4;
            unsigned char *r_json_bytes = malloc(decoded_max + 1);
            if (!r_json_bytes) {
                if (vi > 0) continue; /* OOM — skip undo, inner hash unverified */
            } else {
                int r_json_len = (int)b64_decode(mi->r_raw, r_json_bytes, decoded_max);
                if (r_json_len <= 0) {
                    /* -07 §14.2: a malformed r= base64 payload is a
                       syntax error -- distinct from, and reported before,
                       a post-decode JSON parse failure. This used to
                       silently `continue`, the same silent-drop shape as
                       the JSON-parse case above it (and the duplicate-h=
                       case fixed in commit 66bd3e6): nothing was ever
                       reported for a malformed r= base64 value. */
                    free(r_json_bytes);
                    snprintf(errbuf, errbufsz,
                        "PERMERROR: Message-Instance m=%d syntax error", mi->m);
                    if (trace) trace[vi].r_err = 1;
                    ret = -1; goto done;
                }
                r_json_bytes[r_json_len] = '\0';
                const char *rj = (const char *)r_json_bytes;

                /* -07 §14.2: "errors in a JSON object specifying Recipes
                   should be called out specifically". dkim2_apply_body_recipe()
                   and dkim2_apply_header_recipe() both return NULL on a
                   cJSON_Parse() failure with no way to distinguish that from
                   their other NULL cases, and their call sites below used to
                   just silently no-op (keep the old body / keep the old
                   headers) rather than report anything -- so a malformed r=
                   payload never surfaced as an error at all. Probe the decoded
                   JSON directly here, before either apply_*_recipe() call, so
                   that failure is reported specifically instead of vanishing. */
                /* dkim2_recipe_parse(): a duplicate key (ignoring case) and
                   anything the -07 §5 schema forbids are invalid JSON too. */
                cJSON *probe = dkim2_recipe_parse(rj);
                if (!probe) {
                    free(r_json_bytes);
                    snprintf(errbuf, errbufsz,
                        "PERMERROR: Message-Instance m=%d contains invalid JSON", mi->m);
                    if (trace) trace[vi].r_err = 2;
                    ret = -1; goto done;
                }
                int null_body = 0;
                {
                    cJSON *pb = cJSON_GetObjectItemCaseSensitive(probe, "b");
                    null_body = pb && cJSON_IsNull(pb);
                }
                cJSON_Delete(probe);

                /* Undo this MI's Recipe to reconstruct the previous hop's
                   state -- only meaningful when there IS a previous hop. */
                if (vi > 0) {
                    /* Apply body Recipe */
                    /* The JSON parsed and met the schema above, so a NULL
                       from either apply_* call now means the Recipe does not
                       fit the message (a copy past the last line or field).
                       That is "contains invalid JSON" too (every Recipe error
                       is, by the -07 ruling), not a fall-through to a hash
                       mismatch on the un-undone content. */
                    if (null_body) {
                        /* Previous body is unrecoverable: stop checking
                           bodies from here down (headers still checked). */
                        body_gone = 1;
                        free(cur_body);
                        cur_body = NULL;
                        cur_body_len = 0;
                    } else if (body_gone) {
                        /* Structure is still validated below a null. */
                        if (dkim2_validate_body_recipe(rj) != 0) {
                            free(r_json_bytes);
                            snprintf(errbuf, errbufsz,
                                "PERMERROR: Message-Instance m=%d contains invalid JSON", mi->m);
                            if (trace) trace[vi].body_err = 1;
                            ret = -1; goto done;
                        }
                    } else if (cur_body) {
                        size_t new_len;
                        char *new_body = dkim2_apply_body_recipe(rj, cur_body, cur_body_len, &new_len);
                        if (!new_body) {
                            free(r_json_bytes);
                            snprintf(errbuf, errbufsz,
                                "PERMERROR: Message-Instance m=%d contains invalid JSON", mi->m);
                            if (trace) trace[vi].body_err = 1;
                            ret = -1; goto done;
                        }
                        free(cur_body);
                        cur_body = new_body;
                        cur_body_len = new_len;
                    }

                    /* Apply header Recipe — result is always a new owned array */
                    int new_n = 0;
                    char **new_content = dkim2_apply_header_recipe(rj, content, n_content, &new_n);
                    if (!new_content) {
                        free(r_json_bytes);
                        snprintf(errbuf, errbufsz,
                            "PERMERROR: Message-Instance m=%d contains invalid JSON", mi->m);
                        if (trace) trace[vi].hdr_err = 1;
                        ret = -1; goto done;
                    }
                    if (content_owned) {
                        for (int i = 0; i < n_content; i++) free(content[i]);
                    }
                    free(content);
                    content = new_content;
                    n_content = new_n;
                    content_owned = 1;
                }

                free(r_json_bytes);
            }
        }
    }

done:
    if (content_owned) for (int i = 0; i < n_content; i++) free(content[i]);
    free(content);
    free(cur_body);
    return ret;
}

/* -07 §14.2 for every Message-Instance's r= on its own, highest m= first:
   base64 that does not decode is a syntax error, JSON that does not parse
   or breaks the §5 schema (dkim2_recipe_parse: duplicate keys, step shapes,
   "c" ranges ascending) is invalid JSON. 0, or -1 with the PERMERROR in
   msg. */
static int recipe_fields_error(const dkim2_ctx_t *ctx, char *msg, size_t msgsz) {
    enum { MAX_MI = 64 };
    dkim2_mi_t *mis[MAX_MI];
    int n_mi = dkim2_mi_sorted(ctx->mi_list, mis, MAX_MI);
    for (int vi = n_mi - 1; vi >= 0; vi--) {
        const dkim2_mi_t *mi = mis[vi];
        if (!mi->r_raw) continue;
        size_t max = strlen(mi->r_raw) * 3 / 4 + 4;
        unsigned char *json = malloc(max + 1);
        if (!json) {
            snprintf(msg, msgsz, "TEMPERROR: out of memory");
            return -1;
        }
        int len = (int)b64_decode(mi->r_raw, json, max);
        if (len <= 0) {
            free(json);
            snprintf(msg, msgsz, "PERMERROR: Message-Instance m=%d syntax error", mi->m);
            return -1;
        }
        json[len] = '\0';
        cJSON *r = dkim2_recipe_parse((const char *)json);
        free(json);
        if (!r) {
            snprintf(msg, msgsz, "PERMERROR: Message-Instance m=%d contains invalid JSON", mi->m);
            return -1;
        }
        cJSON_Delete(r);
    }
    return 0;
}

static int verify_mi_hashes(
    dkim2_mi_t **mi_arr, int n_mi,
    char **all_hdrs, int n_all_hdrs,
    const char *initial_body, size_t initial_body_len,
    const dkim2_ctx_t *ctx,
    char *errbuf, size_t errbufsz) {
    return undo_walk(mi_arr, n_mi, all_hdrs, n_all_hdrs, initial_body,
                     initial_body_len, ctx, errbuf, errbufsz, NULL);
}

int dkim2_undo_walk_trace(dkim2_mi_t **mi_arr, int n_mi, char **hdrs, int n_hdrs,
                          const char *body, size_t body_len,
                          dkim2_plan_level_t *trace, char *errbuf, size_t errbufsz) {
    dkim2_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    memset(trace, 0, (size_t)n_mi * sizeof *trace);
    errbuf[0] = '\0';
    return undo_walk(mi_arr, n_mi, hdrs, n_hdrs, body, body_len, &ctx,
                     errbuf, errbufsz, trace);
}

/* -07 §14.7 over ctx->mi_list, sorted by m=. The planned walk (dkim2_plan.c) by
   default: on the plan the caller fed (ctx->plan, e.g. the milter's
   streamed body), else on one made here from ctx->body. The undo walk when
   asked (ctx->undo_walk), when there are no body bytes at all (digest-only
   callers: the top body hash is checked, inner ones cannot be), and for the
   one case the plan does not model. Returns 0, or -1 with errbuf set
   ("FAIL..." / "PERMERROR..."). */
static int verify_ctx_mi_chain(const dkim2_ctx_t *ctx, char *errbuf, size_t errbufsz) {
    const int MAX_MI = 64;
    dkim2_mi_t *mi_sorted[MAX_MI];
    int n_mi = dkim2_mi_sorted(ctx->mi_list, mi_sorted, MAX_MI);
    if (!ctx->undo_walk && (ctx->plan || ctx->body)) {
        dkim2_plan_t *plan = ctx->plan;
        if (!plan) {
            plan = dkim2_plan_new(mi_sorted, n_mi, ctx->headers, ctx->n_headers, 0, 0);
            if (plan && (dkim2_plan_body_update(plan, ctx->body, ctx->body_len) < 0 ||
                         dkim2_plan_body_final(plan) < 0)) {
                dkim2_plan_free(plan);
                plan = NULL;
            }
        } else if (dkim2_plan_body_final(plan) < 0) {
            plan = NULL;
        }
        if (!plan) {
            snprintf(errbuf, errbufsz, "PERMERROR: OOM");
            return -1;
        }
        int rc = dkim2_plan_check(plan, errbuf, errbufsz);
        if (plan != ctx->plan) dkim2_plan_free(plan);
        if (rc <= 0) return rc;
    }
    return verify_mi_hashes(mi_sorted, n_mi, ctx->headers, ctx->n_headers,
                            ctx->body, ctx->body_len, ctx, errbuf, errbufsz);
}

void dkim2_do_verify(dkim2_ctx_t *ctx, dkim2_verify_result_t *result) {
    result->status = DKIM2_PERMERROR;
    result->message[0] = '\0';
    result->sig_i = 0;
    result->domain[0] = '\0';

    /* -07 §9.3: a Message-Instance header that failed to parse --
       whether with a specific reportable cause (duplicate hash algorithm in
       h=, the -2 case) or a plain syntax/malloc failure (-1: a missing
       required tag, a malformed h= entry, or an allocation failure) -- never
       made it into ctx->mi_list. The header-collection path
       (dkim2_message.c/dkim2_milter.c) dropped it and recorded the reason
       here instead via dkim2_mi_parse_err()'s errbuf. Report it immediately,
       before any other check (including DNS/crypto), and regardless of
       whether the affected m= would have been the topmost, signature-covered
       instance or the bottom (m=1) one: it must never simply vanish, and
       must never be misreported as "no Message-Instance for m=N" (the wrong
       error, describing the wrong problem).

       The bottom-MI case matters in its own right: nothing else in this
       function or in verify_mi_hashes() (-07 §14.7, below) independently checks
       for a dropped m=1 -- the only thing that happens to catch it today is
       that m=1's raw bytes are always part of every covering signature's
       -07 §14.6 crypto input (mi->m is always <= any sig's target m), so a drop
       usually surfaces as an incidental "signature verification failed"
       instead. A hand-built message whose signatures were computed to match
       the verifier's already-missing-m=1 reconstruction (see
       c/tests/test_verify.c) passes with no error at all if this mi_error
       check doesn't run first -- i.e. without this check, the bottom-MI case
       fails OPEN in that construction. This check must fire unconditionally,
       before that crypto path is ever reached. */
    /* No DKIM2 header fields at all: "none" (A-R dkim2=none), with no
       error string -- not a PERMERROR (contract C6, 2026-10-18). */
    if (!ctx->mi_list && !ctx->sig_list && !ctx->mi_error[0] && !ctx->sig_error[0]) {
        result->status = DKIM2_NONE;
        return;
    }

    if (ctx->mi_error[0])
        SETSTATUS(DKIM2_PERMERROR, "%s", ctx->mi_error);

    /* Likewise a DKIM2-Signature that did not parse (no i=, an i= that is
       not a positive integer, a missing required tag): a PERMERROR, never
       verified around as if it were absent. */
    if (ctx->sig_error[0])
        SETSTATUS(DKIM2_PERMERROR, "%s", ctx->sig_error);

    /* -07 §9.1/§14.7: each Message-Instance m= value appears once. Check it
       explicitly (inbound and outbound), before any crypto, rather than
       leaving it to an incidental signature or hash failure. */
    for (const dkim2_mi_t *a = ctx->mi_list; a; a = a->next)
        for (const dkim2_mi_t *b = a->next; b; b = b->next)
            if (a->m == b->m)
                SETSTATUS(DKIM2_PERMERROR, "PERMERROR: Message-Instance m=%d appears more than once", a->m);

    /* -07 §9.1: m= values must be contiguous 1..N. Explicit, before any
       crypto: name the first missing m= (§14.2 "missing"). (An unsigned top MI above the top signature
       is still a member of 1..N, so outbound mode needs no exemption; only a
       gap is an error.) */
    {
        int max_m = 0, n_mi = 0;
        for (const dkim2_mi_t *a = ctx->mi_list; a; a = a->next) {
            n_mi++;
            if (a->m > max_m) max_m = a->m;
        }
        for (int want = 1; n_mi && want <= max_m; want++) {
            int found = 0;
            for (const dkim2_mi_t *a = ctx->mi_list; a; a = a->next)
                if (a->m == want) { found = 1; break; }
            if (!found)
                SETSTATUS(DKIM2_PERMERROR,
                    "PERMERROR: Message-Instance m=%d missing", want);
        }
    }

    /* Outbound mode (signer gate): a chain with no signature yet -- just an
       unsigned Message-Instance the signer is about to cover -- has no
       signature to verify; its MI chain is still checked. */
    if (ctx->outbound && !ctx->sig_list && ctx->mi_list) {
        char mi_errbuf[512];
        if (verify_ctx_mi_chain(ctx, mi_errbuf, sizeof mi_errbuf) < 0)
            SETSTATUS((mi_errbuf[0] == 'F') ? DKIM2_FAIL : DKIM2_PERMERROR,
                "%s", mi_errbuf);
        result->status = DKIM2_OK;
        snprintf(result->message, sizeof result->message,
            "PASS: no DKIM2-Signature yet; Message-Instance chain verified");
        return;
    }

    /* -07 §14.2: Message-Instance fields but no DKIM2-Signature: the top
       instance is not signed. */
    if (!ctx->sig_list) {
        int top = 0;
        for (const dkim2_mi_t *a = ctx->mi_list; a; a = a->next)
            if (a->m > top) top = a->m;
        SETSTATUS(DKIM2_PERMERROR, "PERMERROR: Message-Instance m=%d is not signed", top);
    }

    /* Build sorted array of all sigs (ascending i=) */
    const int MAX = 64;
    dkim2_sig_t *sig_arr[MAX]; int n_sigs = 0;
    for (dkim2_sig_t *s = ctx->sig_list; s && n_sigs < MAX; s = s->next)
        sig_arr[n_sigs++] = s;
    for (int i = 1; i < n_sigs; i++) {
        dkim2_sig_t *key = sig_arr[i]; int j = i - 1;
        while (j >= 0 && sig_arr[j]->i > key->i) { sig_arr[j+1] = sig_arr[j]; j--; }
        sig_arr[j+1] = key;
    }

    dkim2_sig_t *latest = sig_arr[n_sigs - 1];
    result->sig_i = latest->i;
    snprintf(result->domain, sizeof result->domain, "%s", latest->d ? latest->d : "");

    /* -07 §10.1: i= sequence must be contiguous 1..N; name the first gap. */
    for (int i = 0; i < n_sigs; i++) {
        if (sig_arr[i]->i != i + 1)
            SETSTATUS(DKIM2_PERMERROR, "PERMERROR: DKIM2-Signature i=%d missing", i + 1);
    }

    /* Find the MI the latest signature covers */
    dkim2_mi_t *covered_mi = NULL;
    for (dkim2_mi_t *m = ctx->mi_list; m; m = m->next)
        if (m->m == latest->m) { covered_mi = m; break; }
    if (!covered_mi)
        SETSTATUS(DKIM2_PERMERROR,
            "PERMERROR: Message-Instance m=%d missing", latest->m);

    /* -07 §14.2: No MI with m= higher than latest->m should exist unsigned */
    for (dkim2_mi_t *m = ctx->mi_list; m; m = m->next) {
        /* Outbound mode: the unsigned top instance is the one the signer is
           about to cover (e.g. a list manager's own m=), so it is allowed. */
        if (!ctx->outbound && m->m > latest->m)
            SETSTATUS(DKIM2_PERMERROR,
                "PERMERROR: Message-Instance m=%d is not signed", m->m);
    }

    /* Contract C9: the rest runs in -07 §14 section order, each section
       over every signature from i=1 up, so the first error found is the
       primary one. */

    /* -07 §14.2: every Message-Instance's r= on its own, highest m= first,
       whether or not the chain walk reaches it. A Recipe that does not fit
       the message (a copy past the end) is the walk's to find (§14.7). */
    {
        char rbuf[256];
        if (recipe_fields_error(ctx, rbuf, sizeof rbuf) < 0)
            SETSTATUS(rbuf[0] == 'T' ? DKIM2_TEMPERROR : DKIM2_PERMERROR, "%s", rbuf);
    }

    /* -07 §14.2, each signature field on its own: the §10.9 duplicate and
       limit rules, and every implemented item's value a padded
       base64string (FWS already removed by the parser). */
    for (int si = 0; si < n_sigs; si++) {
        dkim2_sig_t *sig = sig_arr[si];
        char dup_errbuf[256];
        if (dkim2_sig_check_duplicates(sig, dup_errbuf, sizeof dup_errbuf) < 0)
            SETSTATUS(DKIM2_PERMERROR, "%s", dup_errbuf);
        for (int j = 0; j < sig->n_ssets; j++)
            if (known_sig_alg(sig->ssets[j].alg) && !b64_is_strict(sig->ssets[j].sig_b64))
                SETSTATUS(DKIM2_PERMERROR,
                    "PERMERROR: DKIM2-Signature i=%d syntax error", sig->i);
    }

    /* -07 §14.3: not Validly Signed when made more than 14 days before
       delivery (now), or from more than one day ahead of it. */
    if (!ctx->skip_timestamp_check) {
        uint64_t now = (uint64_t)time(NULL);
        for (int si = 0; si < n_sigs; si++) {
            dkim2_sig_t *sig = sig_arr[si];
            if (sig->t > now + DKIM2_MAX_FUTURE_SECS)
                SETSTATUS(DKIM2_PERMERROR,
                    "PERMERROR: DKIM2-Signature i=%d signature is from the future", sig->i);
            if (now > sig->t + DKIM2_MAX_AGE_SECS)
                SETSTATUS(DKIM2_PERMERROR,
                    "PERMERROR: DKIM2-Signature i=%d signature expired", sig->i);
        }
    }

    /* -07 §14.4: an nd= on the topmost (highest i=) DKIM2-Signature names a
       next signature that is not there ("unexpected nd= tag"). Non-top nd=
       adjacency is checked with the Chain of Custody below. In outbound
       (signer gate) mode the signer has already required nd= to name its own
       domain -- it is about to add that signature -- so the check is
       skipped. */
    if (!ctx->outbound && latest->nd && latest->nd[0])
        SETSTATUS(DKIM2_PERMERROR, "PERMERROR: DKIM2-Signature i=%d unexpected nd= tag", latest->i);

    /* -07 §14.4: Envelope MAIL FROM must match top sig's mf= (domain
       case-insensitive, local-part case-sensitive, null sender aware). */
    if (!ctx->outbound && ctx->mail_from && latest->mf) {
        if (!env_addr_eq(ctx->mail_from, latest->mf))
            SETSTATUS(DKIM2_PERMERROR,
                "PERMERROR: DKIM2-Signature i=%d MAIL FROM %s did not match",
                latest->i, ctx->mail_from);
    }

    /* RCPT TO: every envelope recipient must appear in rt= (-07 §14.4: domains
       match case-insensitively). */
    if (!ctx->outbound && ctx->rcpt_to && latest->rt) {
        for (int i = 0; ctx->rcpt_to[i]; i++) {
            int found = 0;
            for (int j = 0; latest->rt[j]; j++)
                if (env_addr_eq(ctx->rcpt_to[i], latest->rt[j])) { found = 1; break; }
            if (!found)
                SETSTATUS(DKIM2_PERMERROR,
                    "PERMERROR: DKIM2-Signature i=%d RCPT TO %s did not match",
                    latest->i, ctx->rcpt_to[i]);
        }
    }

    /* -07 §14.4: the Chain of Custody, from the tags alone (before any DNS
       or crypto work). */
    {
        char cmsg[256];
        if (check_custody(sig_arr, n_sigs, cmsg, sizeof cmsg) < 0)
            SETSTATUS(DKIM2_PERMERROR, "%s", cmsg);
    }

    /* -07 §14.5 for every signature, then §14.6 for every signature. The
       outcome of a signature's s= items (behaviour spec E):
       1. unimplemented algorithms are ignored; none implemented: PERMERROR
          (a local check with no -07 string, contract C6).
       2. (an implemented item's value is a padded base64string: §14.2 above)
       3. fetch every implemented item's key: DNS failure is TEMPERROR;
          a present but unusable record is PERMERROR for the whole
          signature, even if another item verifies; absent is skipped.
       4. all absent: PERMERROR naming the first.
       5. verify every item that has a key; any failure is FAIL. */
    dkim2_pubkey_t **keys[MAX];
    memset(keys, 0, sizeof keys);
    dkim2_status_t key_status = DKIM2_OK;
    for (int si = 0; si < n_sigs && key_status == DKIM2_OK; si++) {
        dkim2_sig_t *sig = sig_arr[si];
        result->sig_i = sig->i;
        snprintf(result->domain, sizeof result->domain, "%s", sig->d ? sig->d : "");

        int n_known = 0;
        for (int j = 0; j < sig->n_ssets; j++)
            if (known_sig_alg(sig->ssets[j].alg)) n_known++;
        if (n_known == 0) {
            key_status = DKIM2_PERMERROR;
            snprintf(result->message, sizeof result->message,
                "PERMERROR: DKIM2-Signature i=%d has no signature with a supported algorithm", sig->i);
            break;
        }

        keys[si] = calloc((size_t)sig->n_ssets, sizeof *keys[si]);
        if (!keys[si]) {
            key_status = DKIM2_TEMPERROR;
            snprintf(result->message, sizeof result->message, "TEMPERROR: out of memory");
            break;
        }
        const char *first_absent = NULL;
        int n_keys = 0;
        for (int j = 0; j < sig->n_ssets && key_status == DKIM2_OK; j++) {
            dkim2_sigset_t *sset = &sig->ssets[j];
            if (!known_sig_alg(sset->alg)) continue;

            dkim2_status_t dns_status;
            const char *dns_err = NULL;
            /* From the prefetched answer when it settles the lookup. */
            dkim2_pubkey_t *pubkey = dkim2_prefetch_getkey(ctx->prefetch,
                sset->selector, sig->d, &dns_status, &dns_err);
            const char *why = NULL;

            if (!pubkey || pubkey->revoked) {
                dkim2_pubkey_free(pubkey);
                pubkey = NULL;
                if (dns_err == DKIM2_KEYERR_ABSENT) {
                    if (!first_absent) first_absent = sset->selector;
                    continue;
                }
                if (dns_status == DKIM2_TEMPERROR) {
                    key_status = DKIM2_TEMPERROR;
                    snprintf(result->message, sizeof result->message,
                        "TEMPERROR: DKIM2-Signature i=%d public key %s %s",
                        sig->i, sset->selector, dns_err ? dns_err : DKIM2_KEYERR_FETCH);
                    break;
                }
                why = dns_err ? dns_err : DKIM2_KEYERR_SYNTAX;
            } else if (strcmp(pubkey->alg, sig_alg_key_type(sset->alg)) != 0) {
                why = DKIM2_KEYERR_ALG;                     /* -07 §10.9 */
            } else if (strcmp(sset->alg, "rsa-sha256") == 0 &&
                       EVP_PKEY_bits(pubkey->pkey) < 1024) {
                why = "is shorter than 1024 bits";          /* §3.2 */
            }
            if (why) {
                dkim2_pubkey_free(pubkey);
                key_status = DKIM2_PERMERROR;
                snprintf(result->message, sizeof result->message,
                    "PERMERROR: DKIM2-Signature i=%d public key %s %s",
                    sig->i, sset->selector, why);
                break;
            }
            keys[si][j] = pubkey;
            n_keys++;
        }
        if (key_status == DKIM2_OK && n_keys == 0) {
            key_status = DKIM2_PERMERROR;
            snprintf(result->message, sizeof result->message,
                "PERMERROR: DKIM2-Signature i=%d public key %s %s",
                sig->i, first_absent, DKIM2_KEYERR_ABSENT);
        }
    }

    /* -07 §14.6: check every signature that has a key; all failing is
       "selector <s1> incorrect signature", some passing and some failing
       names one of each. */
    for (int si = 0; si < n_sigs && key_status == DKIM2_OK; si++) {
        dkim2_sig_t *sig = sig_arr[si];
        result->sig_i = sig->i;
        snprintf(result->domain, sizeof result->domain, "%s", sig->d ? sig->d : "");
        const char *failed_sel = NULL, *passed_sel = NULL;
        for (int j = 0; j < sig->n_ssets; j++) {
            if (!keys[si][j]) continue;
            size_t sign_input_len;
            unsigned char *sign_input = build_verify_input(
                ctx->mi_list, ctx->sig_list, sig, j, &sign_input_len);
            if (!sign_input) {
                key_status = DKIM2_PERMERROR;
                snprintf(result->message, sizeof result->message,
                    "PERMERROR: Failed to build signing input for DKIM2-Signature i=%d", sig->i);
                break;
            }
            if (dkim2_verify(keys[si][j]->pkey, sig->ssets[j].alg,
                    sign_input, sign_input_len, sig->ssets[j].sig_b64) != 0) {
                if (!failed_sel) failed_sel = sig->ssets[j].selector;
            } else if (!passed_sel) {
                passed_sel = sig->ssets[j].selector;
            }
            free(sign_input);
        }
        if (key_status != DKIM2_OK) break;
        if (failed_sel) {
            key_status = DKIM2_FAIL;
            if (passed_sel)
                snprintf(result->message, sizeof result->message,
                    "FAIL: DKIM2-Signature i=%d signature %s signature %s failed",
                    sig->i, passed_sel, failed_sel);
            else
                snprintf(result->message, sizeof result->message,
                    "FAIL: DKIM2-Signature i=%d selector %s incorrect signature", sig->i, failed_sel);
        }
    }

    for (int si = 0; si < n_sigs; si++) {
        if (!keys[si]) continue;
        for (int j = 0; j < sig_arr[si]->n_ssets; j++) dkim2_pubkey_free(keys[si][j]);
        free(keys[si]);
    }
    if (key_status != DKIM2_OK) {
        result->status = key_status;
        return;
    }
    result->sig_i = latest->i;
    snprintf(result->domain, sizeof result->domain, "%s", latest->d ? latest->d : "");

    /* -07 §14.7: Verify all MI body+header hashes, undoing Recipes for inner hops. */
    {
        char mi_errbuf[512];
        if (verify_ctx_mi_chain(ctx, mi_errbuf, sizeof mi_errbuf) < 0)
            SETSTATUS((mi_errbuf[0] == 'F') ? DKIM2_FAIL : DKIM2_PERMERROR,
                "%s", mi_errbuf);
    }

    /* -07 §14.8: every From the Recipes show, and the current one, is
       Authentic for its relevant signature. */
    {
        char fmsg[256];
        if (check_from_authentic(ctx, sig_arr, n_sigs, fmsg, sizeof fmsg) < 0)
            SETSTATUS(DKIM2_PERMERROR, "%s", fmsg);
    }

    result->status = DKIM2_OK;
    snprintf(result->message, sizeof result->message,
        "PASS: DKIM2-Signature i=%d verified", latest->i);
}
