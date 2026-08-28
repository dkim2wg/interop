#include "dkim2_hash.h"
#include "base64.h"
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/evp.h>

/* spec-06 §3.1: implemented hash algorithms, in wire/index order. */
static const struct {
    const char *name;
    const EVP_MD *(*md)(void);
    size_t len;
} HASH_ALGS[DKIM2_N_HASH_ALGS] = {
    { "sha256", EVP_sha256, 32 },
    { "sha512", EVP_sha512, 64 },
};

int dkim2_hash_alg_index(const char *name) {
    if (!name) return -1;
    for (int i = 0; i < DKIM2_N_HASH_ALGS; i++)
        if (strcasecmp(name, HASH_ALGS[i].name) == 0) return i;
    return -1;
}

const char *dkim2_hash_alg_name(int idx) {
    return (idx >= 0 && idx < DKIM2_N_HASH_ALGS) ? HASH_ALGS[idx].name : NULL;
}

size_t dkim2_hash_alg_len(int idx) {
    return (idx >= 0 && idx < DKIM2_N_HASH_ALGS) ? HASH_ALGS[idx].len : 0;
}

/* ── Streaming body hasher ──────────────────────────────────────────────── */

struct dkim2_body_hasher {
    EVP_MD_CTX *md_ctx[DKIM2_N_HASH_ALGS];
    int pending_crlfs;  /* trailing \r\n pairs held back (not yet hashed) */
    int prev_was_cr;    /* last byte fed was a bare \r (cross-chunk state) */
};

dkim2_body_hasher_t *dkim2_body_hasher_new(void) {
    dkim2_body_hasher_t *bh = calloc(1, sizeof *bh);
    if (!bh) return NULL;
    for (int i = 0; i < DKIM2_N_HASH_ALGS; i++) {
        bh->md_ctx[i] = EVP_MD_CTX_new();
        if (!bh->md_ctx[i] || EVP_DigestInit_ex(bh->md_ctx[i], HASH_ALGS[i].md(), NULL) != 1) {
            for (int j = 0; j <= i; j++) EVP_MD_CTX_free(bh->md_ctx[j]);
            free(bh);
            return NULL;
        }
    }
    return bh;
}

static void flush_pending(dkim2_body_hasher_t *bh) {
    while (bh->pending_crlfs > 0) {
        for (int i = 0; i < DKIM2_N_HASH_ALGS; i++)
            EVP_DigestUpdate(bh->md_ctx[i], "\r\n", 2);
        bh->pending_crlfs--;
    }
}

int dkim2_body_hasher_update(dkim2_body_hasher_t *bh,
                             const char *data, size_t len) {
    size_t i = 0;
    while (i < len) {
        /* Resolve pending bare \r from previous chunk */
        if (bh->prev_was_cr) {
            bh->prev_was_cr = 0;
            if (data[i] == '\n') {
                bh->pending_crlfs++;
                i++;
                continue;
            }
            /* Bare \r: normalise to \r\n, emit as a line terminator */
            flush_pending(bh);
            for (int k = 0; k < DKIM2_N_HASH_ALGS; k++)
                EVP_DigestUpdate(bh->md_ctx[k], "\r\n", 2);
            /* data[i] is unprocessed non-\n; fall through */
        }

        /* Scan for next \r or bare \n */
        size_t j = i;
        while (j < len && data[j] != '\r' && data[j] != '\n') j++;

        if (j > i) {
            /* Real content: flush held-back CRLFs then emit content */
            flush_pending(bh);
            for (int k = 0; k < DKIM2_N_HASH_ALGS; k++)
                EVP_DigestUpdate(bh->md_ctx[k], data + i, j - i);
            i = j;
        } else if (data[i] == '\r') {
            bh->prev_was_cr = 1;
            i++;
        } else { /* bare \n: normalise to \r\n */
            bh->pending_crlfs++;
            i++;
        }
    }
    return 0;
}

int dkim2_body_hasher_final_all(dkim2_body_hasher_t *bh, dkim2_digests_t *out) {
    /* A trailing bare \r counts as one empty line (normalised to \r\n) */
    if (bh->prev_was_cr) bh->pending_crlfs++;
    /* Discard all trailing empty lines; add exactly one canonical CRLF */
    for (int i = 0; i < DKIM2_N_HASH_ALGS; i++) {
        EVP_DigestUpdate(bh->md_ctx[i], "\r\n", 2);
        unsigned int dlen = (unsigned int)HASH_ALGS[i].len;
        if (EVP_DigestFinal_ex(bh->md_ctx[i], out->d[i], &dlen) != 1) return -1;
    }
    return 0;
}

int dkim2_body_hasher_final(dkim2_body_hasher_t *bh,
                            unsigned char digest[DKIM2_HASH_LEN]) {
    dkim2_digests_t all;
    if (dkim2_body_hasher_final_all(bh, &all) < 0) return -1;
    memcpy(digest, all.d[0], DKIM2_HASH_LEN);
    return 0;
}

void dkim2_body_hasher_free(dkim2_body_hasher_t *bh) {
    if (!bh) return;
    for (int i = 0; i < DKIM2_N_HASH_ALGS; i++)
        EVP_MD_CTX_free(bh->md_ctx[i]);
    free(bh);
}

static int digest_buf(const void **parts, const size_t *lens, int nparts, int alg,
                      unsigned char *digest) {
    if (alg < 0 || alg >= DKIM2_N_HASH_ALGS) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int ok = EVP_DigestInit_ex(ctx, HASH_ALGS[alg].md(), NULL);
    for (int i = 0; i < nparts && ok; i++)
        ok = EVP_DigestUpdate(ctx, parts[i], lens[i]);
    unsigned int dlen = (unsigned int)HASH_ALGS[alg].len;
    if (ok) ok = EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* §5.1: strip all trailing empty lines (\r\n), ensure one trailing \r\n, then hash */
int dkim2_body_hash_raw_alg(const char *body, size_t bodylen, int alg,
                            unsigned char *digest) {
    const char *end = body + bodylen;
    while (end >= body + 2 && end[-2] == '\r' && end[-1] == '\n')
        end -= 2;
    size_t clen = (size_t)(end - body);

    const void *parts[2] = { body, "\r\n" };
    size_t  lens[2]      = { clen,    2   };
    int start = clen > 0 ? 0 : 1;
    return digest_buf(parts + start, lens + start, 2 - start, alg, digest);
}

int dkim2_body_hash_raw(const char *body, size_t bodylen,
                        unsigned char digest[DKIM2_HASH_LEN]) {
    return dkim2_body_hash_raw_alg(body, bodylen, 0, digest);
}

int dkim2_body_hash(const char *body, size_t bodylen, char *out, size_t outlen) {
    unsigned char digest[DKIM2_HASH_LEN];
    if (dkim2_body_hash_raw(body, bodylen, digest) < 0) return -1;
    return b64_encode(digest, DKIM2_HASH_LEN, out, outlen) >= 0 ? 0 : -1;
}

/* Returns 1 if this lowercase header name is unsigned per spec-06 §4.
   spec-05 narrowed the old "arc-" prefix to the three RFC 8617 names and
   added a "received-" prefix rule. Note x400-received / x400-trace match
   neither the "x-" nor the "received-" prefix and need their own entries. */
static int hdr_ignore(const char *lname, size_t nlen) {
    static const struct { const char *s; size_t l; } skip[] = {
        {"apparently-to",              13},
        {"arc-authentication-results", 26},
        {"arc-message-signature",      21},
        {"arc-seal",                    8},
        {"authentication-results",     22},
        {"auto-submitted",             14},
        {"delivered-to",               12},
        {"dkim-signature",             14},
        {"dkim2-signature",            15},
        {"dl-expansion-history",       20},
        {"message-instance",           16},
        {"original-recipient",         18},
        {"received",                    8},
        {"return-path",                11},
        {"sio-label-history",          17},
        {"vbr-info",                    8},
        {"x400-received",              13},
        {"x400-trace",                 10},
    };
    for (size_t i = 0; i < sizeof skip / sizeof skip[0]; i++)
        if (nlen == skip[i].l && memcmp(lname, skip[i].s, nlen) == 0) return 1;
    if (nlen >= 2 && memcmp(lname, "x-", 2) == 0) return 1;
    if (nlen >= 9 && memcmp(lname, "received-", 9) == 0) return 1;
    return 0;
}

/* Canonicalize one header for hashing per §5.2.
   Steps: lowercase name; unfold; collapse WSP; trim trailing WSP;
   delete WSP around colon; keep final CRLF.
   Returns malloc'd string or NULL if header should be ignored. */
static char *canon_header_for_hash(const char *hdr) {
    const char *colon = strchr(hdr, ':');
    if (!colon) return NULL;

    size_t namelen = (size_t)(colon - hdr);
    char *lname = malloc(namelen + 1);
    if (!lname) return NULL;
    for (size_t i = 0; i < namelen; i++)
        lname[i] = (char)tolower((unsigned char)hdr[i]);
    lname[namelen] = '\0';

    if (hdr_ignore(lname, namelen)) { free(lname); return NULL; }

    /* Allocate output buffer — can't be larger than input + 4 */
    size_t vallen = strlen(colon + 1);
    char *buf = malloc(namelen + 1 + vallen + 4);
    if (!buf) { free(lname); return NULL; }

    char *p = buf;
    /* Lowercase name (no surrounding WSP) */
    memcpy(p, lname, namelen); p += namelen;
    free(lname);
    /* Colon (no surrounding whitespace per §5.2) */
    *p++ = ':';

    /* Process value: unfold, collapse WSP sequences to single SP, trim leading/trailing WSP */
    const char *v = colon + 1;
    /* Strip trailing CRLF so we can re-add it at end */
    size_t vl = vallen;
    while (vl >= 2 && v[vl-2] == '\r' && v[vl-1] == '\n') vl -= 2;
    while (vl >= 1 && (v[vl-1] == '\r' || v[vl-1] == '\n')) vl--;
    /* §5.2 step 6 (delete WSP at the start of the value) must be applied AFTER
       unfolding, not before: for a header folded immediately after the colon
       ("Message-ID:\r\n <x@y>") the leading WSP is the space that opens the
       continuation line, which only becomes leading once the CRLF is gone.
       Starting the collapse loop already "in" a WSP run swallows that whole
       run, so leading WSP is deleted in either position. */
    int in_wsp = 1;
    for (size_t i = 0; i < vl; i++) {
        unsigned char c = (unsigned char)v[i];
        if (c == '\r') continue;
        if (c == '\n') continue;  /* folded: CRLF is removed, next char is WSP */
        if (c == ' ' || c == '\t') {
            if (!in_wsp) { *p++ = ' '; in_wsp = 1; }
        } else {
            in_wsp = 0;
            *p++ = (char)c;
        }
    }
    /* Trim trailing SP we may have emitted */
    while (p > buf && p[-1] == ' ') p--;
    /* Re-add CRLF per §5.2 "MUST NOT remove the CRLF at the end" */
    *p++ = '\r'; *p++ = '\n'; *p = '\0';
    return buf;
}

/* §5.2 header hash — raw digest */
int dkim2_header_hash_raw_alg(const char **headers, int n_headers, int alg,
                              unsigned char *digest) {
    if (alg < 0 || alg >= DKIM2_N_HASH_ALGS) return -1;

    /* Process in reverse order (bottom-up per §5.2), then stable-sort alphabetically.
       Reversing first ensures same-name headers appear in bottom-up order after sort. */
    char **canon = calloc((size_t)n_headers, sizeof(char *));
    if (!canon) return -1;
    int nc = 0;

    for (int i = n_headers - 1; i >= 0; i--) {
        char *c = canon_header_for_hash(headers[i]);
        if (c) canon[nc++] = c;
    }

    /* Stable insertion sort by header name only (up to the ':').
       qsort is not used because it is not guaranteed stable; stability is required so
       same-name headers keep their bottom-up order from the reverse pass above.
       n is small (typically <20 after filtering) so O(n²) cost is negligible. */
    for (int i = 1; i < nc; i++) {
        char *key = canon[i];
        const char *kcolon = strchr(key, ':');
        size_t klen = kcolon ? (size_t)(kcolon - key) : strlen(key);
        int j = i - 1;
        while (j >= 0) {
            const char *jcolon = strchr(canon[j], ':');
            size_t jlen = jcolon ? (size_t)(jcolon - canon[j]) : strlen(canon[j]);
            size_t cmplen = jlen < klen ? jlen : klen;
            int cmp = strncmp(canon[j], key, cmplen);
            if (cmp == 0) cmp = (jlen > klen) - (jlen < klen);
            if (cmp <= 0) break;
            canon[j + 1] = canon[j];
            j--;
        }
        canon[j + 1] = key;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { for (int i = 0; i < nc; i++) free(canon[i]); free(canon); return -1; }
    EVP_DigestInit_ex(mdctx, HASH_ALGS[alg].md(), NULL);
    for (int i = 0; i < nc; i++) {
        EVP_DigestUpdate(mdctx, canon[i], strlen(canon[i]));
        free(canon[i]);
    }
    free(canon);

    unsigned int dlen = (unsigned int)HASH_ALGS[alg].len;
    EVP_DigestFinal_ex(mdctx, digest, &dlen);
    EVP_MD_CTX_free(mdctx);
    return 0;
}

int dkim2_header_hash_raw(const char **headers, int n_headers,
                          unsigned char digest[DKIM2_HASH_LEN]) {
    return dkim2_header_hash_raw_alg(headers, n_headers, 0, digest);
}

int dkim2_header_hash(const char **headers, int n_headers, char *out, size_t outlen) {
    unsigned char digest[DKIM2_HASH_LEN];
    if (dkim2_header_hash_raw(headers, n_headers, digest) < 0) return -1;
    return b64_encode(digest, DKIM2_HASH_LEN, out, outlen) >= 0 ? 0 : -1;
}
