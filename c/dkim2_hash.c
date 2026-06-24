#include "dkim2_hash.h"
#include "base64.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/evp.h>

#define SHA256_DIGEST_LEN DKIM2_HASH_LEN

/* ── Streaming body hasher ──────────────────────────────────────────────── */

struct dkim2_body_hasher {
    EVP_MD_CTX *md_ctx;
    int pending_crlfs;  /* trailing \r\n pairs held back (not yet hashed) */
    int prev_was_cr;    /* last byte fed was a bare \r (cross-chunk state) */
};

dkim2_body_hasher_t *dkim2_body_hasher_new(void) {
    dkim2_body_hasher_t *bh = calloc(1, sizeof *bh);
    if (!bh) return NULL;
    bh->md_ctx = EVP_MD_CTX_new();
    if (!bh->md_ctx) { free(bh); return NULL; }
    if (EVP_DigestInit_ex(bh->md_ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(bh->md_ctx); free(bh); return NULL;
    }
    return bh;
}

static void flush_pending(dkim2_body_hasher_t *bh) {
    while (bh->pending_crlfs > 0) {
        EVP_DigestUpdate(bh->md_ctx, "\r\n", 2);
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
            EVP_DigestUpdate(bh->md_ctx, "\r\n", 2);
            /* data[i] is unprocessed non-\n; fall through */
        }

        /* Scan for next \r or bare \n */
        size_t j = i;
        while (j < len && data[j] != '\r' && data[j] != '\n') j++;

        if (j > i) {
            /* Real content: flush held-back CRLFs then emit content */
            flush_pending(bh);
            EVP_DigestUpdate(bh->md_ctx, data + i, j - i);
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

int dkim2_body_hasher_final(dkim2_body_hasher_t *bh,
                            unsigned char digest[DKIM2_HASH_LEN]) {
    /* A trailing bare \r counts as one empty line (normalised to \r\n) */
    if (bh->prev_was_cr) bh->pending_crlfs++;
    /* Discard all trailing empty lines; add exactly one canonical CRLF */
    EVP_DigestUpdate(bh->md_ctx, "\r\n", 2);
    unsigned int dlen = DKIM2_HASH_LEN;
    return EVP_DigestFinal_ex(bh->md_ctx, digest, &dlen) == 1 ? 0 : -1;
}

void dkim2_body_hasher_free(dkim2_body_hasher_t *bh) {
    if (!bh) return;
    EVP_MD_CTX_free(bh->md_ctx);
    free(bh);
}

static int sha256_buf(const void **parts, const size_t *lens, int nparts,
                      unsigned char digest[SHA256_DIGEST_LEN]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    for (int i = 0; i < nparts && ok; i++)
        ok = EVP_DigestUpdate(ctx, parts[i], lens[i]);
    unsigned int dlen = SHA256_DIGEST_LEN;
    if (ok) ok = EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* §5.1: strip all trailing empty lines (\r\n), ensure one trailing \r\n, SHA256 */
int dkim2_body_hash_raw(const char *body, size_t bodylen,
                        unsigned char digest[DKIM2_HASH_LEN]) {
    const char *end = body + bodylen;
    while (end >= body + 2 && end[-2] == '\r' && end[-1] == '\n')
        end -= 2;
    size_t clen = (size_t)(end - body);

    const void *parts[2] = { body, "\r\n" };
    size_t  lens[2]      = { clen,    2   };
    int start = clen > 0 ? 0 : 1;
    return sha256_buf(parts + start, lens + start, 2 - start, digest);
}

int dkim2_body_hash(const char *body, size_t bodylen, char *out, size_t outlen) {
    unsigned char digest[DKIM2_HASH_LEN];
    if (dkim2_body_hash_raw(body, bodylen, digest) < 0) return -1;
    return b64_encode(digest, DKIM2_HASH_LEN, out, outlen) >= 0 ? 0 : -1;
}

/* Returns 1 if this lowercase header name should be ignored per §5.2 */
static int hdr_ignore(const char *lname, size_t nlen) {
    static const struct { const char *s; size_t l; } skip[] = {
        {"received",               8},
        {"return-path",           11},
        {"message-instance",      16},
        {"dkim2-signature",       15},
        {"delivered-to",          12},
        {"dkim-signature",        14},
        {"authentication-results", 22},
    };
    for (size_t i = 0; i < sizeof skip / sizeof skip[0]; i++)
        if (nlen == skip[i].l && memcmp(lname, skip[i].s, nlen) == 0) return 1;
    if (nlen >= 2 && lname[0] == 'x' && lname[1] == '-') return 1;
    if (nlen >= 4 && memcmp(lname, "arc-", 4) == 0) return 1;
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
    /* Strip leading WSP (§5.2 step 6: delete WSP at start of value) */
    size_t vi = 0;
    while (vi < vl && (v[vi] == ' ' || v[vi] == '\t')) vi++;

    int in_wsp = 0;
    for (size_t i = vi; i < vl; i++) {
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
int dkim2_header_hash_raw(const char **headers, int n_headers,
                          unsigned char digest[DKIM2_HASH_LEN]) {
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
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    for (int i = 0; i < nc; i++) {
        EVP_DigestUpdate(mdctx, canon[i], strlen(canon[i]));
        free(canon[i]);
    }
    free(canon);

    unsigned int dlen = DKIM2_HASH_LEN;
    EVP_DigestFinal_ex(mdctx, digest, &dlen);
    EVP_MD_CTX_free(mdctx);
    return 0;
}

int dkim2_header_hash(const char **headers, int n_headers, char *out, size_t outlen) {
    unsigned char digest[DKIM2_HASH_LEN];
    if (dkim2_header_hash_raw(headers, n_headers, digest) < 0) return -1;
    return b64_encode(digest, DKIM2_HASH_LEN, out, outlen) >= 0 ? 0 : -1;
}
