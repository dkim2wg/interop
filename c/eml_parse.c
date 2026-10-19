#include "eml_parse.h"
#include "dkim2_hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CRLF-normalise in..in+n into out (room for 2n): a bare CR or bare LF
   becomes CRLF. Runs already in that form are copied whole. */
static size_t crlf_normalise(const unsigned char *in, size_t n, unsigned char *out) {
    size_t o = 0, i = 0;
    while (i < n) {
        size_t k = dkim2_crlf_clean((const char *)in + i, n - i);
        memcpy(out + o, in + i, k);
        o += k;
        i += k;
        if (i == n) break;
        out[o++] = '\r';    /* in[i]: a bare LF or a lone CR */
        out[o++] = '\n';
        i++;
    }
    return o;
}

/* Where the body starts in the raw bytes h..h+n: after the first empty line
   that is not the first line (once normalised, the first "\r\n\r\n"), with
   *found set. Lines end at CRLF, a lone CR or a bare LF. 0 when the bytes
   so far cannot tell; at eof, n with *found clear when there is no such
   line (the whole message is header). */
static size_t raw_body_start(const unsigned char *h, size_t n, int eof, int *found) {
    *found = 0;
    for (size_t i = 0, line = 0; i < n; line++) {
        size_t st = i;
        while (i < n && h[i] != '\r' && h[i] != '\n') i++;
        if (i == n || (h[i] == '\r' && i + 1 == n && !eof)) break;
        i += (h[i] == '\r' && i + 1 < n && h[i + 1] == '\n') ? 2 : 1;
        if (line > 0 && (h[st] == '\r' || h[st] == '\n')) { *found = 1; return i; }
    }
    return eof ? n : 0;
}

static int eml_parse_internal(const char *path,
    char ***headers_out, int *n_headers_out,
    dkim2_digests_t *body_digests_out,
    char **body_out, size_t *body_len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    /* The header block first, read until its end is known. The body is
       then read into a buffer of its own, and copied again only if it
       needs CRLF normalisation. */
    size_t cap = 65536, hn = 0, bs;
    unsigned char *head = NULL;
    int eof = 0, found = 0;
    for (;;) {
        unsigned char *nh = realloc(head, cap);
        if (!nh) { free(head); fclose(f); return -1; }
        head = nh;
        size_t got = fread(head + hn, 1, cap - hn, f);
        eof = got < cap - hn;
        hn += got;
        if ((bs = raw_body_start(head, hn, eof, &found)) || eof) break;
        cap *= 2;
    }
    size_t rest = !eof && fsize > 0 && (size_t)fsize > hn ? (size_t)fsize - hn : 0;
    size_t blen = hn - bs;
    unsigned char *body = malloc(blen + rest + 4);
    unsigned char *buf = malloc(bs * 2 + 4);
    if (!body || !buf) { free(body); free(buf); free(head); fclose(f); return -1; }
    memcpy(body, head + bs, blen);
    blen += fread(body + blen, 1, rest, f);
    fclose(f);
    size_t hlen = crlf_normalise(head, bs, buf);
    buf[hlen] = '\0';
    free(head);
    if (dkim2_crlf_clean((const char *)body, blen) < blen) {
        unsigned char *nb = malloc(blen * 2 + 4);
        if (!nb) { free(body); free(buf); return -1; }
        blen = crlf_normalise(body, blen, nb);
        free(body);
        body = nb;
    }
    body[blen] = '\0';

    /* With the blank line found, buf ends with it: "\r\n\r\n". */
    size_t header_end = found ? hlen - 4 : hlen;

    /* Split header block into logical header fields (handling continuations) */
    int hcap = 32, nh = 0;
    char **hdrs = malloc((size_t)hcap * sizeof(char *));
    if (!hdrs) { free(buf); free(body); return -1; }

    size_t i = 0;
    while (i < header_end) {
        size_t start = i;
        while (i <= header_end && !(buf[i] == '\r' && buf[i+1] == '\n')) i++;
        if (buf[i] == '\r' && buf[i+1] == '\n') i += 2;
        /* Gobble continuation lines */
        while (i < header_end && (buf[i] == ' ' || buf[i] == '\t')) {
            while (i <= header_end && !(buf[i] == '\r' && buf[i+1] == '\n')) i++;
            if (buf[i] == '\r' && buf[i+1] == '\n') i += 2;
        }
        size_t flen = i - start;
        if (flen < 3) continue;

        if (nh >= hcap) {
            hcap *= 2;
            char **tmp = realloc(hdrs, (size_t)hcap * sizeof(char *));
            if (!tmp) { eml_free(hdrs, nh); free(buf); free(body); return -1; }
            hdrs = tmp;
        }
        hdrs[nh] = malloc(flen + 1);
        memcpy(hdrs[nh], buf + start, flen);
        hdrs[nh][flen] = '\0';
        nh++;
    }
    free(buf);

    if (body_digests_out)
        for (int alg = 0; alg < DKIM2_N_HASH_ALGS; alg++)
            dkim2_body_hash_raw_alg((const char *)body, blen, alg, body_digests_out->d[alg]);

    if (body_out && body_len_out) {
        *body_out = (char *)body;
        *body_len_out = blen;
    } else {
        free(body);
    }
    *headers_out   = hdrs;
    *n_headers_out = nh;
    return 0;
}

int eml_parse(const char *path,
              char ***headers_out, int *n_headers_out,
              dkim2_digests_t *body_digests_out) {
    return eml_parse_internal(path, headers_out, n_headers_out, body_digests_out, NULL, NULL);
}

int eml_parse_with_body(const char *path,
                        char ***headers_out, int *n_headers_out,
                        dkim2_digests_t *body_digests_out,
                        char **body_out, size_t *body_len_out) {
    return eml_parse_internal(path, headers_out, n_headers_out, body_digests_out,
                              body_out, body_len_out);
}

/* Feed one normalised byte to the separator-detection + emit state machine. */
static void feed_byte(unsigned char nc, int *sep, int *in_body, FILE *out) {
    if (*in_body) {
        fputc(nc, out);
        return;
    }
    static const unsigned char SEP[4] = {'\r', '\n', '\r', '\n'};
    if (nc == SEP[*sep]) {
        if (++*sep == 4) *in_body = 1;
    } else {
        *sep = (nc == '\r') ? 1 : 0;
    }
}

/* Stream the body of path (CRLF-normalised) to out without buffering it. */
int eml_emit_body(const char *path, FILE *out) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    unsigned char buf[8192];
    size_t nr;
    int prev_cr = 0, sep = 0, in_body = 0;

    while ((nr = fread(buf, 1, sizeof buf, f)) > 0) {
        for (size_t i = 0; i < nr; i++) {
            unsigned char c = buf[i];
            if (prev_cr) {
                prev_cr = 0;
                if (c == '\n') {
                    feed_byte('\r', &sep, &in_body, out);
                    feed_byte('\n', &sep, &in_body, out);
                    continue;
                }
                /* bare \r → \r\n, then fall through to process c */
                feed_byte('\r', &sep, &in_body, out);
                feed_byte('\n', &sep, &in_body, out);
            }
            if (c == '\r') {
                prev_cr = 1;
            } else if (c == '\n') {
                feed_byte('\r', &sep, &in_body, out);
                feed_byte('\n', &sep, &in_body, out);
            } else {
                feed_byte(c, &sep, &in_body, out);
            }
        }
    }
    /* Trailing bare \r in body: normalise to \r\n */
    if (prev_cr && in_body)
        fwrite("\r\n", 1, 2, out);

    fclose(f);
    return 0;
}

void eml_free(char **headers, int n_headers) {
    if (headers) {
        for (int i = 0; i < n_headers; i++) free(headers[i]);
        free(headers);
    }
}
