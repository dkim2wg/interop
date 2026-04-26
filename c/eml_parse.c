#include "eml_parse.h"
#include "dkim2_hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int eml_parse(const char *path,
              char ***headers_out, int *n_headers_out,
              unsigned char body_digest_out[DKIM2_HASH_LEN]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    unsigned char *raw = malloc((size_t)fsize + 4);
    if (!raw) { fclose(f); return -1; }
    size_t n = fread(raw, 1, (size_t)fsize, f);
    fclose(f);
    raw[n] = '\0';

    /* Normalise to CRLF */
    unsigned char *buf = malloc(n * 2 + 4);
    if (!buf) { free(raw); return -1; }
    size_t blen = 0;
    for (size_t i = 0; i < n; ) {
        if (raw[i] == '\r' && i + 1 < n && raw[i+1] == '\n') {
            buf[blen++] = '\r'; buf[blen++] = '\n'; i += 2;
        } else if (raw[i] == '\r') {
            buf[blen++] = '\r'; buf[blen++] = '\n'; i++;
        } else if (raw[i] == '\n') {
            buf[blen++] = '\r'; buf[blen++] = '\n'; i++;
        } else {
            buf[blen++] = raw[i++];
        }
    }
    buf[blen] = '\0';
    free(raw);

    /* Find header/body split (blank line \r\n\r\n) */
    size_t body_start = blen;
    size_t header_end = blen;
    for (size_t i = 0; i + 3 < blen; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' &&
            buf[i+2] == '\r' && buf[i+3] == '\n') {
            header_end = i;
            body_start = i + 4;
            break;
        }
    }

    /* Split header block into logical header fields (handling continuations) */
    int hcap = 32, nh = 0;
    char **hdrs = malloc((size_t)hcap * sizeof(char *));
    if (!hdrs) { free(buf); return -1; }

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
        size_t hlen = i - start;
        if (hlen < 3) continue;

        if (nh >= hcap) {
            hcap *= 2;
            char **tmp = realloc(hdrs, (size_t)hcap * sizeof(char *));
            if (!tmp) { eml_free(hdrs, nh); free(buf); return -1; }
            hdrs = tmp;
        }
        hdrs[nh] = malloc(hlen + 1);
        memcpy(hdrs[nh], buf + start, hlen);
        hdrs[nh][hlen] = '\0';
        nh++;
    }

    /* Hash the body — temp buffer freed immediately after; ctx never holds body bytes */
    size_t body_data_len = (body_start < blen) ? (blen - body_start) : 0;
    dkim2_body_hash_raw((const char *)(buf + body_start), body_data_len, body_digest_out);
    free(buf);

    *headers_out   = hdrs;
    *n_headers_out = nh;
    return 0;
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
