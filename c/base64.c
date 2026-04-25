#include "base64.h"
#include <stddef.h>

static const char enc_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64_encode(const unsigned char *in, size_t inlen, char *out, size_t outlen) {
    size_t i = 0, j = 0;
    while (i < inlen) {
        if (j + 4 >= outlen) return -1;
        size_t start = i;
        unsigned int a = in[i++];
        unsigned int b = (i < inlen) ? in[i++] : 0;
        unsigned int c = (i < inlen) ? in[i++] : 0;
        size_t consumed = i - start;   /* 1, 2, or 3 */
        size_t pad = 3 - consumed;     /* 2, 1, or 0 */
        unsigned int t = (a << 16) | (b << 8) | c;
        out[j++] = enc_table[(t >> 18) & 0x3F];
        out[j++] = enc_table[(t >> 12) & 0x3F];
        out[j++] = (pad > 1) ? '=' : enc_table[(t >> 6) & 0x3F];
        out[j++] = (pad > 0) ? '=' : enc_table[t & 0x3F];
    }
    out[j] = '\0';
    return (int)j;
}

static int dec_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int b64_decode(const char *in, unsigned char *out, size_t outlen) {
    size_t j = 0;
    int buf[4], n = 0;
    for (; *in; in++) {
        /* Skip whitespace per §2.14 */
        if (*in == ' ' || *in == '\t' || *in == '\r' || *in == '\n') continue;
        if (*in == '=') break;
        int v = dec_char(*in);
        if (v < 0) return -1;
        buf[n++] = v;
        if (n == 4) {
            if (j + 3 > outlen) return -1;
            out[j++] = (unsigned char)((buf[0] << 2) | (buf[1] >> 4));
            out[j++] = (unsigned char)((buf[1] << 4) | (buf[2] >> 2));
            out[j++] = (unsigned char)((buf[2] << 6) | buf[3]);
            n = 0;
        }
    }
    if (n >= 2) { if (j >= outlen) return -1; out[j++] = (unsigned char)((buf[0] << 2) | (buf[1] >> 4)); }
    if (n >= 3) { if (j >= outlen) return -1; out[j++] = (unsigned char)((buf[1] << 4) | (buf[2] >> 2)); }
    return (int)j;
}
