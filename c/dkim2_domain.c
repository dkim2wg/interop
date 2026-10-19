#include "dkim2_domain.h"
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

int dkim2_domain_of(const char *addr, char *out, size_t outlen, int *is_literal) {
    if (is_literal) *is_literal = 0;
    if (!addr) return -1;
    const char *at = strrchr(addr, '@');
    if (!at) return -1;
    const char *d = at + 1;
    const char *end = strchr(d, '>');
    if (!end) end = d + strlen(d);
    while (end > d && (end[-1] == ' ' || end[-1] == '\t')) end--;
    size_t n = (size_t)(end - d);
    if (n && d[n - 1] == '.') n--;          /* one trailing dot (Postfix style) */
    if (n == 0 || n >= outlen) return -1;
    for (size_t i = 0; i < n; i++) out[i] = (char)tolower((unsigned char)d[i]);
    out[n] = '\0';
    if (is_literal) *is_literal = out[0] == '[';
    return 0;
}

/* ---- RFC 3492 Punycode (encode only) ---- */

enum { PC_BASE = 36, PC_TMIN = 1, PC_TMAX = 26, PC_SKEW = 38, PC_DAMP = 700,
       PC_BIAS = 72, PC_N = 128 };

static uint32_t pc_adapt(uint32_t delta, uint32_t numpoints, int first) {
    delta = first ? delta / PC_DAMP : delta / 2;
    delta += delta / numpoints;
    uint32_t k = 0;
    while (delta > ((PC_BASE - PC_TMIN) * PC_TMAX) / 2) {
        delta /= PC_BASE - PC_TMIN;
        k += PC_BASE;
    }
    return k + (PC_BASE - PC_TMIN + 1) * delta / (delta + PC_SKEW);
}

static char pc_digit(uint32_t d) { return (char)(d < 26 ? 'a' + d : '0' + (d - 26)); }

/* Encode cp[0..n) into out (no "xn--"); 0, or -1 on overflow / no room. */
static int punycode_encode(const uint32_t *cp, size_t n, char *out, size_t outlen) {
    size_t o = 0;
#define PUT(ch) do { if (o + 1 >= outlen) return -1; out[o++] = (ch); } while (0)
    size_t b = 0;
    for (size_t j = 0; j < n; j++)
        if (cp[j] < 0x80) { PUT((char)cp[j]); b++; }
    if (b) PUT('-');
    uint32_t nn = PC_N, delta = 0, bias = PC_BIAS;
    size_t h = b;
    while (h < n) {
        uint32_t m = UINT32_MAX;
        for (size_t j = 0; j < n; j++)
            if (cp[j] >= nn && cp[j] < m) m = cp[j];
        if ((uint64_t)(m - nn) * (h + 1) > UINT32_MAX - delta) return -1;
        delta += (m - nn) * (uint32_t)(h + 1);
        nn = m;
        for (size_t j = 0; j < n; j++) {
            if (cp[j] < nn && ++delta == 0) return -1;
            if (cp[j] == nn) {
                uint32_t q = delta;
                for (uint32_t k = PC_BASE; ; k += PC_BASE) {
                    uint32_t t = k <= bias ? PC_TMIN : k >= bias + PC_TMAX ? PC_TMAX : k - bias;
                    if (q < t) break;
                    PUT(pc_digit(t + (q - t) % (PC_BASE - t)));
                    q = (q - t) / (PC_BASE - t);
                }
                PUT(pc_digit(q));
                bias = pc_adapt(delta, (uint32_t)(h + 1), h == b);
                delta = 0;
                h++;
            }
        }
        delta++;
        nn++;
    }
    out[o] = '\0';
    return 0;
#undef PUT
}

/* Strict UTF-8 of s[0..len) to code points; the count, or -1. */
static int utf8_decode(const unsigned char *s, size_t len, uint32_t *cp, size_t max) {
    size_t n = 0;
    for (size_t i = 0; i < len; ) {
        unsigned char c = s[i];
        size_t l;
        uint32_t v;
        if (c < 0x80) { l = 1; v = c; }
        else if (c >= 0xC2 && c <= 0xDF) { l = 2; v = c & 0x1F; }
        else if (c >= 0xE0 && c <= 0xEF) { l = 3; v = c & 0x0F; }
        else if (c >= 0xF0 && c <= 0xF4) { l = 4; v = c & 0x07; }
        else return -1;
        if (i + l > len) return -1;
        for (size_t k = 1; k < l; k++) {
            if ((s[i + k] & 0xC0) != 0x80) return -1;
            v = (v << 6) | (s[i + k] & 0x3F);
        }
        if ((l == 3 && v < 0x800) || (l == 4 && (v < 0x10000 || v > 0x10FFFF)) ||
            (v >= 0xD800 && v <= 0xDFFF)) return -1;
        if (n >= max) return -1;
        cp[n++] = v;
        i += l;
    }
    return (int)n;
}

/* Lowercase the code points we can without Unicode tables: ASCII and the
   Latin-1 letters (U+00C0-U+00DE except U+00D7). */
static uint32_t cp_lower(uint32_t c) {
    if (c >= 'A' && c <= 'Z') return c + 32;
    if (c >= 0xC0 && c <= 0xDE && c != 0xD7) return c + 32;
    return c;
}

int dkim2_to_alabel(const char *in, char *out, size_t outlen) {
    size_t o = 0;
    const char *p = in;
    for (;;) {
        const char *dot = strchr(p, '.');
        size_t ll = dot ? (size_t)(dot - p) : strlen(p);
        int ascii = 1;
        for (size_t i = 0; i < ll; i++)
            if ((unsigned char)p[i] >= 0x80) { ascii = 0; break; }
        if (ascii) {
            if (o + ll >= outlen) return -1;
            for (size_t i = 0; i < ll; i++) out[o++] = (char)tolower((unsigned char)p[i]);
        } else {
            uint32_t cp[256];
            int n = utf8_decode((const unsigned char *)p, ll, cp, 256);
            if (n < 0) return -1;
            for (int i = 0; i < n; i++) cp[i] = cp_lower(cp[i]);
            if (o + 4 >= outlen) return -1;
            memcpy(out + o, "xn--", 4);
            o += 4;
            if (punycode_encode(cp, (size_t)n, out + o, outlen - o) < 0) return -1;
            o += strlen(out + o);
        }
        if (!dot) break;
        if (o + 1 >= outlen) return -1;
        out[o++] = '.';
        p = dot + 1;
    }
    out[o] = '\0';
    return 0;
}

int dkim2_relaxed_match(const char *p1, const char *p2) {
    if (!p1 || !p2 || !*p1 || !*p2 || p1[0] == '[' || p2[0] == '[') return 0;
    for (const char *p = p1; ; ) {
        if (strcasecmp(p, p2) == 0) return 1;
        const char *dot = strchr(p, '.');
        if (!dot) return 0;
        p = dot + 1;
    }
}

int dkim2_addr_alabel(const char *addr, char *out, size_t outlen, int *is_literal) {
    char d[512];
    int lit = 0;
    if (dkim2_domain_of(addr, d, sizeof d, &lit) != 0) {
        if (is_literal) *is_literal = 0;
        return -1;
    }
    if (is_literal) *is_literal = lit;
    if (lit) return -1;
    return dkim2_to_alabel(d, out, outlen);
}

/* Copy s[0..n) to out without comments and white space outside quoted
   strings (CFWS); quoted strings are kept, quotes included. 0, or -1 when
   out is too small or CFWS separates two parts of the address. */
static int strip_cfws(const char *s, size_t n, char *out, size_t outlen) {
    size_t o = 0;
    int depth = 0, quote = 0, gap = 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (depth) {
            if (c == '\\' && i + 1 < n) i++;
            else if (c == '(') depth++;
            else if (c == ')') depth--;
            continue;
        }
        if (!quote && c == '(') { depth = 1; gap = o > 0; continue; }
        if (!quote && (c == ' ' || c == '\t' || c == '\r' || c == '\n')) { gap = o > 0; continue; }
        /* CFWS between two parts of the address: "Name a@b" (display text
           with no angle brackets) or "<a b@c>" is not one addr-spec. */
        if (gap) return -1;
        if (o + 2 >= outlen) return -1;
        if (quote && c == '\\' && i + 1 < n) { out[o++] = c; out[o++] = s[++i]; continue; }
        if (c == '"') quote = !quote;
        out[o++] = c;
    }
    out[o] = '\0';
    return 0;
}

int dkim2_from_domain(const char *value, char *out, size_t outlen) {
    if (!value) return -1;
    size_t n = strlen(value);
    const char *ang = NULL, *ang_end = NULL;
    int depth = 0, quote = 0, in_angle = 0, n_angle = 0;
    for (size_t i = 0; i < n; i++) {
        char c = value[i];
        if (quote) {
            if (c == '\\' && i + 1 < n) i++;
            else if (c == '"') quote = 0;
            continue;
        }
        if (depth) {
            if (c == '\\' && i + 1 < n) i++;
            else if (c == '(') depth++;
            else if (c == ')') depth--;
            continue;
        }
        if (c == '"') { quote = 1; continue; }
        if (c == '(') { depth = 1; continue; }
        if (in_angle) {
            if (c == '>') { in_angle = 0; ang_end = value + i; }
            else if (c == '<') return -1;
            continue;
        }
        if (c == '<') {
            if (n_angle++) return -1;               /* a second angle-addr */
            in_angle = 1;
            ang = value + i + 1;
            continue;
        }
        /* At the top level: a list separator, a group, or a stray '>' */
        if (c == ',' || c == ':' || c == ';' || c == '>') return -1;
    }
    if (quote || depth || in_angle) return -1;

    char addr[1024];
    if (ang ? strip_cfws(ang, (size_t)(ang_end - ang), addr, sizeof addr)
            : strip_cfws(value, n, addr, sizeof addr)) return -1;

    /* addr-spec: the domain follows the last '@' (a quoted local part may
       hold one; a domain cannot). */
    const char *at = strrchr(addr, '@');
    if (!at || at == addr || !at[1]) return -1;
    char d[512];
    int lit = 0;
    if (dkim2_domain_of(addr, d, sizeof d, &lit) != 0 || lit) return -1;
    return dkim2_to_alabel(d, out, outlen);
}
