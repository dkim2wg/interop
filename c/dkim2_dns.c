#include "dkim2_dns.h"
#include "tagparse.h"
#include "base64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

/* Optional JSON-based DNS override for testing.
   If dkim2_dns_override is non-NULL, it is called before live DNS.
   Returns malloc'd TXT string, or NULL to fall through to live DNS. */
char *(*dkim2_dns_override)(const char *qname, int *n_records) = NULL;
int (*dkim2_dns_txt_hook)(const char *qname, dkim2_txt_t *out) = NULL;
int (*dkim2_dns_query_hook)(const char *qname, unsigned char *answer, int anslen) = NULL;

const char DKIM2_KEYERR_MULTIPLE[] = "has multiple records";
const char DKIM2_KEYERR_SYNTAX[]   = "has a syntax error";
const char DKIM2_KEYERR_REVOKED[]  = "has been revoked";
const char DKIM2_KEYERR_ALG[]      = "algorithm mismatch";
const char DKIM2_KEYERR_MALFORMED[] = "is malformed";
const char DKIM2_KEYERR_SHORT[]    = "too short";
const char DKIM2_KEYERR_ABSENT[]   = "does not exist";
const char DKIM2_KEYERR_FETCH[]    = "could not be fetched";

#define KEY_SYNTAX() do { *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_SYNTAX; goto out; } while (0)

static int is_wsp(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
static int is_alpha(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
static int is_digit(char c) { return c >= '0' && c <= '9'; }

/* One tag-spec of a record: name and value (FWS around it trimmed). */
typedef struct { const char *n, *v; size_t nl, vl; } rtag_t;

static int rtag_cmp(const void *a, const void *b) {
    const rtag_t *x = a, *y = b;
    size_t l = x->nl < y->nl ? x->nl : y->nl;
    int c = memcmp(x->n, y->n, l);
    return c ? c : (x->nl > y->nl) - (x->nl < y->nl);
}

/* A record (key or Domain Policy Record) as a dns-00 §3.2 tag-list,
   validated as a whole (§3.4.1): every tag-spec is
   [FWS] name [FWS] "=" value, name = ALPHA *(ALPHA / DIGIT / "_"), every
   value VALCHARs with FWS only between them, tag names case sensitive and
   never repeated. Empty tag-specs are skipped. txt[0..len) may be any
   size (a TXT RR of up to 64 KB is attacker-served): one pass, no fixed
   limit, repeats found by sorting. *tags is malloc'd (caller frees, also
   on failure). Returns 0, -1 for a syntax error, -2 out of memory. */
static int scan_record(const char *txt, size_t len, rtag_t **tags, size_t *ntags) {
    rtag_t *t = NULL;
    size_t n = 0, cap = 0;
    *tags = NULL;
    *ntags = 0;
    if (memchr(txt, '\0', len)) return -1;             /* NUL: not a VALCHAR */
    const char *s = txt, *lim = txt + len;
    while (s <= lim) {
        const char *e = memchr(s, ';', (size_t)(lim - s));
        const char *end = e ? e : lim;
        const char *q = s;
        while (q < end && is_wsp(*q)) q++;
        if (q < end) {
            const char *name = q;
            if (!is_alpha(*q)) goto syntax;
            while (q < end && (is_alpha(*q) || is_digit(*q) || *q == '_')) q++;
            size_t nl = (size_t)(q - name);
            while (q < end && is_wsp(*q)) q++;
            if (q == end || *q != '=') goto syntax;
            q++;
            while (q < end && is_wsp(*q)) q++;
            const char *val = q, *vend = end;
            while (vend > val && is_wsp(vend[-1])) vend--;
            for (const char *c = val; c < vend; c++)
                if (!is_wsp(*c) && !((unsigned char)*c >= 0x21 && (unsigned char)*c <= 0x7E))
                    goto syntax;
            if (n == cap) {
                size_t nc = cap ? cap * 2 : 8;
                rtag_t *g = realloc(t, nc * sizeof *g);
                if (!g) { free(t); return -2; }
                t = g;
                cap = nc;
            }
            t[n].n = name; t[n].nl = nl; t[n].v = val; t[n].vl = (size_t)(vend - val);
            n++;
        }
        if (!e) break;
        s = e + 1;
    }
    if (n > 1) {
        rtag_t *sorted = malloc(n * sizeof *sorted);
        if (!sorted) { free(t); return -2; }
        memcpy(sorted, t, n * sizeof *sorted);
        qsort(sorted, n, sizeof *sorted, rtag_cmp);
        int dup = 0;
        for (size_t i = 1; i < n && !dup; i++) dup = rtag_cmp(&sorted[i - 1], &sorted[i]) == 0;
        free(sorted);
        if (dup) goto syntax;
    }
    *tags = t;
    *ntags = n;
    return 0;
syntax:
    *tags = t;
    return -1;
}

/* A key record (dns-00 §3.2, scan_record): v= (if present) is first and
   exactly "DKIM1", p= is required. k= defaults to "rsa"; "rsa" and
   "ed25519" are known, any other k= is never read as a key we know. */
static dkim2_pubkey_t *parse_key_record(const char *txt, size_t txtlen,
    dkim2_status_t *statusp, const char **errp) {
    dkim2_pubkey_t *key = NULL;
    const char *v = NULL, *k = NULL, *p = NULL;
    size_t vl = 0, kl = 0, pl = 0;
    char *pclean = NULL;
    unsigned char *keybuf = NULL;
    rtag_t *tags = NULL;
    size_t ntags = 0;

    int sr = scan_record(txt, txtlen, &tags, &ntags);
    if (sr == -2) { *statusp = DKIM2_TEMPERROR; *errp = "OOM"; goto out; }
    if (sr < 0) KEY_SYNTAX();
    for (size_t i = 0; i < ntags; i++) {
        const rtag_t *t = &tags[i];
        if (t->nl == 1 && t->n[0] == 'v') {
            if (i != 0) KEY_SYNTAX();                   /* v= MUST be first */
            v = t->v; vl = t->vl;
        } else if (t->nl == 1 && t->n[0] == 'k') {
            k = t->v; kl = t->vl;
        } else if (t->nl == 1 && t->n[0] == 'p') {
            p = t->v; pl = t->vl;
        }
        /* h=, n=, s=, t= (retired) and unknown tags are ignored. */
    }

    if (v && !(vl == 5 && memcmp(v, "DKIM1", 5) == 0)) KEY_SYNTAX();
    if (!p) KEY_SYNTAX();

    /* p=: FWS removed; then empty = revoked, else strict base64. */
    pclean = malloc(pl + 1);
    if (!pclean) { *statusp = DKIM2_TEMPERROR; *errp = "OOM"; goto out; }
    size_t cl = 0;
    for (size_t i = 0; i < pl; i++) if (!is_wsp(p[i])) pclean[cl++] = p[i];
    pclean[cl] = '\0';
    if (cl == 0) {
        key = calloc(1, sizeof *key);
        if (!key) { *statusp = DKIM2_TEMPERROR; *errp = "OOM"; goto out; }
        key->revoked = 1;
        *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_REVOKED;
        goto out;
    }
    if (!b64_is_strict(pclean)) KEY_SYNTAX();

    int is_rsa;
    if (!k || (kl == 3 && memcmp(k, "rsa", 3) == 0)) is_rsa = 1;
    else if (kl == 7 && memcmp(k, "ed25519", 7) == 0) is_rsa = 0;
    else { *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_ALG; goto out; }

    keybuf = malloc(cl);
    if (!keybuf) { *statusp = DKIM2_TEMPERROR; *errp = "OOM"; goto out; }
    int keylen = b64_decode(pclean, keybuf, cl);
    if (keylen <= 0) KEY_SYNTAX();

    key = calloc(1, sizeof *key);
    if (!key) { *statusp = DKIM2_TEMPERROR; *errp = "OOM"; goto out; }
    key->alg = strdup(is_rsa ? "rsa" : "ed25519");
    if (!key->alg) { *statusp = DKIM2_TEMPERROR; *errp = "OOM"; goto fail; }
    if (is_rsa) {
        const unsigned char *kp = keybuf;
        key->pkey = d2i_PUBKEY(NULL, &kp, keylen);
        if (key->pkey && EVP_PKEY_get_base_id(key->pkey) != EVP_PKEY_RSA) {
            EVP_PKEY_free(key->pkey); key->pkey = NULL;
        }
        if (!key->pkey) {
            /* Some DKIM keys are published as bare PKCS#1 (RSAPublicKey)
               rather than SubjectPublicKeyInfo; accept both. */
            const unsigned char *kp2 = keybuf;
            key->pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &kp2, keylen);
        }
        /* -09 §3.2, §14.5 (contract E5): an RSA key under 1024 bits
           MUST NOT be used: "too short". */
        if (key->pkey && EVP_PKEY_bits(key->pkey) < 1024) {
            *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_SHORT; goto fail;
        }
    } else if (keylen == 32) {          /* -09 §14.5: exactly 32 octets */
        key->pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, keybuf, (size_t)keylen);
    }
    if (!key->pkey) {                   /* p= is not a key of type k= */
        *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_MALFORMED; goto fail;
    }
    *statusp = DKIM2_OK; *errp = NULL;
    goto out;
fail:
    dkim2_pubkey_free(key);
    key = NULL;
out:
    free(tags);
    free(pclean);
    free(keybuf);
    return key;
}
#undef KEY_SYNTAX

void dkim2_txt_free(dkim2_txt_t *t) {
    if (!t) return;
    for (int i = 0; i < t->n; i++) free(t->rec[i]);
    free(t->rec);
    free(t->len);
    t->rec = NULL;
    t->len = NULL;
    t->n = 0;
}

int dkim2_txt_push(dkim2_txt_t *t, const char *s, size_t len) {
    char **nr = realloc(t->rec, (size_t)(t->n + 1) * sizeof *nr);
    if (!nr) return -1;
    t->rec = nr;
    size_t *nl = realloc(t->len, (size_t)(t->n + 1) * sizeof *nl);
    if (!nl) return -1;
    t->len = nl;
    char *c = malloc(len + 1);
    if (!c) return -1;
    if (len) memcpy(c, s, len);
    c[len] = '\0';
    t->rec[t->n] = c;
    t->len[t->n] = len;
    t->n++;
    return 0;
}

int dkim2_txt_first_tag(const char *rec, size_t len) {
    const char *p = rec, *lim = rec + len;
    while (p < lim && is_wsp(*p)) p++;
    if (p == lim || *p != 'v') return 0;
    p++;
    while (p < lim && is_wsp(*p)) p++;
    if (p == lim || *p != '=') return 0;            /* "vx=", "v;": not v= */
    p++;
    while (p < lim && is_wsp(*p)) p++;
    const char *v = p;
    while (p < lim && *p != ';') p++;
    const char *e = p;                              /* trailing WSP: one pass back */
    while (e > v && is_wsp(e[-1])) e--;
    return (e - v == 5 && memcmp(v, "DKIM1", 5) == 0) ? 1 : 2;
}

int dkim2_dns_txt_from_answer(const unsigned char *answer, int anslen, int herr,
                              dkim2_txt_t *out) {
    out->rec = NULL; out->len = NULL; out->n = 0;
    if (anslen < 0)
        return (herr == HOST_NOT_FOUND || herr == NO_DATA) ? 0 : -1;
    ns_msg msg;
    if (ns_initparse(answer, anslen, &msg) < 0) return -1;
    /* dns-00 §3.4.2.2: the strings of ONE TXT RR are concatenated with
       nothing between them. Non-TXT answers (a CNAME on the way) are
       skipped. */
    int rrcount = ns_msg_count(msg, ns_s_an);
    for (int ri = 0; ri < rrcount; ri++) {
        ns_rr rr;
        if (ns_parserr(&msg, ns_s_an, ri, &rr) < 0) continue;
        if (ns_rr_type(rr) != ns_t_txt) continue;
        const unsigned char *rdata = ns_rr_rdata(rr);
        uint16_t rdlen = ns_rr_rdlen(rr);
        char *txt = malloc((size_t)rdlen + 1);
        if (!txt) { dkim2_txt_free(out); return -2; }
        size_t tpos = 0;
        for (size_t i = 0; i < rdlen; ) {           /* length-prefixed strings */
            size_t slen = rdata[i++];
            if (slen > rdlen - i) slen = rdlen - i;
            memcpy(txt + tpos, rdata + i, slen);
            tpos += slen;
            i += slen;
        }
        int rc = dkim2_txt_push(out, txt, tpos);
        free(txt);
        if (rc < 0) { dkim2_txt_free(out); return -2; }
    }
    return 0;
}

/* A whole DNS message: an answer of any size fits, nothing is cut short. */
#define DNS_ANSWER_MAX 65536

int dkim2_dns_txt_live(const char *qname, dkim2_txt_t *out) {
    out->rec = NULL; out->len = NULL; out->n = 0;
    unsigned char *answer = malloc(DNS_ANSWER_MAX);
    if (!answer) return -2;
    int anslen = dkim2_dns_query_hook
        ? dkim2_dns_query_hook(qname, answer, DNS_ANSWER_MAX)
        : res_query(qname, ns_c_in, ns_t_txt, answer, DNS_ANSWER_MAX);
    int herr = h_errno;
    if (anslen > DNS_ANSWER_MAX) anslen = -1, herr = NO_RECOVERY;
    int rc = dkim2_dns_txt_from_answer(answer, anslen, herr, out);
    free(answer);
    return rc;
}

/* The key from the TXT records at a selector name (-09 §3.7, §14.5;
   contract E4): records whose first tag is v= with a value other than
   DKIM1 are dropped; then none is "does not exist", more than one "has
   multiple records", and the one left is parsed. */
static dkim2_pubkey_t *key_from_records(const dkim2_txt_t *t,
    dkim2_status_t *statusp, const char **errp) {
    int keep = -1, n = 0;
    for (int i = 0; i < t->n; i++) {
        if (dkim2_txt_first_tag(t->rec[i], t->len[i]) == 2) continue;
        if (n++ == 0) keep = i;
    }
    if (n == 0) { *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_ABSENT; return NULL; }
    if (n > 1) { *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_MULTIPLE; return NULL; }
    return parse_key_record(t->rec[keep], t->len[keep], statusp, errp);
}

/* The outcome of a TXT lookup (dkim2_dns_txt_live, a hook) as a key. */
static dkim2_pubkey_t *key_from_lookup(int rc, dkim2_txt_t *t,
    dkim2_status_t *statusp, const char **errp) {
    dkim2_pubkey_t *k = NULL;
    if (rc == -2) { *statusp = DKIM2_TEMPERROR; *errp = "OOM"; }
    else if (rc < 0) { *statusp = DKIM2_TEMPERROR; *errp = DKIM2_KEYERR_FETCH; }
    else k = key_from_records(t, statusp, errp);
    dkim2_txt_free(t);
    return k;
}

dkim2_pubkey_t *dkim2_dns_getkey(const char *selector, const char *domain,
    dkim2_status_t *statusp, const char **errp) {
    char *qname = NULL;
    size_t ql = strlen(selector) + strlen(domain) + sizeof "._domainkey.";
    if (!(qname = malloc(ql))) { *statusp = DKIM2_TEMPERROR; *errp = "OOM"; return NULL; }
    snprintf(qname, ql, "%s._domainkey.%s", selector, domain);
    dkim2_txt_t t = { 0 };
    dkim2_pubkey_t *k = NULL;

    /* dns.json (or a test's record set) first. */
    if (dkim2_dns_txt_hook) {
        int rc = dkim2_dns_txt_hook(qname, &t);
        if (rc != 1) { k = key_from_lookup(rc, &t, statusp, errp); goto done; }
    }
    /* The one-record test override. */
    if (dkim2_dns_override) {
        int n_records = 1;
        char *txt = dkim2_dns_override(qname, &n_records);
        if (txt && n_records > 1) {
            free(txt);
            *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_MULTIPLE; goto done;
        }
        if (!txt && n_records == 0) {
            *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_ABSENT; goto done;
        }
        if (!txt && n_records < 0) {
            *statusp = DKIM2_TEMPERROR; *errp = DKIM2_KEYERR_FETCH; goto done;
        }
        if (txt) {
            int rc = dkim2_txt_push(&t, txt, strlen(txt));
            free(txt);
            k = key_from_lookup(rc < 0 ? -2 : 0, &t, statusp, errp);
            goto done;
        }
    }
    k = key_from_lookup(dkim2_dns_txt_live(qname, &t), &t, statusp, errp);
done:
    free(qname);
    return k;
}

int dkim2_dns_answer_settles(const unsigned char *answer, int anslen, int herr) {
    if (anslen < 0) return herr == HOST_NOT_FOUND || herr == NO_DATA;
    ns_msg msg;
    return ns_initparse(answer, anslen, &msg) == 0;
}

dkim2_pubkey_t *dkim2_dns_key_from_answer(const unsigned char *answer, int anslen,
    int herr, dkim2_status_t *statusp, const char **errp) {
    /* -09 §14.5: NXDOMAIN / no data is "absent" (PERMERROR); anything else
       (SERVFAIL, timeout, refused, an answer that does not parse) could not
       be fetched (TEMPERROR). */
    dkim2_txt_t t;
    return key_from_lookup(dkim2_dns_txt_from_answer(answer, anslen, herr, &t), &t,
                           statusp, errp);
}

/* ---- Domain Policy Record (-09 §3.8; DKIMKEYS -03 §6; contract E3.2) ---- */

static int is_alnum(char c) { return is_alpha(c) || is_digit(c); }

/* f=: a colon-separated list of hyphenated-words, [FWS] around each ':'.
   1 when "strict" is one of them or the list breaks that ABNF (an empty
   member, a member that is not [A-Za-z]([A-Za-z0-9-]*[A-Za-z0-9])?); an
   empty f= is no flags. */
static int f_is_strict(const char *f, size_t fl) {
    if (fl == 0) return 0;
    const char *p = f, *lim = f + fl;
    for (;;) {
        const char *e = memchr(p, ':', (size_t)(lim - p));
        const char *end = e ? e : lim;
        const char *a = p, *b = end;
        while (a < b && is_wsp(*a)) a++;
        while (b > a && is_wsp(b[-1])) b--;
        if (a == b || !is_alpha(*a) || !is_alnum(b[-1])) return 1;
        for (const char *c = a; c < b; c++)
            if (!is_alnum(*c) && *c != '-') return 1;
        if (b - a == 6 && memcmp(a, "strict", 6) == 0) return 1;
        if (!e) return 0;
        p = e + 1;
    }
}

dkim2_policy_t dkim2_policy_from_records(const dkim2_txt_t *t) {
    int keep = -1, n = 0;
    for (int i = 0; i < t->n; i++) {
        if (dkim2_txt_first_tag(t->rec[i], t->len[i]) != 1) continue;
        if (n++ == 0) keep = i;
    }
    if (n == 0) return DKIM2_POLICY_OPEN;
    if (n > 1) return DKIM2_POLICY_MULTIPLE;
    rtag_t *tags = NULL;
    size_t ntags = 0;
    int sr = scan_record(t->rec[keep], t->len[keep], &tags, &ntags);
    dkim2_policy_t pol = DKIM2_POLICY_OPEN;
    if (sr == -2) pol = DKIM2_POLICY_TEMP;
    else if (sr < 0) pol = DKIM2_POLICY_STRICT;          /* fail closed */
    else
        for (size_t i = 0; i < ntags; i++)
            if (tags[i].nl == 1 && tags[i].n[0] == 'f' && f_is_strict(tags[i].v, tags[i].vl))
                pol = DKIM2_POLICY_STRICT;
    free(tags);
    return pol;
}

dkim2_policy_t dkim2_dns_get_policy(const char *dom) {
    size_t ql = strlen(dom) + sizeof "_domainkey.";
    char *qname = malloc(ql);
    if (!qname) return DKIM2_POLICY_TEMP;
    snprintf(qname, ql, "_domainkey.%s", dom);
    dkim2_txt_t t = { 0 };
    int rc = 1;
    if (dkim2_dns_txt_hook) rc = dkim2_dns_txt_hook(qname, &t);
    if (rc == 1 && dkim2_dns_override) {
        int n_records = 1;
        char *txt = dkim2_dns_override(qname, &n_records);
        if (txt) {
            rc = dkim2_txt_push(&t, txt, strlen(txt)) < 0 ? -2 : 0;
            free(txt);
        } else if (n_records == 0) rc = 0;
        else if (n_records < 0) rc = -1;
    }
    if (rc == 1) rc = dkim2_dns_txt_live(qname, &t);
    free(qname);
    dkim2_policy_t pol = rc < 0 ? DKIM2_POLICY_TEMP : dkim2_policy_from_records(&t);
    dkim2_txt_free(&t);
    return pol;
}

void dkim2_pubkey_free(dkim2_pubkey_t *k) {
    if (!k) return;
    EVP_PKEY_free(k->pkey);
    free(k->alg);
    free(k);
}
