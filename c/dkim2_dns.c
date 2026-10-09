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
int (*dkim2_dns_query_hook)(const char *qname, unsigned char *answer, int anslen) = NULL;

const char DKIM2_KEYERR_MULTIPLE[] = "has multiple records";
const char DKIM2_KEYERR_SYNTAX[]   = "has a syntax error";
const char DKIM2_KEYERR_REVOKED[]  = "has been revoked";
const char DKIM2_KEYERR_ALG[]      = "algorithm mismatch";
const char DKIM2_KEYERR_ABSENT[]   = "does not exist";
const char DKIM2_KEYERR_FETCH[]    = "could not be fetched";

#define KEY_SYNTAX() do { *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_SYNTAX; goto out; } while (0)

static int is_wsp(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
static int is_alpha(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
static int is_digit(char c) { return c >= '0' && c <= '9'; }

/* A key record is a dns-00 §3.2 tag-list, validated as a whole (§3.4.1;
   spec-06 §11.5 "MUST validate the key record"): every tag-spec is
   [FWS] name [FWS] "=" value, name = ALPHA *(ALPHA / DIGIT / "_"), tag
   names are case sensitive and may not repeat, v= (if present) is first
   and exactly "DKIM1", p= is required. k= defaults to "rsa"; "rsa" and
   "ed25519" are known, any other k= is never read as a key we know. */
static dkim2_pubkey_t *parse_key_record(const char *txt,
    dkim2_status_t *statusp, const char **errp) {
    dkim2_pubkey_t *key = NULL;
    const char *v = NULL, *k = NULL, *p = NULL;
    size_t vl = 0, kl = 0, pl = 0;
    int ntags = 0;
    char *pclean = NULL;
    unsigned char *keybuf = NULL;

    /* Tag names seen, to reject a repeat. */
    struct { const char *n; size_t l; } seen[64];
    int nseen = 0;

    for (const char *s = txt; ; ) {
        const char *e = strchr(s, ';');
        const char *end = e ? e : s + strlen(s);
        const char *q = s;
        while (q < end && is_wsp(*q)) q++;
        if (q == end) {                 /* empty spec (e.g. after a trailing ';') */
            if (!e) break;
            s = e + 1; continue;
        }
        const char *name = q;
        if (!is_alpha(*q)) KEY_SYNTAX();
        while (q < end && (is_alpha(*q) || is_digit(*q) || *q == '_')) q++;
        size_t nl = (size_t)(q - name);
        while (q < end && is_wsp(*q)) q++;
        if (q == end || *q != '=') KEY_SYNTAX();
        q++;
        while (q < end && is_wsp(*q)) q++;
        const char *val = q, *vend = end;
        while (vend > val && is_wsp(vend[-1])) vend--;

        for (int i = 0; i < nseen; i++)
            if (seen[i].l == nl && memcmp(seen[i].n, name, nl) == 0) KEY_SYNTAX();
        if (nseen == (int)(sizeof seen / sizeof seen[0])) KEY_SYNTAX();
        seen[nseen].n = name; seen[nseen].l = nl; nseen++;

        if (nl == 1 && name[0] == 'v') {
            if (ntags != 0) KEY_SYNTAX();               /* v= MUST be first */
            v = val; vl = (size_t)(vend - val);
        } else if (nl == 1 && name[0] == 'k') {
            k = val; kl = (size_t)(vend - val);
        } else if (nl == 1 && name[0] == 'p') {
            p = val; pl = (size_t)(vend - val);
        }
        /* h=, n=, s=, t= (retired) and unknown tags are ignored. */
        ntags++;
        if (!e) break;
        s = e + 1;
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
    } else {
        key->pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, keybuf, (size_t)keylen);
    }
    if (!key->pkey) {                   /* p= is not a key of type k= */
        *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_SYNTAX; goto fail;
    }
    *statusp = DKIM2_OK; *errp = NULL;
    goto out;
fail:
    dkim2_pubkey_free(key);
    key = NULL;
out:
    free(pclean);
    free(keybuf);
    return key;
}
#undef KEY_SYNTAX

dkim2_pubkey_t *dkim2_dns_getkey(const char *selector, const char *domain,
    dkim2_status_t *statusp, const char **errp) {
    char qname[512];
    snprintf(qname, sizeof qname, "%s._domainkey.%s", selector, domain);

    /* Check override first (used in tests) */
    if (dkim2_dns_override) {
        int n_records = 1;
        char *txt = dkim2_dns_override(qname, &n_records);
        if (txt && n_records > 1) {
            free(txt);
            *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_MULTIPLE; return NULL;
        }
        if (!txt && n_records == 0) {
            *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_ABSENT; return NULL;
        }
        if (!txt && n_records < 0) {
            *statusp = DKIM2_TEMPERROR; *errp = DKIM2_KEYERR_FETCH; return NULL;
        }
        if (txt) {
            dkim2_pubkey_t *k = parse_key_record(txt, statusp, errp);
            free(txt);
            return k;
        }
    }

    /* Live DNS query */
    unsigned char answer[4096];
    int anslen = dkim2_dns_query_hook
        ? dkim2_dns_query_hook(qname, answer, (int)sizeof answer)
        : res_query(qname, ns_c_in, ns_t_txt, answer, (int)sizeof answer);
    if (anslen < 0) {
        /* §11.5: NXDOMAIN / no data is "absent" (PERMERROR); anything else
           (SERVFAIL, timeout, refused) could not be fetched (TEMPERROR). */
        if (h_errno == HOST_NOT_FOUND || h_errno == NO_DATA) {
            *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_ABSENT;
        } else {
            *statusp = DKIM2_TEMPERROR; *errp = DKIM2_KEYERR_FETCH;
        }
        return NULL;
    }

    ns_msg msg;
    if (ns_initparse(answer, anslen, &msg) < 0) {
        *statusp = DKIM2_TEMPERROR; *errp = DKIM2_KEYERR_FETCH; return NULL;
    }

    /* dns-00 §3.4.2.2: the strings of ONE TXT RR are concatenated with
       nothing between them; more than one TXT RR is an error (spec-06
       §11.5). Non-TXT answers (a CNAME on the way) are skipped. */
    int rrcount = ns_msg_count(msg, ns_s_an);
    char *txt = NULL;
    size_t tpos = 0;
    int ntxt = 0;
    for (int ri = 0; ri < rrcount; ri++) {
        ns_rr rr;
        if (ns_parserr(&msg, ns_s_an, ri, &rr) < 0) continue;
        if (ns_rr_type(rr) != ns_t_txt) continue;
        if (++ntxt > 1) {
            free(txt);
            *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_MULTIPLE; return NULL;
        }
        const unsigned char *rdata = ns_rr_rdata(rr);
        uint16_t rdlen = ns_rr_rdlen(rr);
        txt = malloc((size_t)rdlen + 1);
        if (!txt) { *statusp = DKIM2_TEMPERROR; *errp = "OOM"; return NULL; }
        /* TXT RDATA: length-prefixed strings */
        for (size_t i = 0; i < rdlen; ) {
            size_t slen = rdata[i++];
            if (slen > rdlen - i) slen = rdlen - i;
            memcpy(txt + tpos, rdata + i, slen);
            tpos += slen;
            i += slen;
        }
        txt[tpos] = '\0';
    }
    if (ntxt == 0) {
        *statusp = DKIM2_PERMERROR; *errp = DKIM2_KEYERR_ABSENT; return NULL;
    }

    dkim2_pubkey_t *key = parse_key_record(txt, statusp, errp);
    free(txt);
    return key;
}

void dkim2_pubkey_free(dkim2_pubkey_t *k) {
    if (!k) return;
    EVP_PKEY_free(k->pkey);
    free(k->alg);
    free(k);
}
