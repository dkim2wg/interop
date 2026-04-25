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
char *(*dkim2_dns_override)(const char *qname) = NULL;

static dkim2_pubkey_t *parse_key_record(const char *txt,
    dkim2_status_t *statusp, const char **errp) {
    taglist_t *tl = tagparse(txt, NULL);
    if (!tl) {
        *statusp = DKIM2_PERMERROR; *errp = "Key record syntax error"; return NULL;
    }

    const char *v = tag_get(tl, "v");
    if (v && strcmp(v, "DKIM1") != 0) {
        taglist_free(tl);
        *statusp = DKIM2_PERMERROR; *errp = "Not a DKIM1 key record"; return NULL;
    }

    const char *p = tag_get(tl, "p");
    if (!p) {
        taglist_free(tl);
        *statusp = DKIM2_PERMERROR; *errp = "No p= in key record"; return NULL;
    }

    if (*p == '\0') {
        taglist_free(tl);
        dkim2_pubkey_t *k = calloc(1, sizeof *k);
        if (!k) { *statusp = DKIM2_TEMPERROR; *errp = "OOM"; return NULL; }
        k->revoked = 1;
        *statusp = DKIM2_PERMERROR; *errp = "Key revoked";
        return k;
    }

    const char *k_tag = tag_get(tl, "k");
    const char *alg = k_tag ? k_tag : "rsa";

    unsigned char keybuf[4096];
    int keylen = b64_decode(p, keybuf, sizeof keybuf);
    taglist_free(tl);
    if (keylen < 0) {
        *statusp = DKIM2_PERMERROR; *errp = "Key base64 decode error"; return NULL;
    }

    dkim2_pubkey_t *key = calloc(1, sizeof *key);
    if (!key) { *statusp = DKIM2_TEMPERROR; *errp = "OOM"; return NULL; }
    key->alg = strdup(alg);

    if (strcmp(alg, "rsa") == 0) {
        const unsigned char *kp = keybuf;
        key->pkey = d2i_PUBKEY(NULL, &kp, keylen);
    } else if (strcmp(alg, "ed25519") == 0) {
        key->pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, keybuf, (size_t)keylen);
    } else {
        free(key->alg); free(key);
        *statusp = DKIM2_PERMERROR; *errp = "Unknown key algorithm"; return NULL;
    }

    if (!key->pkey) {
        free(key->alg); free(key);
        *statusp = DKIM2_PERMERROR; *errp = "Key import failed"; return NULL;
    }

    *statusp = DKIM2_OK; *errp = NULL;
    return key;
}

dkim2_pubkey_t *dkim2_dns_getkey(const char *selector, const char *domain,
    dkim2_status_t *statusp, const char **errp) {
    char qname[512];
    snprintf(qname, sizeof qname, "%s._domainkey.%s", selector, domain);

    /* Check override first (used in tests) */
    if (dkim2_dns_override) {
        char *txt = dkim2_dns_override(qname);
        if (txt) {
            dkim2_pubkey_t *k = parse_key_record(txt, statusp, errp);
            free(txt);
            return k;
        }
    }

    /* Live DNS query */
    unsigned char answer[4096];
    int anslen = res_query(qname, ns_c_in, ns_t_txt, answer, (int)sizeof answer);
    if (anslen < 0) {
        *statusp = (h_errno == TRY_AGAIN) ? DKIM2_TEMPERROR : DKIM2_PERMERROR;
        *errp = "DNS query failed";
        return NULL;
    }

    ns_msg msg;
    if (ns_initparse(answer, anslen, &msg) < 0) {
        *statusp = DKIM2_PERMERROR; *errp = "DNS response parse error"; return NULL;
    }

    int rrcount = ns_msg_count(msg, ns_s_an);
    if (rrcount == 0) {
        *statusp = DKIM2_PERMERROR; *errp = "No TXT record found"; return NULL;
    }

    /* Collect and concatenate all TXT strings from all RRs */
    char txt[2048];
    size_t tpos = 0;
    for (int ri = 0; ri < rrcount && tpos < sizeof txt - 1; ri++) {
        ns_rr rr;
        if (ns_parserr(&msg, ns_s_an, ri, &rr) < 0) continue;
        if (ns_rr_type(rr) != ns_t_txt) continue;
        const unsigned char *rdata = ns_rr_rdata(rr);
        uint16_t rdlen = ns_rr_rdlen(rr);
        /* TXT RDATA: length-prefixed strings */
        for (size_t i = 0; i < rdlen && tpos < sizeof txt - 1; ) {
            unsigned char slen = rdata[i++];
            size_t copy = slen;
            if (i + copy > rdlen) copy = rdlen - i;
            if (tpos + copy >= sizeof txt) copy = sizeof txt - tpos - 1;
            memcpy(txt + tpos, rdata + i, copy);
            tpos += copy;
            i += slen;
        }
    }
    txt[tpos] = '\0';

    if (tpos == 0) {
        *statusp = DKIM2_PERMERROR; *errp = "Empty TXT record"; return NULL;
    }

    return parse_key_record(txt, statusp, errp);
}

void dkim2_pubkey_free(dkim2_pubkey_t *k) {
    if (!k) return;
    EVP_PKEY_free(k->pkey);
    free(k->alg);
    free(k);
}
