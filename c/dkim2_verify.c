#include "dkim2_verify.h"
#include "dkim2_hash.h"
#include "dkim2_header.h"
#include "dkim2_crypto.h"
#include "dkim2_dns.h"
#include "dkim2_recipe.h"
#include "base64.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <openssl/evp.h>

#define SETSTATUS(s, fmt, ...) do { \
    result->status = (s); \
    snprintf(result->message, sizeof result->message, fmt, ##__VA_ARGS__); \
    return; } while(0)

/* §8.5 canonicalization — same as in dkim2_sign.c.
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

/* Extract domain from an RFC 5321 address string like "<local@domain>" or "local@domain".
   Returns malloc'd lowercase domain string, or NULL. */
static char *addr_domain(const char *addr) {
    const char *at = strrchr(addr, '@');
    if (!at) return NULL;
    at++;
    /* end is exclusive: start at one past the string, walk back past > and \0 */
    const char *end = at + strlen(at); /* points to \0 */
    /* Trim trailing '>' characters (address may be "<local@domain>") */
    while (end > at && end[-1] == '>') end--;
    size_t dlen = (size_t)(end - at);
    char *d = malloc(dlen + 1);
    if (!d) return NULL;
    for (size_t i = 0; i < dlen; i++) d[i] = (char)tolower((unsigned char)at[i]);
    d[dlen] = '\0';
    return d;
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

/* §7.7/§10.4 envelope comparison: local-part case-sensitive, domain
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

/* Relaxed domain match: d must be equal to or a parent domain of mf_domain. */
static int relaxed_domain_match(const char *d, const char *mf_domain) {
    if (strcasecmp(mf_domain, d) == 0) return 1;
    const char *p = mf_domain;
    while (*p) {
        const char *dot = strchr(p, '.');
        if (!dot) break;
        p = dot + 1;
        if (strcasecmp(p, d) == 0) return 1;
    }
    return 0;
}

/* Build signing input for the verifier — same structure as §8.5 signing,
   but for the signature being verified, substitute empty string for its sig value.
   The sig_value_to_empty is the sig_b64 we want to blank out.
   We reconstruct an "incomplete" signature value by using dkim2_sig_format. */
/* Blank sig bytes in a raw DKIM2-Signature value, preserving trailing semicolon.
   Finds the s= tag and replaces each sel:alg:sigvalue with sel:alg: (empty).
   Returns malloc'd string. */
static char *blank_sig_values(const char *raw_val) {
    size_t rlen = strlen(raw_val);

    /* Find the s= tag at a tag boundary (start, or after ';'/WSP), matching
       the tag name case-insensitively per spec-04 §8. */
    const char *s_tag = NULL;
    for (const char *p = raw_val; *p; p++) {
        if ((p[0] == 's' || p[0] == 'S') && p[1] == '=') {
            if (p == raw_val || p[-1] == ';' || p[-1] == ' ' || p[-1] == '\t') {
                s_tag = p;
                break;
            }
        }
    }
    if (!s_tag) return strdup(raw_val); /* no s= tag, return as-is */

    /* Output buffer: prefix + blanked ssets + optional trailing ";" */
    char *out = malloc(rlen + 32);
    if (!out) return NULL;
    size_t pos = 0;

    /* Copy prefix up to and including "s=" */
    size_t prefix_len = (size_t)(s_tag - raw_val) + 2;
    memcpy(out, raw_val, prefix_len);
    pos = prefix_len;

    /* Parse comma-separated selector:alg:sigval entries */
    const char *p = s_tag + 2;
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

static void append_canon(char *buf, size_t *pos, size_t bufsz,
                         const char *hdr_name, const char *val) {
    size_t vl = strlen(val);
    char *full = malloc(vl + strlen(hdr_name) + 5);
    if (!full) return;
    sprintf(full, "%s: %s\r\n", hdr_name, val);
    char *canon = canon_for_sig(full);
    free(full);
    if (canon) {
        size_t cl = strlen(canon);
        if (*pos + cl < bufsz) { memcpy(buf + *pos, canon, cl); *pos += cl; }
        free(canon);
    }
}

static unsigned char *build_verify_input(
    dkim2_mi_t *mi_list, dkim2_sig_t *sig_list,
    dkim2_sig_t *target_sig, int target_sset_idx __attribute__((unused)),
    size_t *out_len) {
    /* Build signing input for target_sig: include only MI headers with m <=
       target_sig->m, and only DKIM2-Signature headers with i <= target_sig->i.
       The email stores them newest-first; spec §9.5 requires ascending order. */
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

    char *buf = malloc(65536);
    if (!buf) return NULL;
    size_t pos = 0;

    /* MI headers ascending m= */
    for (int i = 0; i < n_mi; i++)
        append_canon(buf, &pos, 65536, "message-instance", mi_arr[i]->raw_value);

    /* DKIM2-Signature headers ascending i= */
    for (int i = 0; i < n_sig; i++) {
        dkim2_sig_t *sig = sig_arr[i];
        char *to_use;
        if (sig->i == target_sig->i)
            to_use = blank_sig_values(sig->raw_value);
        else
            to_use = strdup(sig->raw_value);
        if (!to_use) continue;
        append_canon(buf, &pos, 65536, "dkim2-signature", to_use);
        free(to_use);
    }

    *out_len = pos;
    return (unsigned char *)buf;
}

/* Verify all MI body+header hashes, walking from highest to lowest version
   and applying recipes to reconstruct earlier message states.
   Returns 0 on success, sets errbuf on failure. */
static int verify_mi_hashes(
    dkim2_mi_t **mi_arr, int n_mi,
    char **all_hdrs, int n_all_hdrs,
    const char *initial_body, size_t initial_body_len,
    const unsigned char *top_body_digest,
    char *errbuf, size_t errbufsz)
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
    if (initial_body && initial_body_len > 0) {
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
    for (int vi = n_mi - 1; vi >= 0; vi--) {
        dkim2_mi_t *mi = mi_arr[vi];

        for (int hi = 0; hi < mi->n_hsets; hi++) {
            /* Verify body hash */
            unsigned char stored_bh[DKIM2_HASH_LEN];
            int bh_len = (int)b64_decode(mi->hsets[hi].body_hash, stored_bh, sizeof stored_bh);
            if (bh_len != DKIM2_HASH_LEN) {
                snprintf(errbuf, errbufsz, "PERMERROR: bad body hash in MI m=%d", mi->m);
                ret = -1; goto done;
            }
            unsigned char computed_bh[DKIM2_HASH_LEN];
            if (cur_body) {
                dkim2_body_hash_raw(cur_body, cur_body_len, computed_bh);
            } else if (vi == n_mi - 1 && top_body_digest) {
                memcpy(computed_bh, top_body_digest, DKIM2_HASH_LEN);
            } else {
                continue; /* no body bytes for inner MIs; skip */
            }
            if (memcmp(computed_bh, stored_bh, DKIM2_HASH_LEN) != 0) {
                snprintf(errbuf, errbufsz,
                    "FAIL: Message-Instance m=%d body hash mismatch", mi->m);
                ret = -1; goto done;
            }

            /* Verify header hash */
            unsigned char computed_hh[DKIM2_HASH_LEN];
            if (dkim2_header_hash_raw((const char **)content, n_content, computed_hh) < 0) {
                snprintf(errbuf, errbufsz, "PERMERROR: header hash computation failed");
                ret = -1; goto done;
            }
            unsigned char stored_hh[DKIM2_HASH_LEN];
            int hh_len = (int)b64_decode(mi->hsets[hi].hdr_hash, stored_hh, sizeof stored_hh);
            if (hh_len != DKIM2_HASH_LEN || memcmp(computed_hh, stored_hh, DKIM2_HASH_LEN) != 0) {
                snprintf(errbuf, errbufsz,
                    "FAIL: Message-Instance m=%d header hash mismatch", mi->m);
                ret = -1; goto done;
            }
        }

        /* Undo this MI's recipe to reconstruct the previous hop's state */
        if (vi > 0 && mi->r_raw) {
            size_t rraw_len = strlen(mi->r_raw);
            size_t decoded_max = rraw_len * 3 / 4 + 4;
            unsigned char *r_json_bytes = malloc(decoded_max + 1);
            if (!r_json_bytes) continue; /* OOM — skip undo, inner hash unverified */

            int r_json_len = (int)b64_decode(mi->r_raw, r_json_bytes, decoded_max);
            if (r_json_len <= 0) { free(r_json_bytes); continue; }
            r_json_bytes[r_json_len] = '\0';
            const char *rj = (const char *)r_json_bytes;

            /* Apply body recipe */
            if (cur_body) {
                size_t new_len;
                char *new_body = dkim2_apply_body_recipe(rj, cur_body, cur_body_len, &new_len);
                free(cur_body);
                cur_body = new_body;
                cur_body_len = new_body ? new_len : 0;
            }

            /* Apply header recipe — result is always a new owned array */
            int new_n = 0;
            char **new_content = dkim2_apply_header_recipe(rj, content, n_content, &new_n);
            if (new_content) {
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

done:
    if (content_owned) for (int i = 0; i < n_content; i++) free(content[i]);
    free(content);
    free(cur_body);
    return ret;
}

void dkim2_do_verify(dkim2_ctx_t *ctx, dkim2_verify_result_t *result) {
    result->status = DKIM2_PERMERROR;
    result->message[0] = '\0';
    result->sig_i = 0;
    result->domain[0] = '\0';

    /* §10.2: Require at least one DKIM2-Signature */
    if (!ctx->sig_list)
        SETSTATUS(DKIM2_PERMERROR, "PERMERROR: No DKIM2-Signature header");

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

    /* Local policy (stricter than spec-04): the topmost (highest i=)
       DKIM2-Signature MUST NOT carry nd=. The only legitimate nd= producer
       emits the nd= hop together with a matching higher-i= signature, so
       nd= should never appear on the top signature. Non-top nd= adjacency
       (§11.4, matched further below) is unaffected by this check. */
    if (latest->nd && latest->nd[0])
        SETSTATUS(DKIM2_PERMERROR, "DKIM2-Signature i=%d unexpected nd= tag", latest->i);

    /* §7.1: i= sequence must be contiguous 1..N */
    for (int i = 0; i < n_sigs; i++) {
        if (sig_arr[i]->i != i + 1)
            SETSTATUS(DKIM2_PERMERROR,
                "PERMERROR: DKIM2-Signature sequence not contiguous "
                "(expected i=%d, got i=%d)", i + 1, sig_arr[i]->i);
    }

    /* Find the MI the latest signature covers */
    dkim2_mi_t *covered_mi = NULL;
    for (dkim2_mi_t *m = ctx->mi_list; m; m = m->next)
        if (m->m == latest->m) { covered_mi = m; break; }
    if (!covered_mi)
        SETSTATUS(DKIM2_PERMERROR,
            "PERMERROR: No Message-Instance for m=%d", latest->m);

    /* §10.2: No MI with m= higher than latest->m should exist unsigned */
    for (dkim2_mi_t *m = ctx->mi_list; m; m = m->next) {
        if (m->m > latest->m)
            SETSTATUS(DKIM2_PERMERROR,
                "PERMERROR: Message-Instance m=%d is not covered by any signature", m->m);
    }

    /* §10.4: Envelope MAIL FROM must match top sig's mf= (domain
       case-insensitive, local-part case-sensitive, null sender aware). */
    if (ctx->mail_from && latest->mf) {
        if (!env_addr_eq(ctx->mail_from, latest->mf))
            SETSTATUS(DKIM2_PERMERROR,
                "DKIM2-Signature i=%d MAIL FROM %s did not match",
                latest->i, ctx->mail_from);
    }

    /* RCPT TO: every envelope recipient must appear in rt= (§7.7 domains
       match case-insensitively). */
    if (ctx->rcpt_to && latest->rt) {
        for (int i = 0; ctx->rcpt_to[i]; i++) {
            int found = 0;
            for (int j = 0; latest->rt[j]; j++)
                if (env_addr_eq(ctx->rcpt_to[i], latest->rt[j])) { found = 1; break; }
            if (!found)
                SETSTATUS(DKIM2_PERMERROR,
                    "DKIM2-Signature i=%d RCPT TO %s did not match",
                    latest->i, ctx->rcpt_to[i]);
        }
    }

    /* §10.6: Verify ALL signatures i=1..N */
    for (int si = 0; si < n_sigs; si++) {
        dkim2_sig_t *sig = sig_arr[si];
        result->sig_i = sig->i;
        snprintf(result->domain, sizeof result->domain, "%s", sig->d ? sig->d : "");

        /* §10.3: Timestamp check per sig */
        if (!ctx->skip_timestamp_check) {
            uint64_t now = (uint64_t)time(NULL);
            if (sig->t > now + 300)
                SETSTATUS(DKIM2_PERMERROR,
                    "PERMERROR: DKIM2-Signature i=%d timestamp is in the future", sig->i);
            if (now > sig->t + 14ULL * 24 * 3600)
                SETSTATUS(DKIM2_PERMERROR,
                    "PERMERROR: DKIM2-Signature i=%d has expired (t=%llu)",
                    sig->i, (unsigned long long)sig->t);
        }

        /* §7.5/§7.6: mf= and each rt= MUST be a bracketed RFC5321 path.
           nd= hops carry no mf/rt (sig->mf/sig->rt are NULL there) — skip. */
        if (sig->mf && sig->mf[0] &&
            !(sig->mf[0] == '<' && sig->mf[strlen(sig->mf) - 1] == '>'))
            SETSTATUS(DKIM2_PERMERROR,
                "PERMERROR: DKIM2-Signature i=%d: mf= is not a bracketed "
                "RFC5321 reverse-path (spec 7.5)", sig->i);
        for (int ri = 0; sig->rt && sig->rt[ri]; ri++) {
            size_t rn = strlen(sig->rt[ri]);
            if (!(rn >= 2 && sig->rt[ri][0] == '<' && sig->rt[ri][rn - 1] == '>'))
                SETSTATUS(DKIM2_PERMERROR,
                    "PERMERROR: DKIM2-Signature i=%d: rt= entry is not a "
                    "bracketed RFC5321 forward-path (spec 7.6)", sig->i);
        }

        /* §7.7: d= must cover mf= domain (relaxed match) */
        if (sig->mf && strcmp(sig->mf, "<>") != 0) {
            char *mf_d = addr_domain(sig->mf);
            int dm = mf_d ? relaxed_domain_match(sig->d, mf_d) : 0;
            free(mf_d);
            if (!dm)
                SETSTATUS(DKIM2_PERMERROR,
                    "DKIM2-Signature i=%d MAIL FROM and d= do not match",
                    sig->i);
        }

        /* Verify all s= items for this signature */
        int any_pass = 0;
        for (int j = 0; j < sig->n_ssets; j++) {
            dkim2_sigset_t *sset = &sig->ssets[j];

            dkim2_status_t dns_status;
            const char *dns_err = NULL;
            dkim2_pubkey_t *pubkey = dkim2_dns_getkey(
                sset->selector, sig->d, &dns_status, &dns_err);

            if (!pubkey) {
                if (dns_status == DKIM2_TEMPERROR)
                    SETSTATUS(DKIM2_TEMPERROR,
                        "TEMPERROR: DNS lookup for %s._domainkey.%s: %s",
                        sset->selector, sig->d, dns_err ? dns_err : "unknown");
                continue; /* PERMERROR for this sset — try next */
            }
            if (pubkey->revoked) {
                dkim2_pubkey_free(pubkey);
                continue;
            }

            if (strcmp(sset->alg, "rsa-sha256") != 0 &&
                strcmp(sset->alg, "ed25519-sha256") != 0) {
                dkim2_pubkey_free(pubkey);
                continue;
            }

            /* §3.2: RSA keys MUST be at least 1024 bits; skip weaker keys so
               they cannot verify a signature. */
            if (strcmp(sset->alg, "rsa-sha256") == 0 &&
                EVP_PKEY_bits(pubkey->pkey) < 1024) {
                dkim2_pubkey_free(pubkey);
                continue;
            }

            size_t sign_input_len;
            unsigned char *sign_input = build_verify_input(
                ctx->mi_list, ctx->sig_list, sig, j, &sign_input_len);

            if (!sign_input) {
                dkim2_pubkey_free(pubkey);
                SETSTATUS(DKIM2_PERMERROR,
                    "PERMERROR: Failed to build signing input for DKIM2-Signature i=%d", sig->i);
            }

            int vr = dkim2_verify(pubkey->pkey, sset->alg,
                sign_input, sign_input_len, sset->sig_b64);
            dkim2_pubkey_free(pubkey);
            free(sign_input);

            if (vr == 0) { any_pass = 1; break; }
        }

        if (!any_pass)
            SETSTATUS(DKIM2_FAIL,
                "FAIL: DKIM2-Signature i=%d signature verification failed", sig->i);
    }

    /* §8.2: Inter-sig chain of custody — mf= domain of sig[N] must relaxed-match
       at least one rt= domain of sig[N-1] */
    for (int k = 1; k < n_sigs; k++) {
        dkim2_sig_t *cur  = sig_arr[k];
        dkim2_sig_t *prev = sig_arr[k - 1];

        /* draft-04 §11.4: an nd= hop declares the next sig's signing domain;
           nd= MUST exactly match that signature's d=. */
        if (prev->nd) {
            if (!cur->d || strcasecmp(prev->nd, cur->d) != 0)
                SETSTATUS(DKIM2_PERMERROR,
                    "DKIM2-Signature i=%d MAIL nd= does not match",
                    prev->i);
            continue;
        }

        if (!cur->mf)
            SETSTATUS(DKIM2_PERMERROR,
                "DKIM2-Signature i=%d MAIL FROM <> did not match", cur->i);
        if (!prev->rt)
            SETSTATUS(DKIM2_PERMERROR,
                "DKIM2-Signature i=%d RCPT TO <> did not match", prev->i);

        char *cur_mf_d = addr_domain(cur->mf);
        int match = 0;
        for (int j = 0; prev->rt[j] && !match; j++) {
            char *rt_d = addr_domain(prev->rt[j]);
            if (rt_d && cur_mf_d && relaxed_domain_match(rt_d, cur_mf_d))
                match = 1;
            free(rt_d);
        }
        free(cur_mf_d);
        if (!match)
            SETSTATUS(DKIM2_FAIL,
                "DKIM2-Signature i=%d MAIL FROM %s did not match", cur->i, cur->mf);
    }

    /* §10.7: Verify all MI body+header hashes, undoing recipes for inner hops. */
    {
        const int MAX_MI = 64;
        dkim2_mi_t *mi_sorted[MAX_MI]; int n_mi = 0;
        for (dkim2_mi_t *m = ctx->mi_list; m && n_mi < MAX_MI; m = m->next)
            mi_sorted[n_mi++] = m;
        for (int i = 1; i < n_mi; i++) {
            dkim2_mi_t *key = mi_sorted[i]; int j = i - 1;
            while (j >= 0 && mi_sorted[j]->m > key->m) { mi_sorted[j+1] = mi_sorted[j]; j--; }
            mi_sorted[j+1] = key;
        }
        char mi_errbuf[512];
        if (verify_mi_hashes(mi_sorted, n_mi,
                             ctx->headers, ctx->n_headers,
                             ctx->body, ctx->body_len,
                             ctx->body_digest,
                             mi_errbuf, sizeof mi_errbuf) < 0) {
            SETSTATUS(
                (mi_errbuf[0] == 'F') ? DKIM2_FAIL : DKIM2_PERMERROR,
                "%s", mi_errbuf);
        }
    }

    result->status = DKIM2_OK;
    snprintf(result->message, sizeof result->message,
        "PASS: DKIM2-Signature i=%d verified", latest->i);
}
