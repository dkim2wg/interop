#include "dkim2_sign.h"
#include "dkim2_hash.h"
#include "dkim2_header.h"
#include "dkim2_crypto.h"
#include "base64.h"
#include "dkim2_verify.h"
#include "dkim2_recipe.h"
#include "dkim2_domain.h"
#include <cjson/cJSON.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <ctype.h>
#include <openssl/evp.h>

/* A DKIM2-Signature value, malloc'd to fit (rt= may hold any number of
   recipients); NULL on out of memory. sigv "" gives the incomplete value
   that is signed (-08 §12.8). */
static char *sig_value(int i, int m, unsigned long long t, const char *d,
                       const char *mf, const char *rt, const char *flags,
                       const char *sel, const char *alg, const char *sigv) {
    const char *fmt = "i=%d; m=%d; t=%llu; d=%s; mf=%s; rt=%s;%s s=%s:%s:%s;";
    int n = snprintf(NULL, 0, fmt, i, m, t, d, mf, rt, flags, sel, alg, sigv);
    if (n < 0) return NULL;
    char *out = malloc((size_t)n + 1);
    if (out) snprintf(out, (size_t)n + 1, fmt, i, m, t, d, mf, rt, flags, sel, alg, sigv);
    return out;
}

/* RFC5321 path for mf=/rt= (-08 §10.5/§10.6): brackets MUST be present, and
 * a domain with non-ASCII (U-label) labels is recorded as A-labels (§18).
 * Returns a malloc'd string the caller frees. NULL/empty -> "<>". */
static char *to_rfc5321_path(const char *addr) {
    if (!addr || !*addr) return strdup("<>");
    size_t n = strlen(addr);
    int bracketed = addr[0] == '<' && addr[n-1] == '>';
    const char *inner = bracketed ? addr + 1 : addr;
    size_t in_len = bracketed ? n - 2 : n;
    const char *at = NULL;                          /* the last '@' */
    for (size_t i = in_len; i > 0 && !at; i--)
        if (inner[i - 1] == '@') at = inner + i - 1;
    char dom[512];
    if (at && (size_t)(inner + in_len - at - 1) < sizeof dom) {
        size_t dl = (size_t)(inner + in_len - at - 1);
        memcpy(dom, at + 1, dl);
        dom[dl] = '\0';
        int non_ascii = 0;
        for (size_t i = 0; i < dl; i++) if ((unsigned char)dom[i] >= 0x80) non_ascii = 1;
        char alabel[512];
        if (non_ascii && dom[0] != '[' && dkim2_to_alabel(dom, alabel, sizeof alabel) == 0) {
            size_t ll = (size_t)(at - inner), al = strlen(alabel);
            char *out = malloc(ll + al + 4);
            if (!out) return NULL;
            snprintf(out, ll + al + 4, "<%.*s@%s>", (int)ll, inner, alabel);
            return out;
        }
    }
    if (bracketed) return strdup(addr);
    char *out = malloc(n + 3);
    if (out) snprintf(out, n + 3, "<%s>", addr);
    return out;
}

/* -08 §12.8 canonicalization for signature input:
   lowercase name, unfold (remove CRLF+following WSP), delete ALL remaining WSP,
   re-add trailing CRLF.
   Input: "Name: folded value\r\n"
   Returns malloc'd string or NULL. */
static char *canon_for_sig(const char *hdr) {
    size_t len = strlen(hdr);
    char *out = malloc(len + 4);
    if (!out) return NULL;
    char *p = out;

    const char *h = hdr;
    const char *colon = strchr(h, ':');
    if (!colon) { free(out); return NULL; }

    /* Lowercase name */
    for (; h < colon; h++) *p++ = (char)tolower((unsigned char)*h);
    *p++ = ':';
    h++; /* skip colon */

    /* Process value: unfold, delete ALL whitespace */
    while (*h) {
        if (h[0] == '\r' && h[1] == '\n') {
            h += 2;
            while (*h == ' ' || *h == '\t') h++; /* skip fold WSP */
            continue;
        }
        if (*h == ' ' || *h == '\t') { h++; continue; }
        *p++ = *h++;
    }

    /* Ensure trailing CRLF */
    if (p > out && p[-1] == '\n') {
        /* Already ends with \n — check for \r */
        if (p > out + 1 && p[-2] == '\r') {
            /* already \r\n */
        } else {
            /* just \n — replace with \r\n */
            p[-1] = '\r'; *p++ = '\n';
        }
    } else {
        *p++ = '\r'; *p++ = '\n';
    }
    *p = '\0';
    return out;
}

/* Append the -08 §12.8 canonical form of "name: value" to *buf, growing it
   as needed. Returns 0, or -1 on allocation failure: a field is never left
   out, since a signature over less than the whole input cannot verify. */
static int append_sign_field(char **buf, size_t *pos, size_t *cap,
                             const char *name, const char *value) {
    size_t fl = strlen(name) + strlen(value) + 5;
    char *full = malloc(fl);
    if (!full) return -1;
    snprintf(full, fl, "%s: %s\r\n", name, value);
    char *canon = canon_for_sig(full);
    free(full);
    if (!canon) return -1;
    size_t cl = strlen(canon);
    if (*pos + cl + 1 > *cap) {
        size_t want = *cap;
        while (*pos + cl + 1 > want) want *= 2;
        char *grown = realloc(*buf, want);
        if (!grown) { free(canon); return -1; }
        *buf = grown;
        *cap = want;
    }
    memcpy(*buf + *pos, canon, cl);
    *pos += cl;
    free(canon);
    return 0;
}

/* Build the -08 §12.8 signing input:
   Canonicalized MI headers (ascending m=), then DKIM2-Signature headers
   (ascending i=), then the incomplete new signature header (empty sig values).
   Returns malloc'd buffer and sets *out_len. */
static unsigned char *build_sign_input(
    dkim2_mi_t *mi_list, dkim2_sig_t *sig_list,
    const char *new_sig_value, size_t *out_len) {
    /* The lists are in header order -- newest first in a received message --
       so sort them: the signing input is ascending m=, then ascending i=
       (taking the lists as given signed any chain with two or more existing
       instances or signatures in the wrong order). */
    enum { MAXF = 64 };
    dkim2_mi_t *mis[MAXF];
    dkim2_sig_t *sigs[MAXF];
    int n_mi = 0, n_sig = 0;
    for (dkim2_mi_t *mi = mi_list; mi && n_mi < MAXF; mi = mi->next) mis[n_mi++] = mi;
    for (dkim2_sig_t *s = sig_list; s && n_sig < MAXF; s = s->next) sigs[n_sig++] = s;
    for (int i = 1; i < n_mi; i++)
        for (int j = i; j > 0 && mis[j - 1]->m > mis[j]->m; j--) {
            dkim2_mi_t *t = mis[j]; mis[j] = mis[j - 1]; mis[j - 1] = t;
        }
    for (int i = 1; i < n_sig; i++)
        for (int j = i; j > 0 && sigs[j - 1]->i > sigs[j]->i; j--) {
            dkim2_sig_t *t = sigs[j]; sigs[j] = sigs[j - 1]; sigs[j - 1] = t;
        }

    size_t pos = 0, cap = 4096;
    char *buf = malloc(cap);
    if (!buf) return NULL;

    /* MI headers ascending m= — use raw_value when available (existing MIs),
       else format from struct (newly created MI with no raw_value yet) */
    for (int k = 0; k < n_mi; k++) {
        dkim2_mi_t *mi = mis[k];
        char *mi_val = mi->raw_value ? NULL : dkim2_mi_format(mi);
        const char *use_val = mi->raw_value ? mi->raw_value : mi_val;
        int rc = use_val ? append_sign_field(&buf, &pos, &cap, "message-instance", use_val) : -1;
        free(mi_val);
        if (rc < 0) { free(buf); return NULL; }
    }

    /* Existing DKIM2-Signature headers ascending i= (raw_value is the
       complete original header value) */
    for (int k = 0; k < n_sig; k++)
        if (append_sign_field(&buf, &pos, &cap, "dkim2-signature", sigs[k]->raw_value) < 0) {
            free(buf);
            return NULL;
        }

    /* Incomplete new DKIM2-Signature (empty sig values) */
    if (append_sign_field(&buf, &pos, &cap, "dkim2-signature", new_sig_value) < 0) {
        free(buf);
        return NULL;
    }

    *out_len = pos;
    return (unsigned char *)buf;
}

/* Non-zero if a Message-Instance's r= carries a null body Recipe ("b": null,
   -08 §5.2: the previous body cannot be recreated). */
static int mi_null_body(const dkim2_mi_t *mi) {
    if (!mi->r_raw) return 0;
    size_t n = strlen(mi->r_raw);
    unsigned char *buf = malloc(n * 3 / 4 + 5);
    if (!buf) return 0;
    int len = (int)b64_decode(mi->r_raw, buf, n * 3 / 4 + 4);
    int null_body = 0;
    if (len > 0) {
        buf[len] = '\0';
        cJSON *j = dkim2_recipe_parse((const char *)buf);
        if (j) {
            cJSON *b = cJSON_GetObjectItemCaseSensitive(j, "b");
            null_body = b && cJSON_IsNull(b);
            cJSON_Delete(j);
        }
    }
    free(buf);
    return null_body;
}

/* The m= of the highest UNSIGNED Message-Instance with a null body Recipe,
   else 0. A DKIM2-Signature with m=k covers instances 1..k (-08 §10.2),
   so an instance is unsigned when its m= is above the highest m= of every
   parsed (valid i=) signature -- whether it is the top, or another unsigned
   instance was added over it. A null an upstream domain already signed is
   not this hop's doing. *is_top says whether it is the top instance. */
static int unsigned_null_body_mi(const dkim2_ctx_t *ctx, int *is_top) {
    int covered = 0, top_m = 0, null_m = 0;
    for (const dkim2_sig_t *s = ctx->sig_list; s; s = s->next)
        if (s->m > covered) covered = s->m;
    for (const dkim2_mi_t *m = ctx->mi_list; m; m = m->next) {
        if (m->m > top_m) top_m = m->m;
        if (m->m > covered && m->m > null_m && mi_null_body(m)) null_m = m->m;
    }
    *is_top = null_m && null_m == top_m;
    return null_m;
}

/* Signer gate: before extending an existing DKIM2 chain, verify it in
   outbound mode (the unsigned top Message-Instance is the one we are about to
   cover). Returns 0 to go ahead and sign, -1 to refuse with ctx->errmsg set.

   Every instance's body hash is checked when the body is known -- as bytes
   (ctx->body) or streamed into ctx->plan (the milter). With neither, only
   the topmost instance's body hash is checked, against the digest; inner
   instances' header hashes (and the header Recipes) are still walked. */
static int sign_gate(dkim2_ctx_t *ctx, const dkim2_sign_config_t *cfg) {
    if (cfg->skip_chain_check) return 0;
    if (!ctx->mi_list && !ctx->sig_list && !ctx->mi_error[0] && !ctx->sig_error[0])
        return 0;                       /* no existing chain: sign as always */

    /* -08 §12.3/§14.4: an nd= on the top signature names the domain that
       signs next. We may extend the chain only if that is us; the verifier's
       blanket "top signature carries nd=" rejection is lifted in outbound
       mode because this is the check that replaces it. */
    {
        const dkim2_sig_t *top = NULL;
        for (const dkim2_sig_t *s = ctx->sig_list; s; s = s->next)
            if (!top || s->i >= top->i) top = s;
        if (top && top->nd && top->nd[0] &&
            (!cfg->domain || strcasecmp(top->nd, cfg->domain) != 0)) {
            snprintf(ctx->errmsg, sizeof ctx->errmsg,
                "not signing: top signature nd=%.200s names another domain",
                top->nd);
            return -1;
        }
    }

    int save_out = ctx->outbound, save_ts = ctx->skip_timestamp_check;
    ctx->outbound = 1;
    ctx->skip_timestamp_check = cfg->skip_timestamp_check;
    dkim2_verify_result_t res;
    dkim2_do_verify(ctx, &res);
    ctx->outbound = save_out;
    ctx->skip_timestamp_check = save_ts;

    if (res.status != DKIM2_OK) {
        const char *outcome =
            (res.status == DKIM2_FAIL)      ? "fail" :
            (res.status == DKIM2_TEMPERROR) ? "temperror" : "permerror";
        if (strstr(res.message, "Message-Instance") || strstr(res.message, " MI m="))
            snprintf(ctx->errmsg, sizeof ctx->errmsg,
                "not signing: Message-Instance chain does not undo cleanly: %.400s",
                res.message);
        else
            snprintf(ctx->errmsg, sizeof ctx->errmsg,
                "not signing: upstream DKIM2 chain result=%s (%.400s)",
                outcome, res.message);
        return -1;
    }
    int is_top = 0;
    int null_m = unsigned_null_body_mi(ctx, &is_top);
    if (null_m && !cfg->allow_null_body_recipe) {
        snprintf(ctx->errmsg, sizeof ctx->errmsg,
            "not signing: unsigned %sMessage-Instance m=%d has a null body Recipe "
            "(--allow-null-body-recipe not set)", is_top ? "top " : "", null_m);
        return -1;
    }
    return 0;
}

/* -08 §12.4: when this signature is the first (no DKIM2-Signature yet), or
   an instance no signature covers yet changed From, the From header field
   must be Authentic for our d=. Returns 0 to sign, -1 to refuse with
   ctx->errmsg set. */
static int from_refusal(dkim2_ctx_t *ctx, const dkim2_sign_config_t *cfg) {
    int signed_m = 0, need = !ctx->sig_list;
    for (const dkim2_sig_t *s = ctx->sig_list; s; s = s->next)
        if (s->m > signed_m) signed_m = s->m;
    for (const dkim2_mi_t *m = ctx->mi_list; m && !need; m = m->next)
        if (m->m > signed_m && dkim2_mi_changes_from(m)) need = 1;
    if (need && !dkim2_from_authentic(ctx->headers, ctx->n_headers, cfg->domain)) {
        snprintf(ctx->errmsg, sizeof ctx->errmsg,
            "not signing: From header field is not Authentic for d=%.200s",
            cfg->domain ? cfg->domain : "");
        return -1;
    }
    return 0;
}

/* Whether a parser error is one of dkim2_chain_number_error()'s, or a
   missing or malformed i=/m= (the field is then left out of the lists, so
   the next i= and m= cannot be computed). A field syntax error of any
   other kind is included: refusing it costs nothing. */
static int chain_number_refusal(const char *e) {
    return strstr(e, "exceeds the maximum chain") || strstr(e, " syntax error")
        || strstr(e, "tag=i missing") || strstr(e, "tag=m missing");
}

int dkim2_do_sign(dkim2_ctx_t *ctx, const dkim2_sign_config_t *cfg,
    char **mi_out, char **sig_out) {
    /* An i=/m= that is not a chain number (dkim2_chain_number_error; the
       parsers left the field out of the lists) is refused even with the
       gate skipped: the next i= and m= are computed from the existing ones
       below. */
    {
        const char *re = chain_number_refusal(ctx->mi_error)
            ? ctx->mi_error
            : chain_number_refusal(ctx->sig_error)
            ? ctx->sig_error : NULL;
        if (re && cfg->skip_chain_check) {
            snprintf(ctx->errmsg, sizeof ctx->errmsg, "not signing: %.400s", re);
            return -1;
        }
    }
    if (sign_gate(ctx, cfg) < 0) return -1;
    if (!cfg->skip_chain_check && from_refusal(ctx, cfg) < 0) return -1;

    /* -08 §3.1: which hash algorithm(s) to emit in h=. Default (cfg->hash
       NULL) is sha256 only, so default output stays byte-identical to before
       hash agility existed. "--hash both" emits sha256 first, then sha512. */
    int sel_algs[DKIM2_N_HASH_ALGS];
    int n_sel = 0;
    const char *want = cfg->hash ? cfg->hash : "sha256";
    if (strcmp(want, "both") == 0) {
        sel_algs[n_sel++] = 0;
        sel_algs[n_sel++] = 1;
    } else {
        int a = dkim2_hash_alg_index(want);
        if (a < 0) a = 0;
        sel_algs[n_sel++] = a;
    }

    /* -08 §9.3: body hash already computed incrementally (both algorithms);
       header hash computed here per selected algorithm. */
    dkim2_hashset_t hs[DKIM2_N_HASH_ALGS];
    char hh_b64[DKIM2_N_HASH_ALGS][DKIM2_MAX_HASH_LEN * 2];
    char bh_b64[DKIM2_N_HASH_ALGS][DKIM2_MAX_HASH_LEN * 2];
    for (int k = 0; k < n_sel; k++) {
        int a = sel_algs[k];
        size_t alen = dkim2_hash_alg_len(a);

        unsigned char hd[DKIM2_MAX_HASH_LEN];
        if (dkim2_header_hash_raw_alg((const char **)ctx->headers, ctx->n_headers, a, hd) < 0) {
            snprintf(ctx->errmsg, sizeof ctx->errmsg, "header hash failed");
            return -1;
        }
        if (b64_encode(hd, alen, hh_b64[k], sizeof hh_b64[k]) < 0) {
            snprintf(ctx->errmsg, sizeof ctx->errmsg, "header hash encode failed");
            return -1;
        }
        if (b64_encode(ctx->body_digests.d[a], alen, bh_b64[k], sizeof bh_b64[k]) < 0) {
            snprintf(ctx->errmsg, sizeof ctx->errmsg, "body hash encode failed");
            return -1;
        }
        hs[k].alg       = (char *)dkim2_hash_alg_name(a);
        hs[k].hdr_hash  = hh_b64[k];
        hs[k].body_hash = bh_b64[k];
    }

    /* Determine m= for new Message-Instance */
    int new_m = 1;
    for (dkim2_mi_t *mi = ctx->mi_list; mi; mi = mi->next)
        if (mi->m >= new_m) new_m = mi->m + 1;

    /* Check if highest existing MI already has these exact hashes. Only
       applies to the legacy single-sha256 path so --hash semantics stay
       simple: a multi-hash sign always adds a new MI. */
    dkim2_mi_t *latest_mi = NULL;
    for (dkim2_mi_t *mi = ctx->mi_list; mi; mi = mi->next)
        if (!latest_mi || mi->m >= latest_mi->m) latest_mi = mi;   /* highest m=, not list tail */
    if (n_sel == 1 && sel_algs[0] == 0 &&
        latest_mi && latest_mi->n_hsets > 0 &&
        strcmp(latest_mi->hsets[0].hdr_hash, hh_b64[0]) == 0 &&
        strcmp(latest_mi->hsets[0].body_hash, bh_b64[0]) == 0) {
        /* Reuse existing MI — sign against it */
        new_m = latest_mi->m;
    }

    /* Build the new MI struct for signing input */
    dkim2_mi_t new_mi = {0};
    new_mi.m = new_m;
    new_mi.hsets = hs;
    new_mi.n_hsets = n_sel;
    new_mi.next = NULL;

    /* Determine i= for new DKIM2-Signature */
    int new_i = 1;
    for (dkim2_sig_t *sig = ctx->sig_list; sig; sig = sig->next)
        if (sig->i >= new_i) new_i = sig->i + 1;

    /* Base64-encode mf= — normalized to a bracketed RFC5321 path (-08 §10.5) */
    char *mfp = to_rfc5321_path(ctx->mail_from);
    size_t mf_b64_len = mfp ? ((strlen(mfp) + 2) / 3) * 4 + 2 : 0;
    char *mf_b64 = mfp ? malloc(mf_b64_len) : NULL;
    if (!mf_b64) {
        free(mfp);
        snprintf(ctx->errmsg, sizeof ctx->errmsg, "out of memory");
        return -1;
    }
    b64_encode((const unsigned char *)mfp, strlen(mfp), mf_b64, mf_b64_len);
    free(mfp);

    /* Base64-encode each rt= value, comma-separated — each normalized to a
       bracketed RFC5321 path (-08 §10.6). The buffer grows to fit: any
       number of recipients, of any length. */
    size_t rt_cap = 256, rt_pos = 0;
    char *rt_b64 = malloc(rt_cap);
    if (!rt_b64) {
        free(mf_b64);
        snprintf(ctx->errmsg, sizeof ctx->errmsg, "out of memory");
        return -1;
    }
    for (int i = 0; ctx->rcpt_to && ctx->rcpt_to[i]; i++) {
        char *rcpt = to_rfc5321_path(ctx->rcpt_to[i]);
        size_t enc_len = rcpt ? ((strlen(rcpt) + 2) / 3) * 4 + 2 : 0;
        if (rcpt && rt_pos + 1 + enc_len > rt_cap) {
            size_t want = rt_cap;
            while (rt_pos + 1 + enc_len > want) want *= 2;
            char *grown = realloc(rt_b64, want);
            if (grown) { rt_b64 = grown; rt_cap = want; }
            else { free(rcpt); rcpt = NULL; }
        }
        if (!rcpt) {
            free(rt_b64); free(mf_b64);
            snprintf(ctx->errmsg, sizeof ctx->errmsg, "out of memory");
            return -1;
        }
        if (i) rt_b64[rt_pos++] = ',';
        b64_encode((const unsigned char *)rcpt, strlen(rcpt), rt_b64 + rt_pos, rt_cap - rt_pos);
        rt_pos += strlen(rt_b64 + rt_pos);
        free(rcpt);
    }
    rt_b64[rt_pos] = '\0';

    /* Load private key */
    EVP_PKEY *privkey = dkim2_load_privkey(cfg->privkey_path);
    if (!privkey) {
        snprintf(ctx->errmsg, sizeof ctx->errmsg, "failed to load private key: %s", cfg->privkey_path);
        free(mf_b64); free(rt_b64); return -1;
    }

    /* Auto-detect algorithm from key type if not specified */
    const char *alg = cfg->alg;
    if (!alg) {
        int key_id = EVP_PKEY_id(privkey);
        if (key_id == EVP_PKEY_ED25519)      alg = "ed25519-sha256";
        else if (key_id == EVP_PKEY_RSA)     alg = "rsa-sha256";
        else {
            EVP_PKEY_free(privkey);
            free(mf_b64); free(rt_b64);
            snprintf(ctx->errmsg, sizeof ctx->errmsg, "unsupported key type");
            return -1;
        }
    }

    /* Use configured timestamp or current time */
    uint64_t now = cfg->timestamp ? cfg->timestamp : (uint64_t)time(NULL);

    /* -08 §12.5: an intermediary (i > 1) sending copies to more than one
       address sets "exploded" -- when the caller says so (a list that sends
       each recipient its own copy), or when this one copy goes to several
       rt= addresses. Never on i=1. */
    int n_rt = 0;
    for (int i = 0; ctx->rcpt_to && ctx->rcpt_to[i]; i++) n_rt++;
    const char *flags = (new_i > 1 && (cfg->exploded || n_rt > 1)) ? " f=exploded;" : "";

    /* Format incomplete DKIM2-Signature value (empty sig per -08 §12.8) */
    char *incomplete_sig = sig_value(new_i, new_m, (unsigned long long)now,
        cfg->domain, mf_b64, rt_b64, flags, cfg->selector, alg, "");
    if (!incomplete_sig) {
        EVP_PKEY_free(privkey);
        free(mf_b64); free(rt_b64);
        snprintf(ctx->errmsg, sizeof ctx->errmsg, "out of memory");
        return -1;
    }

    /* Build MI list to sign: existing + new (if new_m > any existing) */
    dkim2_mi_t *mi_for_sign = ctx->mi_list;
    dkim2_mi_t *last_existing = NULL;
    int already_in_list = 0;
    for (dkim2_mi_t *m = ctx->mi_list; m; m = m->next) {
        if (m->m == new_m) { already_in_list = 1; break; }
        last_existing = m;
    }
    if (!already_in_list) {
        /* Append new_mi at appropriate position */
        if (!mi_for_sign) {
            mi_for_sign = &new_mi;
        } else {
            /* Append at end */
            last_existing = ctx->mi_list;
            while (last_existing->next) last_existing = last_existing->next;
            last_existing->next = &new_mi;
        }
    }

    /* Build signing input */
    size_t sign_input_len;
    unsigned char *sign_input = build_sign_input(
        mi_for_sign, ctx->sig_list, incomplete_sig, &sign_input_len);
    free(incomplete_sig);

    /* Detach new_mi from list to avoid dangling pointer */
    if (!already_in_list) {
        if (mi_for_sign == &new_mi) {
            mi_for_sign = NULL;
        } else {
            for (dkim2_mi_t *m = ctx->mi_list; m; m = m->next) {
                if (m->next == &new_mi) { m->next = NULL; break; }
            }
        }
    }

    if (!sign_input) {
        EVP_PKEY_free(privkey);
        free(mf_b64); free(rt_b64);
        snprintf(ctx->errmsg, sizeof ctx->errmsg, "failed to build signing input");
        return -1;
    }

    /* Sign */
    char *sig_b64 = dkim2_sign(privkey, alg, sign_input, sign_input_len);
    EVP_PKEY_free(privkey);
    free(sign_input);

    if (!sig_b64) {
        free(mf_b64); free(rt_b64);
        snprintf(ctx->errmsg, sizeof ctx->errmsg, "signing failed");
        return -1;
    }

    /* Format complete DKIM2-Signature value */
    char *complete_sig = sig_value(new_i, new_m, (unsigned long long)now,
        cfg->domain, mf_b64, rt_b64, flags, cfg->selector, alg, sig_b64);
    free(sig_b64);
    free(mf_b64); free(rt_b64);
    if (!complete_sig) {
        snprintf(ctx->errmsg, sizeof ctx->errmsg, "out of memory");
        return -1;
    }

    /* Format MI value (only if new MI was created). dkim2_mi_format joins
       every hash-set with commas, e.g. "sha256:hh:bh,sha512:hh:bh" for
       --hash both — deterministic sha256-then-sha512 order. */
    if (!already_in_list) {
        *mi_out = dkim2_mi_format(&new_mi);
        /* NULL means "reused" to the caller: a signature over an instance
           that is never added would make the chain invalid. */
        if (!*mi_out) {
            free(complete_sig);
            snprintf(ctx->errmsg, sizeof ctx->errmsg, "out of memory");
            return -1;
        }
    } else {
        *mi_out = NULL; /* no new MI header needed */
    }

    *sig_out = complete_sig;
    return 0;
}
