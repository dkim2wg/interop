#include "dkim2_sign.h"
#include "dkim2_hash.h"
#include "dkim2_header.h"
#include "dkim2_crypto.h"
#include "base64.h"
#include "dkim2_verify.h"
#include <cjson/cJSON.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <ctype.h>
#include <openssl/evp.h>

/* RFC5321 path for mf=/rt= (spec 7.5/7.6): brackets MUST be present.
 * Returns a malloc'd string the caller frees. NULL/empty -> "<>". */
static char *to_rfc5321_path(const char *addr) {
    if (!addr || !*addr) return strdup("<>");
    size_t n = strlen(addr);
    if (addr[0] == '<' && addr[n-1] == '>') return strdup(addr);
    char *out = malloc(n + 3);
    snprintf(out, n + 3, "<%s>", addr);
    return out;
}

/* §8.5 canonicalization for signature input:
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

/* Build the §8.5 signing input:
   Canonicalized MI headers (ascending m=), then DKIM2-Signature headers
   (ascending i=), then the incomplete new signature header (empty sig values).
   Returns malloc'd buffer and sets *out_len. */
static unsigned char *build_sign_input(
    dkim2_mi_t *mi_list, dkim2_sig_t *sig_list,
    const char *new_sig_value, size_t *out_len) {
    char *buf = malloc(65536);
    if (!buf) return NULL;
    size_t pos = 0;

    /* MI headers ascending m= — use raw_value when available (existing MIs),
       else format from struct (newly created MI with no raw_value yet) */
    for (dkim2_mi_t *mi = mi_list; mi; mi = mi->next) {
        char *mi_val = mi->raw_value ? NULL : dkim2_mi_format(mi);
        const char *use_val = mi->raw_value ? mi->raw_value : mi_val;
        if (!use_val) { free(buf); return NULL; }
        size_t vl = strlen(use_val);
        char *full = malloc(vl + 24);
        snprintf(full, vl + 24, "message-instance: %s\r\n", use_val);
        free(mi_val);
        char *canon = canon_for_sig(full);
        free(full);
        if (canon) {
            size_t cl = strlen(canon);
            if (pos + cl < 65536) { memcpy(buf + pos, canon, cl); pos += cl; }
            free(canon);
        }
    }

    /* Existing DKIM2-Signature headers ascending i= */
    for (dkim2_sig_t *sig = sig_list; sig; sig = sig->next) {
        /* Use raw_value which is the complete original header value */
        size_t rv_len = strlen(sig->raw_value);
        char *full = malloc(rv_len + 24);
        snprintf(full, rv_len + 24, "dkim2-signature: %s\r\n", sig->raw_value);
        char *canon = canon_for_sig(full);
        free(full);
        if (canon) {
            size_t cl = strlen(canon);
            if (pos + cl < 65536) { memcpy(buf + pos, canon, cl); pos += cl; }
            free(canon);
        }
    }

    /* Incomplete new DKIM2-Signature (empty sig values) */
    size_t ns_len = strlen(new_sig_value);
    char *full = malloc(ns_len + 24);
    snprintf(full, ns_len + 24, "dkim2-signature: %s\r\n", new_sig_value);
    char *canon = canon_for_sig(full);
    free(full);
    if (canon) {
        size_t cl = strlen(canon);
        if (pos + cl < 65536) { memcpy(buf + pos, canon, cl); pos += cl; }
        free(canon);
    }

    *out_len = pos;
    return (unsigned char *)buf;
}

/* The top Message-Instance's m= if it carries a null body Recipe ("b": null,
   spec-06 §4.2: the previous body cannot be recreated) AND no DKIM2-Signature
   covers it (none has that m=, spec-06 §8.2); else 0. A null top an upstream
   domain already signed is not this hop's doing. */
static int top_mi_null_body_unsigned(const dkim2_ctx_t *ctx) {
    const dkim2_mi_t *top = NULL;
    for (const dkim2_mi_t *m = ctx->mi_list; m; m = m->next)
        if (!top || m->m >= top->m) top = m;
    if (!top || !top->r_raw) return 0;
    for (const dkim2_sig_t *s = ctx->sig_list; s; s = s->next)
        if (s->m == top->m) return 0;
    size_t n = strlen(top->r_raw);
    unsigned char *buf = malloc(n * 3 / 4 + 5);
    if (!buf) return 0;
    int len = (int)b64_decode(top->r_raw, buf, n * 3 / 4 + 4);
    int null_body = 0;
    if (len > 0) {
        buf[len] = '\0';
        cJSON *j = cJSON_Parse((const char *)buf);
        if (j) {
            cJSON *b = cJSON_GetObjectItemCaseSensitive(j, "b");
            null_body = (b && cJSON_IsNull(b)) ? top->m : 0;
            cJSON_Delete(j);
        }
    }
    free(buf);
    return null_body;
}

/* Signer gate: before extending an existing DKIM2 chain, verify it in
   outbound mode (the unsigned top Message-Instance is the one we are about to
   cover). Returns 0 to go ahead and sign, -1 to refuse with ctx->errmsg set.

   When ctx->body is NULL (the milter only keeps a body digest) the topmost
   instance's body hash is checked against the digest, but body Recipes cannot
   be undone to check inner instances' body hashes; their header hashes (and
   the header Recipes) are still walked. */
static int sign_gate(dkim2_ctx_t *ctx, const dkim2_sign_config_t *cfg) {
    if (cfg->skip_chain_check) return 0;
    if (!ctx->mi_list && !ctx->sig_list && !ctx->mi_error[0] && !ctx->sig_error[0])
        return 0;                       /* no existing chain: sign as always */

    /* spec-06 §9.3/§11.4: an nd= on the top signature names the domain that
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
    int null_m = top_mi_null_body_unsigned(ctx);
    if (null_m && !cfg->allow_null_body_recipe) {
        snprintf(ctx->errmsg, sizeof ctx->errmsg,
            "not signing: unsigned top Message-Instance m=%d has a null body Recipe "
            "(--allow-null-body-recipe not set)", null_m);
        return -1;
    }
    return 0;
}

int dkim2_do_sign(dkim2_ctx_t *ctx, const dkim2_sign_config_t *cfg,
    char **mi_out, char **sig_out) {
    if (sign_gate(ctx, cfg) < 0) return -1;

    /* spec-06 §3.1: which hash algorithm(s) to emit in h=. Default (cfg->hash
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

    /* §8.3/§8.4: body hash already computed incrementally (both algorithms);
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

    /* Base64-encode mf= — normalized to a bracketed RFC5321 path (spec §7.5) */
    char *mfp = to_rfc5321_path(ctx->mail_from);
    size_t mf_b64_len = ((strlen(mfp) + 2) / 3) * 4 + 2;
    char *mf_b64 = malloc(mf_b64_len);
    b64_encode((const unsigned char *)mfp, strlen(mfp), mf_b64, mf_b64_len);
    free(mfp);

    /* Base64-encode each rt= value, comma-separated — each normalized to a
       bracketed RFC5321 path (spec §7.6) */
    /* Estimate size: each rcpt ~64 chars encoded */
    size_t rt_buf_size = 4096;
    char *rt_b64 = calloc(1, rt_buf_size);
    size_t rt_pos = 0;
    if (ctx->rcpt_to) {
        for (int i = 0; ctx->rcpt_to[i]; i++) {
            char *rcpt = to_rfc5321_path(ctx->rcpt_to[i]);
            size_t rcpt_enc_len = ((strlen(rcpt) + 2) / 3) * 4 + 2;
            char *enc = malloc(rcpt_enc_len);
            b64_encode((const unsigned char *)rcpt, strlen(rcpt), enc, rcpt_enc_len);
            free(rcpt);
            if (i) { rt_b64[rt_pos++] = ','; }
            size_t el = strlen(enc);
            memcpy(rt_b64 + rt_pos, enc, el);
            rt_pos += el;
            free(enc);
        }
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

    /* Format incomplete DKIM2-Signature value (empty sig per §8.5) */
    char incomplete_sig[4096];
    snprintf(incomplete_sig, sizeof incomplete_sig,
        "i=%d; m=%d; t=%llu; d=%s; mf=%s; rt=%s; s=%s:%s:;",
        new_i, new_m, (unsigned long long)now,
        cfg->domain, mf_b64, rt_b64,
        cfg->selector, alg);

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
    char complete_sig[4096];
    snprintf(complete_sig, sizeof complete_sig,
        "i=%d; m=%d; t=%llu; d=%s; mf=%s; rt=%s; s=%s:%s:%s;",
        new_i, new_m, (unsigned long long)now,
        cfg->domain, mf_b64, rt_b64,
        cfg->selector, alg, sig_b64);
    free(sig_b64);

    /* Format MI value (only if new MI was created). dkim2_mi_format joins
       every hash-set with commas, e.g. "sha256:hh:bh,sha512:hh:bh" for
       --hash both — deterministic sha256-then-sha512 order. */
    if (!already_in_list) {
        *mi_out = dkim2_mi_format(&new_mi);
    } else {
        *mi_out = NULL; /* no new MI header needed */
    }

    *sig_out = strdup(complete_sig);
    free(mf_b64); free(rt_b64);
    return 0;
}
