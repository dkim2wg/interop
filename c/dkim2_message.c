#include "dkim2_message.h"
#include "dkim2_internal.h"
#include "dkim2_header.h"
#include "eml_parse.h"
#include "dkim2_plan.h"
#include "dkim2_prefetch.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* Scan header array, parse any Message-Instance and DKIM2-Signature headers
   into ctx->mi_list and ctx->sig_list (ctx->bad_list when they do not). */
void dkim2_ctx_collect(dkim2_ctx_t *ctx) {
    for (int i = 0; i < ctx->n_headers; i++) {
        const char *hdr = ctx->headers[i];
        const char *colon = strchr(hdr, ':');
        if (!colon) continue;
        size_t nl = (size_t)(colon - hdr);
        char name[128] = {0};
        if (nl >= sizeof name) continue;
        for (size_t j = 0; j < nl; j++)
            name[j] = (char)tolower((unsigned char)hdr[j]);

        const char *val = colon + 1;
        while (*val == ' ' || *val == '\t') val++;
        size_t vlen = strlen(val);
        while (vlen > 0 && (val[vlen-1] == '\r' || val[vlen-1] == '\n')) vlen--;
        char *valdup = malloc(vlen + 1);
        if (!valdup) continue;
        memcpy(valdup, val, vlen);
        valdup[vlen] = '\0';

        if (strcmp(name, "message-instance") == 0)
            dkim2_ctx_add_field(ctx, 0, valdup);
        else if (strcmp(name, "dkim2-signature") == 0)
            dkim2_ctx_add_field(ctx, 1, valdup);
        free(valdup);
    }
}

int dkim2_sign_message(const char *eml_path, FILE *out,
                       const dkim2_sign_config_t *cfg,
                       const char *mail_from, char **rcpt_to,
                       char *errbuf, size_t errbufsz)
{
    char **headers = NULL;
    int n_headers = 0;
    dkim2_ctx_t ctx = {0};

    /* Body bytes are kept so the signer gate can check every existing
       Message-Instance's body hash, not only the topmost. */
    if (eml_parse_with_body(eml_path, &headers, &n_headers, &ctx.body_digests,
                            &ctx.body, &ctx.body_len) < 0) {
        snprintf(errbuf, errbufsz, "failed to parse %s", eml_path);
        return -1;
    }

    ctx.headers   = headers;
    ctx.n_headers = n_headers;
    ctx.mail_from = (char *)mail_from;
    ctx.rcpt_to   = rcpt_to;

    dkim2_ctx_collect(&ctx);

    char *mi_val = NULL, *sig_val = NULL;
    int r = dkim2_do_sign(&ctx, cfg, &mi_val, &sig_val);

    dkim2_mi_free(ctx.mi_list);
    dkim2_sig_free(ctx.sig_list);
    dkim2_badfield_free(ctx.bad_list);

    free(ctx.body);
    if (r < 0) {
        /* A gate refusal reads "not signing: ..." -- don't bury it. */
        if (strncmp(ctx.errmsg, "not signing:", 12) == 0)
            snprintf(errbuf, errbufsz, "%s", ctx.errmsg);
        else
            snprintf(errbuf, errbufsz, "signing failed: %s", ctx.errmsg);
        eml_free(headers, n_headers);
        return -1;
    }

    fprintf(out, "DKIM2-Signature: %s\r\n", sig_val);
    if (mi_val)
        fprintf(out, "Message-Instance: %s\r\n", mi_val);
    for (int i = 0; i < n_headers; i++)
        fwrite(headers[i], 1, strlen(headers[i]), out);
    fprintf(out, "\r\n");
    eml_emit_body(eml_path, out);

    free(mi_val);
    free(sig_val);
    eml_free(headers, n_headers);
    return 0;
}

dkim2_verify_result_t dkim2_verify_message(const char *eml_path,
                                            const char *mail_from,
                                            char **rcpt_to,
                                            int skip_timestamp_check)
{
    return dkim2_verify_message_opts(eml_path, mail_from, rcpt_to,
                                     skip_timestamp_check, NULL);
}

dkim2_verify_result_t dkim2_verify_message_opts(const char *eml_path,
                                                 const char *mail_from,
                                                 char **rcpt_to,
                                                 int skip_timestamp_check,
                                                 const dkim2_verify_opts_t *opts)
{
    static const dkim2_verify_opts_t defaults = { 0 };
    if (!opts) opts = &defaults;
    dkim2_verify_result_t result = {DKIM2_PERMERROR, "failed to parse message", 0, ""};

    char **headers = NULL;
    int n_headers = 0;
    dkim2_ctx_t ctx = {0};

    /* No whole-body digests: with the body bytes at hand, every instance's
       body hash is computed from them (by the plan, or the undo walk). */
    if (eml_parse_with_body(eml_path, &headers, &n_headers,
                             NULL, &ctx.body, &ctx.body_len) < 0)
        return result;

    ctx.headers              = headers;
    ctx.n_headers            = n_headers;
    ctx.mail_from            = (char *)mail_from;
    ctx.rcpt_to              = rcpt_to;
    ctx.skip_timestamp_check = skip_timestamp_check;
    ctx.undo_walk            = opts->undo_walk;

    dkim2_ctx_collect(&ctx);

    /* End of headers: the key lookups start, and the chain is planned and
       hashed while they are under way. ctx.body stays for the one case the
       plan hands back to the undo walk. */
    if (!opts->no_prefetch) ctx.prefetch = dkim2_prefetch_start(&ctx);
    if (!opts->undo_walk) {
        ctx.plan = dkim2_plan_new_ctx(&ctx, 0);
        if (ctx.plan) {
            size_t step = opts->chunk ? opts->chunk : ctx.body_len;
            int rc = 0;
            for (size_t at = 0; at < ctx.body_len && rc == 0; at += step)
                rc = dkim2_plan_body_update(ctx.plan, ctx.body + at,
                    ctx.body_len - at < step ? ctx.body_len - at : step);
            if (rc == 0) rc = dkim2_plan_body_final(ctx.plan);
            if (rc < 0) { dkim2_plan_free(ctx.plan); ctx.plan = NULL; }
        }
    }

    dkim2_do_verify(&ctx, &result);

    dkim2_plan_free(ctx.plan);
    dkim2_prefetch_free(ctx.prefetch);
    dkim2_mi_free(ctx.mi_list);
    dkim2_sig_free(ctx.sig_list);
    dkim2_badfield_free(ctx.bad_list);
    free(ctx.body);
    eml_free(headers, n_headers);
    return result;
}
