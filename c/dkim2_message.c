#include "dkim2_message.h"
#include "dkim2_internal.h"
#include "dkim2_header.h"
#include "eml_parse.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* Scan header array, parse any Message-Instance and DKIM2-Signature headers
   into ctx->mi_list and ctx->sig_list. */
static void collect_dkim2_headers(dkim2_ctx_t *ctx) {
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

        if (strcmp(name, "message-instance") == 0) {
            dkim2_mi_t *mi = dkim2_mi_parse(valdup);
            if (mi) {
                dkim2_mi_t **tail = &ctx->mi_list;
                while (*tail) tail = &(*tail)->next;
                *tail = mi;
            }
        } else if (strcmp(name, "dkim2-signature") == 0) {
            dkim2_sig_t *sig = dkim2_sig_parse(valdup);
            if (sig) {
                dkim2_sig_t **tail = &ctx->sig_list;
                while (*tail) tail = &(*tail)->next;
                *tail = sig;
            }
        }
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

    if (eml_parse(eml_path, &headers, &n_headers, &ctx.body_digests) < 0) {
        snprintf(errbuf, errbufsz, "failed to parse %s", eml_path);
        return -1;
    }

    ctx.headers   = headers;
    ctx.n_headers = n_headers;
    ctx.mail_from = (char *)mail_from;
    ctx.rcpt_to   = rcpt_to;

    collect_dkim2_headers(&ctx);

    char *mi_val = NULL, *sig_val = NULL;
    int r = dkim2_do_sign(&ctx, cfg, &mi_val, &sig_val);

    dkim2_mi_free(ctx.mi_list);
    dkim2_sig_free(ctx.sig_list);

    if (r < 0) {
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
    dkim2_verify_result_t result = {DKIM2_PERMERROR, "failed to parse message", 0, ""};

    char **headers = NULL;
    int n_headers = 0;
    dkim2_ctx_t ctx = {0};

    if (eml_parse_with_body(eml_path, &headers, &n_headers,
                             &ctx.body_digests, &ctx.body, &ctx.body_len) < 0)
        return result;

    ctx.headers              = headers;
    ctx.n_headers            = n_headers;
    ctx.mail_from            = (char *)mail_from;
    ctx.rcpt_to              = rcpt_to;
    ctx.skip_timestamp_check = skip_timestamp_check;

    collect_dkim2_headers(&ctx);
    dkim2_do_verify(&ctx, &result);

    dkim2_mi_free(ctx.mi_list);
    dkim2_sig_free(ctx.sig_list);
    free(ctx.body);
    eml_free(headers, n_headers);
    return result;
}
