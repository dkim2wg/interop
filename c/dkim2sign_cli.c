#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dkim2_internal.h"
#include "dkim2_header.h"
#include "dkim2_sign.h"
#include "eml_parse.h"

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <email.eml> -s SELECTOR -d DOMAIN -k KEYFILE\n"
        "       [--mailfrom ADDR] [--rcptto ADDR]... [--timestamp N]\n",
        prog);
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) usage(argv[0]);

    const char *eml_path  = argv[1];
    const char *selector  = NULL;
    const char *domain    = NULL;
    const char *keyfile   = NULL;
    const char *mailfrom  = "<>";
    char *rcptto[64];
    int n_rcpt = 0;
    long long timestamp = -1;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc)
            selector = argv[++i];
        else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc)
            domain = argv[++i];
        else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc)
            keyfile = argv[++i];
        else if (strcmp(argv[i], "--mailfrom") == 0 && i + 1 < argc)
            mailfrom = argv[++i];
        else if (strcmp(argv[i], "--rcptto") == 0 && i + 1 < argc) {
            if (n_rcpt < 63) rcptto[n_rcpt++] = argv[++i];
        } else if (strcmp(argv[i], "--timestamp") == 0 && i + 1 < argc)
            timestamp = atoll(argv[++i]);
        else { fprintf(stderr, "Unknown option: %s\n", argv[i]); usage(argv[0]); }
    }

    if (!selector || !domain || !keyfile) {
        fprintf(stderr, "-s, -d, and -k are required\n");
        usage(argv[0]);
    }

    /* Pass 1: parse headers + compute body digest (body bytes never buffered) */
    char **headers = NULL;
    int n_headers = 0;
    dkim2_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    if (eml_parse(eml_path, &headers, &n_headers, ctx.body_digest) < 0) {
        perror(eml_path); return 1;
    }

    /* Build signing context */
    ctx.headers   = headers;
    ctx.n_headers = n_headers;
    ctx.mail_from = (char *)mailfrom;
    rcptto[n_rcpt] = NULL;
    ctx.rcpt_to   = n_rcpt > 0 ? rcptto : NULL;
    ctx.n_rcpt    = n_rcpt;

    /* Parse any existing DKIM2 headers (for reviser/multi-hop case) */
    for (int i = 0; i < n_headers; i++) {
        const char *hdr = headers[i];
        const char *colon = strchr(hdr, ':');
        if (!colon) continue;
        size_t namelen = (size_t)(colon - hdr);
        char name[128];
        if (namelen >= sizeof name) continue;
        memcpy(name, hdr, namelen);
        name[namelen] = '\0';

        const char *val = colon + 1;
        while (*val == ' ' || *val == '\t') val++;
        size_t vlen = strlen(val);
        while (vlen > 0 && (val[vlen-1] == '\r' || val[vlen-1] == '\n')) vlen--;
        char *valdup = malloc(vlen + 1);
        memcpy(valdup, val, vlen);
        valdup[vlen] = '\0';

        if (strcasecmp(name, "Message-Instance") == 0) {
            dkim2_mi_t *mi = dkim2_mi_parse(valdup);
            if (mi) {
                dkim2_mi_t **tail = &ctx.mi_list;
                while (*tail) tail = &(*tail)->next;
                *tail = mi;
            }
        } else if (strcasecmp(name, "DKIM2-Signature") == 0) {
            dkim2_sig_t *sig = dkim2_sig_parse(valdup);
            if (sig) {
                dkim2_sig_t **tail = &ctx.sig_list;
                while (*tail) tail = &(*tail)->next;
                *tail = sig;
            }
        }
        free(valdup);
    }

    /* Determine algorithm from key file */
    dkim2_sign_config_t cfg = {
        .domain       = (char *)domain,
        .selector     = (char *)selector,
        .privkey_path = (char *)keyfile,
        .alg          = NULL,   /* auto-detect from key */
        .timestamp    = (timestamp >= 0) ? (uint64_t)timestamp : 0,
    };

    char *mi_val = NULL, *sig_val = NULL;
    if (dkim2_do_sign(&ctx, &cfg, &mi_val, &sig_val) != 0) {
        fprintf(stderr, "Sign failed: %s\n", ctx.errmsg);
        eml_free(headers, n_headers);
        return 1;
    }

    /* Output: new headers prepended, then original message */
    /* DKIM2-Signature first, then Message-Instance (prepended = reversed order) */
    printf("DKIM2-Signature: %s\r\n", sig_val);
    if (mi_val) printf("Message-Instance: %s\r\n", mi_val);

    for (int i = 0; i < n_headers; i++)
        fwrite(headers[i], 1, strlen(headers[i]), stdout);
    printf("\r\n");

    /* Pass 2: stream body straight from disk — no body buffer ever needed */
    eml_emit_body(eml_path, stdout);

    free(mi_val);
    free(sig_val);
    dkim2_mi_free(ctx.mi_list);
    dkim2_sig_free(ctx.sig_list);
    eml_free(headers, n_headers);
    return 0;
}
