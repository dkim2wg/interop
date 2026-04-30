#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dkim2_internal.h"
#include "dkim2_header.h"
#include "dkim2_verify.h"
#include "dkim2_dns.h"
#include "eml_parse.h"
#include "cjson/cJSON.h"

static cJSON *g_dns_json = NULL;

/* DNS override: look up selector._domainkey.domain in dns.json */
static char *dns_json_lookup(const char *qname) {
    if (!g_dns_json) return NULL;

    /* qname format: selector._domainkey.domain */
    const char *marker = strstr(qname, "._domainkey.");
    if (!marker) return NULL;

    size_t sel_len = (size_t)(marker - qname);
    char selector[256];
    if (sel_len >= sizeof selector) return NULL;
    memcpy(selector, qname, sel_len);
    selector[sel_len] = '\0';

    const char *domain = marker + strlen("._domainkey.");

    /* dns.json: { "domain": { "sel._domainkey": [["txt", "v=DKIM1;..."]] } } */
    cJSON *dom_obj = cJSON_GetObjectItemCaseSensitive(g_dns_json, domain);
    if (!dom_obj) return NULL;

    char key[512];
    snprintf(key, sizeof key, "%s._domainkey", selector);
    cJSON *records = cJSON_GetObjectItemCaseSensitive(dom_obj, key);
    if (!records || !cJSON_IsArray(records)) return NULL;

    /* First element: ["txt", "v=DKIM1;..."] */
    cJSON *first = cJSON_GetArrayItem(records, 0);
    if (!first || !cJSON_IsArray(first)) return NULL;

    cJSON *txt = cJSON_GetArrayItem(first, 1);
    if (!txt || !cJSON_IsString(txt)) return NULL;

    return strdup(txt->valuestring);
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <email.eml> --dns-json <path> [--mailfrom <addr>] "
        "[--rcptto <addr>]... [-v]\n", prog);
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) usage(argv[0]);

    const char *eml_path = argv[1];
    const char *dns_json_path = NULL;
    const char *mailfrom = NULL;
    char *rcptto[64];
    int n_rcpt = 0;
    int verbose = 0;
    int no_timestamp = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--dns-json") == 0 && i + 1 < argc)
            dns_json_path = argv[++i];
        else if (strcmp(argv[i], "--mailfrom") == 0 && i + 1 < argc)
            mailfrom = argv[++i];
        else if (strcmp(argv[i], "--rcptto") == 0 && i + 1 < argc) {
            if (n_rcpt < 63) rcptto[n_rcpt++] = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            verbose = 1;
        else if (strcmp(argv[i], "--no-timestamp-check") == 0)
            no_timestamp = 1;
        else if (strcmp(argv[i], "--full-chain") == 0)
            ; /* body bytes are always kept; full-chain MI hash walk is automatic */
        else { fprintf(stderr, "Unknown option: %s\n", argv[i]); usage(argv[0]); }
    }

    if (!dns_json_path) { fprintf(stderr, "--dns-json required\n"); usage(argv[0]); }

    /* Load dns.json */
    FILE *jf = fopen(dns_json_path, "r");
    if (!jf) { perror(dns_json_path); return 1; }
    fseek(jf, 0, SEEK_END);
    long jsize = ftell(jf); rewind(jf);
    char *jbuf = malloc((size_t)jsize + 1);
    fread(jbuf, 1, (size_t)jsize, jf);
    jbuf[jsize] = '\0';
    fclose(jf);
    g_dns_json = cJSON_Parse(jbuf);
    free(jbuf);
    if (!g_dns_json) { fprintf(stderr, "Failed to parse %s\n", dns_json_path); return 1; }
    dkim2_dns_override = dns_json_lookup;

    /* Parse the email (keep body bytes for full-chain MI hash verification) */
    char **headers = NULL;
    int n_headers = 0;
    dkim2_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    if (eml_parse_with_body(eml_path, &headers, &n_headers, ctx.body_digest,
                            &ctx.body, &ctx.body_len) < 0) {
        perror(eml_path); cJSON_Delete(g_dns_json); return 1;
    }

    /* Build verify context */
    ctx.headers              = headers;
    ctx.n_headers            = n_headers;
    ctx.skip_timestamp_check = no_timestamp;

    /* Set MAIL FROM and RCPT TO from command line (or skip check if not provided) */
    ctx.mail_from = mailfrom ? (char *)mailfrom : NULL;
    rcptto[n_rcpt] = NULL;
    ctx.rcpt_to = n_rcpt > 0 ? rcptto : NULL;

    /* Parse DKIM2 headers */
    for (int i = 0; i < n_headers; i++) {
        const char *hdr = headers[i];
        /* Find colon to split name from value */
        const char *colon = strchr(hdr, ':');
        if (!colon) continue;
        size_t namelen = (size_t)(colon - hdr);
        char name[128];
        if (namelen >= sizeof name) continue;
        memcpy(name, hdr, namelen);
        name[namelen] = '\0';

        const char *val = colon + 1;
        while (*val == ' ' || *val == '\t') val++;
        /* Strip trailing \r\n */
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

    /* Verify */
    dkim2_verify_result_t result;
    dkim2_do_verify(&ctx, &result);

    if (verbose || result.status != DKIM2_OK)
        fprintf(stderr, "%s\n", result.message);

    dkim2_mi_free(ctx.mi_list);
    dkim2_sig_free(ctx.sig_list);
    free(ctx.body);
    eml_free(headers, n_headers);
    cJSON_Delete(g_dns_json);

    return (result.status == DKIM2_OK) ? 0 : 1;
}
