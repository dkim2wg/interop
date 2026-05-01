#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dkim2_message.h"
#include "dkim2_dns.h"
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

    rcptto[n_rcpt] = NULL;
    dkim2_verify_result_t result = dkim2_verify_message(
        eml_path, mailfrom, n_rcpt > 0 ? rcptto : NULL, no_timestamp);

    if (verbose || result.status != DKIM2_OK)
        fprintf(stderr, "%s\n", result.message);

    cJSON_Delete(g_dns_json);
    return (result.status == DKIM2_OK) ? 0 : 1;
}
