#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dkim2_message.h"
#include "dkim2_dns.h"
#include "dkim2_dnsjson.h"

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <email.eml> --dns-json <path> [--mailfrom <addr>] "
        "[--rcptto <addr>]... [--ignore-timestamps] [-v]\n", prog);
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
        else if (strcmp(argv[i], "--ignore-timestamps") == 0)
            no_timestamp = 1;
        else if (strcmp(argv[i], "--full-chain") == 0)
            ; /* body bytes are always kept; full-chain MI hash walk is automatic */
        else { fprintf(stderr, "Unknown option: %s\n", argv[i]); usage(argv[0]); }
    }

    if (!dns_json_path) { fprintf(stderr, "--dns-json required\n"); usage(argv[0]); }

    char jerr[256];
    if (dkim2_dns_json_load(dns_json_path, jerr, sizeof jerr) < 0) {
        fprintf(stderr, "%s\n", jerr);
        return 1;
    }

    rcptto[n_rcpt] = NULL;
    dkim2_verify_result_t result = dkim2_verify_message(
        eml_path, mailfrom, n_rcpt > 0 ? rcptto : NULL, no_timestamp);

    if (verbose || result.status != DKIM2_OK)
        fprintf(stderr, "%s\n", result.message);

    dkim2_dns_json_free();
    return (result.status == DKIM2_OK) ? 0 : 1;
}
