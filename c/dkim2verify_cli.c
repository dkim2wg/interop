#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dkim2_message.h"
#include "dkim2_dns.h"
#include "dkim2_dnsjson.h"

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <email.eml> [--dns-json <path>] [--mailfrom <addr>] "
        "[--rcptto <addr>]... [--ignore-timestamps] [--undo-walk] "
        "[--no-prefetch] [-v]\n"
        "  Keys come from live DNS unless --dns-json is given.\n"
        "  --undo-walk    check the Message-Instance chain by rebuilding each\n"
        "                 earlier message (the reference for the planned walk)\n"
        "  --no-prefetch  look each key up only when it is needed\n", prog);
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
    dkim2_verify_opts_t opts = { 0 };

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
        else if (strcmp(argv[i], "--undo-walk") == 0)
            opts.undo_walk = 1;
        else if (strcmp(argv[i], "--no-prefetch") == 0)
            opts.no_prefetch = 1;
        else if (strcmp(argv[i], "--full-chain") == 0)
            ; /* body bytes are always kept; full-chain MI hash walk is automatic */
        else { fprintf(stderr, "Unknown option: %s\n", argv[i]); usage(argv[0]); }
    }

    char jerr[256];
    if (dns_json_path && dkim2_dns_json_load(dns_json_path, jerr, sizeof jerr) < 0) {
        fprintf(stderr, "%s\n", jerr);
        return 1;
    }

    rcptto[n_rcpt] = NULL;
    dkim2_verify_result_t result = dkim2_verify_message_opts(
        eml_path, mailfrom, n_rcpt > 0 ? rcptto : NULL, no_timestamp, &opts);

    /* No DKIM2 header fields: the result is "none", with no error string
       (not a pass either). */
    if (result.status == DKIM2_NONE)
        fprintf(stderr, "none\n");
    else if (verbose || result.status != DKIM2_OK)
        fprintf(stderr, "%s\n", result.message);

    dkim2_dns_json_free();
    return (result.status == DKIM2_OK) ? 0 : 1;
}
