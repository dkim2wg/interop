#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dkim2_message.h"

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

    dkim2_sign_config_t cfg = {
        .domain       = (char *)domain,
        .selector     = (char *)selector,
        .privkey_path = (char *)keyfile,
        .alg          = NULL,
        .timestamp    = (timestamp >= 0) ? (uint64_t)timestamp : 0,
    };
    rcptto[n_rcpt] = NULL;

    char errbuf[512];
    if (dkim2_sign_message(eml_path, stdout, &cfg,
                           mailfrom, n_rcpt > 0 ? rcptto : NULL,
                           errbuf, sizeof errbuf) != 0) {
        fprintf(stderr, "Sign failed: %s\n", errbuf);
        return 1;
    }
    return 0;
}
