/* Cross-implementation benchmark harness: verify every listed message,
   keys from one dns.json, timestamps off; planned walk then undo walk. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dkim2_message.h"
#include "dkim2_dnsjson.h"

static double now(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec + ts.tv_nsec / 1e9; }

int main(int argc, char **argv) {
    char err[256];
    if (argc < 4 || dkim2_dns_json_load(argv[2], err, sizeof err) < 0) { fprintf(stderr, "usage/dns: %s\n", err); return 2; }
    int reps = atoi(argv[3]);
    char **paths = NULL; size_t n = 0, cap = 0; char line[4096];
    FILE *l = fopen(argv[1], "r");
    while (fgets(line, sizeof line, l)) {
        line[strcspn(line, "\n")] = 0;
        if (!*line) continue;
        if (n == cap) paths = realloc(paths, (cap = cap ? 2 * cap : 256) * sizeof *paths);
        paths[n++] = strdup(line);
    }
    fclose(l);
    for (int undo = 0; undo <= 1; undo++) {
        dkim2_verify_opts_t o = { .undo_walk = undo, .no_prefetch = 1, .chunk = 0 };
        double best = 1e9; int pass = 0, fail = 0;
        for (int r = 0; r < reps; r++) {
            pass = fail = 0;
            double t = now();
            for (size_t i = 0; i < n; i++) {
                dkim2_verify_result_t res = dkim2_verify_message_opts(paths[i], NULL, NULL, 1, &o);
                if (res.status == DKIM2_OK) pass++; else fail++;
            }
            double d = now() - t; if (d < best) best = d;
        }
        printf("c %s %.3f fail=%d,pass=%d\n", undo ? "undo" : "plan", best, fail, pass);
    }
    return 0;
}
