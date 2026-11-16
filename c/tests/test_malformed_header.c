/* CVE-2026-129847: a line in the header section that is not a header
   field -- no colon, white space in or nothing before the name, or a first
   line that starts with white space (a continuation of nothing) -- is in no
   Message-Instance header hash, so it could be added to a signed message
   unseen while other parsers read it. Such a header section is malformed:
   the verifier says "PERMERROR: malformed header field" before any other
   check (when the message has a DKIM2 field at all), and the signer
   refuses. Checked here on the field predicate, on the file parser (the
   line is kept, not dropped), in memory (spec_harness.h) and through the
   file entry points the CLIs use. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "../dkim2_internal.h"
#include "../dkim2_sign.h"
#include "../dkim2_verify.h"
#include "../dkim2_header.h"
#include "../dkim2_dns.h"
#include "../dkim2_crypto.h"
#include "../dkim2_hash.h"
#include "../dkim2_message.h"
#include "../eml_parse.h"
#include "../base64.h"

#define HARNESS_KEY_PATH "/tmp/dkim2_test_malformed_header.pem"
#include "spec_harness.h"

static const char *MALFORMED = "PERMERROR: malformed header field";

/* The bad lines of the report, as the file parser hands them over (one
   logical field, CRLF-terminated). */
static const char *BAD[] = {
    "NoColonHere\r\n",
    "Sub ject: x\r\n",
    ":Empty: x\r\n",
    "\tSub\r\n",
    "NoColon\r\n continued\r\n",
};
#define N_BAD (int)(sizeof BAD / sizeof BAD[0])

static void test_predicate(void) {
    for (int k = 0; k < N_BAD; k++)
        CHECK(dkim2_header_field_malformed(BAD[k]));
    CHECK(dkim2_header_field_malformed(" Subject: evil\r\n"));
    CHECK(dkim2_header_field_malformed("\r\n"));
    CHECK(dkim2_header_field_malformed(""));
    CHECK(dkim2_header_field_malformed("x"));
    /* Fields: the RFC 5322 obsolete syntax allows WSP before the colon.
       A fold there is not WSP: RFC 5322 allows none, and every
       implementation here calls it malformed. */
    CHECK(!dkim2_header_field_malformed("Subject: x\r\n"));
    CHECK(!dkim2_header_field_malformed("Subject:x"));
    CHECK(!dkim2_header_field_malformed("Subject : x\r\n"));
    CHECK(!dkim2_header_field_malformed("Subject\t: x\r\n"));
    CHECK(dkim2_header_field_malformed("Subject\r\n : x\r\n"));
    CHECK(!dkim2_header_field_malformed("X-Long: a\r\n b\r\n"));
    CHECK(dkim2_headers_malformed(NULL, 0) == 0);
}

static char g_tmp[256];

static void write_file(const char *path, const char *s) {
    FILE *f = fopen(path, "wb");
    fwrite(s, 1, strlen(s), f);
    fclose(f);
}

/* The file parser keeps every line of the header section: a line that is
   not a field becomes an entry of its own (and is then malformed), it is
   not dropped. */
static void test_parser_keeps_lines(void) {
    struct { const char *in; int n; int bad_at; const char *bad; } cases[] = {
        { "From: a@example.com\r\nNoColonHere\r\nSubject: x\r\n\r\nbody\r\n", 3, 1, "NoColonHere\r\n" },
        { " Subject: evil\r\nFrom: a@example.com\r\n\r\nbody\r\n", 2, 0, " Subject: evil\r\n" },
        { "From: a@example.com\nx", 2, 1, "x" },          /* header only, short last line */
        { "\r\nFrom: a@example.com\r\n\r\nbody\r\n", 2, 0, "\r\n" },  /* an empty first line */
    };
    for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        write_file(g_tmp, cases[c].in);
        char **h = NULL;
        int nh = 0;
        CHECK(eml_parse(g_tmp, &h, &nh, NULL) == 0);
        CHECK(nh == cases[c].n);
        if (nh == cases[c].n) {
            CHECK(strcmp(h[cases[c].bad_at], cases[c].bad) == 0);
            CHECK(dkim2_headers_malformed((const char **)h, nh));
        }
        eml_free(h, nh);
    }
}

/* Insert line at position at (0: the very top). */
static void msg_insert(msg_t *m, int at, const char *line) {
    memmove(m->h + at + 1, m->h + at, (size_t)(m->n - at) * sizeof m->h[0]);
    m->h[at] = strdup(line);
    m->n++;
}

static void test_verify_in_memory(void) {
    /* A signed message passes, then fails with the line added anywhere. */
    msg_t m;
    base_signed(&m, "a@example.com");
    CHECK_PASS(verify(&m));
    for (int k = 0; k < N_BAD; k++)
        for (int at = 1; at <= m.n; at += m.n - 1) {
            msg_t c;
            msg_copy(&c, &m);
            msg_insert(&c, at, BAD[k]);
            dkim2_verify_result_t r = verify(&c);
            CHECK(r.status == DKIM2_PERMERROR);
            CHECK_MSG(r, MALFORMED);
            r = verify_mode(&c, 1);
            CHECK_MSG(r, MALFORMED);
            msg_free(&c);
        }
    {   /* A first line that starts with WSP. */
        msg_t c;
        msg_copy(&c, &m);
        msg_insert(&c, 0, " Subject: evil\r\n");
        CHECK_MSG(verify(&c), MALFORMED);
        msg_free(&c);
    }
    {   /* Before every other check: with an instance gap too (C9 step d)... */
        msg_t c;
        msg_copy(&c, &m);
        msg_add_top(&c, "Message-Instance", "m=3; h=sha256:AAAA:AAAA;");
        msg_insert(&c, 2, "NoColonHere\r\n");
        CHECK_MSG(verify(&c), MALFORMED);
        msg_free(&c);
    }
    {   /* ...and before the chain-length check (C9 step a). */
        msg_t c;
        msg_copy(&c, &m);
        for (int k = 0; k < 33; k++)
            msg_add_top(&c, "Message-Instance", "m=1; h=sha256:AAAA:AAAA;");
        msg_insert(&c, c.n, "NoColonHere\r\n");
        CHECK_MSG(verify(&c), MALFORMED);
        msg_free(&c);
    }
    {   /* A field that does not parse is a DKIM2 field all the same. */
        msg_t c;
        msg_init(&c, "a@example.com", "test", "Hello\r\n");
        msg_add_top(&c, "DKIM2-Signature", "junk");
        msg_insert(&c, 1, "NoColonHere\r\n");
        CHECK_MSG(verify(&c), MALFORMED);
        msg_free(&c);
    }
    {   /* No DKIM2 field: still none, there is no DKIM2 result to give. */
        msg_t c;
        msg_init(&c, "a@example.com", "test", "Hello\r\n");
        msg_insert(&c, 1, "NoColonHere\r\n");
        dkim2_verify_result_t r = verify(&c);
        CHECK(r.status == DKIM2_NONE);
        msg_free(&c);
    }
    {   /* WSP before the colon is a field (obsolete syntax): signed over, it
           verifies. */
        msg_t c;
        msg_init(&c, "a@example.com", "test", "Hello\r\n");
        msg_insert(&c, 1, "X-Obs : y\r\n");
        add_mi(&c, NULL);
        add_sig(&c, 1, 1, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
        CHECK_PASS(verify(&c));
        msg_free(&c);
    }
    msg_free(&m);
}

/* The same class of fault by another route: "DKIM2-Signature : x" (WSP
   before the colon, RFC 5322 obsolete syntax) is a DKIM2 field, so no
   header hash covers it, and it must be read as one -- not ignored as if
   its name were something else. */
static void test_obs_dkim2_field_names(void) {
    msg_t m;
    base_signed(&m, "a@example.com");
    const char *junk[] = { "DKIM2-Signature : junk\r\n", "Message-Instance\t: junk\r\n" };
    for (int k = 0; k < 2; k++) {
        msg_t c;
        msg_copy(&c, &m);
        msg_insert(&c, 2, junk[k]);
        dkim2_verify_result_t r = verify(&c);
        if (r.status == DKIM2_OK)
            printf("FAIL %s:%d: \"%.*s\" ignored: %s\n", __FILE__, __LINE__,
                   (int)strcspn(junk[k], "\r"), junk[k], r.message), g_fail++;
        msg_free(&c);
    }
    {   /* A whole valid chain written that way still verifies. */
        msg_t c;
        msg_copy(&c, &m);
        for (int i = 0; i < c.n; i++) {
            char *colon = strchr(c.h[i], ':');
            if (strncmp(c.h[i], "DKIM2-Signature:", 16) && strncmp(c.h[i], "Message-Instance:", 17))
                continue;
            char *t = malloc(strlen(c.h[i]) + 2);
            sprintf(t, "%.*s :%s", (int)(colon - c.h[i]), c.h[i], colon + 1);
            free(c.h[i]);
            c.h[i] = t;
        }
        CHECK_PASS(verify(&c));
        msg_free(&c);
    }
    msg_free(&m);
}

static void test_sign_in_memory(void) {
    char *rcpts[] = { "<list@lists.example.org>", NULL };
    char err[512];
    /* Refused with no chain yet, and over an existing one. */
    for (int chained = 0; chained < 2; chained++)
        for (int k = 0; k < N_BAD; k++) {
            msg_t c;
            if (chained) base_signed(&c, "a@example.com");
            else msg_init(&c, "a@example.com", "test", "Hello\r\n");
            msg_insert(&c, 1, BAD[k]);
            CHECK(lib_sign(&c, "example.com", "<a@example.com>", rcpts, 0,
                           err, sizeof err, NULL, 0) < 0);
            CHECK(strstr(err, "malformed header field") != NULL);
            msg_free(&c);
        }
    {   /* The obsolete syntax signs. */
        msg_t c;
        msg_init(&c, "a@example.com", "test", "Hello\r\n");
        msg_insert(&c, 1, "X-Obs : y\r\n");
        CHECK(lib_sign(&c, "example.com", "<a@example.com>", rcpts, 0,
                       err, sizeof err, NULL, 0) == 0);
        msg_free(&c);
    }
}

/* Through the file entry points the dkim2sign and dkim2verify CLIs use. */
static void test_files(void) {
    char *rcpts[] = { "<list@lists.example.org>", NULL };
    dkim2_sign_config_t cfg = {
        .domain = "example.com", .selector = "sel", .privkey_path = (char *)KEY_PATH,
        .alg = "ed25519-sha256",
    };
    char err[512] = "";
    char signed_path[300];
    snprintf(signed_path, sizeof signed_path, "%s.signed", g_tmp);

    write_file(g_tmp, "From: a@example.com\r\nTo: list@lists.example.org\r\n"
                      "Subject: x\r\n\r\nHello\r\n");
    FILE *out = fopen(signed_path, "wb");
    CHECK(dkim2_sign_message(g_tmp, out, &cfg, "<a@example.com>", rcpts, err, sizeof err) == 0);
    fclose(out);
    dkim2_verify_result_t r = dkim2_verify_message(signed_path, NULL, NULL, 0);
    CHECK_PASS(r);

    /* The signed file with a line added after its first field, and with
       one in front of everything. */
    FILE *f = fopen(signed_path, "rb");
    char buf[16384];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = '\0';
    char *eol = strstr(buf, "\r\n") + 2;
    for (int k = 0; k <= N_BAD; k++) {
        const char *line = k < N_BAD ? BAD[k] : " Subject: evil\r\n";
        /* In a file, a line starting with WSP after a field continues it:
           only the very first line is a continuation of nothing. */
        if (k < N_BAD && (line[0] == ' ' || line[0] == '\t')) continue;
        char *t = malloc(n + 64);
        if (k < N_BAD)
            snprintf(t, n + 64, "%.*s%s%s", (int)(eol - buf), buf, line, eol);
        else
            snprintf(t, n + 64, "%s%s", line, buf);
        write_file(g_tmp, t);
        free(t);
        r = dkim2_verify_message(g_tmp, NULL, NULL, 0);
        CHECK(r.status == DKIM2_PERMERROR);
        CHECK_MSG(r, MALFORMED);
    }

    /* The signer refuses a file with such a line. */
    write_file(g_tmp, "From: a@example.com\r\nNoColonHere\r\nSubject: x\r\n\r\nHello\r\n");
    out = fopen(signed_path, "wb");
    CHECK(dkim2_sign_message(g_tmp, out, &cfg, "<a@example.com>", rcpts, err, sizeof err) < 0);
    fclose(out);
    CHECK(strcmp(err, "not signing: malformed header field") == 0);
    remove(signed_path);
}

int main(void) {
    snprintf(g_tmp, sizeof g_tmp, "/tmp/dkim2_test_malformed_header.%d.eml", (int)getpid());
    harness_init();
    test_predicate();
    test_parser_keeps_lines();
    test_verify_in_memory();
    test_obs_dkim2_field_names();
    test_sign_in_memory();
    test_files();
    remove(g_tmp);
    harness_done();
    if (g_fail) { printf("test_malformed_header: %d failure(s)\n", g_fail); return 1; }
    printf("test_malformed_header: all passed\n");
    return 0;
}
