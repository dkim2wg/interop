/* dkim2_domain.c: domain_of, A-labels (RFC 3492), the relaxed domain match
   (-07 §7.2) and the From mailbox parser used for From Authentic (§11). */
#include <stdio.h>
#include <string.h>
#include "../dkim2_domain.h"

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

static int dom_is(const char *addr, const char *want, int want_lit) {
    char out[256];
    int lit = -1;
    if (dkim2_domain_of(addr, out, sizeof out, &lit) != 0) return 0;
    return strcmp(out, want) == 0 && lit == want_lit;
}

static int alabel_is(const char *in, const char *want) {
    char out[256];
    return dkim2_to_alabel(in, out, sizeof out) == 0 && strcmp(out, want) == 0;
}

static int from_is(const char *value, const char *want) {
    char out[256];
    return dkim2_from_domain(value, out, sizeof out) == 0 && strcmp(out, want) == 0;
}

static int from_fails(const char *value) {
    char out[256];
    return dkim2_from_domain(value, out, sizeof out) != 0;
}

int main(void) {
    /* domain_of: last '@' to '>', lowercased, one trailing dot dropped */
    CHECK(dom_is("<a@example.com>", "example.com", 0));
    CHECK(dom_is("<A@Example.COM.>", "example.com", 0));
    CHECK(dom_is("a@b.example", "b.example", 0));
    CHECK(dom_is("<\"x@y\"@mail.example.org>", "mail.example.org", 0));
    CHECK(dom_is("<x@[192.0.2.1]>", "[192.0.2.1]", 1));
    {
        char out[64];
        int lit;
        CHECK(dkim2_domain_of("<>", out, sizeof out, &lit) != 0);
        CHECK(dkim2_domain_of("<a@>", out, sizeof out, &lit) != 0);
        CHECK(dkim2_domain_of("nobody", out, sizeof out, &lit) != 0);
        CHECK(dkim2_domain_of("<a@example.com>", out, 4, &lit) != 0);
    }

    /* A-labels: RFC 3492 encode of each non-ASCII label */
    CHECK(alabel_is("example.com", "example.com"));
    CHECK(alabel_is("Example.COM", "example.com"));
    CHECK(alabel_is("b\xc3\xbc" "cher.example", "xn--bcher-kva.example"));
    CHECK(alabel_is("B\xc3\x9c" "CHER.example", "xn--bcher-kva.example"));   /* Ü lowercased */
    /* RFC 3492 §7.1 (L) Chinese (simplified) */
    CHECK(alabel_is("\xe4\xbb\x96\xe4\xbb\xac\xe4\xb8\xba\xe4\xbb\x80\xe4\xb9\x88"
                    "\xe4\xb8\x8d\xe8\xaf\xb4\xe4\xb8\xad\xe6\x96\x87",
                    "xn--ihqwcrb4cv8a8dqg056pqjye"));
    /* Japanese "konnichiwa" */
    CHECK(alabel_is("\xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1\xe3\x81\xaf",
                    "xn--28j2a3ar1p"));
    {
        char out[64];
        CHECK(dkim2_to_alabel("caf\xe9.example", out, sizeof out) != 0);       /* not UTF-8 */
        CHECK(dkim2_to_alabel("\xed\xa0\x80.example", out, sizeof out) != 0);  /* surrogate */
        CHECK(dkim2_to_alabel("\xc0\xaf.example", out, sizeof out) != 0);      /* overlong */
    }
    {
        char out[256];
        int lit = 0;
        CHECK(dkim2_addr_alabel("<u@B\xc3\xbc" "cher.Example.>", out, sizeof out, &lit) == 0 &&
              strcmp(out, "xn--bcher-kva.example") == 0 && lit == 0);
        CHECK(dkim2_addr_alabel("<u@[192.0.2.1]>", out, sizeof out, &lit) != 0 && lit == 1);
    }

    /* relaxed match: only Parameter1 is shortened */
    CHECK(dkim2_relaxed_match("example.com", "example.com"));
    CHECK(dkim2_relaxed_match("mail.example.com", "example.com"));
    CHECK(dkim2_relaxed_match("a.b.example.com", "EXAMPLE.com"));
    CHECK(!dkim2_relaxed_match("example.com", "mail.example.com"));
    CHECK(!dkim2_relaxed_match("badexample.com", "example.com"));
    CHECK(!dkim2_relaxed_match("com", "example.com"));
    CHECK(!dkim2_relaxed_match("[192.0.2.1]", "[192.0.2.1]"));
    CHECK(!dkim2_relaxed_match("example.com", "[192.0.2.1]"));

    /* From: exactly one mailbox, never a literal */
    CHECK(from_is("a@example.com", "example.com"));
    CHECK(from_is("A <a@example.com>", "example.com"));
    CHECK(from_is(" \"Doe, John\" <john@Example.COM>", "example.com"));
    CHECK(from_is("a@sub.example.com (comment, with comma)", "sub.example.com"));
    CHECK(from_is("=?utf-8?q?Caf=C3=A9?=\r\n <a@example.com>", "example.com"));
    CHECK(from_is("\"a<b>@c\" <x@example.org>", "example.org"));
    CHECK(from_is("u@b\xc3\xbc" "cher.example", "xn--bcher-kva.example"));
    CHECK(from_fails("a@example.com, b@example.com"));
    CHECK(from_fails("A <a@example.com>, B <b@example.com>"));
    CHECK(from_fails("a@[192.0.2.1]"));
    CHECK(from_fails("Group: a@example.com;"));
    CHECK(from_fails("undisclosed-recipients:;"));
    CHECK(from_fails(""));
    CHECK(from_fails("nobody"));
    CHECK(from_fails("<>"));
    CHECK(from_fails("A <a@example.com> <b@example.com>"));

    if (g_fail) { printf("test_domain: %d failure(s)\n", g_fail); return 1; }
    printf("test_domain: all passed\n");
    return 0;
}
