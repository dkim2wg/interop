/* draft-ietf-dkim-dkim2-spec-08: the implementation contract's D1-D10
   (docs/superpowers/specs/2026-10-28-dkim2-spec-08-design.md), on
   messages built and signed in memory (spec_harness.h).

   D11 (DSN generation) and D12 (Provisionally Verified) do not apply: the C
   implementation has neither (c/TODO-dsn.md). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <cjson/cJSON.h>
#include "../dkim2_internal.h"
#include "../dkim2_sign.h"
#include "../dkim2_verify.h"
#include "../dkim2_header.h"
#include "../dkim2_dns.h"
#include "../dkim2_crypto.h"
#include "../dkim2_hash.h"
#include "../dkim2_message.h"
#include "../dkim2_recipe.h"
#include "../tagparse.h"
#include "../base64.h"

#define HARNESS_KEY_PATH "/tmp/dkim2_test_spec08.pem"
#include "spec_harness.h"

/* D1: Auto-Submitted and VBR-Info are hashed (-08 §4). */
static void test_hashed_fields(void) {
    CHECK(!dkim2_hdr_ignored("auto-submitted", 14));
    CHECK(!dkim2_hdr_ignored("vbr-info", 8));
    CHECK(dkim2_hdr_ignored("received", 8));
    CHECK(dkim2_hdr_ignored("x-anything", 10));
    static const char *fields[] = { "Auto-Submitted", "VBR-Info" };
    for (int k = 0; k < 2; k++) {
        msg_t m;
        msg_init(&m, "a@example.com", "test", "Hello\r\n");
        msg_add_bottom(&m, fields[k], "auto-generated");
        add_mi(&m, NULL);
        add_sig(&m, 1, 1, "example.com", "<a@example.com>", "<list@lists.example.org>", NULL);
        CHECK_PASS(verify(&m));
        msg_set(&m, fields[k], "no");
        CHECK_MSG(verify(&m), "FAIL: Message-Instance m=1 header hash sha256 mismatch");
        msg_free(&m);
    }
}

int main(void) {
    harness_init();

    test_hashed_fields();

    harness_done();
    if (g_fail) { printf("test_spec08: %d failure(s)\n", g_fail); return 1; }
    printf("test_spec08: all passed\n");
    return 0;
}
