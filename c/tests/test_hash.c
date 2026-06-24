#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../dkim2_hash.h"

int main(void) {
    char out[64];

    /* §5.1 body hash: trailing empty lines stripped, then hash "\r\n" appended */

    /* Empty body → SHA256 of "\r\n" */
    assert(dkim2_body_hash("", 0, out, sizeof out) == 0);
    /* sha256("\r\n") = Yp2GsR6Z02...  verify not empty */
    assert(strlen(out) == 44); /* base64 of 32 bytes = 44 chars with padding */

    /* Body with trailing empty lines treated same as no trailing empty lines */
    const char *body1 = "Hello\r\n\r\n\r\n";
    const char *body2 = "Hello\r\n";
    char h1[64], h2[64];
    assert(dkim2_body_hash(body1, strlen(body1), h1, sizeof h1) == 0);
    assert(dkim2_body_hash(body2, strlen(body2), h2, sizeof h2) == 0);
    assert(strcmp(h1, h2) == 0);

    /* Body with non-empty content after stripped trailing lines */
    const char *body3 = "Line1\r\nLine2\r\n";
    const char *body4 = "Line1\r\nLine2\r\n\r\n";
    char h3[64], h4[64];
    assert(dkim2_body_hash(body3, strlen(body3), h3, sizeof h3) == 0);
    assert(dkim2_body_hash(body4, strlen(body4), h4, sizeof h4) == 0);
    assert(strcmp(h3, h4) == 0);

    /* Different body → different hash */
    char h5[64];
    assert(dkim2_body_hash("Other\r\n", 7, h5, sizeof h5) == 0);
    assert(strcmp(h2, h5) != 0);

    /* §5.2 header hash: ignored headers, lowercased names, sorted */

    /* Ignored headers don't affect hash */
    const char *hdrs_a[] = {
        "From: sender@example.com\r\n",
        "Subject: Test\r\n",
        "Received: from foo\r\n",       /* ignored */
        "X-Custom: stuff\r\n",          /* ignored */
        "DKIM-Signature: v=1;\r\n",     /* ignored */
    };
    const char *hdrs_b[] = {
        "From: sender@example.com\r\n",
        "Subject: Test\r\n",
    };
    char ha[64], hb[64];
    assert(dkim2_header_hash(hdrs_a, 5, ha, sizeof ha) == 0);
    assert(dkim2_header_hash(hdrs_b, 2, hb, sizeof hb) == 0);
    assert(strcmp(ha, hb) == 0);

    /* §4.1 (draft-03): Delivered-To is ignored in the header hash */
    const char *hdrs_dt[] = {
        "From: sender@example.com\r\n",
        "Subject: Test\r\n",
        "Delivered-To: someone@example.com\r\n", /* ignored */
    };
    char hdt[64];
    assert(dkim2_header_hash(hdrs_dt, 3, hdt, sizeof hdt) == 0);
    assert(strcmp(hdt, hb) == 0);

    /* Header name case doesn't matter for hash */
    const char *hdrs_c[] = { "FROM: sender@example.com\r\n" };
    const char *hdrs_d[] = { "from: sender@example.com\r\n" };
    char hc[64], hd[64];
    assert(dkim2_header_hash(hdrs_c, 1, hc, sizeof hc) == 0);
    assert(dkim2_header_hash(hdrs_d, 1, hd, sizeof hd) == 0);
    assert(strcmp(hc, hd) == 0);

    /* Folded header treated same as unfolded */
    const char *hdrs_e[] = { "Subject: foo\r\n bar\r\n" };
    const char *hdrs_f[] = { "Subject: foo bar\r\n" };
    char he[64], hf[64];
    assert(dkim2_header_hash(hdrs_e, 1, he, sizeof he) == 0);
    assert(dkim2_header_hash(hdrs_f, 1, hf, sizeof hf) == 0);
    assert(strcmp(he, hf) == 0);

    puts("hash: all tests passed");
    return 0;
}
