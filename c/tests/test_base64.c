#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../base64.h"

int main(void) {
    char out[256];
    int n;

    /* Basic encode */
    n = b64_encode((const unsigned char *)"Hello, World!", 13, out, sizeof out);
    assert(n > 0);
    assert(strcmp(out, "SGVsbG8sIFdvcmxkIQ==") == 0);

    /* Decode ignoring FWS per §2.14 */
    unsigned char dec[64];
    int m = b64_decode("SGVs bG8s\r\n IFdv\tcmxkIQ==", dec, sizeof dec);
    assert(m == 13);
    assert(memcmp(dec, "Hello, World!", 13) == 0);

    /* Empty input */
    n = b64_encode((const unsigned char *)"", 0, out, sizeof out);
    assert(n == 0);
    assert(strcmp(out, "") == 0);

    /* Round-trip binary */
    const unsigned char bin[] = {0x00, 0xFF, 0xAB, 0x12};
    char enc[16];
    unsigned char rt[8];
    b64_encode(bin, 4, enc, sizeof enc);
    int rlen = b64_decode(enc, rt, sizeof rt);
    assert(rlen == 4);
    assert(memcmp(rt, bin, 4) == 0);

    /* Padding variants */
    /* 1 byte: 2 base64 chars + == */
    b64_encode((const unsigned char *)"A", 1, out, sizeof out);
    assert(strcmp(out, "QQ==") == 0);
    /* 2 bytes: 3 base64 chars + = */
    b64_encode((const unsigned char *)"AB", 2, out, sizeof out);
    assert(strcmp(out, "QUI=") == 0);

    puts("base64: all tests passed");
    return 0;
}
