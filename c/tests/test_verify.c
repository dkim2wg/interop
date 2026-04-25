#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "../dkim2_internal.h"
#include "../dkim2_sign.h"
#include "../dkim2_verify.h"
#include "../dkim2_header.h"
#include "../dkim2_dns.h"
#include "../base64.h"

/* DNS override: returns the key record for test._domainkey.example.com */
static char *g_dns_txt = NULL;

static char *test_dns_override(const char *qname) {
    if (strcmp(qname, "test._domainkey.example.com") == 0 && g_dns_txt)
        return strdup(g_dns_txt);
    return NULL;
}

int main(void) {
    /* Generate Ed25519 key pair */
    EVP_PKEY *privkey = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    assert(kctx != NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_keygen(kctx, &privkey);
    EVP_PKEY_CTX_free(kctx);
    assert(privkey != NULL);

    /* Write private key to temp file */
    FILE *f = fopen("/tmp/dkim2_test_sign.pem", "w");
    assert(f != NULL);
    PEM_write_PrivateKey(f, privkey, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    /* Get raw public key bytes and base64-encode for DNS record */
    size_t publen = 32;
    unsigned char pubbuf[32];
    EVP_PKEY_get_raw_public_key(privkey, pubbuf, &publen);
    EVP_PKEY_free(privkey);

    char pub_b64[64];
    extern int b64_encode(const unsigned char *, size_t, char *, size_t);
    b64_encode(pubbuf, publen, pub_b64, sizeof pub_b64);

    /* Build DNS TXT record value */
    char dns_txt[256];
    snprintf(dns_txt, sizeof dns_txt, "v=DKIM1; k=ed25519; p=%s", pub_b64);
    g_dns_txt = dns_txt;
    dkim2_dns_override = test_dns_override;

    /* Build a test message context */
    dkim2_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);

    const char *raw_headers[] = {
        "From: sender@example.com\r\n",
        "To: recipient@example.org\r\n",
        "Subject: Test DKIM2 message\r\n",
    };
    ctx.headers = (char **)raw_headers;
    ctx.n_headers = 3;

    const char *body_text = "Hello, world!\r\n";
    ctx.body_buf = (unsigned char *)body_text;
    ctx.body_len = strlen(body_text);
    ctx.mail_from = "<sender@example.com>";

    char *rcpts[] = { "<recipient@example.org>", NULL };
    ctx.rcpt_to = rcpts;
    ctx.n_rcpt = 1;

    /* Sign the message */
    dkim2_sign_config_t cfg = {
        .domain      = "example.com",
        .selector    = "test",
        .privkey_path = "/tmp/dkim2_test_sign.pem",
        .alg         = "ed25519-sha256",
    };

    char *mi_val = NULL, *sig_val = NULL;
    int r = dkim2_do_sign(&ctx, &cfg, &mi_val, &sig_val);
    assert(r == 0);
    assert(mi_val != NULL);
    assert(sig_val != NULL);

    printf("MI:  %s\n", mi_val);
    printf("Sig: %s\n", sig_val);

    /* Now verify: parse the produced headers and add them to a new ctx */
    dkim2_ctx_t vctx;
    memset(&vctx, 0, sizeof vctx);

    /* Add original headers + new MI + new Sig headers */
    char mi_hdr[1024], sig_hdr[2048];
    snprintf(mi_hdr, sizeof mi_hdr, "Message-Instance: %s\r\n", mi_val);
    snprintf(sig_hdr, sizeof sig_hdr, "DKIM2-Signature: %s\r\n", sig_val);

    char *all_headers[16];
    int nh = 0;
    all_headers[nh++] = (char *)raw_headers[0];
    all_headers[nh++] = (char *)raw_headers[1];
    all_headers[nh++] = (char *)raw_headers[2];
    all_headers[nh++] = mi_hdr;
    all_headers[nh++] = sig_hdr;

    vctx.headers = all_headers;
    vctx.n_headers = nh;
    vctx.body_buf = (unsigned char *)body_text;
    vctx.body_len = strlen(body_text);
    vctx.mail_from = "<sender@example.com>";
    vctx.rcpt_to = rcpts;
    vctx.n_rcpt = 1;

    /* Parse MI and Sig headers */
    vctx.mi_list = dkim2_mi_parse(mi_val);
    assert(vctx.mi_list != NULL);
    vctx.sig_list = dkim2_sig_parse(sig_val);
    assert(vctx.sig_list != NULL);

    dkim2_verify_result_t vresult;
    dkim2_do_verify(&vctx, &vresult);

    printf("Verify result: %s\n", vresult.message);
    assert(vresult.status == DKIM2_OK);

    dkim2_mi_free(vctx.mi_list);
    dkim2_sig_free(vctx.sig_list);
    free(mi_val);
    free(sig_val);

    puts("sign+verify: all tests passed");
    return 0;
}
