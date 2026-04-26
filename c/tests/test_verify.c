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

static char *g_dns_txt = NULL;

static char *test_dns_override(const char *qname) {
    if (strcmp(qname, "test._domainkey.example.com") == 0 && g_dns_txt)
        return strdup(g_dns_txt);
    return NULL;
}

/* Helper: sign a standard test message. Returns 0 on success. Caller frees *mi_out, *sig_out. */
static int sign_test_message(
    const char *mail_from, char *rcpts[],
    const char *privkey_path, const char *domain, const char *sel,
    const char **raw_hdrs, int n_hdrs,
    const char *body,
    char **mi_out, char **sig_out) {
    dkim2_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.headers = (char **)raw_hdrs;
    ctx.n_headers = n_hdrs;
    dkim2_body_hash_raw(body, strlen(body), ctx.body_digest);
    ctx.mail_from = (char *)mail_from;
    ctx.rcpt_to = rcpts;
    dkim2_sign_config_t cfg = {
        .domain = (char *)domain, .selector = (char *)sel,
        .privkey_path = (char *)privkey_path, .alg = "ed25519-sha256",
    };
    return dkim2_do_sign(&ctx, &cfg, mi_out, sig_out);
}

/* Helper: verify a standard test message. Returns the result status. */
static dkim2_status_t verify_test_message(
    const char *mail_from, char *rcpts[],
    const char **raw_hdrs, int n_raw_hdrs,
    const char *body, const char *mi_val, const char *sig_val) {
    dkim2_ctx_t vctx;
    memset(&vctx, 0, sizeof vctx);

    char mi_hdr[1024], sig_hdr[2048];
    snprintf(mi_hdr, sizeof mi_hdr, "Message-Instance: %s\r\n", mi_val);
    snprintf(sig_hdr, sizeof sig_hdr, "DKIM2-Signature: %s\r\n", sig_val);

    /* Build header array: original headers + MI + Sig */
    char **all_hdrs = malloc((size_t)(n_raw_hdrs + 4) * sizeof(char *));
    for (int i = 0; i < n_raw_hdrs; i++) all_hdrs[i] = (char *)raw_hdrs[i];
    all_hdrs[n_raw_hdrs]     = mi_hdr;
    all_hdrs[n_raw_hdrs + 1] = sig_hdr;

    vctx.headers = all_hdrs;
    vctx.n_headers = n_raw_hdrs + 2;
    dkim2_body_hash_raw(body, strlen(body), vctx.body_digest);
    vctx.mail_from = (char *)mail_from;
    vctx.rcpt_to = rcpts;
    vctx.mi_list = dkim2_mi_parse(mi_val);
    vctx.sig_list = dkim2_sig_parse(sig_val);

    dkim2_verify_result_t res;
    dkim2_do_verify(&vctx, &res);

    dkim2_status_t st = res.status;
    dkim2_mi_free(vctx.mi_list);
    dkim2_sig_free(vctx.sig_list);
    free(all_hdrs);
    return st;
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

    FILE *f = fopen("/tmp/dkim2_test_sign.pem", "w");
    assert(f != NULL);
    PEM_write_PrivateKey(f, privkey, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    size_t publen = 32;
    unsigned char pubbuf[32];
    EVP_PKEY_get_raw_public_key(privkey, pubbuf, &publen);
    EVP_PKEY_free(privkey);

    char pub_b64[64];
    b64_encode(pubbuf, publen, pub_b64, sizeof pub_b64);

    char dns_txt[256];
    snprintf(dns_txt, sizeof dns_txt, "v=DKIM1; k=ed25519; p=%s", pub_b64);
    g_dns_txt = dns_txt;
    dkim2_dns_override = test_dns_override;

    const char *raw_headers[] = {
        "From: sender@example.com\r\n",
        "To: recipient@example.org\r\n",
        "Subject: Test DKIM2 message\r\n",
    };
    const char *body = "Hello, world!\r\n";
    char *rcpts[] = { "<recipient@example.org>", NULL };
    const char *mail_from = "<sender@example.com>";

    /* --- Happy path --- */
    char *mi_val = NULL, *sig_val = NULL;
    int r = sign_test_message(mail_from, rcpts,
        "/tmp/dkim2_test_sign.pem", "example.com", "test",
        raw_headers, 3, body, &mi_val, &sig_val);
    assert(r == 0 && mi_val != NULL && sig_val != NULL);

    dkim2_status_t st = verify_test_message(
        mail_from, rcpts, raw_headers, 3, body, mi_val, sig_val);
    assert(st == DKIM2_OK);

    /* --- Error: tampered body → hash mismatch → FAIL --- */
    st = verify_test_message(mail_from, rcpts, raw_headers, 3,
        "TAMPERED body!\r\n", mi_val, sig_val);
    assert(st == DKIM2_FAIL);

    /* --- Error: wrong MAIL FROM → PERMERROR --- */
    st = verify_test_message("<wrong@example.com>", rcpts,
        raw_headers, 3, body, mi_val, sig_val);
    assert(st == DKIM2_PERMERROR);

    /* --- Error: wrong RCPT TO → PERMERROR --- */
    char *wrong_rcpts[] = { "<wrong@example.org>", NULL };
    st = verify_test_message(mail_from, wrong_rcpts,
        raw_headers, 3, body, mi_val, sig_val);
    assert(st == DKIM2_PERMERROR);

    /* --- Error: tampered sig → FAIL --- */
    char tampered_sig[strlen(sig_val) + 1];
    strcpy(tampered_sig, sig_val);
    /* Flip a char in the base64 signature */
    char *sval = strstr(tampered_sig, "ed25519-sha256:");
    assert(sval != NULL);
    sval += strlen("ed25519-sha256:");
    sval[0] = (sval[0] == 'A') ? 'B' : 'A';
    st = verify_test_message(mail_from, rcpts,
        raw_headers, 3, body, mi_val, tampered_sig);
    assert(st == DKIM2_FAIL);

    /* --- Error: DNS lookup fails (unknown selector) → FAIL (no passing ssets) --- */
    char *orig_dns = g_dns_txt;
    g_dns_txt = NULL; /* DNS override returns NULL → live DNS would fail */
    /* Replace selector with one that won't match the override */
    /* Build a sig with a different selector */
    char *mi2 = NULL, *sig2 = NULL;
    /* Use a different selector (won't be in DNS override) */
    dkim2_sign_config_t cfg2 = {
        .domain="example.com", .selector="badsel",
        .privkey_path="/tmp/dkim2_test_sign.pem", .alg="ed25519-sha256"
    };
    dkim2_ctx_t ctx2;
    memset(&ctx2, 0, sizeof ctx2);
    ctx2.headers = (char **)raw_headers; ctx2.n_headers = 3;
    dkim2_body_hash_raw(body, strlen(body), ctx2.body_digest);
    ctx2.mail_from = (char *)mail_from; ctx2.rcpt_to = rcpts;
    dkim2_do_sign(&ctx2, &cfg2, &mi2, &sig2);
    g_dns_txt = orig_dns;
    /* DNS for "badsel" selector not in override → fail */
    if (mi2 && sig2) {
        /* Temporarily null the override to force DNS miss */
        char *saved_txt = g_dns_txt;
        g_dns_txt = NULL;
        st = verify_test_message(mail_from, rcpts, raw_headers, 3, body, mi2, sig2);
        g_dns_txt = saved_txt;
        assert(st == DKIM2_FAIL); /* no passing ssets */
        free(mi2); free(sig2);
    }

    /* --- Error: no DKIM2-Signature → PERMERROR --- */
    {
        dkim2_ctx_t vctx;
        memset(&vctx, 0, sizeof vctx);
        vctx.headers = (char **)raw_headers; vctx.n_headers = 3;
        vctx.body_buf = (unsigned char *)body; vctx.body_len = strlen(body);
        vctx.mail_from = (char *)mail_from; vctx.rcpt_to = rcpts;
        vctx.mi_list = NULL; vctx.sig_list = NULL;
        dkim2_verify_result_t res;
        dkim2_do_verify(&vctx, &res);
        assert(res.status == DKIM2_PERMERROR);
    }

    /* --- Error: MI missing for signature's m= → PERMERROR --- */
    {
        dkim2_ctx_t vctx;
        memset(&vctx, 0, sizeof vctx);
        vctx.headers = (char **)raw_headers; vctx.n_headers = 3;
        vctx.body_buf = (unsigned char *)body; vctx.body_len = strlen(body);
        vctx.mail_from = (char *)mail_from; vctx.rcpt_to = rcpts;
        vctx.mi_list = NULL; /* no MI */
        vctx.sig_list = dkim2_sig_parse(sig_val);
        dkim2_verify_result_t res;
        dkim2_do_verify(&vctx, &res);
        assert(res.status == DKIM2_PERMERROR);
        dkim2_sig_free(vctx.sig_list);
    }

    free(mi_val);
    free(sig_val);
    puts("sign+verify: all tests passed");
    return 0;
}
