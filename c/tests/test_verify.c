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
        dkim2_body_hash_raw(body, strlen(body), vctx.body_digest);
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
        dkim2_body_hash_raw(body, strlen(body), vctx.body_digest);
        vctx.mail_from = (char *)mail_from; vctx.rcpt_to = rcpts;
        vctx.mi_list = NULL; /* no MI */
        vctx.sig_list = dkim2_sig_parse(sig_val);
        dkim2_verify_result_t res;
        dkim2_do_verify(&vctx, &res);
        assert(res.status == DKIM2_PERMERROR);
        dkim2_sig_free(vctx.sig_list);
    }

    /* --- Error: mf= present but not bracketed (spec 7.5) → PERMERROR --- */
    {
        /* Locate "mf=<b64>;" in sig_val, decode it, strip the brackets
           (RFC5321 path -> bare address), and re-encode as bare base64. */
        char *mf_tag = strstr(sig_val, "mf=");
        assert(mf_tag != NULL);
        char *mf_b64_start = mf_tag + 3;
        char *mf_b64_end = strchr(mf_b64_start, ';');
        assert(mf_b64_end != NULL);
        size_t mf_b64_len = (size_t)(mf_b64_end - mf_b64_start);

        char mf_b64[256];
        assert(mf_b64_len < sizeof mf_b64);
        memcpy(mf_b64, mf_b64_start, mf_b64_len);
        mf_b64[mf_b64_len] = '\0';

        unsigned char decoded[256];
        int declen = b64_decode(mf_b64, decoded, sizeof decoded);
        assert(declen > 0);
        decoded[declen] = '\0';
        assert(decoded[0] == '<' && decoded[declen - 1] == '>');

        /* Strip the brackets to produce the bare (non-conformant) address */
        char bare[256];
        memcpy(bare, decoded + 1, (size_t)(declen - 2));
        bare[declen - 2] = '\0';

        char bare_b64[256];
        b64_encode((const unsigned char *)bare, strlen(bare), bare_b64, sizeof bare_b64);

        /* Rebuild sig_val with the bare-form mf= base64 spliced in */
        char tampered_mf_sig[4096];
        size_t prefix_len = (size_t)(mf_b64_start - sig_val);
        snprintf(tampered_mf_sig, sizeof tampered_mf_sig, "%.*s%s%s",
            (int)prefix_len, sig_val, bare_b64, mf_b64_end);

        dkim2_status_t bad_mf_st = verify_test_message(
            mail_from, rcpts, raw_headers, 3, body, mi_val, tampered_mf_sig);
        assert(bad_mf_st == DKIM2_PERMERROR);

        /* Confirm the failure message cites 7.5 */
        dkim2_ctx_t vctx;
        memset(&vctx, 0, sizeof vctx);
        char mi_hdr[1024], sig_hdr[2048];
        snprintf(mi_hdr, sizeof mi_hdr, "Message-Instance: %s\r\n", mi_val);
        snprintf(sig_hdr, sizeof sig_hdr, "DKIM2-Signature: %s\r\n", tampered_mf_sig);
        char *all_hdrs[5];
        for (int i = 0; i < 3; i++) all_hdrs[i] = (char *)raw_headers[i];
        all_hdrs[3] = mi_hdr;
        all_hdrs[4] = sig_hdr;
        vctx.headers = all_hdrs;
        vctx.n_headers = 5;
        dkim2_body_hash_raw(body, strlen(body), vctx.body_digest);
        vctx.mail_from = (char *)mail_from;
        vctx.rcpt_to = rcpts;
        vctx.mi_list = dkim2_mi_parse(mi_val);
        vctx.sig_list = dkim2_sig_parse(tampered_mf_sig);
        dkim2_verify_result_t res;
        dkim2_do_verify(&vctx, &res);
        assert(res.status == DKIM2_PERMERROR);
        assert(strstr(res.message, "7.5") != NULL);
        dkim2_mi_free(vctx.mi_list);
        dkim2_sig_free(vctx.sig_list);
    }

    /* --- Error: top-level nd= (spec-04 local policy) → PERMERROR ---
       The only legitimate nd= producer emits an nd= hop together with a
       matching higher-i= signature, so nd= must never appear on the
       topmost (highest i=) DKIM2-Signature. */
    {
        dkim2_sig_t *s1 = dkim2_sig_parse(
            "i=1; m=1; t=1; d=fwd.example.com; mf=PA==; rt=PA==; "
            "s=test:ed25519-sha256:AAAA");
        dkim2_sig_t *s2 = dkim2_sig_parse(
            "i=2; m=2; t=1; d=fwd.example.com; nd=next.example.com; "
            "s=test:ed25519-sha256:AAAA");
        assert(s1 != NULL && s2 != NULL);
        s1->next = s2;

        dkim2_ctx_t vctx;
        memset(&vctx, 0, sizeof vctx);
        vctx.sig_list = s1;

        dkim2_verify_result_t res;
        dkim2_do_verify(&vctx, &res);
        assert(res.status == DKIM2_PERMERROR);
        assert(strstr(res.message, "unexpected nd= tag") != NULL);

        dkim2_sig_free(vctx.sig_list);
    }

    /* --- Regression: non-top nd= (legitimate hand-off hop) must NOT be
       rejected by the new top-nd= check. The existing adjacency match
       (prev->nd must equal cur->d, §11.4) still governs it, and the sig
       chain proceeds to later checks instead of being killed here. --- */
    {
        dkim2_sig_t *s1 = dkim2_sig_parse(
            "i=1; m=1; t=1; d=fwd.example.com; nd=next.example.com; "
            "s=test:ed25519-sha256:AAAA");
        dkim2_sig_t *s2 = dkim2_sig_parse(
            "i=2; m=2; t=1; d=next.example.com; mf=PA==; rt=PA==; "
            "s=test:ed25519-sha256:AAAA");
        assert(s1 != NULL && s2 != NULL);
        s1->next = s2;

        dkim2_ctx_t vctx;
        memset(&vctx, 0, sizeof vctx);
        vctx.sig_list = s1;

        dkim2_verify_result_t res;
        dkim2_do_verify(&vctx, &res);
        /* Top sig (i=2) carries no nd=, so it must never be rejected with
           our new local-policy message — it fails later for unrelated
           reasons (no Message-Instance / DNS / crypto). */
        assert(strstr(res.message, "unexpected nd= tag") == NULL);

        dkim2_sig_free(vctx.sig_list);
    }

    free(mi_val);
    free(sig_val);
    puts("sign+verify: all tests passed");
    return 0;
}
