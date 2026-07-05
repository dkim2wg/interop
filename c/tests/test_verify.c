#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "../dkim2_internal.h"
#include "../dkim2_sign.h"
#include "../dkim2_verify.h"
#include "../dkim2_header.h"
#include "../dkim2_dns.h"
#include "../dkim2_crypto.h"
#include "../base64.h"

/* Mirror of the production §8.5 canonicalization used by both the signer
   (dkim2_sign.c: canon_for_sig) and the verifier (dkim2_verify.c:
   canon_for_sig / append_canon): lowercase header name, strip all
   whitespace from the value, terminate with CRLF. Used here only to
   hand-build a valid signing input for a synthetic nd= hop, since the
   C signer itself has no way to emit nd= (see test below). */
static void test_canon_append(char *buf, size_t *pos,
                              const char *hdr_name, const char *value) {
    for (const char *h = hdr_name; *h; h++)
        buf[(*pos)++] = (char)tolower((unsigned char)*h);
    buf[(*pos)++] = ':';
    for (const char *h = value; *h; h++) {
        if (*h == ' ' || *h == '\t' || *h == '\r' || *h == '\n') continue;
        buf[(*pos)++] = *h;
    }
    buf[(*pos)++] = '\r';
    buf[(*pos)++] = '\n';
}

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

/* Helper: verify a standard test message. Fills *res_out with the full
   result (status + message), so callers can assert on the canonical
   error string, not just the status code. */
static void verify_test_message_full(
    const char *mail_from, char *rcpts[],
    const char **raw_hdrs, int n_raw_hdrs,
    const char *body, const char *mi_val, const char *sig_val,
    dkim2_verify_result_t *res_out) {
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

    dkim2_do_verify(&vctx, res_out);

    dkim2_mi_free(vctx.mi_list);
    dkim2_sig_free(vctx.sig_list);
    free(all_hdrs);
}

/* Helper: verify a standard test message. Returns the result status. */
static dkim2_status_t verify_test_message(
    const char *mail_from, char *rcpts[],
    const char **raw_hdrs, int n_raw_hdrs,
    const char *body, const char *mi_val, const char *sig_val) {
    dkim2_verify_result_t res;
    verify_test_message_full(mail_from, rcpts, raw_hdrs, n_raw_hdrs,
        body, mi_val, sig_val, &res);
    return res.status;
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

    /* --- Error: wrong MAIL FROM → PERMERROR, canonical spec-04 message --- */
    {
        dkim2_verify_result_t res;
        verify_test_message_full("<wrong@example.com>", rcpts,
            raw_headers, 3, body, mi_val, sig_val, &res);
        assert(res.status == DKIM2_PERMERROR);
        assert(strstr(res.message,
            "DKIM2-Signature i=1 MAIL FROM <wrong@example.com> did not match") != NULL);
        st = res.status;
    }

    /* --- Error: wrong RCPT TO → PERMERROR, canonical spec-04 message --- */
    char *wrong_rcpts[] = { "<wrong@example.org>", NULL };
    {
        dkim2_verify_result_t res;
        verify_test_message_full(mail_from, wrong_rcpts,
            raw_headers, 3, body, mi_val, sig_val, &res);
        assert(res.status == DKIM2_PERMERROR);
        assert(strstr(res.message,
            "DKIM2-Signature i=1 RCPT TO <wrong@example.org> did not match") != NULL);
        st = res.status;
    }

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

    /* --- Error: d= does not relaxed-match mf= domain → PERMERROR,
       canonical spec-04 message (§7.7 check fires before crypto, so
       tampering d= post-signature doesn't need to preserve validity). --- */
    {
        char *d_tag = strstr(sig_val, "d=example.com");
        assert(d_tag != NULL);
        char tampered_d_sig[4096];
        size_t prefix_len = (size_t)(d_tag - sig_val);
        snprintf(tampered_d_sig, sizeof tampered_d_sig, "%.*sd=other-domain.com%s",
            (int)prefix_len, sig_val, d_tag + strlen("d=example.com"));

        dkim2_verify_result_t res;
        verify_test_message_full(mail_from, rcpts, raw_headers, 3, body,
            mi_val, tampered_d_sig, &res);
        assert(res.status == DKIM2_PERMERROR);
        assert(strstr(res.message,
            "DKIM2-Signature i=1 MAIL FROM and d= do not match") != NULL);
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

    /* --- Error: chain-of-custody nd= adjacency mismatch (§11.4) → PERMERROR,
       canonical spec-04 message (verbatim "MAIL nd=" typo, per spec-04).
       The C signer cannot emit nd= itself, so hop i=1 is hand-signed here:
       its own DKIM2-Signature header (with a genuine nd= tag) is covered by
       its own signature, so tampering it after the fact would invalidate the
       crypto — instead we build a real signing input (matching
       build_verify_input's canonicalization) and sign it directly with the
       test keypair already registered in the DNS override. Hop i=2 is
       produced by the normal signer, chained onto hop i=1, so both hops
       carry genuinely valid signatures and the chain-custody check (which
       runs after full per-signature crypto verification) is actually
       reached. */
    {
        uint64_t now = (uint64_t)time(NULL);

        /* Hop i=1: hand-built, carries nd= pointing at a domain that will
           NOT match hop i=2's d=, to trigger the adjacency mismatch. */
        char sig1_incomplete[512];
        snprintf(sig1_incomplete, sizeof sig1_incomplete,
            "i=1;m=1;t=%llu;d=example.com;nd=wrong-nd.example.com;"
            "s=test:ed25519-sha256:;",
            (unsigned long long)now);

        char sign_input_buf[4096];
        size_t pos = 0;
        test_canon_append(sign_input_buf, &pos, "message-instance", mi_val);
        test_canon_append(sign_input_buf, &pos, "dkim2-signature", sig1_incomplete);

        EVP_PKEY *sign_privkey = dkim2_load_privkey("/tmp/dkim2_test_sign.pem");
        assert(sign_privkey != NULL);
        char *sig1_b64 = dkim2_sign(sign_privkey, "ed25519-sha256",
            (unsigned char *)sign_input_buf, pos);
        EVP_PKEY_free(sign_privkey);
        assert(sig1_b64 != NULL);

        char sig1_final[600];
        snprintf(sig1_final, sizeof sig1_final,
            "i=1;m=1;t=%llu;d=example.com;nd=wrong-nd.example.com;"
            "s=test:ed25519-sha256:%s;",
            (unsigned long long)now, sig1_b64);
        free(sig1_b64);

        dkim2_sig_t *sig1_parsed = dkim2_sig_parse(sig1_final);
        assert(sig1_parsed != NULL);

        /* Hop i=2: normal signer, chained onto hop i=1 (new i=2, real mf=/rt=,
           d=example.com — deliberately NOT matching hop i=1's nd=). */
        dkim2_ctx_t ctx2;
        memset(&ctx2, 0, sizeof ctx2);
        ctx2.headers = (char **)raw_headers;
        ctx2.n_headers = 3;
        dkim2_body_hash_raw(body, strlen(body), ctx2.body_digest);
        char *hop2_mail_from = "<recipient@example.com>";
        char *hop2_rcpts[] = { "<dest@example.com>", NULL };
        ctx2.mail_from = hop2_mail_from;
        ctx2.rcpt_to = hop2_rcpts;
        ctx2.mi_list = NULL;
        ctx2.sig_list = sig1_parsed;
        dkim2_sign_config_t cfg2 = {
            .domain = "example.com", .selector = "test",
            .privkey_path = "/tmp/dkim2_test_sign.pem", .alg = "ed25519-sha256",
        };
        char *mi2_out = NULL, *sig2_out = NULL;
        int r2 = dkim2_do_sign(&ctx2, &cfg2, &mi2_out, &sig2_out);
        assert(r2 == 0 && mi2_out != NULL && sig2_out != NULL);

        dkim2_sig_t *sig2_parsed = dkim2_sig_parse(sig2_out);
        assert(sig2_parsed != NULL);
        sig1_parsed->next = sig2_parsed;

        dkim2_ctx_t vctx;
        memset(&vctx, 0, sizeof vctx);
        vctx.mi_list = dkim2_mi_parse(mi2_out);
        vctx.sig_list = sig1_parsed;

        dkim2_verify_result_t res;
        dkim2_do_verify(&vctx, &res);
        assert(res.status == DKIM2_PERMERROR);
        assert(strstr(res.message,
            "DKIM2-Signature i=1 MAIL nd= does not match") != NULL);

        dkim2_mi_free(vctx.mi_list);
        dkim2_sig_free(vctx.sig_list); /* frees sig1_parsed + chained sig2_parsed */
        free(mi2_out);
        free(sig2_out);
    }

    /* --- Error: inter-signature chain-of-custody break (§8.2) → FAIL,
       canonical spec-04 message (matches Perl Verifier.pm's _verify_chain:
       "DKIM2-Signature i=%d MAIL FROM %s did not match"). Both hops are
       produced by the normal signer (no nd= involved this time), chained
       via ctx2.sig_list so hop i=2 gets a real, independently-verifiable
       signature. hop1's rt= is scoped to a subdomain (sub.example.com)
       while hop2's mf= is the parent domain (example.com) — both fall
       under the same d=example.com (so DNS-key lookup and the §7.7 d=/mf=
       check both succeed for hop2 and crypto passes for both hops), but
       relaxed-domain-match requires the *previous* rt= to be equal-or-
       parent of the *current* mf=, and "sub.example.com" is not a parent
       of "example.com" — so the custody check (which runs after per-sig
       crypto verification) is the one that fires. */
    {
        char *hop1_rcpts[] = { "<mid@sub.example.com>", NULL };
        char *mi1_out = NULL, *sig1_out = NULL;
        int r1 = sign_test_message(mail_from, hop1_rcpts,
            "/tmp/dkim2_test_sign.pem", "example.com", "test",
            raw_headers, 3, body, &mi1_out, &sig1_out);
        assert(r1 == 0 && mi1_out != NULL && sig1_out != NULL);

        dkim2_sig_t *sig1_parsed = dkim2_sig_parse(sig1_out);
        assert(sig1_parsed != NULL);

        dkim2_ctx_t ctx2;
        memset(&ctx2, 0, sizeof ctx2);
        ctx2.headers = (char **)raw_headers;
        ctx2.n_headers = 3;
        dkim2_body_hash_raw(body, strlen(body), ctx2.body_digest);
        char *hop2_mail_from = "<attacker@example.com>"; /* not covered by hop1's sub.example.com rt= */
        char *hop2_rcpts[] = { "<final@example.com>", NULL };
        ctx2.mail_from = hop2_mail_from;
        ctx2.rcpt_to = hop2_rcpts;
        ctx2.mi_list = NULL;
        ctx2.sig_list = sig1_parsed;
        dkim2_sign_config_t cfg2 = {
            .domain = "example.com", .selector = "test",
            .privkey_path = "/tmp/dkim2_test_sign.pem", .alg = "ed25519-sha256",
        };
        char *mi2_out = NULL, *sig2_out = NULL;
        int r2 = dkim2_do_sign(&ctx2, &cfg2, &mi2_out, &sig2_out);
        assert(r2 == 0 && mi2_out != NULL && sig2_out != NULL);

        dkim2_sig_t *sig2_parsed = dkim2_sig_parse(sig2_out);
        assert(sig2_parsed != NULL);
        sig1_parsed->next = sig2_parsed;

        dkim2_ctx_t vctx;
        memset(&vctx, 0, sizeof vctx);
        vctx.mi_list = dkim2_mi_parse(mi2_out);
        vctx.sig_list = sig1_parsed;

        dkim2_verify_result_t res;
        dkim2_do_verify(&vctx, &res);
        assert(res.status == DKIM2_FAIL);
        assert(strstr(res.message,
            "DKIM2-Signature i=2 MAIL FROM <attacker@example.com> did not match") != NULL);

        dkim2_mi_free(vctx.mi_list);
        dkim2_sig_free(vctx.sig_list); /* frees sig1_parsed + chained sig2_parsed */
        free(mi1_out);
        free(sig1_out);
        free(mi2_out);
        free(sig2_out);
    }

    free(mi_val);
    free(sig_val);
    puts("sign+verify: all tests passed");
    return 0;
}
