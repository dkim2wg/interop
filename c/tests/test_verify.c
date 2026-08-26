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
#include "../dkim2_message.h"
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
    dkim2_body_hash_raw(body, strlen(body), ctx.body_digests.d[0]);
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
    dkim2_body_hash_raw(body, strlen(body), vctx.body_digests.d[0]);
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

    /* --- Error: wrong MAIL FROM → PERMERROR, canonical spec-05 message --- */
    {
        dkim2_verify_result_t res;
        verify_test_message_full("<wrong@example.com>", rcpts,
            raw_headers, 3, body, mi_val, sig_val, &res);
        assert(res.status == DKIM2_PERMERROR);
        assert(strstr(res.message,
            "DKIM2-Signature i=1 MAIL FROM <wrong@example.com> did not match") != NULL);
        st = res.status;
    }

    /* --- Error: wrong RCPT TO → PERMERROR, canonical spec-05 message --- */
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

    /* --- Error: DNS lookup fails (unknown Selector) → FAIL (no passing ssets) --- */
    char *orig_dns = g_dns_txt;
    g_dns_txt = NULL; /* DNS override returns NULL → live DNS would fail */
    /* Replace Selector with one that won't match the override */
    /* Build a sig with a different Selector */
    char *mi2 = NULL, *sig2 = NULL;
    /* Use a different Selector (won't be in DNS override) */
    dkim2_sign_config_t cfg2 = {
        .domain="example.com", .selector="badsel",
        .privkey_path="/tmp/dkim2_test_sign.pem", .alg="ed25519-sha256"
    };
    dkim2_ctx_t ctx2;
    memset(&ctx2, 0, sizeof ctx2);
    ctx2.headers = (char **)raw_headers; ctx2.n_headers = 3;
    dkim2_body_hash_raw(body, strlen(body), ctx2.body_digests.d[0]);
    ctx2.mail_from = (char *)mail_from; ctx2.rcpt_to = rcpts;
    dkim2_do_sign(&ctx2, &cfg2, &mi2, &sig2);
    g_dns_txt = orig_dns;
    /* DNS for "badsel" Selector not in override → fail */
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
        dkim2_body_hash_raw(body, strlen(body), vctx.body_digests.d[0]);
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
        dkim2_body_hash_raw(body, strlen(body), vctx.body_digests.d[0]);
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
        dkim2_body_hash_raw(body, strlen(body), vctx.body_digests.d[0]);
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
       canonical spec-05 message (§7.7 check fires before crypto, so
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

    /* --- Error: top-level nd= (spec-05 local policy) → PERMERROR ---
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

    /* --- Error: Chain of Custody nd= adjacency mismatch (§11.4) → PERMERROR,
       canonical spec-05 message (verbatim "MAIL nd=" typo, per spec-05).
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
        dkim2_body_hash_raw(body, strlen(body), ctx2.body_digests.d[0]);
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

    /* --- Error: inter-signature Chain of Custody break (§8.2) → FAIL,
       canonical spec-05 message (matches Perl Verifier.pm's _verify_chain:
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
        dkim2_body_hash_raw(body, strlen(body), ctx2.body_digests.d[0]);
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

    /* --- Regression (fix round 1): a duplicate hash algorithm in a
       Message-Instance h= must be reported as the exact spec-05 §7.3
       PERMERROR through the REAL ingestion path, not just detected by
       dkim2_mi_parse() in isolation. Before this fix, dkim2_message.c's
       collect_dkim2_headers() (and dkim2_milter.c's cb_header(), same
       pattern) silently dropped a Message-Instance header whenever
       dkim2_mi_parse() returned NULL, so the duplicate never reached
       dkim2_do_verify() at all -- the exact PERMERROR string existed only
       in a comment and in a unit test that called the parser directly.
       This drives a complete on-disk message through dkim2_verify_message(),
       the same entry point the CLI and milter use, to prove the fix reaches
       production, not just the parser. */
    {
        const char *path = "/tmp/dkim2_test_dup_mi_top.eml";
        FILE *ef = fopen(path, "w");
        assert(ef != NULL);
        /* Single MI (m=1, duplicate sha256 hash-set) covered by the one
           (syntactically valid, cryptographically irrelevant here) signature.
           mf=/rt= are the well-known base64 encodings of
           "<user@example.com>" / "<rcpt@example.org>" used elsewhere in this
           file; the envelope isn't checked (mail_from/rcpt_to passed as NULL
           below) since the mi_error check must fire first, before that. */
        fprintf(ef,
            "From: sender@example.com\n"
            "To: recipient@example.org\n"
            "Subject: Test DKIM2 message\n"
            "Message-Instance: m=1; h=sha256:AAA:BBB,sha256:CCC:DDD;\n"
            "DKIM2-Signature: i=1; m=1; t=1; d=example.com; "
            "mf=PHVzZXJAZXhhbXBsZS5jb20+; rt=PHJjcHRAZXhhbXBsZS5vcmc+; "
            "s=test:ed25519-sha256:AAAA;\n"
            "\n"
            "Hello, world!\n");
        fclose(ef);

        dkim2_verify_result_t res = dkim2_verify_message(path, NULL, NULL, 1);
        assert(res.status == DKIM2_PERMERROR);
        assert(strcmp(res.message,
            "PERMERROR Message-Instance m=1 has a duplicate hash algorithm") == 0);
        remove(path);
    }

    /* --- Same regression, but the duplicate-h= MI is NOT the top-covered
       instance (m=1 is bad; the top signature covers m=2, which is clean).
       This is the specific case the reviewer called out: with no MI-gap/
       contiguity check in dkim2_do_verify(), a non-top malformed MI that
       collect_dkim2_headers() drops has nothing else to catch it and simply
       vanishes -- no error at all, rather than the wrong error. The
       ctx->mi_error check runs unconditionally, before the signature loop
       even looks at which m= is topmost, so it must still fire here. --- */
    {
        const char *path = "/tmp/dkim2_test_dup_mi_nontop.eml";
        FILE *ef = fopen(path, "w");
        assert(ef != NULL);
        fprintf(ef,
            "From: sender@example.com\n"
            "To: recipient@example.org\n"
            "Subject: Test DKIM2 message\n"
            "Message-Instance: m=1; h=sha256:AAA:BBB,sha256:CCC:DDD;\n"
            "Message-Instance: m=2; h=sha256:EEE:FFF;\n"
            "DKIM2-Signature: i=1; m=2; t=1; d=example.com; "
            "mf=PHVzZXJAZXhhbXBsZS5jb20+; rt=PHJjcHRAZXhhbXBsZS5vcmc+; "
            "s=test:ed25519-sha256:AAAA;\n"
            "\n"
            "Hello, world!\n");
        fclose(ef);

        dkim2_verify_result_t res = dkim2_verify_message(path, NULL, NULL, 1);
        assert(res.status == DKIM2_PERMERROR);
        assert(strcmp(res.message,
            "PERMERROR Message-Instance m=1 has a duplicate hash algorithm") == 0);
        remove(path);
    }

    /* --- spec-05 §11.2 end-to-end: a malformed r= JSON payload on a real,
       validly-signed two-hop message must be reported as the specific
       "contains invalid JSON" PERMERROR by dkim2_do_verify() -- the same
       function dkim2_verify_message() (the CLI/milter entry point) calls --
       not silently dropped. Before this fix, dkim2_apply_body_recipe() and
       dkim2_apply_header_recipe() (dkim2_recipe.c) both returned NULL on a
       cJSON_Parse() failure with no way to tell that apart from their other
       NULL cases, and their two call sites in verify_mi_hashes()
       (dkim2_verify.c) just silently kept the prior body/headers rather than
       reporting anything -- so a malformed r= payload never surfaced as an
       error at all, it just silently failed to undo.
       The C signer has no way to emit an r= tag itself (dkim2_do_sign()
       never attaches a Recipe), so -- exactly like the hand-built nd= hop
       above -- hop i=2 is hand-signed: a real signing input is built with
       test_canon_append() (matching build_verify_input()'s canonicalization)
       over both Message-Instance headers (m=1 unmodified, m=2 carrying the
       malformed r=) and both DKIM2-Signature headers, then signed directly
       with the test keypair already registered in the DNS override. This
       drives the complete real §10.6 crypto verification and §10.7 MI-hash/
       undo logic in dkim2_do_verify(), not just dkim2_apply_*_recipe() or
       cJSON_Parse() in isolation. */
    {
        uint64_t now = (uint64_t)time(NULL);

        char *mi1_out = NULL, *sig1_out = NULL;
        char *hop1_rcpts[] = { "<mid@example.com>", NULL };
        int r1 = sign_test_message("<sender@example.com>", hop1_rcpts,
            "/tmp/dkim2_test_sign.pem", "example.com", "test",
            raw_headers, 3, body, &mi1_out, &sig1_out);
        assert(r1 == 0 && mi1_out != NULL && sig1_out != NULL);

        /* m=2 carries the SAME (genuinely correct) header/body hashes as
           m=1 -- content is unmodified between hops, which is legal (a
           Recipe-less/identical MI asserting "no change" is accepted by
           every implementation here) -- plus a malformed r= tag. "eyJoIjog"
           is base64 of `{"h": `, truncated so it decodes to invalid
           (incomplete) JSON, not merely a semantic rejection like a null
           header Recipe. */
        dkim2_mi_t *mi1_parsed = dkim2_mi_parse(mi1_out);
        assert(mi1_parsed && mi1_parsed->n_hsets >= 1);
        char mi2_val[512];
        snprintf(mi2_val, sizeof mi2_val, "m=2; h=%s:%s:%s; r=eyJoIjog;",
            mi1_parsed->hsets[0].alg,
            mi1_parsed->hsets[0].hdr_hash,
            mi1_parsed->hsets[0].body_hash);
        dkim2_mi_free(mi1_parsed);

        char mf2_b64[128], rt2_b64[128];
        b64_encode((const unsigned char *)"<mid@example.com>",
            strlen("<mid@example.com>"), mf2_b64, sizeof mf2_b64);
        b64_encode((const unsigned char *)"<final@example.com>",
            strlen("<final@example.com>"), rt2_b64, sizeof rt2_b64);

        char sig2_incomplete[512];
        snprintf(sig2_incomplete, sizeof sig2_incomplete,
            "i=2;m=2;t=%llu;d=example.com;mf=%s;rt=%s;s=test:ed25519-sha256:;",
            (unsigned long long)now, mf2_b64, rt2_b64);

        char sign_input_buf[4096];
        size_t pos = 0;
        test_canon_append(sign_input_buf, &pos, "message-instance", mi1_out);
        test_canon_append(sign_input_buf, &pos, "message-instance", mi2_val);
        test_canon_append(sign_input_buf, &pos, "dkim2-signature", sig1_out);
        test_canon_append(sign_input_buf, &pos, "dkim2-signature", sig2_incomplete);

        EVP_PKEY *sign_privkey = dkim2_load_privkey("/tmp/dkim2_test_sign.pem");
        assert(sign_privkey != NULL);
        char *sig2_b64 = dkim2_sign(sign_privkey, "ed25519-sha256",
            (unsigned char *)sign_input_buf, pos);
        EVP_PKEY_free(sign_privkey);
        assert(sig2_b64 != NULL);

        char sig2_final[600];
        snprintf(sig2_final, sizeof sig2_final,
            "i=2;m=2;t=%llu;d=example.com;mf=%s;rt=%s;s=test:ed25519-sha256:%s;",
            (unsigned long long)now, mf2_b64, rt2_b64, sig2_b64);
        free(sig2_b64);

        dkim2_sig_t *sig1_parsed = dkim2_sig_parse(sig1_out);
        dkim2_sig_t *sig2_parsed = dkim2_sig_parse(sig2_final);
        assert(sig1_parsed && sig2_parsed);
        sig1_parsed->next = sig2_parsed;

        dkim2_mi_t *mi1p = dkim2_mi_parse(mi1_out);
        dkim2_mi_t *mi2p = dkim2_mi_parse(mi2_val);
        assert(mi1p && mi2p);
        mi1p->next = mi2p;

        dkim2_ctx_t vctx;
        memset(&vctx, 0, sizeof vctx);
        vctx.headers = (char **)raw_headers;
        vctx.n_headers = 3;
        dkim2_body_hash_raw(body, strlen(body), vctx.body_digests.d[0]);
        vctx.mi_list = mi1p;
        vctx.sig_list = sig1_parsed;

        dkim2_verify_result_t res;
        dkim2_do_verify(&vctx, &res);
        assert(res.status == DKIM2_PERMERROR);
        assert(strcmp(res.message,
            "PERMERROR Message-Instance m=2 contains invalid JSON") == 0);

        dkim2_mi_free(vctx.mi_list);
        dkim2_sig_free(vctx.sig_list); /* frees sig1_parsed + chained sig2_parsed */
        free(mi1_out);
        free(sig1_out);
    }

    /* --- spec-05 §11.2 ruling: a bad-base64 r= value is a DIFFERENT error
       from a post-decode JSON parse failure, and must stay distinct:
       "PERMERROR ... syntax error" (§11.2 lists this explicitly for
       malformed field content), never "contains invalid JSON" -- the
       payload here never even reaches JSON parsing. Same two-hop
       construction as the invalid-JSON test above, just with "!!!!"
       (not valid base64) in place of "eyJoIjog". Before this fix,
       b64_decode() failing here just did a silent `continue`, the same
       silent-drop shape fixed for the JSON-parse case above -- nothing was
       ever reported for a malformed r= base64 value. */
    {
        uint64_t now = (uint64_t)time(NULL);

        char *mi1_out = NULL, *sig1_out = NULL;
        char *hop1_rcpts[] = { "<mid@example.com>", NULL };
        int r1 = sign_test_message("<sender@example.com>", hop1_rcpts,
            "/tmp/dkim2_test_sign.pem", "example.com", "test",
            raw_headers, 3, body, &mi1_out, &sig1_out);
        assert(r1 == 0 && mi1_out != NULL && sig1_out != NULL);

        dkim2_mi_t *mi1_parsed = dkim2_mi_parse(mi1_out);
        assert(mi1_parsed && mi1_parsed->n_hsets >= 1);
        char mi2_val[512];
        snprintf(mi2_val, sizeof mi2_val, "m=2; h=%s:%s:%s; r=!!!!;",
            mi1_parsed->hsets[0].alg,
            mi1_parsed->hsets[0].hdr_hash,
            mi1_parsed->hsets[0].body_hash);
        dkim2_mi_free(mi1_parsed);

        char mf2_b64[128], rt2_b64[128];
        b64_encode((const unsigned char *)"<mid@example.com>",
            strlen("<mid@example.com>"), mf2_b64, sizeof mf2_b64);
        b64_encode((const unsigned char *)"<final@example.com>",
            strlen("<final@example.com>"), rt2_b64, sizeof rt2_b64);

        char sig2_incomplete[512];
        snprintf(sig2_incomplete, sizeof sig2_incomplete,
            "i=2;m=2;t=%llu;d=example.com;mf=%s;rt=%s;s=test:ed25519-sha256:;",
            (unsigned long long)now, mf2_b64, rt2_b64);

        char sign_input_buf[4096];
        size_t pos = 0;
        test_canon_append(sign_input_buf, &pos, "message-instance", mi1_out);
        test_canon_append(sign_input_buf, &pos, "message-instance", mi2_val);
        test_canon_append(sign_input_buf, &pos, "dkim2-signature", sig1_out);
        test_canon_append(sign_input_buf, &pos, "dkim2-signature", sig2_incomplete);

        EVP_PKEY *sign_privkey = dkim2_load_privkey("/tmp/dkim2_test_sign.pem");
        assert(sign_privkey != NULL);
        char *sig2_b64 = dkim2_sign(sign_privkey, "ed25519-sha256",
            (unsigned char *)sign_input_buf, pos);
        EVP_PKEY_free(sign_privkey);
        assert(sig2_b64 != NULL);

        char sig2_final[600];
        snprintf(sig2_final, sizeof sig2_final,
            "i=2;m=2;t=%llu;d=example.com;mf=%s;rt=%s;s=test:ed25519-sha256:%s;",
            (unsigned long long)now, mf2_b64, rt2_b64, sig2_b64);
        free(sig2_b64);

        dkim2_sig_t *sig1_parsed = dkim2_sig_parse(sig1_out);
        dkim2_sig_t *sig2_parsed = dkim2_sig_parse(sig2_final);
        assert(sig1_parsed && sig2_parsed);
        sig1_parsed->next = sig2_parsed;

        dkim2_mi_t *mi1p = dkim2_mi_parse(mi1_out);
        dkim2_mi_t *mi2p = dkim2_mi_parse(mi2_val);
        assert(mi1p && mi2p);
        mi1p->next = mi2p;

        dkim2_ctx_t vctx;
        memset(&vctx, 0, sizeof vctx);
        vctx.headers = (char **)raw_headers;
        vctx.n_headers = 3;
        dkim2_body_hash_raw(body, strlen(body), vctx.body_digests.d[0]);
        vctx.mi_list = mi1p;
        vctx.sig_list = sig1_parsed;

        dkim2_verify_result_t res;
        dkim2_do_verify(&vctx, &res);
        assert(res.status == DKIM2_PERMERROR);
        assert(strcmp(res.message,
            "PERMERROR Message-Instance m=2 syntax error") == 0);
        assert(strstr(res.message, "invalid JSON") == NULL);

        dkim2_mi_free(vctx.mi_list);
        dkim2_sig_free(vctx.sig_list); /* frees sig1_parsed + chained sig2_parsed */
        free(mi1_out);
        free(sig1_out);
    }

    /* --- spec-05 §9.1: the BOTTOM (m=1) instance MAY carry Recipes too
       ("if it is wished to record any changes made to a message as it
       enters the DKIM2 ecosystem"). It never participates in the undo walk
       (there is no earlier state to reconstruct), so before this fix the
       validity check -- gated on `vi > 0` -- silently skipped it entirely.
       A single-instance (m=1 only) message, hand-signed so its own
       signature legitimately covers the malformed r= bytes. */
    {
        uint64_t now = (uint64_t)time(NULL);

        char *mi1_out = NULL, *sig1_out = NULL;
        char *hop1_rcpts[] = { "<rcpt@example.com>", NULL };
        int r1 = sign_test_message("<sender@example.com>", hop1_rcpts,
            "/tmp/dkim2_test_sign.pem", "example.com", "test",
            raw_headers, 3, body, &mi1_out, &sig1_out);
        assert(r1 == 0 && mi1_out != NULL && sig1_out != NULL);

        dkim2_mi_t *mi1_parsed = dkim2_mi_parse(mi1_out);
        assert(mi1_parsed && mi1_parsed->n_hsets >= 1);
        char mi1_val[512];
        snprintf(mi1_val, sizeof mi1_val, "m=1; h=%s:%s:%s; r=eyJoIjog;",
            mi1_parsed->hsets[0].alg,
            mi1_parsed->hsets[0].hdr_hash,
            mi1_parsed->hsets[0].body_hash);
        dkim2_mi_free(mi1_parsed);

        char mf1_b64[128], rt1_b64[128];
        b64_encode((const unsigned char *)"<sender@example.com>",
            strlen("<sender@example.com>"), mf1_b64, sizeof mf1_b64);
        b64_encode((const unsigned char *)"<rcpt@example.com>",
            strlen("<rcpt@example.com>"), rt1_b64, sizeof rt1_b64);

        char sig1_incomplete[512];
        snprintf(sig1_incomplete, sizeof sig1_incomplete,
            "i=1;m=1;t=%llu;d=example.com;mf=%s;rt=%s;s=test:ed25519-sha256:;",
            (unsigned long long)now, mf1_b64, rt1_b64);

        char sign_input_buf[4096];
        size_t pos = 0;
        test_canon_append(sign_input_buf, &pos, "message-instance", mi1_val);
        test_canon_append(sign_input_buf, &pos, "dkim2-signature", sig1_incomplete);

        EVP_PKEY *sign_privkey = dkim2_load_privkey("/tmp/dkim2_test_sign.pem");
        assert(sign_privkey != NULL);
        char *sig1_b64 = dkim2_sign(sign_privkey, "ed25519-sha256",
            (unsigned char *)sign_input_buf, pos);
        EVP_PKEY_free(sign_privkey);
        assert(sig1_b64 != NULL);

        char sig1_final[600];
        snprintf(sig1_final, sizeof sig1_final,
            "i=1;m=1;t=%llu;d=example.com;mf=%s;rt=%s;s=test:ed25519-sha256:%s;",
            (unsigned long long)now, mf1_b64, rt1_b64, sig1_b64);
        free(sig1_b64);

        dkim2_sig_t *sig1_parsed = dkim2_sig_parse(sig1_final);
        dkim2_mi_t *mi1p = dkim2_mi_parse(mi1_val);
        assert(sig1_parsed && mi1p);

        dkim2_ctx_t vctx;
        memset(&vctx, 0, sizeof vctx);
        vctx.headers = (char **)raw_headers;
        vctx.n_headers = 3;
        dkim2_body_hash_raw(body, strlen(body), vctx.body_digests.d[0]);
        vctx.mi_list = mi1p;
        vctx.sig_list = sig1_parsed;

        dkim2_verify_result_t res;
        dkim2_do_verify(&vctx, &res);
        assert(res.status == DKIM2_PERMERROR);
        assert(strcmp(res.message,
            "PERMERROR Message-Instance m=1 contains invalid JSON") == 0);

        dkim2_mi_free(vctx.mi_list);
        dkim2_sig_free(vctx.sig_list);
        free(mi1_out);
        free(sig1_out);
    }

    /* --- Regression (fix round: item 1, spec-05-upgrade final review): the
       BOTTOM (m=1) Message-Instance fails to parse with -1 (a malformed h=
       hash-set entry -- not the already-fixed -2 duplicate-hash case), while
       a real, otherwise-fully-valid m=2 hop sits on top with its own valid
       signature chain (i=1 covering m=1, i=2 covering m=2). i=1's signature
       is hand-signed over exactly the broken wire bytes of mi1, modeling a
       signer that faithfully signs whatever it emitted (e.g. a malloc
       failure while serializing h=, followed by signing the corrupted
       result anyway) -- the realistic construction for this bug.

       Before the item-1 fix: collect_dkim2_headers() dropped mi1 from
       ctx->mi_list with mi_error left empty (dkim2_mi_parse_err() only
       populated errbuf for -2), so the ctx->mi_error check at the top of
       dkim2_do_verify() never fired. Empirically (see PROBE result recorded
       below), this construction still ended up FAIL "DKIM2-Signature i=1
       signature verification failed" -- not because anything noticed the
       broken bottom MI, but only incidentally: build_verify_input() can only
       include a Message-Instance's raw_value from ctx->mi_list, and since
       every signature's target m is >= 1, mi1's content is always part of
       every covering signature's input, so dropping it always desyncs the
       reconstructed signing input from whatever a real signer produced. That
       is NOT a real protection -- see the second block below, which proves
       it fails OPEN (DKIM2_OK) once that incidental crypto correlation is
       removed. After the fix, ctx->mi_error is set for -1 too and fires
       unconditionally before any crypto is attempted, so both constructions
       now report the same explicit PERMERROR. */
    {
        uint64_t now = (uint64_t)time(NULL);
        char mi1_broken[128];
        snprintf(mi1_broken, sizeof mi1_broken, "m=1; h=NOTAHASHSET;");

        char *mi1_out = NULL, *sig1_out = NULL;
        char *hop1_rcpts[] = { "<mid@example.com>", NULL };
        int r1 = sign_test_message("<sender@example.com>", hop1_rcpts,
            "/tmp/dkim2_test_sign.pem", "example.com", "test",
            raw_headers, 3, body, &mi1_out, &sig1_out);
        assert(r1 == 0 && mi1_out != NULL && sig1_out != NULL);

        dkim2_mi_t *mi1_parsed = dkim2_mi_parse(mi1_out);
        assert(mi1_parsed && mi1_parsed->n_hsets >= 1);
        char mi2_val[512];
        snprintf(mi2_val, sizeof mi2_val, "m=2; h=%s:%s:%s;",
            mi1_parsed->hsets[0].alg,
            mi1_parsed->hsets[0].hdr_hash,
            mi1_parsed->hsets[0].body_hash);
        dkim2_mi_free(mi1_parsed);

        char mf1_b64[128], rt1_b64[128];
        b64_encode((const unsigned char *)"<sender@example.com>",
            strlen("<sender@example.com>"), mf1_b64, sizeof mf1_b64);
        b64_encode((const unsigned char *)"<mid@example.com>",
            strlen("<mid@example.com>"), rt1_b64, sizeof rt1_b64);
        char sig1_incomplete[512];
        snprintf(sig1_incomplete, sizeof sig1_incomplete,
            "i=1;m=1;t=%llu;d=example.com;mf=%s;rt=%s;s=test:ed25519-sha256:;",
            (unsigned long long)now, mf1_b64, rt1_b64);

        char mf2_b64[128], rt2_b64[128];
        b64_encode((const unsigned char *)"<mid@example.com>",
            strlen("<mid@example.com>"), mf2_b64, sizeof mf2_b64);
        b64_encode((const unsigned char *)"<final@example.com>",
            strlen("<final@example.com>"), rt2_b64, sizeof rt2_b64);
        char sig2_incomplete[512];
        snprintf(sig2_incomplete, sizeof sig2_incomplete,
            "i=2;m=2;t=%llu;d=example.com;mf=%s;rt=%s;s=test:ed25519-sha256:;",
            (unsigned long long)now, mf2_b64, rt2_b64);

        EVP_PKEY *sign_privkey = dkim2_load_privkey("/tmp/dkim2_test_sign.pem");
        assert(sign_privkey != NULL);

        char sign_input1[4096]; size_t pos1 = 0;
        test_canon_append(sign_input1, &pos1, "message-instance", mi1_broken);
        test_canon_append(sign_input1, &pos1, "dkim2-signature", sig1_incomplete);
        char *sig1_b64 = dkim2_sign(sign_privkey, "ed25519-sha256",
            (unsigned char *)sign_input1, pos1);
        assert(sig1_b64 != NULL);
        char sig1_final[600];
        snprintf(sig1_final, sizeof sig1_final,
            "i=1;m=1;t=%llu;d=example.com;mf=%s;rt=%s;s=test:ed25519-sha256:%s;",
            (unsigned long long)now, mf1_b64, rt1_b64, sig1_b64);
        free(sig1_b64);

        char sign_input2[4096]; size_t pos2 = 0;
        test_canon_append(sign_input2, &pos2, "message-instance", mi1_broken);
        test_canon_append(sign_input2, &pos2, "message-instance", mi2_val);
        test_canon_append(sign_input2, &pos2, "dkim2-signature", sig1_final);
        test_canon_append(sign_input2, &pos2, "dkim2-signature", sig2_incomplete);
        char *sig2_b64 = dkim2_sign(sign_privkey, "ed25519-sha256",
            (unsigned char *)sign_input2, pos2);
        assert(sig2_b64 != NULL);
        EVP_PKEY_free(sign_privkey);
        char sig2_final[600];
        snprintf(sig2_final, sizeof sig2_final,
            "i=2;m=2;t=%llu;d=example.com;mf=%s;rt=%s;s=test:ed25519-sha256:%s;",
            (unsigned long long)now, mf2_b64, rt2_b64, sig2_b64);
        free(sig2_b64);

        const char *path = "/tmp/dkim2_test_bottom_mi_dash1_probe.eml";
        FILE *ef = fopen(path, "w");
        assert(ef != NULL);
        fprintf(ef,
            "From: sender@example.com\r\n"
            "To: recipient@example.org\r\n"
            "Subject: Test DKIM2 message\r\n"
            "Message-Instance: %s\r\n"
            "Message-Instance: %s\r\n"
            "DKIM2-Signature: %s\r\n"
            "DKIM2-Signature: %s\r\n"
            "\r\n"
            "%s",
            mi1_broken, mi2_val, sig1_final, sig2_final, body);
        fclose(ef);

        dkim2_verify_result_t res = dkim2_verify_message(path, NULL, NULL, 1);
        remove(path);
        assert(res.status == DKIM2_PERMERROR);
        assert(strcmp(res.message,
            "PERMERROR Message-Instance m=1 syntax error") == 0);

        free(mi1_out);
        free(sig1_out);
    }

    /* --- Regression, second construction: what if the signatures were
       already consistent with the verifier's post-drop reconstruction (i.e.
       computed as though mi1 were never part of the signing input at all --
       matching exactly what build_verify_input() sees once mi1 is dropped
       from ctx->mi_list)? This isolates whether ANYTHING other than the
       incidental crypto correlation above would have caught the dropped
       bottom MI. It does not model a realistic external attacker (nothing
       in this codebase's signer produces this shape today), but it
       definitively answers item 1(a): before the fix, this construction
       verified as DKIM2_OK ("PASS: DKIM2-Signature i=2 verified") -- proving
       the bottom-MI -1 case fails OPEN once its only incidental protection
       (crypto happening to include mi1's bytes) is removed. The
       unconditional ctx->mi_error check added by the fix closes this
       regardless of construction. */
    {
        uint64_t now = (uint64_t)time(NULL);
        char mi1_broken[128];
        snprintf(mi1_broken, sizeof mi1_broken, "m=1; h=NOTAHASHSET;");

        char *mi1_out = NULL, *sig1_out = NULL;
        char *hop1_rcpts[] = { "<mid@example.com>", NULL };
        int r1 = sign_test_message("<sender@example.com>", hop1_rcpts,
            "/tmp/dkim2_test_sign.pem", "example.com", "test",
            raw_headers, 3, body, &mi1_out, &sig1_out);
        assert(r1 == 0 && mi1_out != NULL && sig1_out != NULL);

        dkim2_mi_t *mi1_parsed = dkim2_mi_parse(mi1_out);
        assert(mi1_parsed && mi1_parsed->n_hsets >= 1);
        char mi2_val[512];
        snprintf(mi2_val, sizeof mi2_val, "m=2; h=%s:%s:%s;",
            mi1_parsed->hsets[0].alg,
            mi1_parsed->hsets[0].hdr_hash,
            mi1_parsed->hsets[0].body_hash);
        dkim2_mi_free(mi1_parsed);

        char mf1_b64[128], rt1_b64[128];
        b64_encode((const unsigned char *)"<sender@example.com>",
            strlen("<sender@example.com>"), mf1_b64, sizeof mf1_b64);
        b64_encode((const unsigned char *)"<mid@example.com>",
            strlen("<mid@example.com>"), rt1_b64, sizeof rt1_b64);
        char sig1_incomplete[512];
        snprintf(sig1_incomplete, sizeof sig1_incomplete,
            "i=1;m=1;t=%llu;d=example.com;mf=%s;rt=%s;s=test:ed25519-sha256:;",
            (unsigned long long)now, mf1_b64, rt1_b64);

        char mf2_b64[128], rt2_b64[128];
        b64_encode((const unsigned char *)"<mid@example.com>",
            strlen("<mid@example.com>"), mf2_b64, sizeof mf2_b64);
        b64_encode((const unsigned char *)"<final@example.com>",
            strlen("<final@example.com>"), rt2_b64, sizeof rt2_b64);
        char sig2_incomplete[512];
        snprintf(sig2_incomplete, sizeof sig2_incomplete,
            "i=2;m=2;t=%llu;d=example.com;mf=%s;rt=%s;s=test:ed25519-sha256:;",
            (unsigned long long)now, mf2_b64, rt2_b64);

        EVP_PKEY *sign_privkey = dkim2_load_privkey("/tmp/dkim2_test_sign.pem");
        assert(sign_privkey != NULL);

        /* sig1 signs ONLY its own (blanked) header -- exactly what
           build_verify_input() reconstructs once mi1 is missing from
           ctx->mi_list. */
        char sign_input1[4096]; size_t pos1 = 0;
        test_canon_append(sign_input1, &pos1, "dkim2-signature", sig1_incomplete);
        char *sig1_b64 = dkim2_sign(sign_privkey, "ed25519-sha256",
            (unsigned char *)sign_input1, pos1);
        assert(sig1_b64 != NULL);
        char sig1_final[600];
        snprintf(sig1_final, sizeof sig1_final,
            "i=1;m=1;t=%llu;d=example.com;mf=%s;rt=%s;s=test:ed25519-sha256:%s;",
            (unsigned long long)now, mf1_b64, rt1_b64, sig1_b64);
        free(sig1_b64);

        /* sig2 signs mi2 + sig1(final) + sig2(blanked) -- again, exactly
           what build_verify_input() reconstructs (mi1 absent). */
        char sign_input2[4096]; size_t pos2 = 0;
        test_canon_append(sign_input2, &pos2, "message-instance", mi2_val);
        test_canon_append(sign_input2, &pos2, "dkim2-signature", sig1_final);
        test_canon_append(sign_input2, &pos2, "dkim2-signature", sig2_incomplete);
        char *sig2_b64 = dkim2_sign(sign_privkey, "ed25519-sha256",
            (unsigned char *)sign_input2, pos2);
        assert(sig2_b64 != NULL);
        EVP_PKEY_free(sign_privkey);
        char sig2_final[600];
        snprintf(sig2_final, sizeof sig2_final,
            "i=2;m=2;t=%llu;d=example.com;mf=%s;rt=%s;s=test:ed25519-sha256:%s;",
            (unsigned long long)now, mf2_b64, rt2_b64, sig2_b64);
        free(sig2_b64);

        const char *path = "/tmp/dkim2_test_bottom_mi_dash1_probe2.eml";
        FILE *ef = fopen(path, "w");
        assert(ef != NULL);
        fprintf(ef,
            "From: sender@example.com\r\n"
            "To: recipient@example.org\r\n"
            "Subject: Test DKIM2 message\r\n"
            "Message-Instance: %s\r\n"
            "Message-Instance: %s\r\n"
            "DKIM2-Signature: %s\r\n"
            "DKIM2-Signature: %s\r\n"
            "\r\n"
            "%s",
            mi1_broken, mi2_val, sig1_final, sig2_final, body);
        fclose(ef);

        dkim2_verify_result_t res = dkim2_verify_message(path, NULL, NULL, 1);
        remove(path);
        assert(res.status == DKIM2_PERMERROR);
        assert(strcmp(res.message,
            "PERMERROR Message-Instance m=1 syntax error") == 0);

        free(mi1_out);
        free(sig1_out);
    }

    free(mi_val);
    free(sig_val);
    puts("sign+verify: all tests passed");
    return 0;
}
