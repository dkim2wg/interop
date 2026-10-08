/* Null body Recipe ("b": null, spec-06 §4.2): the previous BODY cannot be
   recreated, but header Recipes are mandatory (§5.1) so the header history
   below the null must still be walked and checked.

   Includes dkim2_verify.c so the static chain walk (verify_mi_hashes) can be
   driven directly with hand-built Message-Instance chains. */
#include "../dkim2_verify.c"
#include <assert.h>

static void mkhash(char *out, size_t outsz, const char **hdrs, int nh,
                   const char *body) {
    unsigned char bh[DKIM2_MAX_HASH_LEN], hh[DKIM2_MAX_HASH_LEN];
    dkim2_body_hash_raw_alg(body, strlen(body), 0, bh);
    dkim2_header_hash_raw_alg(hdrs, nh, 0, hh);
    char bb[128], hb[128];
    size_t al = dkim2_hash_alg_len(0);
    b64_encode(bh, al, bb, sizeof bb);
    b64_encode(hh, al, hb, sizeof hb);
    snprintf(out, outsz, "sha256:%s:%s", hb, bb);
}

static dkim2_mi_t *mkmi(int m, const char **hdrs, int nh, const char *body,
                        const char *rjson) {
    char h[512], v[2048];
    mkhash(h, sizeof h, hdrs, nh, body);
    if (rjson) {
        char rb[1024];
        b64_encode((const unsigned char *)rjson, strlen(rjson), rb, sizeof rb);
        snprintf(v, sizeof v, "m=%d; h=%s; r=%s;", m, h, rb);
    } else {
        snprintf(v, sizeof v, "m=%d; h=%s;", m, h);
    }
    dkim2_mi_t *mi = dkim2_mi_parse(v);
    assert(mi);
    return mi;
}

static int run(dkim2_mi_t **mis, int n, const char **top, int ntop,
               const char *topbody, char *err, size_t errsz) {
    char *hdrs[8];
    for (int i = 0; i < ntop; i++) hdrs[i] = (char *)top[i];
    dkim2_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    dkim2_body_hash_raw_alg(topbody, strlen(topbody), 0, ctx.body_digests.d[0]);
    err[0] = '\0';
    return verify_mi_hashes(mis, n, hdrs, ntop, topbody, strlen(topbody),
                            &ctx, err, errsz);
}

int main(void) {
    const char *F = "From: a@example.com\r\n", *T = "To: list@example.org\r\n";
    const char *S1 = "Subject: hi\r\n", *S2 = "Subject: [L] hi\r\n";
    const char *S3 = "Subject: [M] [L] hi\r\n";
    const char *T2 = "To: other@example.org\r\n";
    const char *B1 = "one\r\ntwo\r\n";
    const char *B2 = "rewritten\r\n";
    const char *B3 = "rewritten\r\nfooter\r\n";
    char err[256];

    const char *h1[] = { F, T, S1 };
    const char *h2[] = { F, T, S2 };
    const char *h3[] = { F, T, S3 };
    const char *r2 = "{\"h\":{\"subject\":[{\"d\":[\"hi\"]}]},\"b\":null}";

    /* null at m=2 over signed m=1 -> pass */
    {
        dkim2_mi_t *m[2] = { mkmi(1, h1, 3, B1, NULL), mkmi(2, h2, 3, B2, r2) };
        { int rr = run(m, 2, h2, 3, B2, err, sizeof err); if (rr) fprintf(stderr, "ERR %s\n", err); assert(rr == 0); }
        dkim2_mi_free(m[0]); dkim2_mi_free(m[1]);
    }
    /* null at m=3 over a normal (non-null) m=2 -> pass; m=2's body Recipe is
       not applied and its body hash is not checked (the body is gone) */
    {
        const char *r3 = "{\"h\":{\"subject\":[{\"d\":[\"[L] hi\"]}]},\"b\":null}";
        const char *r2n = "{\"h\":{\"subject\":[{\"d\":[\"hi\"]}]},"
                          "\"b\":[{\"d\":[\"junk\"]}]}";
        dkim2_mi_t *m[3] = { mkmi(1, h1, 3, B1, NULL), mkmi(2, h2, 3, B2, r2n),
                             mkmi(3, h3, 3, B3, r3) };
        assert(run(m, 3, h3, 3, B3, err, sizeof err) == 0);
        for (int i = 0; i < 3; i++) dkim2_mi_free(m[i]);
    }
    /* negative control, NO null at m=2/m=3 body Recipe being null: m=3 has an
       ordinary body Recipe and m=2's body hash is wrong, so the chain must
       fail at m=2 body hash (proves bodies ARE checked without a null) */
    {
        const char *r3b = "{\"h\":{\"subject\":[{\"d\":[\"[L] hi\"]}]},"
                          "\"b\":[{\"c\":[1,1]}]}";
        dkim2_mi_t *m[3] = { mkmi(1, h1, 3, B1, NULL), mkmi(2, h2, 3, "bad\r\n", r2),
                             mkmi(3, h3, 3, B3, r3b) };
        assert(run(m, 3, h3, 3, B3, err, sizeof err) != 0);
        assert(strstr(err, "m=2 body hash mismatch"));
        for (int i = 0; i < 3; i++) dkim2_mi_free(m[i]);
    }
    /* forged history below the null: To changed, hidden from header Recipe */
    {
        const char *hf[] = { F, T2, S2 };
        dkim2_mi_t *m[2] = { mkmi(1, h1, 3, B1, NULL), mkmi(2, hf, 3, B2, r2) };
        assert(run(m, 2, hf, 3, B2, err, sizeof err) != 0);
        assert(strstr(err, "m=1 header hash mismatch"));
        dkim2_mi_free(m[0]); dkim2_mi_free(m[1]);
    }
    /* header Recipe that does not apply below the null -> failure */
    {
        const char *rbad = "{\"h\":{\"subject\":[{\"c\":[5,5]}]},\"b\":null}";
        dkim2_mi_t *m[2] = { mkmi(1, h1, 3, B1, NULL), mkmi(2, h2, 3, B2, rbad) };
        assert(run(m, 2, h2, 3, B2, err, sizeof err) != 0);
        dkim2_mi_free(m[0]); dkim2_mi_free(m[1]);
    }
    /* top instance still gets a full check: wrong top body hash fails */
    {
        dkim2_mi_t *m[2] = { mkmi(1, h1, 3, B1, NULL), mkmi(2, h2, 3, "x\r\n", r2) };
        assert(run(m, 2, h2, 3, B2, err, sizeof err) != 0);
        assert(strstr(err, "m=2 body hash mismatch"));
        dkim2_mi_free(m[0]); dkim2_mi_free(m[1]);
    }
    /* EMPTY top body: clean chain (m=2 header-only Recipe) -> pass */
    {
        const char *r = "{\"h\":{\"subject\":[{\"d\":[\"hi\"]}]}}";
        dkim2_mi_t *m[2] = { mkmi(1, h1, 3, "", NULL), mkmi(2, h2, 3, "", r) };
        assert(run(m, 2, h2, 3, "", err, sizeof err) == 0);
        dkim2_mi_free(m[0]); dkim2_mi_free(m[1]);
    }
    /* EMPTY top body, To change hidden from m=2's header Recipe -> fail */
    {
        const char *hf[] = { F, T2, S2 };
        const char *r = "{\"h\":{\"subject\":[{\"d\":[\"hi\"]}]}}";
        dkim2_mi_t *m[2] = { mkmi(1, h1, 3, "", NULL), mkmi(2, hf, 3, "", r) };
        assert(run(m, 2, hf, 3, "", err, sizeof err) != 0);
        assert(strstr(err, "m=1 header hash mismatch"));
        dkim2_mi_free(m[0]); dkim2_mi_free(m[1]);
    }
    /* null BELOW an ordinary instance: m=3 ordinary (header Recipe only,
       body unchanged) over m=2 null over m=1 -> pass; forged -> fail at m=1 */
    {
        const char *r3 = "{\"h\":{\"subject\":[{\"d\":[\"[L] hi\"]}]}}";
        dkim2_mi_t *m[3] = { mkmi(1, h1, 3, B1, NULL), mkmi(2, h2, 3, B2, r2),
                             mkmi(3, h3, 3, B2, r3) };
        assert(run(m, 3, h3, 3, B2, err, sizeof err) == 0);
        for (int i = 0; i < 3; i++) dkim2_mi_free(m[i]);

        const char *hf2[] = { F, T2, S2 }, *hf3[] = { F, T2, S3 };
        dkim2_mi_t *f[3] = { mkmi(1, h1, 3, B1, NULL), mkmi(2, hf2, 3, B2, r2),
                             mkmi(3, hf3, 3, B2, r3) };
        assert(run(f, 3, hf3, 3, B2, err, sizeof err) != 0);
        assert(strstr(err, "m=1 header hash mismatch"));
        for (int i = 0; i < 3; i++) dkim2_mi_free(f[i]);
    }
    printf("test_null_body: all passed\n");
    return 0;
}
