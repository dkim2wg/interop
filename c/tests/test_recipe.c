#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "../dkim2_recipe.h"

int main(void) {
    size_t out_len;

    /* spec-06 §5 schema: "c" items are integers >= 1. A copy range given as
       JSON strings -- {"c":["1","1"]}, which one list manager emitted -- or
       with a zero/negative/non-integer bound is a malformed Recipe and must be
       rejected, not applied. cJSON reports valueint 0 for a string, so the
       old code indexed lines[-1] and crashed (2026-10-04, replaying Sympa
       output through util/charset-corpus.sh). */
    {
        const char *b3 = "L1\r\nL2\r\nL3\r\n";
        size_t n;
        assert(dkim2_apply_body_recipe("{\"b\":[{\"c\":[\"1\",\"1\"]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"c\":[0,1]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"c\":[2,1]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"c\":[1.5,2]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"c\":[1]}]}", b3, strlen(b3), &n) == NULL);
        char *hdrs[] = { "Precedence: list\r\n", "Subject: x\r\n" };
        int n_out;
        assert(dkim2_apply_header_recipe("{\"h\":{\"precedence\":[{\"c\":[\"1\",\"1\"]}]}}", hdrs, 2, &n_out) == NULL);
        assert(dkim2_apply_header_recipe("{\"h\":{\"precedence\":[{\"c\":[0,0]}]}}", hdrs, 2, &n_out) == NULL);
        /* and the well-formed equivalent still works */
        char **ok = dkim2_apply_header_recipe("{\"h\":{\"precedence\":[{\"c\":[1,1]}]}}", hdrs, 2, &n_out);
        assert(ok != NULL && n_out == 2);
        for (int i = 0; i < n_out; i++) free(ok[i]);
        free(ok);
    }

    /* Body Recipe: copy lines 1-2 of 3-line body */
    const char *body = "Line1\r\nLine2\r\nLine3\r\n";
    const char *r1 = "{\"b\":[{\"c\":[1,2]}]}";
    char *result = dkim2_apply_body_recipe(r1, body, strlen(body), &out_len);
    assert(result != NULL);
    assert(out_len == strlen("Line1\r\nLine2\r\n"));
    assert(memcmp(result, "Line1\r\nLine2\r\n", out_len) == 0);
    free(result);

    /* Body Recipe: data step emits new lines */
    const char *r2 = "{\"b\":[{\"d\":[\"Hello\",\"World\"]}]}";
    result = dkim2_apply_body_recipe(r2, body, strlen(body), &out_len);
    assert(result != NULL);
    assert(memcmp(result, "Hello\r\nWorld\r\n", out_len) == 0);
    free(result);

    /* Body Recipe: null b= means body unchanged */
    const char *r3 = "{\"b\":null}";
    result = dkim2_apply_body_recipe(r3, body, strlen(body), &out_len);
    assert(result != NULL);
    assert(out_len == strlen(body));
    assert(memcmp(result, body, out_len) == 0);
    free(result);

    /* Body Recipe: empty Recipe {} means body unchanged */
    const char *r4 = "{}";
    result = dkim2_apply_body_recipe(r4, body, strlen(body), &out_len);
    assert(result != NULL);
    assert(out_len == strlen(body));
    free(result);

    /* Body Recipe: mixed copy and data steps */
    const char *r5 = "{\"b\":[{\"c\":[1,1]},{\"d\":[\"New\"]},{\"c\":[3,3]}]}";
    result = dkim2_apply_body_recipe(r5, body, strlen(body), &out_len);
    assert(result != NULL);
    assert(memcmp(result, "Line1\r\nNew\r\nLine3\r\n", out_len) == 0);
    free(result);

    /* Body Recipe generation: identical bodies */
    const char *b1 = "Hello\r\nWorld\r\n";
    int impossible = 0;
    char *recipe = dkim2_gen_body_recipe(b1, strlen(b1), b1, strlen(b1), &impossible);
    assert(recipe != NULL);
    assert(impossible == 0);
    assert(strcmp(recipe, "{}") == 0);
    free(recipe);

    /* Body Recipe generation: different bodies — round-trip */
    const char *old_body = "Line1\r\nLine2\r\nLine3\r\n";
    const char *new_body = "Line1\r\nChanged\r\nLine3\r\n";
    recipe = dkim2_gen_body_recipe(old_body, strlen(old_body), new_body, strlen(new_body), &impossible);
    assert(recipe != NULL);
    assert(impossible == 0);
    /* Apply generated Recipe to old_body; should yield new_body */
    result = dkim2_apply_body_recipe(recipe, old_body, strlen(old_body), &out_len);
    free(recipe);
    assert(result != NULL);
    assert(out_len == strlen(new_body));
    assert(memcmp(result, new_body, out_len) == 0);
    free(result);

    /* Header Recipe: remove all instances of a field */
    char *hdrs[] = {
        (char *)"From: alice@example.com\r\n",
        (char *)"Subject: Hello\r\n",
        (char *)"X-Custom: value\r\n",
        NULL
    };
    int n_out = 0;
    char **new_hdrs = dkim2_apply_header_recipe(
        "{\"h\":{\"x-custom\":[]}}", hdrs, 3, &n_out);
    assert(new_hdrs != NULL);
    assert(n_out == 2);
    /* Check that x-custom is gone */
    for (int i = 0; i < n_out; i++)
        assert(strstr(new_hdrs[i], "X-Custom") == NULL);
    for (int i = 0; i < n_out; i++) free(new_hdrs[i]);
    free(new_hdrs);

    /* draft-03 §5.1: a null header Recipe must be rejected (returns NULL) */
    int n_null = 0;
    char **null_h = dkim2_apply_header_recipe("{\"h\":null}", hdrs, 3, &n_null);
    assert(null_h == NULL);

    /* Header Recipe generation always emits lowercase keys (canonical form),
       regardless of the supplied field-name case. */
    char *new_only[] = { (char *)"List-ID: <l.example.com>\r\n", NULL };
    char *hr = dkim2_gen_header_recipe("List-ID", NULL, 0, new_only, 1);
    assert(hr != NULL);
    assert(strstr(hr, "\"list-id\"") != NULL);
    assert(strstr(hr, "List-ID") == NULL);
    free(hr);

    /* A Recipe naming SEVERAL header fields: removing the first one leaves a
       NULL hole in the working array (holes are only compacted at the very
       end), so every later lookup must tolerate them. Mailman Recipes name a
       dozen fields, so this is the normal case, not an edge case. */
    char *multi[] = {
        (char *)"From: alice@example.com\r\n",
        (char *)"Subject: [List] Hello\r\n",
        (char *)"List-Id: <l.example.com>\r\n",
        (char *)"Precedence: list\r\n",
        NULL
    };
    int n_multi = 0;
    char **red = dkim2_apply_header_recipe(
        "{\"h\":{\"list-id\":[],\"precedence\":[],"
        "\"subject\":[{\"d\":[\"Hello\"]}]}}", multi, 4, &n_multi);
    assert(red != NULL);
    assert(n_multi == 2);            /* From + rewritten Subject */
    int seen_from = 0, seen_subj = 0;
    for (int i = 0; i < n_multi; i++) {
        assert(strstr(red[i], "List-Id") == NULL);
        assert(strstr(red[i], "Precedence") == NULL);
        if (strstr(red[i], "From:")) seen_from = 1;
        if (strstr(red[i], "subject: Hello\r\n")) seen_subj = 1;
    }
    assert(seen_from && seen_subj);
    for (int i = 0; i < n_multi; i++) free(red[i]);
    free(red);

    /* ---- "c" range ordering (spec-06 §5.1, extended to body lists) and
       end-of-list bounds. Each start must exceed the previous end; an end
       past the last item is a rejection, not a clamp. ---- */
    {
        const char *b3 = "L1\r\nL2\r\nL3\r\n";
        size_t n;
        /* descending */
        assert(dkim2_apply_body_recipe("{\"b\":[{\"c\":[3,3]},{\"c\":[1,1]}]}", b3, strlen(b3), &n) == NULL);
        /* overlapping */
        assert(dkim2_apply_body_recipe("{\"b\":[{\"c\":[1,2]},{\"c\":[2,3]}]}", b3, strlen(b3), &n) == NULL);
        /* same range twice */
        assert(dkim2_apply_body_recipe("{\"b\":[{\"c\":[1,3]},{\"c\":[1,3]}]}", b3, strlen(b3), &n) == NULL);
        /* end beyond count (used to be silently clamped) */
        assert(dkim2_apply_body_recipe("{\"b\":[{\"c\":[1,4]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"c\":[4,4]}]}", b3, strlen(b3), &n) == NULL);
        /* ascending with a literal between is fine, and the literal does not
           reset the ordering constraint */
        char *r = dkim2_apply_body_recipe("{\"b\":[{\"c\":[1,1]},{\"d\":[\"x\"]},{\"c\":[3,3]}]}", b3, strlen(b3), &n);
        assert(r && n == 11 && memcmp(r, "L1\r\nx\r\nL3\r\n", n) == 0);
        free(r);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"c\":[2,2]},{\"d\":[\"x\"]},{\"c\":[1,1]}]}", b3, strlen(b3), &n) == NULL);

        char *hdrs3[] = { "X: top\r\n", "X: mid\r\n", "X: bot\r\n" };   /* bot = 1, top = 3 */
        int n_out;
        assert(dkim2_apply_header_recipe("{\"h\":{\"x\":[{\"c\":[2,2]},{\"c\":[1,1]}]}}", hdrs3, 3, &n_out) == NULL);
        assert(dkim2_apply_header_recipe("{\"h\":{\"x\":[{\"c\":[1,2]},{\"c\":[2,3]}]}}", hdrs3, 3, &n_out) == NULL);
        assert(dkim2_apply_header_recipe("{\"h\":{\"x\":[{\"c\":[1,4]}]}}", hdrs3, 3, &n_out) == NULL);
        assert(dkim2_apply_header_recipe("{\"h\":{\"x\":[{\"c\":[0,1]}]}}", hdrs3, 3, &n_out) == NULL);
        assert(dkim2_apply_header_recipe("{\"h\":{\"x\":[{\"c\":[1,\"2\"]}]}}", hdrs3, 3, &n_out) == NULL);
        /* a field with no instances: any copy is out of range */
        assert(dkim2_apply_header_recipe("{\"h\":{\"absent\":[{\"c\":[1,1]}]}}", hdrs3, 3, &n_out) == NULL);
        /* and a legal reorder-free selection works: keep 1 and 3, drop 2 */
        char **ok = dkim2_apply_header_recipe("{\"h\":{\"x\":[{\"c\":[1,1]},{\"c\":[3,3]}]}}", hdrs3, 3, &n_out);
        assert(ok && n_out == 2);
        assert(strcmp(ok[0], "X: top\r\n") == 0 && strcmp(ok[1], "X: bot\r\n") == 0);
        for (int i = 0; i < n_out; i++) free(ok[i]);
        free(ok);
    }

    /* ---- "b" steps: base64 literals carrying raw octets ---- */
    {
        const char *b3 = "L1\r\nL2\r\nL3\r\n";
        size_t n;
        /* "\xb1\xa4" = saQ=   "caf\xe9" = Y2Fm6Q== */
        char *r = dkim2_apply_body_recipe(
            "{\"b\":[{\"c\":[1,1]},{\"b\":[\"saQ=\",\"Y2Fm6Q==\"]},{\"c\":[3,3]}]}",
            b3, strlen(b3), &n);
        const char want[] = "L1\r\n\xb1\xa4\r\ncaf\xe9\r\nL3\r\n";
        assert(r != NULL);
        assert(n == sizeof want - 1);
        assert(memcmp(r, want, n) == 0);
        free(r);

        /* an empty "b" item is an empty line, like an empty "d" string */
        r = dkim2_apply_body_recipe("{\"b\":[{\"b\":[\"\"]}]}", b3, strlen(b3), &n);
        assert(r && n == 2 && memcmp(r, "\r\n", 2) == 0);
        free(r);

        /* rejections: not base64; whitespace inside; URL-safe alphabet;
           trailing junk after padding; decoded CR; decoded LF; non-string */
        assert(dkim2_apply_body_recipe("{\"b\":[{\"b\":[\"c@f=\"]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"b\":[\"sa Q=\"]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"b\":[\"sa-_\"]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"b\":[\"saQ=x\"]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"b\":[\"YQ1i\"]}]}", b3, strlen(b3), &n) == NULL);  /* a\rb */
        assert(dkim2_apply_body_recipe("{\"b\":[{\"b\":[\"YQpi\"]}]}", b3, strlen(b3), &n) == NULL);  /* a\nb */
        assert(dkim2_apply_body_recipe("{\"b\":[{\"b\":[\"YQ0K\"]}]}", b3, strlen(b3), &n) == NULL);  /* a\r\n */
        assert(dkim2_apply_body_recipe("{\"b\":[{\"b\":[1]}]}", b3, strlen(b3), &n) == NULL);

        /* header side: same bytes come back inside the field value */
        char *hdrs1[] = { "Subject: plain\r\n" };
        int n_out;
        char **hh = dkim2_apply_header_recipe(
            "{\"h\":{\"subject\":[{\"b\":[\"Y2Fm6Q==\"]},{\"d\":[\"ascii\"]},{\"b\":[\"saQ=\"]}]}}",
            hdrs1, 1, &n_out);
        assert(hh != NULL && n_out == 3);
        /* new values are bottom-up, so they land top-down reversed */
        assert(strcmp(hh[0], "subject: \xb1\xa4\r\n") == 0);
        assert(strcmp(hh[1], "subject: ascii\r\n") == 0);
        assert(strcmp(hh[2], "subject: caf\xe9\r\n") == 0);
        for (int i = 0; i < n_out; i++) free(hh[i]);
        free(hh);
        assert(dkim2_apply_header_recipe("{\"h\":{\"subject\":[{\"b\":[\"YQ1i\"]}]}}", hdrs1, 1, &n_out) == NULL);
        assert(dkim2_apply_header_recipe("{\"h\":{\"subject\":[{\"b\":[\"YQpi\"]}]}}", hdrs1, 1, &n_out) == NULL);
        assert(dkim2_apply_header_recipe("{\"h\":{\"subject\":[{\"b\":[\"!!\"]}]}}", hdrs1, 1, &n_out) == NULL);
    }

    /* ---- generation: 8-bit literals become "b" items, JSON stays 7-bit,
       and the result round-trips through apply ---- */
    {
        const char *old_b = "Line1\r\nLine2\r\nLine3\r\n";
        const char *new_b = "Line1\r\nLine2\r\ncaf\xe9\r\nascii\r\n\xb1\xa4\r\n";
        int imp = 0;
        char *rc = dkim2_gen_body_recipe(old_b, strlen(old_b), new_b, strlen(new_b), &imp);
        assert(rc && imp == 0);
        for (const char *p = rc; *p; p++) assert((unsigned char)*p < 0x80);
        assert(strstr(rc, "\"b\":[\"Y2Fm6Q==\"]") != NULL);
        assert(strstr(rc, "\"d\":[\"ascii\"]") != NULL);
        assert(strstr(rc, "\"b\":[\"saQ=\"]") != NULL);
        size_t n;
        char *r = dkim2_apply_body_recipe(rc, old_b, strlen(old_b), &n);
        assert(r && n == strlen(new_b) && memcmp(r, new_b, n) == 0);
        free(r);
        free(rc);

        /* consecutive 8-bit lines coalesce into one "b" step */
        const char *new_b2 = "caf\xe9\r\nth\xe9\r\n";
        rc = dkim2_gen_body_recipe(old_b, strlen(old_b), new_b2, strlen(new_b2), &imp);
        assert(rc && strstr(rc, "{\"b\":[{\"b\":[\"Y2Fm6Q==\",\"dGjp\"]}]}") != NULL);
        free(rc);

        /* header: an 8-bit value is a "b" item and applies back to the bytes */
        char *new_hdr[] = { "Subject: caf\xe9\r\n" };
        char *hr = dkim2_gen_header_recipe("Subject", NULL, 0, new_hdr, 1);
        assert(hr != NULL);
        for (const char *p = hr; *p; p++) assert((unsigned char)*p < 0x80);
        assert(strcmp(hr, "{\"h\":{\"subject\":[{\"b\":[\"Y2Fm6Q==\"]}]}}") == 0);
        int n_out;
        char **hh = dkim2_apply_header_recipe(hr, NULL, 0, &n_out);
        assert(hh && n_out == 1 && strcmp(hh[0], "subject: caf\xe9\r\n") == 0);
        free(hh[0]); free(hh); free(hr);

        /* a folded 8-bit value is emitted unfolded (no CR/LF in the literal),
           so what we generate is something our own apply will accept */
        char *folded[] = { "Subject: caf\xe9\r\n th\xe9\r\n" };
        hr = dkim2_gen_header_recipe("Subject", NULL, 0, folded, 1);
        assert(hr != NULL);
        hh = dkim2_apply_header_recipe(hr, NULL, 0, &n_out);
        assert(hh && n_out == 1 && strcmp(hh[0], "subject: caf\xe9 th\xe9\r\n") == 0);
        free(hh[0]); free(hh); free(hr);
    }

    /* ---- generation: reordered duplicate headers never produce a copy
       range that goes backwards; the displaced instance is a literal ---- */
    {
        /* bottom-up arrays: old = [A(1), B(2)], new = [B, A] */
        char *old_f[] = { "X: A\r\n", "X: B\r\n" };
        char *new_f[] = { "X: B\r\n", "X: A\r\n" };
        char *hr = dkim2_gen_header_recipe("X", old_f, 2, new_f, 2);
        assert(hr != NULL);
        assert(strcmp(hr, "{\"h\":{\"x\":[{\"c\":[2,2]},{\"d\":[\"A\"]}]}}") == 0);
        /* message top-down is B then A; after the Recipe it must be A then B */
        char *msg[] = { "X: B\r\n", "X: A\r\n" };
        int n_out;
        char **hh = dkim2_apply_header_recipe(hr, msg, 2, &n_out);
        assert(hh && n_out == 2);
        assert(strcmp(hh[0], "x: A\r\n") == 0 && strcmp(hh[1], "X: B\r\n") == 0);
        free(hh[0]); free(hh[1]); free(hh); free(hr);

        /* the same instance repeated: second occurrence must not re-copy */
        char *old_1[] = { "X: A\r\n" };
        char *new_dup[] = { "X: A\r\n", "X: A\r\n" };
        hr = dkim2_gen_header_recipe("X", old_1, 1, new_dup, 2);
        assert(hr && strcmp(hr, "{\"h\":{\"x\":[{\"c\":[1,1]},{\"d\":[\"A\"]}]}}") == 0);
        char *msg1[] = { "X: A\r\n" };
        hh = dkim2_apply_header_recipe(hr, msg1, 1, &n_out);
        assert(hh && n_out == 2);
        free(hh[0]); free(hh[1]); free(hh); free(hr);

        /* body: a block duplicated in the new body gets copied once, then
           emitted literally, so the generated Recipe is accepted by apply */
        const char *old_b = "a\r\nb\r\nc\r\n";
        const char *new_b = "a\r\nb\r\nc\r\na\r\nb\r\nc\r\n";
        int imp = 0;
        char *rc = dkim2_gen_body_recipe(old_b, strlen(old_b), new_b, strlen(new_b), &imp);
        assert(rc && imp == 0);
        assert(strcmp(rc, "{\"b\":[{\"c\":[1,3]},{\"d\":[\"a\",\"b\",\"c\"]}]}") == 0);
        size_t n;
        char *r = dkim2_apply_body_recipe(rc, old_b, strlen(old_b), &n);
        assert(r && n == strlen(new_b) && memcmp(r, new_b, n) == 0);
        free(r); free(rc);
    }

    /* ---- cross-implementation alignment: CR/LF in "d", canonical base64
       padding in "b", and empty literal arrays are all malformed ---- */
    {
        const char *b3 = "L1\r\nL2\r\nL3\r\n";
        char *hdrs1[] = { "Subject: plain\r\n" };
        size_t n;
        int n_out;
        /* (1) "d" item containing CR or LF */
        assert(dkim2_apply_body_recipe("{\"b\":[{\"d\":[\"a\\rb\"]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"d\":[\"a\\nb\"]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"d\":[\"ok\",\"a\\r\\n\"]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_header_recipe("{\"h\":{\"subject\":[{\"d\":[\"a\\rb\"]}]}}", hdrs1, 1, &n_out) == NULL);
        assert(dkim2_apply_header_recipe("{\"h\":{\"subject\":[{\"d\":[\"a\\nb\"]}]}}", hdrs1, 1, &n_out) == NULL);
        /* (2) "b" must be canonical padded base64: "QUI" rejected, "QUI=" ok */
        assert(dkim2_apply_body_recipe("{\"b\":[{\"b\":[\"QUI\"]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"b\":[\"QQ\"]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"b\":[\"QUJD=\"]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_header_recipe("{\"h\":{\"subject\":[{\"b\":[\"QUI\"]}]}}", hdrs1, 1, &n_out) == NULL);
        char *r = dkim2_apply_body_recipe("{\"b\":[{\"b\":[\"QUI=\",\"QQ==\",\"QUJD\"]}]}", b3, strlen(b3), &n);
        assert(r && n == 12 && memcmp(r, "AB\r\nA\r\nABC\r\n", n) == 0);
        free(r);
        /* (3) empty "d" or "b" array (schema minItems 1) */
        assert(dkim2_apply_body_recipe("{\"b\":[{\"d\":[]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"b\":[]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_body_recipe("{\"b\":[{\"c\":[1,1]},{\"d\":[]}]}", b3, strlen(b3), &n) == NULL);
        assert(dkim2_apply_header_recipe("{\"h\":{\"subject\":[{\"d\":[]}]}}", hdrs1, 1, &n_out) == NULL);
        assert(dkim2_apply_header_recipe("{\"h\":{\"subject\":[{\"b\":[]}]}}", hdrs1, 1, &n_out) == NULL);
        /* an empty step LIST is still the legal "remove all instances" */
        char **ok = dkim2_apply_header_recipe("{\"h\":{\"subject\":[]}}", hdrs1, 1, &n_out);
        assert(ok && n_out == 0);
        free(ok);
    }

    /* A duplicate key anywhere in the Recipe JSON is invalid: cJSON keeps
       the first of two equal keys and every other parser here the last, so
       {"b":[...],"b":null} was a null body Recipe to some verifiers and a
       real one to others. */
    {
        static const char *dup[] = {
            "{\"b\":[{\"c\":[1,1]}],\"b\":null}",
            "{\"b\":null,\"b\":[{\"c\":[1,1]}]}",
            "{\"h\":{\"subject\":[],\"subject\":[]}}",
            "{\"h\":{\"subject\":[]},\"h\":{}}",
            "{\"h\":{\"subject\":[],\"subj\\u0065ct\":[]}}",
            NULL };
        for (int k = 0; dup[k]; k++) {
            assert(dkim2_recipe_parse(dup[k]) == NULL);
            assert(dkim2_validate_body_recipe(dup[k]) == -1);
            size_t ol;
            assert(dkim2_apply_body_recipe(dup[k], "a\r\n", 3, &ol) == NULL);
        }
        struct cJSON *ok = dkim2_recipe_parse(
            "{\"h\":{\"subject\":[{\"d\":[\"b\"]}],\"to\":[]},\"b\":[{\"d\":[\"b\"]}]}");
        assert(ok);
        dkim2_recipe_free(ok);
    }

    /* ---- runs of identical fields (behaviour spec F.6): 16,000
       identical Comments: fields plus one added, exact recipes ---- */
    {
        enum { N = 16000 };
        char **old_f = malloc(N * sizeof *old_f);
        char **new_f = malloc((N + 1) * sizeof *new_f);
        for (int i = 0; i < N; i++) old_f[i] = "Comments: x\r\n";
        struct { int at; const char *want; } cases[] = {
            { N,     "{\"h\":{\"comments\":[{\"c\":[1,16000]},{\"d\":[\"y\"]}]}}" },
            { 0,     "{\"h\":{\"comments\":[{\"d\":[\"y\"]},{\"c\":[1,16000]}]}}" },
            { N / 2, "{\"h\":{\"comments\":[{\"c\":[1,8000]},{\"d\":[\"y\"]},{\"c\":[8001,16000]}]}}" },
            { -1,    "{\"h\":{\"comments\":[{\"c\":[1,16000]},{\"d\":[\"x\"]}]}}" },
        };
        for (size_t k = 0; k < sizeof cases / sizeof cases[0]; k++) {
            for (int i = 0, j = 0; i <= N; i++)
                new_f[i] = (i == cases[k].at) ? "Comments: y\r\n" : old_f[j < N ? j++ : N - 1];
            char *hr = dkim2_gen_header_recipe("Comments", old_f, N, new_f, N + 1);
            assert(hr);
            if (strcmp(hr, cases[k].want) != 0) { printf("  got %s\n", hr); assert(0); }
            free(hr);
        }
        free(old_f); free(new_f);
    }

    puts("recipe: all tests passed");
    return 0;
}
