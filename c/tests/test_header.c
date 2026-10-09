#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "../dkim2_header.h"
#include "../dkim2_verify.h"

int main(void) {
    /* --- Message-Instance parsing --- */
    dkim2_mi_t *mi = dkim2_mi_parse("m=1; h=sha256:aGVhZGVy:Ym9keQ==");
    assert(mi != NULL);
    assert(mi->m == 1);
    assert(mi->n_hsets == 1);
    assert(strcmp(mi->hsets[0].alg, "sha256") == 0);
    assert(strcmp(mi->hsets[0].hdr_hash, "aGVhZGVy") == 0);
    assert(strcmp(mi->hsets[0].body_hash, "Ym9keQ==") == 0);
    assert(mi->r_raw == NULL);
    dkim2_mi_free(mi);

    /* MI with Recipe */
    mi = dkim2_mi_parse("m=2; h=sha256:aaa:bbb; r=e30=");
    assert(mi != NULL);
    assert(mi->m == 2);
    assert(mi->r_raw != NULL);
    assert(strcmp(mi->r_raw, "e30=") == 0);
    dkim2_mi_free(mi);

    /* MI with multiple hash sets (distinct algorithms) */
    mi = dkim2_mi_parse("m=1; h=sha256:hh1:bh1,sha512:hh2:bh2");
    assert(mi != NULL);
    assert(mi->n_hsets == 2);
    assert(strcmp(mi->hsets[1].hdr_hash, "hh2") == 0);
    dkim2_mi_free(mi);

    /* spec-06 §7.3: an algorithm MUST NOT be present more than once */
    assert(dkim2_mi_parse("m=1; h=sha256:AAA:BBB,sha256:CCC:DDD;") == NULL);
    /* ...detected case-insensitively (RFC 5234) */
    assert(dkim2_mi_parse("m=1; h=sha256:AAA:BBB,SHA256:CCC:DDD;") == NULL);
    /* ...but two different algorithms are fine */
    dkim2_mi_t *ok_mi = dkim2_mi_parse("m=1; h=sha256:AAA:BBB,sha512:CCC:DDD;");
    assert(ok_mi != NULL);
    assert(ok_mi->n_hsets == 2);
    dkim2_mi_free(ok_mi);

    /* --- DKIM2-Signature parsing --- */
    /* base64("<user@example.com>") = "PHVzZXJAZXhhbXBsZS5jb20+" */
    /* base64("<rcpt@example.org>") = "PHJjcHRAZXhhbXBsZS5vcmc+" */
    dkim2_sig_t *sig = dkim2_sig_parse(
        "i=1; m=1; t=1745798400; "
        "mf=PHVzZXJAZXhhbXBsZS5jb20+; "
        "rt=PHJjcHRAZXhhbXBsZS5vcmc+; "
        "d=example.com; "
        "s=sel1:rsa-sha256:AAAA");
    assert(sig != NULL);
    assert(sig->i == 1);
    assert(sig->m == 1);
    assert(sig->t == 1745798400ULL);
    assert(strcmp(sig->mf, "<user@example.com>") == 0);
    assert(sig->rt != NULL && sig->rt[0] != NULL);
    assert(strcmp(sig->rt[0], "<rcpt@example.org>") == 0);
    assert(sig->rt[1] == NULL);
    assert(strcmp(sig->d, "example.com") == 0);
    assert(sig->n_ssets == 1);
    assert(strcmp(sig->ssets[0].selector, "sel1") == 0);
    assert(strcmp(sig->ssets[0].alg, "rsa-sha256") == 0);
    assert(strcmp(sig->ssets[0].sig_b64, "AAAA") == 0);
    dkim2_sig_free(sig);

    /* Folding whitespace inside tag values (spec-06 §2.12): FWS may appear
       inside a base64 string and around the colons of an s= item, and MUST be
       ignored when the value is used.  A fold between the Selector colon and
       the algorithm token used to leave CRLF+TAB glued to the algorithm name. */
    sig = dkim2_sig_parse(
        "i=1; m=1; t=1745798400; "
        "mf=PHVzZXJAZXh\r\n\thbXBsZS5jb20+; "
        "rt=PHJjcHRAZXh\r\n\thbXBsZS5vcmc+; "
        "d=example.com; "
        "s=sel1:\r\n\trsa-sha256:\r\n\tAA\r\n\tAA");
    assert(sig != NULL);
    assert(strcmp(sig->mf, "<user@example.com>") == 0);
    assert(sig->rt != NULL && sig->rt[0] != NULL);
    assert(strcmp(sig->rt[0], "<rcpt@example.org>") == 0);
    assert(sig->n_ssets == 1);
    assert(strcmp(sig->ssets[0].selector, "sel1") == 0);
    assert(strcmp(sig->ssets[0].alg, "rsa-sha256") == 0);
    assert(strcmp(sig->ssets[0].sig_b64, "AAAA") == 0);
    dkim2_sig_free(sig);

    /* Same, folded with space-continuation rather than tab */
    sig = dkim2_sig_parse(
        "i=1; m=1; t=1745798400; "
        "mf=PHVzZXJAZXhhbXBsZS5jb20+; "
        "rt=PHJjcHRAZXhhbXBsZS5vcmc+; "
        "d=example.com; "
        "s=sel1:\r\n rsa-sha256:AAAA");
    assert(sig != NULL);
    assert(strcmp(sig->ssets[0].alg, "rsa-sha256") == 0);
    dkim2_sig_free(sig);

    /* Multiple rt= values */
    /* base64("<a@example.com>") = "PGFAZXhhbXBsZS5jb20+" */
    /* base64("<b@example.com>") = "PGJAZXhhbXBsZS5jb20+" */
    sig = dkim2_sig_parse(
        "i=2; m=2; t=1745798400; "
        "mf=PHVzZXJAZXhhbXBsZS5jb20+; "
        "rt=PGFAZXhhbXBsZS5jb20+,PGJAZXhhbXBsZS5jb20+; "
        "d=example.com; "
        "s=sel1:ed25519-sha256:BBBB");
    assert(sig != NULL);
    assert(sig->rt[0] != NULL && sig->rt[1] != NULL && sig->rt[2] == NULL);
    dkim2_sig_free(sig);

    /* i= must be a positive integer in ASCII digits; anything else is a
       PERMERROR saying so, and any other parse failure says "malformed". */
    {
        static const char *bad_i[] = {
            "m=2; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example",
            "i=; m=2; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example",
            "i=0; m=2; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example",
            "i=abc; m=2; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example",
            "i=-1; m=2; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example",
            "i=+1; m=2; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example",
            "i=1x; m=2; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example",
            NULL };
        char eb[256];
        for (int k = 0; bad_i[k]; k++) {
            assert(dkim2_sig_parse(bad_i[k]) == NULL);
            assert(dkim2_sig_parse_err(bad_i[k], eb, sizeof eb) == NULL);
            assert(strcmp(eb, "PERMERROR DKIM2-Signature has a missing or malformed i= tag") == 0);
        }
        assert(dkim2_sig_parse_err("i=1; m=1; t=1; d=e.example", eb, sizeof eb) == NULL);
        assert(strcmp(eb, "PERMERROR DKIM2-Signature is malformed") == 0);
        dkim2_sig_t *ok = dkim2_sig_parse_err(
            "i=3; m=2; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example", eb, sizeof eb);
        assert(ok && ok->i == 3 && eb[0] == '\0');
        dkim2_sig_free(ok);
    }

    /* Every i= and m= is a chain number: 1*DIGIT in ASCII (atoi() alone
       would take "4294967297x" as 4294967297 and " 1x" as 1), at most three
       digits naming 1..DKIM2_MAX_CHAIN_NUMBER (100), so "01" and "001" are
       1; and no more than DKIM2_MAX_CHAIN_LENGTH (32). Anything else is a
       PERMERROR saying so -- never atoi()'d into an overflowed or truncated
       number. */
    {
        assert(DKIM2_MAX_CHAIN_LENGTH == 32);
        assert(DKIM2_MAX_CHAIN_NUMBER == 100);
        static const char *ok_n[] = { "1", "9", "32", "01", "001", "032", NULL };
        static const char *len_n[] = { "33", "99", "100", NULL };
        static const char *num_n[] = { "101", "999", "0001", "4294967297",
            "99999999999999999999", NULL };
        static const char *mal_n[] = { "", "0", "000", "abc", "1x", "4294967297x",
            "30000000x", "0_1", "+1", "-1", "\xef\xbc\x91", NULL };
        char eb[256], v[256];
        for (int k = 0; ok_n[k]; k++)
            assert(dkim2_chain_number_error("Message-Instance", "m", ok_n[k], eb, sizeof eb) == 0);
        assert(dkim2_chain_number_error("Message-Instance", "m", NULL, eb, sizeof eb) == 0);
        for (int k = 0; len_n[k]; k++) {
            assert(dkim2_chain_number_error("Message-Instance", "m", len_n[k], eb, sizeof eb) != 0);
            assert(strcmp(eb, "PERMERROR Message-Instance m= exceeds the maximum chain length of 32") == 0);
        }
        for (int k = 0; mal_n[k]; k++) {
            assert(dkim2_chain_number_error("Message-Instance", "m", mal_n[k], eb, sizeof eb) != 0);
            assert(strcmp(eb, "PERMERROR Message-Instance has a malformed m= tag") == 0);

            snprintf(v, sizeof v, "i=2; m=%s; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example", mal_n[k]);
            assert(dkim2_sig_parse(v) == NULL);
            assert(dkim2_sig_parse_err(v, eb, sizeof eb) == NULL);
            assert(strcmp(eb, "PERMERROR DKIM2-Signature has a malformed m= tag") == 0);

            snprintf(v, sizeof v, "m=%s; h=sha256:AAAA:BBBB", mal_n[k]);
            assert(dkim2_mi_parse(v) == NULL);
            assert(dkim2_mi_parse_err(v, eb, sizeof eb) == NULL);
            assert(strcmp(eb, "PERMERROR Message-Instance has a malformed m= tag") == 0);
        }
        assert(dkim2_chain_number_error("DKIM2-Signature", "i", "abc", eb, sizeof eb) != 0);
        assert(strcmp(eb, "PERMERROR DKIM2-Signature has a missing or malformed i= tag") == 0);

        static const char *const *bad_sets[] = { len_n, num_n };
        static const char *bad_why[] = { "length of 32", "number of 100" };
        for (int b = 0; b < 2; b++) {
            const char *const *bad_n = bad_sets[b];
            char want[256];
            for (int k = 0; bad_n[k]; k++) {
                snprintf(v, sizeof v, "i=%s; m=2; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example", bad_n[k]);
                assert(dkim2_sig_parse(v) == NULL);
                assert(dkim2_sig_parse_err(v, eb, sizeof eb) == NULL);
                snprintf(want, sizeof want, "PERMERROR DKIM2-Signature i= exceeds the maximum chain %s", bad_why[b]);
                assert(strcmp(eb, want) == 0);

                snprintf(v, sizeof v, "i=2; m=%s; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example", bad_n[k]);
                assert(dkim2_sig_parse(v) == NULL);
                assert(dkim2_sig_parse_err(v, eb, sizeof eb) == NULL);
                snprintf(want, sizeof want, "PERMERROR DKIM2-Signature m= exceeds the maximum chain %s", bad_why[b]);
                assert(strcmp(eb, want) == 0);

                snprintf(v, sizeof v, "m=%s; h=sha256:AAAA:BBBB", bad_n[k]);
                assert(dkim2_mi_parse(v) == NULL);
                assert(dkim2_mi_parse_err(v, eb, sizeof eb) == NULL);
                snprintf(want, sizeof want, "PERMERROR Message-Instance m= exceeds the maximum chain %s", bad_why[b]);
                assert(strcmp(eb, want) == 0);
            }
        }
        dkim2_sig_t *s32 = dkim2_sig_parse_err(
            "i=32; m=32; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example", eb, sizeof eb);
        assert(s32 && s32->i == 32 && s32->m == 32 && eb[0] == '\0');
        dkim2_sig_free(s32);
        dkim2_sig_t *s001 = dkim2_sig_parse_err(
            "i=001; m=01; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example", eb, sizeof eb);
        assert(s001 && s001->i == 1 && s001->m == 1 && eb[0] == '\0');
        dkim2_sig_free(s001);
        dkim2_mi_t *m001 = dkim2_mi_parse_err("m=001; h=sha256:AAAA:BBBB", eb, sizeof eb);
        assert(m001 && m001->m == 1);
        dkim2_mi_free(m001);
    }

    /* Missing required tag → NULL */
    sig = dkim2_sig_parse("i=1; m=1; t=123; d=example.com; s=sel:rsa-sha256:XXX");
    assert(sig == NULL); /* neither nd= nor mf=+rt= present */

    /* draft-03 §8.7: nd= parsed, mf=/rt= absent */
    sig = dkim2_sig_parse(
        "i=2; m=2; t=1745798400; d=fwd.example; nd=mx.dest.example; "
        "s=sel1:rsa-sha256:AAAA");
    assert(sig != NULL);
    assert(sig->nd != NULL && strcmp(sig->nd, "mx.dest.example") == 0);
    assert(sig->mf == NULL && sig->rt == NULL);
    /* Format round-trip: nd= emitted, mf=/rt= omitted */
    {
        char *out = dkim2_sig_format(sig, 1);
        assert(out != NULL);
        assert(strstr(out, "nd=mx.dest.example") != NULL);
        assert(strstr(out, "mf=") == NULL);
        assert(strstr(out, "rt=") == NULL);
        free(out);
    }
    dkim2_sig_free(sig);

    /* draft-03 §8: nd= together with mf=/rt= → NULL (mutually exclusive) */
    sig = dkim2_sig_parse(
        "i=2; m=2; t=1; d=fwd.example; nd=mx.dest.example; "
        "mf=PHVzZXJAZXhhbXBsZS5jb20+; rt=PGFAZXhhbXBsZS5jb20+; "
        "s=sel1:rsa-sha256:AAAA");
    assert(sig == NULL);

    /* draft-03 §8.10: f= flags parsed and round-tripped (incl. feedhere) */
    sig = dkim2_sig_parse(
        "i=1; m=1; t=1; d=ex.example; "
        "mf=PHVzZXJAZXhhbXBsZS5jb20+; rt=PGFAZXhhbXBsZS5jb20+; "
        "f=donotmodify,feedhere; s=sel1:rsa-sha256:AAAA");
    assert(sig != NULL);
    assert(sig->flags != NULL);
    assert(sig->flags[0] && strcmp(sig->flags[0], "donotmodify") == 0);
    assert(sig->flags[1] && strcmp(sig->flags[1], "feedhere") == 0);
    assert(sig->flags[2] == NULL);
    {
        char *out = dkim2_sig_format(sig, 1);
        assert(out != NULL);
        assert(strstr(out, "f=donotmodify,feedhere") != NULL);
        free(out);
    }
    dkim2_sig_free(sig);

    /* --- spec-06 §8.9: DKIM2-Signature s= duplicate/limit checks --- */
    char errbuf[256];

    /* clean signature list has no errors */
    sig = dkim2_sig_parse(
        "i=1; m=1; t=1; d=ex.example; "
        "mf=PHVzZXJAZXhhbXBsZS5jb20+; rt=PGFAZXhhbXBsZS5jb20+; "
        "s=sel1:rsa-sha256:AAA,sel2:ed25519-sha256:BBB");
    assert(sig != NULL);
    assert(dkim2_sig_check_duplicates(sig, errbuf, sizeof errbuf) == 0);
    dkim2_sig_free(sig);

    /* a Selector MUST NOT repeat */
    sig = dkim2_sig_parse(
        "i=3; m=1; t=1; d=ex.example; "
        "mf=PHVzZXJAZXhhbXBsZS5jb20+; rt=PGFAZXhhbXBsZS5jb20+; "
        "s=sel1:rsa-sha256:AAA,sel1:ed25519-sha256:BBB");
    assert(sig != NULL);
    assert(dkim2_sig_check_duplicates(sig, errbuf, sizeof errbuf) == -1);
    assert(strcmp(errbuf, "PERMERROR DKIM2-Signature i=3 has a duplicate selector") == 0);
    dkim2_sig_free(sig);

    /* ...detected case-insensitively (Selector is a Domain, §3.5) */
    sig = dkim2_sig_parse(
        "i=1; m=1; t=1; d=ex.example; "
        "mf=PHVzZXJAZXhhbXBsZS5jb20+; rt=PGFAZXhhbXBsZS5jb20+; "
        "s=Sel1:rsa-sha256:AAA,sel1:ed25519-sha256:BBB");
    assert(sig != NULL);
    assert(dkim2_sig_check_duplicates(sig, errbuf, sizeof errbuf) == -1);
    assert(strstr(errbuf, "has a duplicate selector") != NULL);
    dkim2_sig_free(sig);

    /* same algorithm twice with distinct Selectors is allowed */
    sig = dkim2_sig_parse(
        "i=1; m=1; t=1; d=ex.example; "
        "mf=PHVzZXJAZXhhbXBsZS5jb20+; rt=PGFAZXhhbXBsZS5jb20+; "
        "s=sel1:rsa-sha256:AAA,sel2:rsa-sha256:BBB");
    assert(sig != NULL);
    assert(dkim2_sig_check_duplicates(sig, errbuf, sizeof errbuf) == 0);
    dkim2_sig_free(sig);

    /* three same-algorithm signatures exceed the selector limit */
    sig = dkim2_sig_parse(
        "i=2; m=1; t=1; d=ex.example; "
        "mf=PHVzZXJAZXhhbXBsZS5jb20+; rt=PGFAZXhhbXBsZS5jb20+; "
        "s=sel1:rsa-sha256:AAA,sel2:rsa-sha256:BBB,sel3:rsa-sha256:CCC");
    assert(sig != NULL);
    assert(dkim2_sig_check_duplicates(sig, errbuf, sizeof errbuf) == -1);
    assert(strcmp(errbuf, "PERMERROR DKIM2-Signature i=2 has more selectors than allowed") == 0);
    dkim2_sig_free(sig);

    /* duplicate-selector and excess-selector are independent: two sigs
       sharing algorithm AND selector is a duplicate-selector error, not
       an excess-selector error (the count is 2, not 3+) */
    sig = dkim2_sig_parse(
        "i=1; m=1; t=1; d=ex.example; "
        "mf=PHVzZXJAZXhhbXBsZS5jb20+; rt=PGFAZXhhbXBsZS5jb20+; "
        "s=sel1:rsa-sha256:AAA,sel1:rsa-sha256:BBB");
    assert(sig != NULL);
    assert(dkim2_sig_check_duplicates(sig, errbuf, sizeof errbuf) == -1);
    assert(strstr(errbuf, "duplicate selector") != NULL);
    assert(strstr(errbuf, "more selectors than allowed") == NULL);
    dkim2_sig_free(sig);

    puts("header: all tests passed");
    return 0;
}
