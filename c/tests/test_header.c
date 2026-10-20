#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "../dkim2_header.h"
#include "../dkim2_verify.h"
#include "../base64.h"

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

    /* -07 §9.3: an algorithm MUST NOT be present more than once */
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

    /* Folding whitespace inside tag values (-07 §2.12): FWS may appear
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
       PERMERROR saying so; a missing required tag is "tag=<y> missing" (-07 §14.2). */
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
        /* C6: a missing i= is "i= tag=i missing"; one that is not a
           positive integer is "i=<as written> syntax error". */
        static const char *bad_i_want[] = {
            "PERMERROR: DKIM2-Signature i= tag=i missing",
            "PERMERROR: DKIM2-Signature i= syntax error",
            "PERMERROR: DKIM2-Signature i=0 syntax error",
            "PERMERROR: DKIM2-Signature i=abc syntax error",
            "PERMERROR: DKIM2-Signature i=-1 syntax error",
            "PERMERROR: DKIM2-Signature i=+1 syntax error",
            "PERMERROR: DKIM2-Signature i=1x syntax error",
        };
        char eb[256];
        for (int k = 0; bad_i[k]; k++) {
            assert(dkim2_sig_parse(bad_i[k]) == NULL);
            assert(dkim2_sig_parse_err(bad_i[k], eb, sizeof eb) == NULL);
            assert(strcmp(eb, bad_i_want[k]) == 0);
        }
        assert(dkim2_sig_parse_err("i=1; m=1; t=1; d=e.example", eb, sizeof eb) == NULL);
        assert(strcmp(eb, "PERMERROR: DKIM2-Signature i=1 tag=s missing") == 0);
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
        char eb[256], v[256], want[256];
        for (int k = 0; ok_n[k]; k++)
            assert(dkim2_chain_number_error("Message-Instance", "m", ok_n[k], NULL, eb, sizeof eb) == 0);
        assert(dkim2_chain_number_error("Message-Instance", "m", NULL, NULL, eb, sizeof eb) == 0);
        for (int k = 0; len_n[k]; k++) {
            assert(dkim2_chain_number_error("Message-Instance", "m", len_n[k], NULL, eb, sizeof eb) != 0);
            snprintf(want, sizeof want, "PERMERROR: Message-Instance m=%s exceeds the maximum chain length of 32", len_n[k]);
            assert(strcmp(eb, want) == 0);
        }
        for (int k = 0; mal_n[k]; k++) {
            assert(dkim2_chain_number_error("Message-Instance", "m", mal_n[k], NULL, eb, sizeof eb) != 0);
            snprintf(want, sizeof want, "PERMERROR: Message-Instance m=%s syntax error", mal_n[k]);
            assert(strcmp(eb, want) == 0);

            snprintf(v, sizeof v, "i=2; m=%s; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example", mal_n[k]);
            assert(dkim2_sig_parse(v) == NULL);
            assert(dkim2_sig_parse_err(v, eb, sizeof eb) == NULL);
            assert(strcmp(eb, "PERMERROR: DKIM2-Signature i=2 syntax error") == 0);

            snprintf(v, sizeof v, "m=%s; h=sha256:AAAA:BBBB", mal_n[k]);
            assert(dkim2_mi_parse(v) == NULL);
            assert(dkim2_mi_parse_err(v, eb, sizeof eb) == NULL);
            snprintf(want, sizeof want, "PERMERROR: Message-Instance m=%s syntax error", mal_n[k]);
            assert(strcmp(eb, want) == 0);
        }
        assert(dkim2_chain_number_error("DKIM2-Signature", "i", "abc", NULL, eb, sizeof eb) != 0);
        assert(strcmp(eb, "PERMERROR: DKIM2-Signature i=abc syntax error") == 0);

        static const char *const *bad_sets[] = { len_n, num_n };
        static const char *bad_why[] = { "length of 32", "number of 100" };
        for (int b = 0; b < 2; b++) {
            const char *const *bad_n = bad_sets[b];
            for (int k = 0; bad_n[k]; k++) {
                snprintf(v, sizeof v, "i=%s; m=2; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example", bad_n[k]);
                assert(dkim2_sig_parse(v) == NULL);
                assert(dkim2_sig_parse_err(v, eb, sizeof eb) == NULL);
                snprintf(want, sizeof want, "PERMERROR: DKIM2-Signature i=%s exceeds the maximum chain %s", bad_n[k], bad_why[b]);
                assert(strcmp(eb, want) == 0);

                snprintf(v, sizeof v, "i=2; m=%s; t=1; d=e.example; s=a:rsa-sha256:AA; nd=x.example", bad_n[k]);
                assert(dkim2_sig_parse(v) == NULL);
                assert(dkim2_sig_parse_err(v, eb, sizeof eb) == NULL);
                snprintf(want, sizeof want, "PERMERROR: DKIM2-Signature i=2 m=%s exceeds the maximum chain %s", bad_n[k], bad_why[b]);
                assert(strcmp(eb, want) == 0);

                snprintf(v, sizeof v, "m=%s; h=sha256:AAAA:BBBB", bad_n[k]);
                assert(dkim2_mi_parse(v) == NULL);
                assert(dkim2_mi_parse_err(v, eb, sizeof eb) == NULL);
                snprintf(want, sizeof want, "PERMERROR: Message-Instance m=%s exceeds the maximum chain %s", bad_n[k], bad_why[b]);
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

    /* -07 §10.10: f= flags parsed and round-tripped (incl. feedhere) */
    sig = dkim2_sig_parse(
        "i=1; m=1; t=1; d=ex.example; "
        "mf=PHVzZXJAZXhhbXBsZS5jb20+; rt=PGFAZXhhbXBsZS5jb20+; "
        "f=exploded,feedhere; s=sel1:rsa-sha256:AAAA");
    assert(sig != NULL);
    assert(sig->flags != NULL);
    assert(sig->flags[0] && strcmp(sig->flags[0], "exploded") == 0);
    assert(sig->flags[1] && strcmp(sig->flags[1], "feedhere") == 0);
    assert(sig->flags[2] == NULL);
    {
        char *out = dkim2_sig_format(sig, 1);
        assert(out != NULL);
        assert(strstr(out, "f=exploded,feedhere") != NULL);
        free(out);
    }
    dkim2_sig_free(sig);

    /* --- -07 §10.9: DKIM2-Signature s= duplicate/limit checks --- */
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
    assert(strcmp(errbuf, "PERMERROR: DKIM2-Signature i=3 has a duplicate selector") == 0);
    dkim2_sig_free(sig);

    /* ...detected case-insensitively (Selector is a Domain, -07 §3.6) */
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
    assert(strcmp(errbuf, "PERMERROR: DKIM2-Signature i=2 has more selectors than allowed") == 0);
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

    /* dkim2_sig_format / dkim2_mi_format of fields of any size: they used
       fixed 8192/4096-byte buffers (and 512 bytes per base64 address), and
       ran past them with many rt= values, a long address or a long r=. */
    {
        enum { N = 200 };
        static char raw[65536], line[160], enc[2048];
        char mf[600] = "<";
        /* 400 octets: within the parser's 512, but over 512 once in base64 */
        memset(mf + 1, 'x', 386);
        snprintf(mf + 387, sizeof mf - 387, "@example.com>");
        b64_encode((const unsigned char *)mf, strlen(mf), enc, sizeof enc);
        int pos = snprintf(raw, sizeof raw, "i=1; m=1; t=1; d=example.com; mf=%s; rt=", enc);
        for (int i = 0; i < N; i++) {
            snprintf(line, sizeof line, "<recipient-%03d-with-a-rather-long-local-part@dest.example>", i);
            b64_encode((const unsigned char *)line, strlen(line), enc, sizeof enc);
            pos += snprintf(raw + pos, sizeof raw - pos, "%s%s", i ? "," : "", enc);
        }
        snprintf(raw + pos, sizeof raw - pos, "; s=sel:ed25519-sha256:AAAA;");
        dkim2_sig_t *big = dkim2_sig_parse(raw);
        assert(big != NULL);
        char *out = dkim2_sig_format(big, 0);
        assert(out != NULL);
        dkim2_sig_t *back = dkim2_sig_parse(out);
        assert(back != NULL);
        int n = 0;
        while (back->rt && back->rt[n]) n++;
        assert(n == N);
        assert(strcmp(back->mf, mf) == 0);
        assert(strcmp(back->rt[N - 1], line) == 0);
        free(out);
        dkim2_sig_free(back);
        dkim2_sig_free(big);

        static char mraw[16384];
        int mp = snprintf(mraw, sizeof mraw, "m=2; h=sha256:AAAA:BBBB; r=");
        memset(mraw + mp, 'A', 10000);
        snprintf(mraw + mp + 10000, sizeof mraw - mp - 10000, ";");
        dkim2_mi_t *bigmi = dkim2_mi_parse(mraw);
        assert(bigmi != NULL);
        char *mout = dkim2_mi_format(bigmi);
        assert(mout != NULL && strlen(mout) == strlen(mraw));
        free(mout);
        dkim2_mi_free(bigmi);
    }

    puts("header: all tests passed");
    return 0;
}
