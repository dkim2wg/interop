#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "../dkim2_header.h"

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

    /* MI with recipe */
    mi = dkim2_mi_parse("m=2; h=sha256:aaa:bbb; r=e30=");
    assert(mi != NULL);
    assert(mi->m == 2);
    assert(mi->r_raw != NULL);
    assert(strcmp(mi->r_raw, "e30=") == 0);
    dkim2_mi_free(mi);

    /* MI with multiple hash sets */
    mi = dkim2_mi_parse("m=1; h=sha256:hh1:bh1,sha256:hh2:bh2");
    assert(mi != NULL);
    assert(mi->n_hsets == 2);
    assert(strcmp(mi->hsets[1].hdr_hash, "hh2") == 0);
    dkim2_mi_free(mi);

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

    /* Missing required tag → NULL */
    sig = dkim2_sig_parse("i=1; m=1; t=123; d=example.com; s=sel:rsa-sha256:XXX");
    assert(sig == NULL); /* mf= missing */

    puts("header: all tests passed");
    return 0;
}
