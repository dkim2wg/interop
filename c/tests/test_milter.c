/* The milter's -07 behaviour (contract C2, C7), driven through its
   callbacks with a fake libmilter (tests/stub/libmilter/mfapi.h; the smfi_*
   functions below record what the milter asks for):
     - verify mode: no DKIM2 fields is A-R dkim2=none and accepted; a
       PERMERROR/FAIL is rejected 550 5.7.1 and a TEMPERROR 451 4.7.5, with
       the -07 string as the reply text;
     - sign mode: a signer refusal is rejected 550 5.7.1 with the reason
       (it used to be accepted unsigned); X-DKIM2-Exploded asks for
       f=exploded, is left out of the signed header fields and deleted;
       two recipients at i > 1 set f=exploded without it. */
#define main dkim2_milter_main
#define syslog test_syslog          /* records what the milter logs */
#include "../dkim2_milter.c"
#undef syslog
#undef main

#include "../dkim2_dns.h"
#include "../dkim2_message.h"
#include "../dkim2_crypto.h"
#include "../base64.h"
#include <openssl/pem.h>
#include <stdarg.h>

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

/* ---- fake libmilter ---- */

struct smfi_str {
    void *priv;
    char rcode[8], xcode[16], reply[1024];
    int n_add, n_ins, n_chg;
    char add[8][4096], ins[8][1024], chg[8][128];
};

int smfi_setpriv(SMFICTX *c, void *p) { c->priv = p; return MI_SUCCESS; }
void *smfi_getpriv(SMFICTX *c) { return c->priv; }
int smfi_setreply(SMFICTX *c, char *r, char *x, char *m) {
    snprintf(c->rcode, sizeof c->rcode, "%s", r);
    snprintf(c->xcode, sizeof c->xcode, "%s", x);
    snprintf(c->reply, sizeof c->reply, "%s", m);
    return MI_SUCCESS;
}
int smfi_addheader(SMFICTX *c, char *n, char *v) {
    if (c->n_add < 8) snprintf(c->add[c->n_add++], sizeof c->add[0], "%s: %s", n, v);
    return MI_SUCCESS;
}
int smfi_insheader(SMFICTX *c, int i, char *n, char *v) {
    (void)i;
    if (c->n_ins < 8) snprintf(c->ins[c->n_ins++], sizeof c->ins[0], "%s: %s", n, v);
    return MI_SUCCESS;
}
int smfi_chgheader(SMFICTX *c, char *n, int i, char *v) {
    if (c->n_chg < 8) snprintf(c->chg[c->n_chg++], sizeof c->chg[0], "%s[%d]=%s", n, i, v ? v : "(delete)");
    return MI_SUCCESS;
}
int smfi_setconn(char *s) { (void)s; return MI_SUCCESS; }
int smfi_register(struct smfiDesc d) { (void)d; return MI_SUCCESS; }
int smfi_main(void) { return MI_SUCCESS; }

/* ---- the log ---- */

static char g_log[8][512];
static int g_n_log;

void test_syslog(int prio, const char *fmt, ...) {
    (void)prio;
    va_list ap;
    va_start(ap, fmt);
    if (g_n_log < 8) vsnprintf(g_log[g_n_log++], sizeof g_log[0], fmt, ap);
    va_end(ap);
}

static int logged(const char *needle) {
    for (int i = 0; i < g_n_log; i++)
        if (strstr(g_log[i], needle)) return 1;
    return 0;
}

/* ---- keys and DNS ---- */

static const char *KEY = "/tmp/dkim2_test_milter.pem";
static char g_txt[256];
static int g_dns_fail;

static char *dns(const char *q, int *n) {
    if (g_dns_fail) { *n = -1; return NULL; }
    if (strncmp(q, "sel._domainkey.", 15) == 0) return strdup(g_txt);
    *n = 0;
    return NULL;
}

/* ---- one SMTP transaction through the callbacks ---- */

typedef struct { const char *name, *value; } hdr_t;

static sfsistat run(SMFICTX *c, const char *from, char **rcpts, const hdr_t *h, const char *body) {
    memset(c, 0, sizeof *c);
    cb_connect(c, "localhost", NULL);
    char *fa[] = { (char *)from, NULL };
    cb_envfrom(c, fa);
    for (int i = 0; rcpts[i]; i++) {
        char *ra[] = { rcpts[i], NULL };
        cb_envrcpt(c, ra);
    }
    for (int i = 0; h[i].name; i++) cb_header(c, (char *)h[i].name, (char *)h[i].value);
    cb_eoh(c);
    cb_body(c, (unsigned char *)body, strlen(body));
    sfsistat r = cb_eom(c);
    cb_close(c);
    return r;
}

static int added_with(const SMFICTX *c, const char *name, const char *needle) {
    for (int i = 0; i < c->n_add; i++)
        if (strncmp(c->add[i], name, strlen(name)) == 0 && strstr(c->add[i], needle)) return 1;
    return 0;
}

static void set_mode(char mode, const char *domain) {
    g_cfg.mode = mode;
    g_cfg.domain = (char *)domain;
    g_cfg.selector = "sel";
    g_cfg.privkey_path = (char *)KEY;
    g_cfg.alg = "ed25519-sha256";
    g_cfg.authservid = "mx.test";
}

int main(void) {
    EVP_PKEY *pk = NULL;
    EVP_PKEY_CTX *kc = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(kc);
    EVP_PKEY_keygen(kc, &pk);
    EVP_PKEY_CTX_free(kc);
    FILE *f = fopen(KEY, "w");
    PEM_write_PrivateKey(f, pk, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    unsigned char pub[32];
    size_t pl = sizeof pub;
    EVP_PKEY_get_raw_public_key(pk, pub, &pl);
    EVP_PKEY_free(pk);
    char p64[64];
    b64_encode(pub, pl, p64, sizeof p64);
    snprintf(g_txt, sizeof g_txt, "v=DKIM1; k=ed25519; p=%s", p64);
    dkim2_dns_override = dns;

    SMFICTX c;
    const char *body = "Hello\r\n";
    char *one[] = { "<list@lists.example.org>", NULL };
    hdr_t plain[] = { { "From", "a@example.com" }, { "To", "list@lists.example.org" },
                      { "Subject", "hi" }, { NULL, NULL } };

    /* verify: no DKIM2 fields -> none, accepted, no reply */
    set_mode('v', NULL);
    CHECK(run(&c, "<a@example.com>", one, plain, body) == SMFIS_ACCEPT);
    CHECK(c.n_ins == 1 && strcmp(c.ins[0], "Authentication-Results: mx.test; dkim2=none") == 0);
    CHECK(c.rcode[0] == '\0');

    /* sign mode, i=1: From not Authentic for d=, and no upstream DKIM2
       header fields -> delivered unsigned (as the Perl milters do), the
       hint removed, no reply */
    set_mode('s', "example.net");
    hdr_t plain_hint[] = { { "From", "a@example.com" }, { "To", "list@lists.example.org" },
                           { "Subject", "hi" }, { "X-DKIM2-Exploded", "yes" }, { NULL, NULL } };
    CHECK(run(&c, "<a@example.net>", one, plain_hint, body) == SMFIS_ACCEPT);
    CHECK(c.rcode[0] == '\0');
    CHECK(c.n_add == 0);
    CHECK(c.n_chg == 1 && strcmp(c.chg[0], "X-DKIM2-Exploded[1]=(delete)") == 0);
    /* ...and the log names the From domain against d= (final review I3) */
    CHECK(logged("From domain example.com is not d=example.net or below it"));
    g_n_log = 0;
    {   /* display text with no angle brackets: the field is logged */
        hdr_t bare[] = { { "From", "A a@example.com" }, { "Subject", "hi" }, { NULL, NULL } };
        CHECK(run(&c, "<a@example.net>", one, bare, body) == SMFIS_ACCEPT);
        CHECK(logged("From domain (not one mailbox: A a@example.com) is not d=example.net"));
        g_n_log = 0;
    }

    /* sign mode, i=1 by example.com (the hint is ignored at i=1) */
    set_mode('s', "example.com");
    hdr_t hinted1[] = { { "From", "a@example.com" }, { "To", "list@lists.example.org" },
                        { "Subject", "hi" }, { "X-DKIM2-Exploded", "yes" }, { NULL, NULL } };
    CHECK(run(&c, "<a@example.com>", one, hinted1, body) == SMFIS_ACCEPT);
    CHECK(c.n_add == 2 && added_with(&c, "DKIM2-Signature", "i=1;"));
    CHECK(!added_with(&c, "DKIM2-Signature", "exploded"));
    CHECK(c.n_chg == 1 && strcmp(c.chg[0], "X-DKIM2-Exploded[1]=(delete)") == 0);
    char mi1[4096], sig1[4096];
    snprintf(mi1, sizeof mi1, "%s", strchr(c.add[0], ':') + 2);
    snprintf(sig1, sizeof sig1, "%s", strchr(c.add[1], ':') + 2);
    if (strncmp(c.add[0], "DKIM2", 5) == 0) {            /* order not assumed */
        snprintf(sig1, sizeof sig1, "%s", strchr(c.add[0], ':') + 2);
        snprintf(mi1, sizeof mi1, "%s", strchr(c.add[1], ':') + 2);
    }

    /* the list hop, i=2, with the hint: f=exploded, hint deleted (twice
       here: last index first), and the result verifies */
    set_mode('s', "example.org");
    hdr_t hinted2[] = { { "DKIM2-Signature", sig1 }, { "Message-Instance", mi1 },
                        { "X-DKIM2-Exploded", "yes" },
                        { "From", "a@example.com" }, { "To", "list@lists.example.org" },
                        { "Subject", "hi" }, { "X-DKIM2-Exploded", "yes" }, { NULL, NULL } };
    char *dest[] = { "<r1@dest.example>", NULL };
    CHECK(run(&c, "<list-bounces@lists.example.org>", dest, hinted2, body) == SMFIS_ACCEPT);
    CHECK(added_with(&c, "DKIM2-Signature", "i=2;") && added_with(&c, "DKIM2-Signature", "f=exploded"));
    CHECK(c.n_chg == 2 && strcmp(c.chg[0], "X-DKIM2-Exploded[2]=(delete)") == 0 &&
          strcmp(c.chg[1], "X-DKIM2-Exploded[1]=(delete)") == 0);
    char sig2[4096] = "";
    for (int i = 0; i < c.n_add; i++)
        if (strncmp(c.add[i], "DKIM2-Signature", 15) == 0)
            snprintf(sig2, sizeof sig2, "%s", strchr(c.add[i], ':') + 2);

    /* ...which the verify milter accepts (envelope of the list hop) */
    set_mode('v', NULL);
    hdr_t signed2[] = { { "DKIM2-Signature", sig2 }, { "DKIM2-Signature", sig1 },
                        { "Message-Instance", mi1 },
                        { "From", "a@example.com" }, { "To", "list@lists.example.org" },
                        { "Subject", "hi" }, { NULL, NULL } };
    CHECK(run(&c, "<list-bounces@lists.example.org>", dest, signed2, body) == SMFIS_ACCEPT);
    CHECK(c.n_ins == 1 && strstr(c.ins[0], "dkim2=pass") != NULL);

    /* i=2 with two recipients and no hint: f=exploded anyway */
    set_mode('s', "example.org");
    hdr_t chain1[] = { { "DKIM2-Signature", sig1 }, { "Message-Instance", mi1 },
                       { "From", "a@example.com" }, { "To", "list@lists.example.org" },
                       { "Subject", "hi" }, { NULL, NULL } };
    char *two[] = { "<r1@dest.example>", "<r2@dest.example>", NULL };
    CHECK(run(&c, "<list-bounces@lists.example.org>", two, chain1, body) == SMFIS_ACCEPT);
    CHECK(added_with(&c, "DKIM2-Signature", "f=exploded") && c.n_chg == 0);
    /* ...and one recipient, no hint: no flag */
    CHECK(run(&c, "<list-bounces@lists.example.org>", dest, chain1, body) == SMFIS_ACCEPT);
    CHECK(added_with(&c, "DKIM2-Signature", "i=2;") && !added_with(&c, "DKIM2-Signature", "exploded"));

    /* a refusal with an upstream DKIM2-Signature is 550 5.7.1, not signed:
       example.net cannot sign a From changed to list@lists.example.org */
    set_mode('s', "example.net");
    {
        hdr_t moved[] = { { "DKIM2-Signature", sig1 }, { "Message-Instance", mi1 },
                          { "From", "a@example.org" }, { "To", "list@lists.example.org" },
                          { "Subject", "hi" }, { NULL, NULL } };
        CHECK(run(&c, "<b@example.net>", dest, moved, body) == SMFIS_REJECT);
        CHECK(strcmp(c.rcode, "550") == 0 && strcmp(c.xcode, "5.7.1") == 0);
        CHECK(strncmp(c.reply, "not signing:", 12) == 0);
        CHECK(c.n_add == 0);
    }
    /* a refusal on Message-Instances alone (no signature): delivered
       unsigned, the unsigned instances removed */
    {
        hdr_t mi_only[] = { { "Message-Instance", mi1 },
                            { "From", "a@example.com" }, { "To", "list@lists.example.org" },
                            { "Subject", "hi" }, { NULL, NULL } };
        CHECK(run(&c, "<a@example.net>", one, mi_only, body) == SMFIS_ACCEPT);
        CHECK(c.rcode[0] == '\0' && c.n_add == 0);
        CHECK(c.n_chg == 1 && strcmp(c.chg[0], "Message-Instance[1]=(delete)") == 0);
    }

    /* verify: a PERMERROR is 550 5.7.1 with the -07 string */
    set_mode('v', NULL);
    hdr_t unsigned_mi[] = { { "Message-Instance", mi1 }, { "From", "a@example.com" },
                            { "To", "list@lists.example.org" }, { "Subject", "hi" }, { NULL, NULL } };
    CHECK(run(&c, "<a@example.com>", one, unsigned_mi, body) == SMFIS_REJECT);
    CHECK(strcmp(c.rcode, "550") == 0 && strcmp(c.xcode, "5.7.1") == 0);
    CHECK(strcmp(c.reply, "PERMERROR: Message-Instance m=1 is not signed") == 0);

    /* verify: a FAIL (tampered body) is 550 5.7.1 too */
    CHECK(run(&c, "<a@example.com>", one, chain1, "Tampered\r\n") == SMFIS_REJECT);
    CHECK(strcmp(c.rcode, "550") == 0 && strcmp(c.reply, "FAIL: Message-Instance m=1 body hash sha256 mismatch") == 0);

    /* verify: a DNS failure is TEMPERROR, 451 4.7.5 */
    g_dns_fail = 1;
    CHECK(run(&c, "<a@example.com>", one, chain1, body) == SMFIS_TEMPFAIL);
    CHECK(strcmp(c.rcode, "451") == 0 && strcmp(c.xcode, "4.7.5") == 0);
    CHECK(strncmp(c.reply, "TEMPERROR: DKIM2-Signature i=1 public key sel could not be fetched", 66) == 0);
    g_dns_fail = 0;

    /* the reply text doubles '%' and drops control characters */
    set_reply(&c, "550", "5.7.1", "a%b\r\nc");
    CHECK(strcmp(c.reply, "a%%b  c") == 0);

    remove(KEY);
    if (g_fail) { printf("test_milter: %d failure(s)\n", g_fail); return 1; }
    printf("test_milter: all passed\n");
    return 0;
}
