#include <libmilter/mfapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include "dkim2_internal.h"
#include "dkim2_sign.h"
#include "dkim2_verify.h"
#include "dkim2_header.h"
#include "dkim2_plan.h"
#include "dkim2_prefetch.h"

/* Global config */
static struct {
    char *socket;
    char  mode;          /* 's'=sign, 'v'=verify, 'r'=revise */
    char *domain;
    char *selector;
    char *privkey_path;
    char *alg;
    char *authservid;    /* for Authentication-Results */
    int   allow_null_body_recipe; /* sign a chain with an UNSIGNED MI with a null body Recipe */
} g_cfg;

/* -07 §12.5 hint: a list manager that sends each recipient its own copy
   marks every copy with this header so the signer adds f=exploded. Its
   presence (any value; "yes" is what is sent) is the request; signing
   milters delete it before signing. */
#define EXPLODED_HINT "X-DKIM2-Exploded"

/* Per-message state */
typedef struct {
    dkim2_ctx_t ctx;
    int n_exploded_hint;    /* X-DKIM2-Exploded fields seen (sign modes) */
} conn_state_t;

static void state_reset(conn_state_t *s) {
    s->n_exploded_hint = 0;
    dkim2_ctx_t *c = &s->ctx;
    for (int i = 0; i < c->n_headers; i++) free(c->headers[i]);
    free(c->headers);
    dkim2_body_hasher_free(c->body_hasher);
    dkim2_plan_free(c->plan);
    dkim2_prefetch_free(c->prefetch);
    free(c->mail_from);
    if (c->rcpt_to) {
        for (int i = 0; i < c->n_rcpt; i++) free(c->rcpt_to[i]);
        free(c->rcpt_to);
    }
    dkim2_mi_free(c->mi_list);
    dkim2_sig_free(c->sig_list);
    memset(c, 0, sizeof *c);
}

static sfsistat cb_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr) {
    (void)hostname; (void)hostaddr;
    conn_state_t *s = calloc(1, sizeof *s);
    if (!s) return SMFIS_TEMPFAIL;
    smfi_setpriv(ctx, s);
    return SMFIS_CONTINUE;
}

static sfsistat cb_envfrom(SMFICTX *ctx, char **argv) {
    conn_state_t *s = smfi_getpriv(ctx);
    /* Reset per-message state on each new envelope */
    state_reset(s);
    s->ctx.mail_from = strdup(argv[0]);
    return SMFIS_CONTINUE;
}

static sfsistat cb_envrcpt(SMFICTX *ctx, char **argv) {
    conn_state_t *s = smfi_getpriv(ctx);
    dkim2_ctx_t *c = &s->ctx;
    int n = c->n_rcpt;
    c->rcpt_to = realloc(c->rcpt_to, (size_t)(n + 2) * sizeof(char *));
    c->rcpt_to[n]     = strdup(argv[0]);
    c->rcpt_to[n + 1] = NULL;
    c->n_rcpt++;
    return SMFIS_CONTINUE;
}

static sfsistat cb_header(SMFICTX *ctx, char *name, char *value) {
    conn_state_t *s = smfi_getpriv(ctx);
    dkim2_ctx_t *c = &s->ctx;

    /* The exploded hint is not part of the message we sign: count it and
       leave it out of the header fields (it is deleted at end of message). */
    if (g_cfg.mode != 'v' && strcasecmp(name, EXPLODED_HINT) == 0) {
        s->n_exploded_hint++;
        return SMFIS_CONTINUE;
    }

    /* Store "Name: value\r\n" */
    size_t hlen = strlen(name) + 2 + strlen(value) + 3;
    char *hdr = malloc(hlen);
    if (!hdr) return SMFIS_TEMPFAIL;
    snprintf(hdr, hlen, "%s: %s\r\n", name, value);

    if (c->n_headers >= c->hdr_cap) {
        int newcap = c->hdr_cap ? c->hdr_cap * 2 : 16;
        char **tmp = realloc(c->headers, (size_t)newcap * sizeof(char *));
        if (!tmp) { free(hdr); return SMFIS_TEMPFAIL; }
        c->headers = tmp;
        c->hdr_cap = newcap;
    }
    c->headers[c->n_headers++] = hdr;

    /* Parse DKIM2 headers as they arrive */
    if (strcasecmp(name, "Message-Instance") == 0) {
        char errbuf[256];
        dkim2_mi_t *mi = dkim2_mi_parse_err(value, errbuf, sizeof errbuf);
        if (mi) {
            dkim2_mi_t **tail = &c->mi_list;
            while (*tail) tail = &(*tail)->next;
            *tail = mi;
        } else if (errbuf[0] && !c->mi_error[0]) {
            /* Keep the first specific parse error; a later MI header
               failing for an unrelated reason shouldn't overwrite it. */
            snprintf(c->mi_error, sizeof c->mi_error, "%s", errbuf);
        }
    } else if (strcasecmp(name, "DKIM2-Signature") == 0) {
        char errbuf[256];
        dkim2_sig_t *sig = dkim2_sig_parse_err(value, errbuf, sizeof errbuf);
        if (sig) {
            dkim2_sig_t **tail = &c->sig_list;
            while (*tail) tail = &(*tail)->next;
            *tail = sig;
        } else if (!c->sig_error[0]) {
            /* Never skipped silently: dkim2_do_verify() PERMERRORs. */
            snprintf(c->sig_error, sizeof c->sig_error, "%s", errbuf);
        }
    }
    return SMFIS_CONTINUE;
}

static sfsistat cb_eoh(SMFICTX *ctx) {
    conn_state_t *s = smfi_getpriv(ctx);
    dkim2_ctx_t *c = &s->ctx;
    c->body_hasher = dkim2_body_hasher_new();
    if (!c->body_hasher) return SMFIS_TEMPFAIL;
    /* The header fields are all known: start the key lookups, and plan the
       Message-Instance chain walk so the body is checked as it streams in
       (both verifying and the signer gate use them). The body itself is
       never kept. */
    if (c->mi_list || c->sig_list) {
        c->prefetch = dkim2_prefetch_start(c);
        c->plan = dkim2_plan_new_ctx(c, 1);
        if (!c->plan) return SMFIS_TEMPFAIL;
    }
    return SMFIS_CONTINUE;
}

static sfsistat cb_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen) {
    conn_state_t *s = smfi_getpriv(ctx);
    dkim2_ctx_t *c = &s->ctx;
    if (dkim2_body_hasher_update(c->body_hasher, (const char *)bodyp, bodylen) < 0)
        return SMFIS_TEMPFAIL;
    if (c->plan && dkim2_plan_body_update(c->plan, (const char *)bodyp, bodylen) < 0)
        return SMFIS_TEMPFAIL;
    return SMFIS_CONTINUE;
}

/* smfi_setreply() text: printable, no CR/LF, and a '%' doubled (a single
   one makes libmilter ignore the text). */
static void set_reply(SMFICTX *ctx, const char *rcode, const char *xcode, const char *text) {
    char buf[1024];
    size_t o = 0;
    for (const char *p = text; *p && o + 3 < sizeof buf; p++) {
        unsigned char ch = (unsigned char)*p;
        if (ch == '%') { buf[o++] = '%'; buf[o++] = '%'; }
        else if (ch >= 0x20 && ch < 0x7F) buf[o++] = (char)ch;
        else buf[o++] = ' ';
    }
    buf[o] = '\0';
    if (smfi_setreply(ctx, (char *)rcode, (char *)xcode, buf) != MI_SUCCESS)
        syslog(LOG_WARNING, "dkim2-milter: smfi_setreply %s %s failed", rcode, xcode);
}

static sfsistat cb_eom(SMFICTX *ctx) {
    conn_state_t *s = smfi_getpriv(ctx);
    dkim2_ctx_t *c = &s->ctx;
    char ar_value[1024];

    /* Finalise body digests (every implemented algorithm) — no body buffer
       needed beyond this point */
    if (dkim2_body_hasher_final_all(c->body_hasher, &c->body_digests) < 0)
        return SMFIS_TEMPFAIL;
    dkim2_body_hasher_free(c->body_hasher);
    c->body_hasher = NULL;

    if (g_cfg.mode == 'v') {
        dkim2_verify_result_t result;
        dkim2_do_verify(c, &result);

        const char *outcome =
            (result.status == DKIM2_OK)        ? "pass" :
            (result.status == DKIM2_NONE)      ? "none" :
            (result.status == DKIM2_FAIL)       ? "fail" :
            (result.status == DKIM2_TEMPERROR)  ? "temperror" : "permerror";

        /* No DKIM2 header fields: dkim2=none, with no error string. */
        if (result.status == DKIM2_NONE)
            snprintf(ar_value, sizeof ar_value, "%s; dkim2=none",
                g_cfg.authservid ? g_cfg.authservid : "localhost");
        else
            snprintf(ar_value, sizeof ar_value, "%s; dkim2=%s (%s)",
                g_cfg.authservid ? g_cfg.authservid : "localhost",
                outcome, result.message);

        smfi_insheader(ctx, 0, "Authentication-Results", ar_value);

        /* -07 §13.2: signatures missing or not verifying are 550 5.7.1, a
           key that could not be fetched (DNS) 451 4.7.5, with the -07
           string as the reply text. */
        if (result.status == DKIM2_FAIL || result.status == DKIM2_PERMERROR) {
            syslog(LOG_INFO, "dkim2-milter: verify %s: %s", outcome, result.message);
            set_reply(ctx, "550", "5.7.1", result.message);
            return SMFIS_REJECT;
        }
        if (result.status == DKIM2_TEMPERROR) {
            syslog(LOG_INFO, "dkim2-milter: verify %s: %s", outcome, result.message);
            set_reply(ctx, "451", "4.7.5", result.message);
            return SMFIS_TEMPFAIL;
        }

    } else {
        /* Signer (and reviser: sign with new MI) */
        dkim2_sign_config_t cfg = {
            .domain       = g_cfg.domain,
            .selector     = g_cfg.selector,
            .privkey_path = g_cfg.privkey_path,
            .alg          = g_cfg.alg,
            .allow_null_body_recipe = g_cfg.allow_null_body_recipe,
            .exploded     = s->n_exploded_hint > 0,
        };
        char *mi_val = NULL, *sig_val = NULL;
        if (dkim2_do_sign(c, &cfg, &mi_val, &sig_val) != 0) {
            /* Signer refusal: an existing DKIM2 chain that does not verify
               (or a null body Recipe on an unsigned instance, without
               allow_null_body_recipe), or a From that is not Authentic for
               our domain. -07 §12/§13: such a message is not to be signed or
               forwarded, so it is rejected 550 5.7.1 with the reason (it
               used to be delivered unsigned). Every Message-Instance's body
               and header hashes are checked, by the plan fed in cb_body. */
            if (strncmp(c->errmsg, "not signing:", 12) == 0) {
                syslog(LOG_WARNING, "dkim2-milter: %s", c->errmsg);
                set_reply(ctx, "550", "5.7.1", c->errmsg);
                return SMFIS_REJECT;
            }
            syslog(LOG_ERR, "dkim2-milter: sign failed: %s", c->errmsg);
            return SMFIS_TEMPFAIL;
        }
        /* The hint is not passed on (deleted last instance first, so the
           indexes of the ones still to go do not move). */
        for (int k = s->n_exploded_hint; k >= 1; k--)
            smfi_chgheader(ctx, EXPLODED_HINT, k, NULL);
        if (mi_val) smfi_addheader(ctx, "Message-Instance", mi_val);   /* NULL: reused */
        smfi_addheader(ctx, "DKIM2-Signature",   sig_val);
        free(mi_val);
        free(sig_val);
    }

    return SMFIS_ACCEPT;
}

static sfsistat cb_abort(SMFICTX *ctx) {
    conn_state_t *s = smfi_getpriv(ctx);
    if (s) state_reset(s);
    return SMFIS_CONTINUE;
}

static sfsistat cb_close(SMFICTX *ctx) {
    conn_state_t *s = smfi_getpriv(ctx);
    if (s) {
        state_reset(s);
        free(s);
        smfi_setpriv(ctx, NULL);
    }
    return SMFIS_CONTINUE;
}

static struct smfiDesc smfilter = {
    "dkim2-milter",
    SMFI_VERSION,
    SMFIF_ADDHDRS | SMFIF_CHGHDRS,
    cb_connect,
    NULL,           /* helo */
    cb_envfrom,
    cb_envrcpt,
    cb_header,
    cb_eoh,
    cb_body,
    cb_eom,
    cb_abort,
    cb_close,
    NULL,           /* unknown */
    NULL,           /* data */
    NULL,           /* negotiate */
};

static void load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); exit(1); }
    char line[512];
    while (fgets(line, sizeof line, f)) {
        char *eq = strchr(line, '=');
        if (!eq || line[0] == '#') continue;
        *eq = '\0';
        char *k = line;
        char *v = eq + 1;
        v[strcspn(v, "\r\n")] = '\0';
        if      (strcmp(k, "socket")     == 0) g_cfg.socket     = strdup(v);
        else if (strcmp(k, "mode")       == 0) g_cfg.mode       = v[0];
        else if (strcmp(k, "domain")     == 0) g_cfg.domain     = strdup(v);
        else if (strcmp(k, "selector")   == 0) g_cfg.selector   = strdup(v);
        else if (strcmp(k, "privkey")    == 0) g_cfg.privkey_path = strdup(v);
        else if (strcmp(k, "alg")        == 0) g_cfg.alg        = strdup(v);
        else if (strcmp(k, "authservid") == 0) g_cfg.authservid = strdup(v);
        else if (strcmp(k, "allow_null_body_recipe") == 0)
            g_cfg.allow_null_body_recipe = (v[0] == '1' || v[0] == 'y' || v[0] == 'Y' || v[0] == 't' || v[0] == 'T');
    }
    fclose(f);

    if (!g_cfg.socket) { fprintf(stderr, "config: socket= required\n"); exit(1); }
    if (!g_cfg.mode)   { fprintf(stderr, "config: mode= required (s/v/r)\n"); exit(1); }
    if (g_cfg.mode == 's' || g_cfg.mode == 'r') {
        if (!g_cfg.domain)       { fprintf(stderr, "config: domain= required for signing\n"); exit(1); }
        if (!g_cfg.selector)     { fprintf(stderr, "config: selector= required for signing\n"); exit(1); }
        if (!g_cfg.privkey_path) { fprintf(stderr, "config: privkey= required for signing\n"); exit(1); }
    }
    if (!g_cfg.alg) g_cfg.alg = "ed25519-sha256";
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config-file>\n", argv[0]);
        return 1;
    }
    load_config(argv[1]);

    openlog("dkim2-milter", LOG_PID, LOG_MAIL);
    syslog(LOG_INFO, "starting in mode=%c", g_cfg.mode);

    if (smfi_setconn(g_cfg.socket) == MI_FAILURE) {
        fprintf(stderr, "smfi_setconn(%s) failed\n", g_cfg.socket);
        return 1;
    }
    if (smfi_register(smfilter) == MI_FAILURE) {
        fprintf(stderr, "smfi_register failed\n");
        return 1;
    }
    return smfi_main();
}
