/* Minimal stand-in for libmilter's mfapi.h, for tests/test_milter.c: it
   compiles dkim2_milter.c against a fake libmilter (the test defines the
   smfi_* functions), so the milter's callbacks run without sendmail. */
#pragma once
#include <sys/socket.h>
typedef struct smfi_str SMFICTX;
typedef int sfsistat;
typedef struct sockaddr _SOCK_ADDR;
#define SMFIS_CONTINUE 0
#define SMFIS_REJECT 1
#define SMFIS_DISCARD 2
#define SMFIS_ACCEPT 3
#define SMFIS_TEMPFAIL 4
#define MI_SUCCESS 0
#define MI_FAILURE (-1)
#define SMFI_VERSION 2
#define SMFIF_ADDHDRS 0x01
#define SMFIF_CHGHDRS 0x10
struct smfiDesc {
    char *xxfi_name; int xxfi_version; unsigned long xxfi_flags;
    sfsistat (*xxfi_connect)(SMFICTX *, char *, _SOCK_ADDR *);
    sfsistat (*xxfi_helo)(SMFICTX *, char *);
    sfsistat (*xxfi_envfrom)(SMFICTX *, char **);
    sfsistat (*xxfi_envrcpt)(SMFICTX *, char **);
    sfsistat (*xxfi_header)(SMFICTX *, char *, char *);
    sfsistat (*xxfi_eoh)(SMFICTX *);
    sfsistat (*xxfi_body)(SMFICTX *, unsigned char *, size_t);
    sfsistat (*xxfi_eom)(SMFICTX *);
    sfsistat (*xxfi_abort)(SMFICTX *);
    sfsistat (*xxfi_close)(SMFICTX *);
    sfsistat (*xxfi_unknown)(SMFICTX *, const char *);
    sfsistat (*xxfi_data)(SMFICTX *);
    sfsistat (*xxfi_negotiate)(SMFICTX *, unsigned long, unsigned long, unsigned long, unsigned long,
                               unsigned long *, unsigned long *, unsigned long *, unsigned long *);
};
int smfi_setpriv(SMFICTX *, void *);
void *smfi_getpriv(SMFICTX *);
int smfi_setreply(SMFICTX *, char *, char *, char *);
int smfi_addheader(SMFICTX *, char *, char *);
int smfi_insheader(SMFICTX *, int, char *, char *);
int smfi_chgheader(SMFICTX *, char *, int, char *);
int smfi_setconn(char *);
int smfi_register(struct smfiDesc);
int smfi_main(void);
