#pragma once
#include <stdio.h>
#include "dkim2_sign.h"
#include "dkim2_verify.h"

/* Sign a .eml file, writing the signed message to out.
   Output is: DKIM2-Signature header, Message-Instance header (if new),
   original headers, blank line, original body — all with CRLF line endings.
   Returns 0 on success, -1 on error (errbuf set). */
int dkim2_sign_message(const char *eml_path, FILE *out,
                       const dkim2_sign_config_t *cfg,
                       const char *mail_from, char **rcpt_to,
                       char *errbuf, size_t errbufsz);

/* Verify a .eml file. Parses headers + body, builds verify context,
   runs dkim2_do_verify, frees everything, returns result.
   DNS lookup uses the currently-registered dkim2_dns_override. */
dkim2_verify_result_t dkim2_verify_message(const char *eml_path,
                                            const char *mail_from,
                                            char **rcpt_to,
                                            int skip_timestamp_check);
