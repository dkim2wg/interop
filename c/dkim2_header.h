#pragma once
#include "dkim2_internal.h"

/* Parse a Message-Instance header value (everything after "Message-Instance:").
   Returns allocated struct or NULL on parse error. */
dkim2_mi_t *dkim2_mi_parse(const char *value);

/* Same as dkim2_mi_parse, but on failure (NULL) writes a specific,
   reportable reason to errbuf when one applies (currently: spec-05 §7.3
   duplicate hash algorithm in h=, formatted as the full PERMERROR string).
   errbuf is left as an empty string for any other failure (malloc/syntax) --
   those remain indistinguishable from "no Message-Instance present" to the
   caller, same as dkim2_mi_parse. errbuf/errbufsz may be NULL/0, in which
   case this behaves exactly like dkim2_mi_parse. */
dkim2_mi_t *dkim2_mi_parse_err(const char *value, char *errbuf, size_t errbufsz);

void dkim2_mi_free(dkim2_mi_t *mi);

/* Format a Message-Instance header value (caller frees). */
char *dkim2_mi_format(const dkim2_mi_t *mi);

/* Parse a DKIM2-Signature header value.
   mf= and rt= are base64-decoded into the struct.
   Returns allocated struct or NULL if any required tag is absent. */
dkim2_sig_t *dkim2_sig_parse(const char *value);
void dkim2_sig_free(dkim2_sig_t *sig);

/* Format a DKIM2-Signature header value.
   If empty_sig is non-zero, s= signature values are set to "" (for §8.5 signing input).
   Caller frees. */
char *dkim2_sig_format(const dkim2_sig_t *sig, int empty_sig);
