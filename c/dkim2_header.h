#pragma once
#include "dkim2_internal.h"

/* Every i= and m= names one hop, and a chain has at most this many. */
#define DKIM2_MAX_CHAIN_LENGTH 32

/* Non-zero when v is ASCII digits naming a number above
   DKIM2_MAX_CHAIN_LENGTH, or longer than two digits (never converted, so it
   cannot overflow). Anything else -- NULL, empty, non-digits -- is 0: left to
   the syntax checks. The parsers below reject such an i= or m= with
   "PERMERROR <field> <tag>= exceeds the maximum chain length of 32". */
int dkim2_chain_number_out_of_range(const char *v);

/* Parse a Message-Instance header value (everything after "Message-Instance:").
   Returns allocated struct or NULL on parse error. */
dkim2_mi_t *dkim2_mi_parse(const char *value);

/* Same as dkim2_mi_parse, but on failure (NULL) writes a specific,
   reportable reason to errbuf when one applies (currently: spec-06 §7.3
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
/* As dkim2_sig_parse(); on failure errbuf gets the PERMERROR to report:
   "PERMERROR DKIM2-Signature has a missing or malformed i= tag" when i= is
   missing or not a positive integer; "PERMERROR DKIM2-Signature i= (or m=)
   exceeds the maximum chain length of 32" when one is out of range; else
   "PERMERROR DKIM2-Signature is malformed". */
dkim2_sig_t *dkim2_sig_parse_err(const char *value, char *errbuf, size_t errbufsz);
void dkim2_sig_free(dkim2_sig_t *sig);

/* Format a DKIM2-Signature header value.
   If empty_sig is non-zero, s= signature values are set to "" (for §8.5 signing input).
   Caller frees. */
char *dkim2_sig_format(const dkim2_sig_t *sig, int empty_sig);
