#pragma once
#include "dkim2_internal.h"

/* Every i= and m= names one hop, and a chain has at most this many. */
#define DKIM2_MAX_CHAIN_LENGTH 32

/* The largest number an i= or m= may be written as (at most three digits). */
#define DKIM2_MAX_CHAIN_NUMBER 100

/* 0 when v is a chain number, or NULL (an absent tag is left to the
   callers). Otherwise non-zero, with the PERMERROR written to errbuf:
   not 1*DIGIT in ASCII, or zero: "PERMERROR <field> has a malformed <tag>=
   tag" ("has a missing or malformed i= tag" for i=); more than three digits
   or above DKIM2_MAX_CHAIN_NUMBER: "PERMERROR <field> <tag>= exceeds the
   maximum chain number of 100"; above DKIM2_MAX_CHAIN_LENGTH: "... exceeds
   the maximum chain length of 32". "01" and "001" are 1; nothing is
   converted that could overflow. errbuf/errbufsz may be NULL/0. */
int dkim2_chain_number_error(const char *field, const char *tag, const char *v,
                             char *errbuf, size_t errbufsz);

/* Parse a Message-Instance header value (everything after "Message-Instance:").
   Tag names are case insignificant; a tag repeated in any case is a parse
   error ("PERMERROR Message-Instance m=<x> syntax error" via _err).
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
   missing or not a positive integer; the dkim2_chain_number_error() text
   when i= or m= is not a chain number; "PERMERROR DKIM2-Signature i=<x>
   syntax error" when t= is not 1*DIGIT (spec-06 §8.4); else "PERMERROR
   DKIM2-Signature is malformed". */
dkim2_sig_t *dkim2_sig_parse_err(const char *value, char *errbuf, size_t errbufsz);
void dkim2_sig_free(dkim2_sig_t *sig);

/* Format a DKIM2-Signature header value.
   If empty_sig is non-zero, s= signature values are set to "" (for §8.5 signing input).
   Caller frees. */
char *dkim2_sig_format(const dkim2_sig_t *sig, int empty_sig);
