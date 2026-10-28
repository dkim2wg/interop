#pragma once
#include <stddef.h>

/* Address domains, A-labels and the relaxed domain match (-08 §7.2, §18;
   contract C3). */

/* The domain of an RFC 5321 path or address ("<a@Example.COM.>",
   "a@b.example"): the text between the last '@' and the closing '>' (or the
   end), lowercased (ASCII), with one trailing dot removed. *is_literal is
   set when it is a domain literal ("[192.0.2.1]"). Returns 0, or -1 when
   there is no '@', the domain is empty, or it does not fit in out. */
int dkim2_domain_of(const char *addr, char *out, size_t outlen, int *is_literal);

/* The domain with every label that holds non-ASCII (UTF-8) octets
   lowercased and turned into "xn--" + Punycode (RFC 3492); ASCII labels
   are lowercased and kept. No other IDNA mapping is done. Returns 0, or -1
   for invalid UTF-8, a label Punycode cannot encode, or no room in out. */
int dkim2_to_alabel(const char *in, char *out, size_t outlen);

/* -08 §7.2: 1 when Parameter1 p1 equals p2 (caseless), or does after
   removing leftmost labels from p1 only; 0 otherwise, and always 0 when
   either is a domain literal (starts with '['). */
int dkim2_relaxed_match(const char *p1, const char *p2);

/* dkim2_domain_of() then dkim2_to_alabel(): the A-label domain of an
   address. Returns 0, or -1 (also for a domain literal, *is_literal set). */
int dkim2_addr_alabel(const char *addr, char *out, size_t outlen, int *is_literal);

/* The domain of the single mailbox in a From header field value (unfolded
   or not): "Name <a@b>", "a@b", with comments and quoted strings allowed.
   Written to out as an A-label, lowercased, one trailing dot removed.
   Returns 0, or -1 when the value is not exactly one mailbox (a list, a
   group, none at all) or its domain is a literal (-08 §11). */
int dkim2_from_domain(const char *value, char *out, size_t outlen);
