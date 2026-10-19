#include "dkim2_domain.h"
int dkim2_domain_of(const char *addr, char *out, size_t outlen, int *is_literal) { (void)addr; (void)out; (void)outlen; (void)is_literal; return -1; }
int dkim2_to_alabel(const char *in, char *out, size_t outlen) { (void)in; (void)out; (void)outlen; return -1; }
int dkim2_relaxed_match(const char *p1, const char *p2) { (void)p1; (void)p2; return 0; }
int dkim2_addr_alabel(const char *addr, char *out, size_t outlen, int *is_literal) { (void)addr; (void)out; (void)outlen; (void)is_literal; return -1; }
int dkim2_from_domain(const char *value, char *out, size_t outlen) { (void)value; (void)out; (void)outlen; return -1; }
