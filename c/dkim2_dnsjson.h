#include <stddef.h>
#pragma once
/* Test/harness DNS: load a dns.json ({ "domain": { "sel._domainkey":
   [["txt", "v=DKIM1;..."]] } }) and install it as dkim2_dns_override, so key
   lookups are answered from the file and fall through to live DNS for
   anything it does not hold.  Returns 0 on success, -1 with errbuf set. */
int dkim2_dns_json_load(const char *path, char *errbuf, size_t errbufsz);
/* Release what dkim2_dns_json_load kept and remove the override. */
void dkim2_dns_json_free(void);
