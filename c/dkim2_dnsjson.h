#include <stddef.h>
#pragma once
/* Test/harness DNS: load a dns.json ({ "domain": { "sel._domainkey":
   [["txt", "v=DKIM1;..."]], "_domainkey": [...] } }) and install it as
   dkim2_dns_txt_hook, so key lookups are answered from the file and fall
   through to live DNS for anything it does not hold, and Domain Policy
   Record lookups ("_domainkey") are answered from the file alone.  Returns 0 on success, -1 with errbuf set. */
int dkim2_dns_json_load(const char *path, char *errbuf, size_t errbufsz);
/* Release what dkim2_dns_json_load kept and remove the override. */
void dkim2_dns_json_free(void);
