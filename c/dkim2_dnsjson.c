#include "dkim2_dnsjson.h"
#include "dkim2_dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

static cJSON *g_dns_json = NULL;

/* qname is selector._domainkey.domain */
static char *dns_json_lookup(const char *qname) {
    if (!g_dns_json) return NULL;
    const char *marker = strstr(qname, "._domainkey.");
    if (!marker) return NULL;

    size_t sel_len = (size_t)(marker - qname);
    char selector[256];
    if (sel_len >= sizeof selector) return NULL;
    memcpy(selector, qname, sel_len);
    selector[sel_len] = '\0';

    const char *domain = marker + strlen("._domainkey.");
    cJSON *dom_obj = cJSON_GetObjectItemCaseSensitive(g_dns_json, domain);
    if (!dom_obj) return NULL;

    char key[512];
    snprintf(key, sizeof key, "%s._domainkey", selector);
    cJSON *records = cJSON_GetObjectItemCaseSensitive(dom_obj, key);
    if (!records || !cJSON_IsArray(records)) return NULL;
    cJSON *first = cJSON_GetArrayItem(records, 0);
    if (!first || !cJSON_IsArray(first)) return NULL;
    cJSON *txt = cJSON_GetArrayItem(first, 1);
    if (!txt || !cJSON_IsString(txt)) return NULL;
    return strdup(txt->valuestring);
}

void dkim2_dns_json_free(void) {
    if (dkim2_dns_override == dns_json_lookup) dkim2_dns_override = NULL;
    cJSON_Delete(g_dns_json);
    g_dns_json = NULL;
}

int dkim2_dns_json_load(const char *path, char *errbuf, size_t errbufsz) {
    FILE *jf = fopen(path, "r");
    if (!jf) { snprintf(errbuf, errbufsz, "cannot open %s", path); return -1; }
    fseek(jf, 0, SEEK_END);
    long jsize = ftell(jf);
    rewind(jf);
    if (jsize < 0) { fclose(jf); snprintf(errbuf, errbufsz, "cannot read %s", path); return -1; }
    char *jbuf = malloc((size_t)jsize + 1);
    if (!jbuf) { fclose(jf); snprintf(errbuf, errbufsz, "out of memory"); return -1; }
    size_t got = fread(jbuf, 1, (size_t)jsize, jf);
    fclose(jf);
    jbuf[got] = '\0';
    cJSON *j = cJSON_Parse(jbuf);
    free(jbuf);
    if (!j) { snprintf(errbuf, errbufsz, "failed to parse %s", path); return -1; }
    dkim2_dns_json_free();
    g_dns_json = j;
    dkim2_dns_override = dns_json_lookup;
    return 0;
}
