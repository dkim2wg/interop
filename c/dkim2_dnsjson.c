#include "dkim2_dnsjson.h"
#include "dkim2_dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <cjson/cJSON.h>

static cJSON *g_dns_json = NULL;

/* qname is selector._domainkey.domain. Each entry of the name's list is
   one record, ["txt", "string", "string", ...]: its strings are concatenated
   (dns-00 §3.4.2.2), and more than one TXT record is reported through
   *n_records so the key lookup sees what DNS would give it. */
static char *dns_json_lookup(const char *qname, int *n_records) {
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

    char *txt = NULL;
    int ntxt = 0;
    cJSON *rec;
    cJSON_ArrayForEach(rec, records) {
        if (!cJSON_IsArray(rec)) continue;
        cJSON *type = cJSON_GetArrayItem(rec, 0);
        if (!type || !cJSON_IsString(type) || strcasecmp(type->valuestring, "txt") != 0)
            continue;
        if (++ntxt > 1) continue;
        size_t len = 0;
        for (int i = 1; i < cJSON_GetArraySize(rec); i++) {
            cJSON *str = cJSON_GetArrayItem(rec, i);
            if (cJSON_IsString(str)) len += strlen(str->valuestring);
        }
        txt = malloc(len + 1);
        if (!txt) return NULL;
        txt[0] = '\0';
        for (int i = 1; i < cJSON_GetArraySize(rec); i++) {
            cJSON *str = cJSON_GetArrayItem(rec, i);
            if (cJSON_IsString(str)) strcat(txt, str->valuestring);
        }
    }
    if (ntxt == 0) return NULL;
    *n_records = ntxt;
    return txt;
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
