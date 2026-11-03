#include "dkim2_dnsjson.h"
#include "dkim2_dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <cjson/cJSON.h>

static cJSON *g_dns_json = NULL;

/* qname is selector._domainkey.domain (a key) or _domainkey.domain (a
   Domain Policy Record). Each entry of the name's list is one record,
   ["txt", "string", "string", ...]: its strings are concatenated (dns-00
   §3.4.2.2), and every TXT record is handed back, so the lookup sees what
   DNS would give it. A key name the file does not hold falls through to
   the next source (live DNS); for a policy name the file is the whole
   zone: no entry is no record (contract E3.3). */
static int dns_json_txt(const char *qname, dkim2_txt_t *out) {
    if (!g_dns_json) return 1;
    const char *domain, *key;
    size_t key_len;
    int policy = strncmp(qname, "_domainkey.", 11) == 0;
    if (policy) {
        domain = qname + 11;
        key = "_domainkey";
        key_len = 10;
    } else {
        const char *marker = strstr(qname, "._domainkey.");
        if (!marker) return 1;
        domain = marker + strlen("._domainkey.");
        key = qname;
        key_len = (size_t)(marker - qname) + strlen("._domainkey");
    }
    cJSON *dom_obj = cJSON_GetObjectItemCaseSensitive(g_dns_json, domain);
    cJSON *records = NULL;
    for (cJSON *c = dom_obj ? dom_obj->child : NULL; c && !records; c = c->next)
        if (c->string && strlen(c->string) == key_len && memcmp(c->string, key, key_len) == 0)
            records = c;
    if (!records || !cJSON_IsArray(records)) return policy ? 0 : 1;

    cJSON *rec;
    cJSON_ArrayForEach(rec, records) {
        if (!cJSON_IsArray(rec)) continue;
        cJSON *type = cJSON_GetArrayItem(rec, 0);
        if (!type || !cJSON_IsString(type) || strcasecmp(type->valuestring, "txt") != 0)
            continue;
        size_t len = 0;
        for (cJSON *str = type->next; str; str = str->next)
            if (cJSON_IsString(str)) len += strlen(str->valuestring);
        char *txt = malloc(len + 1);
        if (!txt) { dkim2_txt_free(out); return -1; }
        size_t pos = 0;
        for (cJSON *str = type->next; str; str = str->next)
            if (cJSON_IsString(str)) {
                size_t l = strlen(str->valuestring);
                memcpy(txt + pos, str->valuestring, l);
                pos += l;
            }
        int rc = dkim2_txt_push(out, txt, pos);
        free(txt);
        if (rc < 0) { dkim2_txt_free(out); return -1; }
    }
    return 0;
}

void dkim2_dns_json_free(void) {
    if (dkim2_dns_txt_hook == dns_json_txt) dkim2_dns_txt_hook = NULL;
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
    dkim2_dns_txt_hook = dns_json_txt;
    return 0;
}
