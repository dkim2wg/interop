#include "tagparse.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static char *strdup_trim(const char *s, const char *end) {
    while (s < end && isspace((unsigned char)*s)) s++;
    while (end > s && isspace((unsigned char)end[-1])) end--;
    size_t n = (size_t)(end - s);
    char *r = malloc(n + 1);
    if (!r) return NULL;
    memcpy(r, s, n);
    r[n] = '\0';
    return r;
}

taglist_t *tagparse(const char *input, const char **errp) {
    taglist_t *tl = calloc(1, sizeof *tl);
    if (!tl) return NULL;
    tag_entry_t **tail = &tl->head;
    const char *p = input;
    while (*p) {
        /* Skip leading whitespace */
        while (isspace((unsigned char)*p)) p++;
        if (!*p) break;
        /* Find '=' */
        const char *name_start = p;
        while (*p && *p != '=' && *p != ';') p++;
        if (*p != '=') {
            /* bare semicolons or trailing whitespace — skip */
            if (*p == ';') { p++; continue; }
            break;
        }
        const char *name_end = p++;
        /* Find end of value (next unquoted ';' or end of string) */
        const char *val_start = p;
        while (*p && *p != ';') p++;
        const char *val_end = p;
        if (*p == ';') p++;

        tag_entry_t *e = calloc(1, sizeof *e);
        if (!e) { taglist_free(tl); return NULL; }
        e->name  = strdup_trim(name_start, name_end);
        e->value = strdup_trim(val_start, val_end);
        if (!e->name || !e->value) { free(e->name); free(e->value); free(e); taglist_free(tl); return NULL; }
        /* Lowercase name in-place */
        for (char *c = e->name; *c; c++) *c = (char)tolower((unsigned char)*c);
        /* §8: "there MUST be only one of each kind" — flag any repeat. */
        for (tag_entry_t *o = tl->head; o; o = o->next)
            if (strcmp(o->name, e->name) == 0) { tl->duplicate = 1; break; }
        *tail = e;
        tail = &e->next;
    }
    (void)errp;
    return tl;
}

const char *tag_get(const taglist_t *tl, const char *name) {
    /* Build lowercase version of name for comparison */
    char lname[64];
    size_t i;
    for (i = 0; name[i] && i < sizeof lname - 1; i++)
        lname[i] = (char)tolower((unsigned char)name[i]);
    lname[i] = '\0';
    for (tag_entry_t *e = tl->head; e; e = e->next)
        if (strcmp(e->name, lname) == 0) return e->value;
    return NULL;
}

void taglist_free(taglist_t *tl) {
    if (!tl) return;
    for (tag_entry_t *e = tl->head, *next; e; e = next) {
        next = e->next;
        free(e->name);
        free(e->value);
        free(e);
    }
    free(tl);
}
