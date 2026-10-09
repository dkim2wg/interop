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

static int is_fws(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
static int is_alpha(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }

/* spec-06 §7, §8: split on ';'. An empty fragment (";;", a trailing ';')
   is skipped; any other must be
     [FWS] name [FWS] "=" [FWS] [value] [FWS]
   with name = ALPHA *(ALPHA / DIGIT / "_") and value =
   x-tag-char *([FWS] x-tag-char), x-tag-char = %x21-3A / %x3C-7E. Anything
   else sets tl->syntax_error: the caller rejects the whole field. A
   fragment that is not even name "=" is left out of the list. */
taglist_t *tagparse(const char *input, const char **errp) {
    taglist_t *tl = calloc(1, sizeof *tl);
    if (!tl) return NULL;
    tag_entry_t **tail = &tl->head;
    const char *p = input;
    while (*p) {
        const char *frag = p;
        while (*p && *p != ';') p++;
        const char *fend = p;
        if (*p == ';') p++;

        const char *q = frag;
        while (q < fend && is_fws(*q)) q++;
        if (q == fend) continue;                    /* empty fragment */
        const char *name_start = q;
        if (!is_alpha(*q)) { tl->syntax_error = 1; continue; }
        while (q < fend && (is_alpha(*q) || (*q >= '0' && *q <= '9') || *q == '_')) q++;
        const char *name_end = q;
        while (q < fend && is_fws(*q)) q++;
        if (q == fend || *q != '=') { tl->syntax_error = 1; continue; }
        const char *val_start = ++q;
        int bad = 0;
        for (; q < fend; q++)
            if (!is_fws(*q) && !((unsigned char)*q >= 0x21 && (unsigned char)*q <= 0x7E)) bad = 1;
        /* A bad value is still recorded, so a caller can name the tag
           (e.g. "malformed m= tag") -- the field is rejected either way. */
        if (bad) tl->syntax_error = 1;
        const char *val_end = fend;

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
