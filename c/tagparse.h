#pragma once

typedef struct tag_entry {
    char *name;             /* tag name, as written (case sensitive) */
    char *value;            /* tag value (whitespace-trimmed) */
    struct tag_entry *next;
} tag_entry_t;

typedef struct {
    tag_entry_t *head;
    int duplicate; /* nonzero if a tag name appeared more than once, compared
                    exactly (-08 §8) */
    int syntax_error; /* nonzero if a non-empty fragment is not a well-formed
                         tag-spec (-08 §8) */
} taglist_t;

/* Parse "name=value; name=value; ..." tag list.
   Tag names are kept as written (-08 §8, contract D10). Values have leading/trailing whitespace stripped.
   errp (if non-NULL) is set to a static error string on failure.
   Returns allocated taglist_t, or NULL on allocation failure. */
taglist_t *tagparse(const char *input, const char **errp);

/* Return tag value (no copy — valid until taglist_free).
   Tag names match exactly: "M" is not "m".
   Returns NULL if tag not present. */
const char *tag_get(const taglist_t *tl, const char *name);

void taglist_free(taglist_t *tl);
