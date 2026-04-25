#pragma once

typedef struct tag_entry {
    char *name;             /* lowercase tag name */
    char *value;            /* tag value (whitespace-trimmed) */
    struct tag_entry *next;
} tag_entry_t;

typedef struct { tag_entry_t *head; } taglist_t;

/* Parse "name=value; name=value; ..." tag list.
   Tag names are lowercased. Values have leading/trailing whitespace stripped.
   errp (if non-NULL) is set to a static error string on failure.
   Returns allocated taglist_t, or NULL on allocation failure. */
taglist_t *tagparse(const char *input, const char **errp);

/* Return tag value (no copy — valid until taglist_free).
   Tag name lookup is case-insensitive.
   Returns NULL if tag not present. */
const char *tag_get(const taglist_t *tl, const char *name);

void taglist_free(taglist_t *tl);
