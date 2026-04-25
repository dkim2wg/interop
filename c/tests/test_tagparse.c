#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../tagparse.h"

int main(void) {
    /* Basic parsing */
    taglist_t *tl = tagparse("i = 3 ; m=2;t=1234567890;d=example.com", NULL);
    assert(tl != NULL);
    assert(strcmp(tag_get(tl, "i"), "3") == 0);
    assert(strcmp(tag_get(tl, "m"), "2") == 0);
    assert(strcmp(tag_get(tl, "d"), "example.com") == 0);
    assert(tag_get(tl, "s") == NULL);
    taglist_free(tl);

    /* Case-insensitive tag names */
    tl = tagparse("D=example.com;S=sel1", NULL);
    assert(strcmp(tag_get(tl, "d"), "example.com") == 0);
    assert(strcmp(tag_get(tl, "D"), "example.com") == 0);
    assert(strcmp(tag_get(tl, "s"), "sel1") == 0);
    taglist_free(tl);

    /* Multi-char tag names (mf=, rt=) */
    tl = tagparse("mf=dXNlckBleGFtcGxlLmNvbQ==;rt=PGE+,PGI+", NULL);
    assert(strcmp(tag_get(tl, "mf"), "dXNlckBleGFtcGxlLmNvbQ==") == 0);
    assert(strcmp(tag_get(tl, "rt"), "PGE+,PGI+") == 0);
    taglist_free(tl);

    /* Value with whitespace is trimmed */
    tl = tagparse("k = rsa ; p = AAAA ", NULL);
    assert(strcmp(tag_get(tl, "k"), "rsa") == 0);
    assert(strcmp(tag_get(tl, "p"), "AAAA") == 0);
    taglist_free(tl);

    /* Trailing semicolon is OK */
    tl = tagparse("a=1;b=2;", NULL);
    assert(strcmp(tag_get(tl, "a"), "1") == 0);
    assert(strcmp(tag_get(tl, "b"), "2") == 0);
    taglist_free(tl);

    /* Empty string produces empty list */
    tl = tagparse("", NULL);
    assert(tl != NULL);
    assert(tag_get(tl, "x") == NULL);
    taglist_free(tl);

    puts("tagparse: all tests passed");
    return 0;
}
