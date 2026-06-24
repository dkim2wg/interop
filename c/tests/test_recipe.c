#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "../dkim2_recipe.h"

int main(void) {
    size_t out_len;

    /* Body recipe: copy lines 1-2 of 3-line body */
    const char *body = "Line1\r\nLine2\r\nLine3\r\n";
    const char *r1 = "{\"b\":[{\"c\":[1,2]}]}";
    char *result = dkim2_apply_body_recipe(r1, body, strlen(body), &out_len);
    assert(result != NULL);
    assert(out_len == strlen("Line1\r\nLine2\r\n"));
    assert(memcmp(result, "Line1\r\nLine2\r\n", out_len) == 0);
    free(result);

    /* Body recipe: data step emits new lines */
    const char *r2 = "{\"b\":[{\"d\":[\"Hello\",\"World\"]}]}";
    result = dkim2_apply_body_recipe(r2, body, strlen(body), &out_len);
    assert(result != NULL);
    assert(memcmp(result, "Hello\r\nWorld\r\n", out_len) == 0);
    free(result);

    /* Body recipe: null b= means body unchanged */
    const char *r3 = "{\"b\":null}";
    result = dkim2_apply_body_recipe(r3, body, strlen(body), &out_len);
    assert(result != NULL);
    assert(out_len == strlen(body));
    assert(memcmp(result, body, out_len) == 0);
    free(result);

    /* Body recipe: empty recipe {} means body unchanged */
    const char *r4 = "{}";
    result = dkim2_apply_body_recipe(r4, body, strlen(body), &out_len);
    assert(result != NULL);
    assert(out_len == strlen(body));
    free(result);

    /* Body recipe: mixed copy and data steps */
    const char *r5 = "{\"b\":[{\"c\":[1,1]},{\"d\":[\"New\"]},{\"c\":[3,3]}]}";
    result = dkim2_apply_body_recipe(r5, body, strlen(body), &out_len);
    assert(result != NULL);
    assert(memcmp(result, "Line1\r\nNew\r\nLine3\r\n", out_len) == 0);
    free(result);

    /* Body recipe generation: identical bodies */
    const char *b1 = "Hello\r\nWorld\r\n";
    int impossible = 0;
    char *recipe = dkim2_gen_body_recipe(b1, strlen(b1), b1, strlen(b1), &impossible);
    assert(recipe != NULL);
    assert(impossible == 0);
    assert(strcmp(recipe, "{}") == 0);
    free(recipe);

    /* Body recipe generation: different bodies — round-trip */
    const char *old_body = "Line1\r\nLine2\r\nLine3\r\n";
    const char *new_body = "Line1\r\nChanged\r\nLine3\r\n";
    recipe = dkim2_gen_body_recipe(old_body, strlen(old_body), new_body, strlen(new_body), &impossible);
    assert(recipe != NULL);
    assert(impossible == 0);
    /* Apply generated recipe to old_body; should yield new_body */
    result = dkim2_apply_body_recipe(recipe, old_body, strlen(old_body), &out_len);
    free(recipe);
    assert(result != NULL);
    assert(out_len == strlen(new_body));
    assert(memcmp(result, new_body, out_len) == 0);
    free(result);

    /* Header recipe: remove all instances of a field */
    char *hdrs[] = {
        (char *)"From: alice@example.com\r\n",
        (char *)"Subject: Hello\r\n",
        (char *)"X-Custom: value\r\n",
        NULL
    };
    int n_out = 0;
    char **new_hdrs = dkim2_apply_header_recipe(
        "{\"h\":{\"x-custom\":[]}}", hdrs, 3, &n_out);
    assert(new_hdrs != NULL);
    assert(n_out == 2);
    /* Check that x-custom is gone */
    for (int i = 0; i < n_out; i++)
        assert(strstr(new_hdrs[i], "X-Custom") == NULL);
    for (int i = 0; i < n_out; i++) free(new_hdrs[i]);
    free(new_hdrs);

    /* draft-03 §5.1: a null header recipe must be rejected (returns NULL) */
    int n_null = 0;
    char **null_h = dkim2_apply_header_recipe("{\"h\":null}", hdrs, 3, &n_null);
    assert(null_h == NULL);

    puts("recipe: all tests passed");
    return 0;
}
