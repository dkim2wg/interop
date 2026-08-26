package dkim2

import (
	"strings"
	"testing"
)

// spec-05 §5.1: header field names in the JSON Recipes MUST be lower case
// (matching against the message stays case-insensitive).
func TestRecipeKeysLowercased(t *testing.T) {
	r := &Recipe{Headers: map[string][]RecipeStep{
		"List-ID": {}, "Reply-To": {}, "X-Weird-CASE": {},
	}}
	b, err := encodeRecipe(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"list-id"`, `"reply-to"`, `"x-weird-case"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	for _, bad := range []string{"List-ID", "Reply-To", "CASE"} {
		if strings.Contains(s, bad) {
			t.Errorf("unexpected mixed-case %q in %s", bad, s)
		}
	}
}

func TestNullHeaderRecipeRejected(t *testing.T) {
	// draft-04 §5.1: "h": null is no longer permitted.
	if _, err := parseRecipe([]byte(`{"h":null,"b":[{"c":[1,1]}]}`)); err == nil {
		t.Fatal("null header recipe must be rejected (draft-04 §5.1)")
	}
}

func TestNullBodyRecipeAllowed(t *testing.T) {
	// A null body recipe is still permitted.
	if _, err := parseRecipe([]byte(`{"b":null}`)); err != nil {
		t.Fatalf("null body recipe must still parse: %v", err)
	}
}

func TestAbsentHeaderRecipeAllowed(t *testing.T) {
	if _, err := parseRecipe([]byte(`{"b":[{"c":[1,1]}]}`)); err != nil {
		t.Fatalf("absent header recipe must parse: %v", err)
	}
}

func TestMalformedRecipeJSONIsSpecificPermerror(t *testing.T) {
	// spec-05 §11.2: JSON errors are called out specifically, not as a
	// generic syntax error.
	_, err := parseMI(`Message-Instance: m=2; h=sha256:AAA:BBB; r=eyJoIjog;`)
	if err == nil {
		t.Fatal("expected an error for malformed recipe JSON")
	}
	want := "PERMERROR Message-Instance m=2 contains invalid JSON"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestNullHeaderRecipeStaysDistinctFromInvalidJSON(t *testing.T) {
	// The §5.1 null-header-recipe rejection is valid JSON with an invalid
	// value; it must keep its own message, not be relabeled as the §11.2
	// invalid-JSON PERMERROR.
	_, err := parseMI(`Message-Instance: m=3; h=sha256:AAA:BBB; r=eyJoIjpudWxsfQ==;`)
	if err == nil {
		t.Fatal("expected an error for a null header recipe")
	}
	if strings.Contains(err.Error(), "contains invalid JSON") {
		t.Errorf("null header recipe wrongly reported as invalid JSON: %v", err)
	}
	if !strings.Contains(err.Error(), "null header recipe") {
		t.Errorf("got %q, want it to name the null header recipe", err.Error())
	}
}
