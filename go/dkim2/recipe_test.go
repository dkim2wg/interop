package dkim2

import (
	"strings"
	"testing"
)

// Recipe header keys are always emitted lowercase (canonical form), regardless
// of the case supplied — header field names are case-insensitive.
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
