package dkim2

import "testing"

func TestNullHeaderRecipeRejected(t *testing.T) {
	// draft-03 §5.1: "h": null is no longer permitted.
	if _, err := parseRecipe([]byte(`{"h":null,"b":[{"c":[1,1]}]}`)); err == nil {
		t.Fatal("null header recipe must be rejected (draft-03 §5.1)")
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
