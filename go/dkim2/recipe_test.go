package dkim2

import (
	"encoding/base64"
	"strings"
	"testing"
)

// -08 §5: the JSON keys MUST be lower case; header field names
// still match the message case-insensitively (§5.1).
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
	// §5 schema: "h" is an object, never null.
	if _, err := parseRecipe([]byte(`{"h":null,"b":[{"c":[1,1]}]}`)); err == nil {
		t.Fatal("null header recipe must be rejected (§5)")
	}
}

func TestNullBodyRecipeAllowed(t *testing.T) {
	// A null body Recipe is still permitted.
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
	// §14.2: JSON errors are called out specifically, not as a
	// generic syntax error.
	_, err := parseMI(`Message-Instance: m=2; h=sha256:AAAA:BBBB; r=eyJoIjog;`)
	if err == nil {
		t.Fatal("expected an error for malformed recipe JSON")
	}
	want := "PERMERROR: Message-Instance m=2 contains invalid JSON"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestNullHeaderRecipeIsInvalidJSON(t *testing.T) {
	// -08: a breach of the §5 schema above step level, such as "h": null, is reported as
	// "contains invalid JSON" like a JSON syntax error.
	_, err := parseMI(`Message-Instance: m=3; h=sha256:AAAA:BBBB; r=eyJoIjpudWxsfQ==;`)
	if err == nil || err.Error() != "PERMERROR: Message-Instance m=3 contains invalid JSON" {
		t.Fatalf("null header recipe: got %v", err)
	}
}

// A duplicate key anywhere in the Recipe JSON is invalid JSON: parsers
// disagree on which value wins (C's took the first, encoding/json the last),
// so {"b":[...],"b":null} was a null body Recipe to some verifiers and a real
// one to others.
func TestDuplicateRecipeKeyIsInvalidJSON(t *testing.T) {
	for _, raw := range []string{
		`{"b":[{"c":[1,1]}],"b":null}`, `{"b":null,"b":[{"c":[1,1]}]}`,
		`{"h":{"subject":[],"subject":[]}}`, `{"h":{"subject":[]},"h":{}}`,
		`{"h":{"subject":[],"subj\u0065ct":[]}}`,
	} {
		r := base64.StdEncoding.EncodeToString([]byte(raw))
		_, err := parseMI("Message-Instance: m=2; h=sha256:AAAA:BBBB; r=" + r + ";")
		if err == nil || err.Error() != "PERMERROR: Message-Instance m=2 contains invalid JSON" {
			t.Errorf("%s: err = %v", raw, err)
		}
	}
	if _, err := parseRecipe([]byte(`{"h":{"subject":[{"d":["b"]}],"to":[]},"b":[{"d":["b"]}]}`)); err != nil {
		t.Errorf("the same key in different objects: %v", err)
	}
}
