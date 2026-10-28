package dkim2

// Tests for draft-ietf-dkim-dkim2-spec-08, item by item of the contract
// (docs/superpowers/specs/2026-10-28-dkim2-spec-08-design.md, D1-D13).
// They reuse the -07 suite's fake DNS and signing helpers (spec07_test.go).

import (
	"bytes"
	"testing"
)

// ---- D10: tag names and JSON keys are strictly lowercase ----

func TestSpec08D10TagNamesStrictLowercase(t *testing.T) {
	// An uppercase tag name is an unknown tag: ignored, never a duplicate.
	tvl := parseTagValueList("m=1; M=2")
	if tvl.duplicate != "" || tvl.get("m") != "1" {
		t.Fatalf(`"m=1; M=2": duplicate %q, m=%q`, tvl.duplicate, tvl.get("m"))
	}
	if parseTagValueList("M=1").has("m") {
		t.Fatal(`"M=1" has no m= tag`)
	}

	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	skip := VerifyOptions{SkipTimestampCheck: true}
	for _, tc := range []struct {
		name     string
		from, to string
		want     string
	}{
		{"D= is not d=", "d=example.com;", "D=example.com;", "PERMERROR: DKIM2-Signature i=1 tag=d missing"},
		{"M= is not m=", "Message-Instance: m=1;", "Message-Instance: M=1;", "PERMERROR: Message-Instance m= tag=m missing"},
		{"T= twin is not a duplicate", "t=1740000000;", "t=1740000000; T=1;", "FAIL: DKIM2-Signature i=1 selector s07 incorrect signature"},
	} {
		msg := bytes.Replace(hop1, []byte(tc.from), []byte(tc.to), 1)
		if got := primary07(t, msg, skip); got != tc.want {
			t.Errorf("%s: primary %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSpec08D10JSONKeysStrictLowercase(t *testing.T) {
	const invalid = "PERMERROR: Message-Instance m=2 contains invalid JSON"
	for _, js := range []string{
		`{"B":null}`,
		`{"H":{"subject":[{"c":[1,1]}]}}`,
		`{"h":{"Subject":[{"c":[1,1]}]}}`,
		`{"b":[{"C":[1,1]}]}`,
		`{"b":[{"D":["x"]}]}`,
		`{"b":[],"X":1}`,
		// Duplicates are compared exactly, after unescaping.
		`{"b":null,"b":null}`,
	} {
		if _, err := parseMI(miWithRecipe(2, js)); err == nil || err.Error() != invalid {
			t.Errorf("parseMI(%s) = %v, want %q", js, err, invalid)
		}
	}
	// Non-ASCII letters are not judged.
	if _, err := parseMI(miWithRecipe(2, `{"h":{"x-É":[{"d":["v"]}]}}`)); err != nil {
		t.Errorf("a non-ASCII capital in a key: %v", err)
	}
}
