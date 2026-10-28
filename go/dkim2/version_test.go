package dkim2

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The code targets draft-ietf-dkim-dkim2-spec-08 (contract D13): no
// pointer into an older draft may remain, in the library, its tests or the
// commands, and "Validly Signed" is now "Fully Verified".  History notes
// that name the draft that made a change ("spec-05 §4 narrowed ...") are
// not pointers; the -07 ones are named below, each with the reason it
// stays.
// reDraft07 is a mention of draft -07 ("-07", "spec-07"), not a date's month.
var reDraft07 = regexp.MustCompile(`(^|[^0-9])-07([^0-9]|$)`)

func TestNoStaleSpecVersion(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	cmds, _ := filepath.Glob("../cmd/*/*.go")
	files = append(files, cmds...)
	if len(cmds) == 0 {
		t.Fatal("no command sources found under ../cmd")
	}
	// file -> lines holding "-07" that are history, not pointers.
	history := map[string][]string{
		"spec07_test.go": {
			// The suite written for the -07 contract (C1-C9), named for it.
			"// Shared behaviour tests for draft-ietf-dkim-dkim2-spec-07 (the U1..D1 table",
			"// of the -07 upgrade plan).",
			"// K1: -07 matched keys case-insensitively; -08 (contract D10) does not: an",
			"// ---- -07 error strings (contract C6), as -08 states them ----",
		},
		"spec08_test.go": {
			"// They reuse the -07 suite's fake DNS and signing helpers (spec07_test.go).",
		},
		"tagvalue.go": {
			// -08's ruling reverses the -07 contract's Decision 2.
			"// Tag names are case sensitive (§8; contract D10, reversing -07's",
		},
	}
	for _, f := range files {
		if strings.HasSuffix(f, "version_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, tok := range []string{"draft-01", "draft-02", "draft-03", "draft-06", "spec-06",
			"draft-07", "Validly Signed"} {
			if strings.Contains(string(b), tok) {
				t.Errorf("%s contains stale %q", f, tok)
			}
		}
	lines:
		for n, line := range strings.Split(string(b), "\n") {
			if !reDraft07.MatchString(line) {
				continue
			}
			for _, h := range history[filepath.Base(f)] {
				if strings.HasPrefix(strings.TrimSpace(line), h) {
					continue lines
				}
			}
			t.Errorf("%s:%d mentions -07: %s", f, n+1, strings.TrimSpace(line))
		}
	}
}
