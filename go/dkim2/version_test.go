package dkim2

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The code targets -07: no reference to an older draft may remain, in the
// library or the commands, except history notes that name the draft that
// made a change ("spec-05 §4 narrowed ...").
func TestNoStaleSpecVersion(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	cmds, _ := filepath.Glob("../cmd/*/*.go")
	files = append(files, cmds...)
	if len(cmds) == 0 {
		t.Fatal("no command sources found under ../cmd")
	}
	for _, f := range files {
		if strings.HasSuffix(f, "version_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, tok := range []string{"draft-01", "draft-02", "draft-03", "draft-06", "spec-06"} {
			if strings.Contains(string(b), tok) {
				t.Errorf("%s contains stale %q", f, tok)
			}
		}
	}
}
