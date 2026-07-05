package dkim2

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoStaleSpecVersion(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "version_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, tok := range []string{"draft-01", "draft-02", "draft-03"} {
			if strings.Contains(string(b), tok) {
				t.Errorf("%s contains stale %q", f, tok)
			}
		}
	}
}
