package dkim2

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestHeaderDiff(t *testing.T) {
	tests := map[string]struct {
		Old    string
		New    string
		Recipe string
	}{
		"reorder": {
			"reorder.old",
			"reorder.new",
			"reorder.want.json",
		},
		"deleted": {
			"deleted.old",
			"deleted.new",
			"deleted.want.json",
		},
		"ranges": {
			"ranges.old",
			"ranges.new",
			"ranges.want.json",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			oldMail := headerFromString(t, string(slurpDiff(t, tc.Old)))
			newMail := headerFromString(t, string(slurpDiff(t, tc.New)))
			recipeHeaders := diffHeaders(context.Background(), oldMail, newMail)

			wantRecipe := string(slurpDiff(t, tc.Recipe))
			gotB, err := json.Marshal(recipeHeaders)
			gotRecipe := string(gotB)
			if err != nil {
				t.Fatalf("failed to marshal recipe headers: %v", err)
			}
			//t.Log(gotRecipe)

			if diff := jsonDiff(wantRecipe, string(gotRecipe)); diff != "" {
				t.Errorf("header recipe mismatch (-want +got):\n%s", diff)
			}

			// If we apply the recipe to newMail we should get oldMail
			recipe := Recipe{
				HeaderRecipes: recipeHeaders,
			}
			got, err := recipe.Header(newMail)
			if err != nil {
				t.Errorf("failed to apply recipe header: %v", err)
			}
			_ = got
		})
	}
}

func slurpDiff(t testing.TB, filename string) []byte {
	data, err := os.ReadFile(filepath.Join("testdata", "diff", filename))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func jsonDiff(x, y string) string {
	xform := cmp.Transformer("JSONcmp", func(s string) (m map[string]interface{}) {
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			panic(fmt.Sprintf("json.Unmarshal(%s) got unexpected error %#v", s, err))
		}
		return m
	})
	opt := cmp.FilterPath(func(p cmp.Path) bool {
		for _, ps := range p {
			if tr, ok := ps.(cmp.Transform); ok && tr.Option() == xform {
				return false
			}
		}
		return true
	}, xform)
	return cmp.Diff(x, y, opt)
}
