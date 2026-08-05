package dkim2

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBodyRecipe(t *testing.T) {
	tests := map[string]struct {
		New    string
		Old    string
		Recipe string
	}{
		"body": {
			New:    "body.new",
			Old:    "body.old",
			Recipe: "body.want.json",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			newBody := forceCRLF(slurpBody(t, tc.New))
			oldBody := forceCRLF(slurpBody(t, tc.Old))
			wantRecipe := string(slurpBody(t, tc.Recipe))

			recipeBody := diffBody(bytes.NewReader(oldBody), bytes.NewReader(newBody))
			gotB, err := json.Marshal(Recipe{BodyRecipes: recipeBody})
			gotRecipe := string(gotB)

			if err != nil {
				t.Fatalf("failed to marshal recipe body: %v", err)
			}
			//t.Log(gotRecipe)

			//fmt.Printf("newBody=%q\n", string(newBody))
			//fmt.Printf("oldBody=%q\n", string(oldBody))

			if diff := jsonDiff(wantRecipe, string(gotRecipe)); diff != "" {
				t.Errorf("body recipe mismatch (-want +got):\n%s", diff)
			}

			recipe := Recipe{
				BodyRecipes: recipeBody,
			}
			w := bytes.Buffer{}
			err = recipe.Body(bytes.NewReader(newBody), &w)
			if err != nil {
				t.Errorf("failed to apply recipe body: %v", err)
			}
			got := w.String()
			if diff := cmp.Diff(string(oldBody), got); diff != "" {
				t.Errorf("body result mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func forceCRLF(b []byte) []byte {
	return regexp.MustCompile(`\r?\n`).ReplaceAll(b, []byte("\r\n"))
}

func slurpBody(t testing.TB, filename string) []byte {
	data, err := os.ReadFile(filepath.Join("testdata", "body", filename))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
