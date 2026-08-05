package dkim2

import (
	"encoding/json"
	"maps"
	"net/mail"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRecipe_Header(t *testing.T) {
	tests := map[string]struct {
		recipe  string
		input   string
		want    string
		wantErr bool
	}{
		"no_change": {
			"no_change.json",
			"no_change.in",
			"no_change.want",
			false,
		},
		"cannot_recreate": {
			"cannot_recreate.json",
			"cannot_recreate.in",
			"cannot_recreate.want",
			false,
		},
		"preserve_unmentioned": {
			"preserve_unmentioned.json",
			"preserve_unmentioned.in",
			"preserve_unmentioned.want",
			false,
		},
		"copy_one": {
			"copy_one.json",
			"copy_one.in",
			"copy_one.want",
			false,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			recipeJson := slurpRecipe(t, tc.recipe)
			var discard any
			err := json.Unmarshal(recipeJson, &discard)
			if err != nil {
				t.Fatalf("invalid JSON in recipe: %v", err)
			}
			_ = discard

			var recipe Recipe
			err = json.Unmarshal(recipeJson, &recipe)
			if err != nil {
				t.Fatalf("failed to unmarshal recipe: %v", err)
			}

			input := headerFromString(t, string(slurpRecipe(t, tc.input)))
			want := headerFromString(t, string(slurpRecipe(t, tc.want)))

			got, err := recipe.Header(input)
			if (err != nil) != tc.wantErr {
				t.Errorf("recipe.Header() error = %v, wantErr %v", err, tc.wantErr)
			}

			// TODO(steve): use go-cmp
			wantString := headerToString(want)
			gotString := headerToString(got)
			if gotString != wantString {
				t.Errorf("recipe.Header() got = %v, want %v", gotString, wantString)
			}
		})
	}
}

func headerFromString(t testing.TB, s string) map[string][]string {
	if strings.HasPrefix(s, "<nil>") {
		return nil
	}
	msg, err := mail.ReadMessage(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	ret := make(map[string][]string, len(msg.Header))
	for k, v := range msg.Header {
		ret[strings.ToLower(k)] = v
	}
	return ret
}

func headerToString(h map[string][]string) string {
	if h == nil {
		return "<nil>\n"
	}
	var builder strings.Builder
	for _, key := range slices.Sorted(maps.Keys(h)) {
		for _, value := range h[key] {
			builder.WriteString(key)
			builder.WriteString(": ")
			builder.WriteString(value)
			builder.WriteString("\n")
		}
	}
	return builder.String()
}

func slurpRecipe(t testing.TB, filename string) []byte {
	data, err := os.ReadFile(filepath.Join("testdata", "recipe", filename))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
