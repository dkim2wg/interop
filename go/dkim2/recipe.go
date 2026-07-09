package dkim2

import (
	"encoding/json"
	"errors"
)

// RecipeStep is one step in a body or header recipe.
type RecipeStep struct {
	Copy *[2]int  `json:"c,omitempty"`
	Data []string `json:"d,omitempty"`
}

// Recipe describes changes made to a message at one hop.
type Recipe struct {
	Headers map[string][]RecipeStep `json:"h,omitempty"`
	Body    []RecipeStep            `json:"b,omitempty"`
}

func parseRecipe(data []byte) (*Recipe, error) {
	// draft-04 §5.1: an explicit JSON null for "h" is no longer permitted
	// (distinct from an absent "h", which means the headers were unchanged).
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err == nil {
		if v, ok := probe["h"]; ok && string(v) == "null" {
			return nil, errors.New("null header recipe not permitted (draft-04 §5.1)")
		}
	}
	var r Recipe
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func encodeRecipe(r *Recipe) ([]byte, error) {
	// Header field names are case-insensitive; always emit recipe (h) keys in
	// canonical lowercase form (not yet mandated by the draft, but we do it).
	if len(r.Headers) > 0 {
		lower := make(map[string][]RecipeStep, len(r.Headers))
		for k, v := range r.Headers {
			lower[lowerName(k)] = v
		}
		rc := *r
		rc.Headers = lower
		return json.Marshal(&rc)
	}
	return json.Marshal(r)
}

// ComputeDiff computes the Recipe that describes how afterHeaders/afterBody
// differs from beforeHeaders/beforeBody. Returns nil if nothing changed.
func ComputeDiff(beforeHeaders []Header, beforeBody []byte,
	afterHeaders []Header, afterBody []byte) (*Recipe, error) {
	r := &Recipe{}
	changed := false

	beforeLines := splitLines(beforeBody)
	afterLines := splitLines(afterBody)
	if !equalStringSlices(beforeLines, afterLines) {
		changed = true
		r.Body = diffLines(beforeLines, afterLines)
	}

	beforeByName := groupHeadersByName(beforeHeaders)
	afterByName := groupHeadersByName(afterHeaders)

	nameSet := make(map[string]bool)
	for _, h := range beforeHeaders {
		nameSet[lowerName(h.Name)] = true
	}
	for _, h := range afterHeaders {
		nameSet[lowerName(h.Name)] = true
	}

	for name := range nameSet {
		if shouldExcludeHeader(name) {
			continue
		}
		before := beforeByName[name]
		after := afterByName[name]
		if !equalHeaderSlices(before, after) {
			changed = true
			if r.Headers == nil {
				r.Headers = make(map[string][]RecipeStep)
			}
			r.Headers[name] = headerRecipeSteps(before, after)
		}
	}

	if !changed {
		return nil, nil
	}
	return r, nil
}

func lowerName(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

func splitLines(body []byte) []string {
	var lines []string
	start := 0
	for i := 0; i < len(body); i++ {
		if body[i] == '\n' {
			line := string(body[start:i])
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(body) {
		lines = append(lines, string(body[start:]))
	}
	return lines
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalHeaderSlices(a, b []Header) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Raw != b[i].Raw {
			return false
		}
	}
	return true
}

func groupHeadersByName(headers []Header) map[string][]Header {
	m := make(map[string][]Header)
	for _, h := range headers {
		n := lowerName(h.Name)
		m[n] = append(m[n], h)
	}
	return m
}

func diffLines(before, after []string) []RecipeStep {
	afterIdx := make(map[string][]int)
	for i, l := range after {
		afterIdx[l] = append(afterIdx[l], i+1)
	}

	var steps []RecipeStep
	for _, l := range before {
		if idxs, ok := afterIdx[l]; ok && len(idxs) > 0 {
			c := [2]int{idxs[0], idxs[0]}
			steps = append(steps, RecipeStep{Copy: &c})
			afterIdx[l] = idxs[1:] // consume the used index
		} else {
			steps = append(steps, RecipeStep{Data: []string{l}})
		}
	}
	return steps
}

func headerRecipeSteps(before, after []Header) []RecipeStep {
	afterBottomUp := make([]Header, len(after))
	copy(afterBottomUp, after)
	for i, j := 0, len(afterBottomUp)-1; i < j; i, j = i+1, j-1 {
		afterBottomUp[i], afterBottomUp[j] = afterBottomUp[j], afterBottomUp[i]
	}

	afterIdx := make(map[string][]int)
	for i, h := range afterBottomUp {
		afterIdx[h.Raw] = append(afterIdx[h.Raw], i+1)
	}

	beforeBottomUp := make([]Header, len(before))
	copy(beforeBottomUp, before)
	for i, j := 0, len(beforeBottomUp)-1; i < j; i, j = i+1, j-1 {
		beforeBottomUp[i], beforeBottomUp[j] = beforeBottomUp[j], beforeBottomUp[i]
	}

	var steps []RecipeStep
	for _, h := range beforeBottomUp {
		if idxs, ok := afterIdx[h.Raw]; ok && len(idxs) > 0 {
			c := [2]int{idxs[0], idxs[0]}
			steps = append(steps, RecipeStep{Copy: &c})
			afterIdx[h.Raw] = idxs[1:]
		} else {
			steps = append(steps, RecipeStep{Data: []string{h.Value}})
		}
	}
	return steps
}
