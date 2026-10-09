package dkim2

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// flatString renders a flat recipe in the vector form for comparison.
func flatString(steps []bodyDiffStep) string {
	parts := make([]string, len(steps))
	for i, st := range steps {
		if st.Lit {
			b, _ := json.Marshal(st.Line)
			parts[i] = string(b)
		} else {
			parts[i] = fmt.Sprintf("[%d,%d]", st.From, st.To)
		}
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func TestBodyDiffVectors(t *testing.T) {
	data, err := os.ReadFile("../../vectors/body-diff.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []struct {
			Name        string          `json:"name"`
			Cur         []string        `json:"cur"`
			Prev        []string        `json:"prev"`
			MaxLiterals *int            `json:"max_literals"`
			Expect      json.RawMessage `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range file.Cases {
		L := MaxRecipeLiterals
		if c.MaxLiterals != nil {
			L = *c.MaxLiterals
		}
		steps, kind := bodyDiff(c.Cur, c.Prev, L)
		var want string
		if json.Unmarshal(c.Expect, &want) == nil {
			got := map[bodyDiffKind]string{bodyDiffOK: "steps", bodyDiffIdentical: "identical", bodyDiffTooBig: "too_big"}[kind]
			if got != want {
				t.Errorf("%s: got %s %s, want %s", c.Name, got, flatString(steps), want)
			}
			continue
		}
		var exp []any
		if err := json.Unmarshal(c.Expect, &exp); err != nil {
			t.Fatalf("%s: bad expect: %v", c.Name, err)
		}
		norm, _ := json.Marshal(exp)
		if kind != bodyDiffOK {
			t.Errorf("%s: got kind %d, want %s", c.Name, kind, norm)
			continue
		}
		if got := flatString(steps); got != string(norm) {
			t.Errorf("%s:\n got  %s\n want %s", c.Name, got, norm)
		}
	}
}

func repeatLines(n int, f func(i int) string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = f(i)
	}
	return out
}

func TestBodyDiffAlternatingFast(t *testing.T) {
	ab := repeatLines(4000, func(i int) string { return []string{"a", "b"}[i%2] })
	ba := repeatLines(4000, func(i int) string { return []string{"b", "a"}[i%2] })
	start := time.Now()
	steps, kind := bodyDiff(ab, ba, MaxRecipeLiterals)
	el := time.Since(start)
	t.Logf("alternating 4000: %v, %d steps", el, len(steps))
	if kind != bodyDiffOK {
		t.Fatalf("kind %d", kind)
	}
	lits := 0
	for _, st := range steps {
		if st.Lit {
			lits++
		}
	}
	if lits > 1 {
		t.Errorf("%d literals, want <= 1", lits)
	}
	if el > 50*time.Millisecond {
		t.Errorf("took %v, want < 50ms", el)
	}
}

// 30000 "x" then 30000 "y" vs the reverse needs 60000 edits; the search
// gives up at the round limit dmax (2000) after ~2M work units.
func TestBodyDiffWorkBudget(t *testing.T) {
	xy := append(repeatLines(30000, func(int) string { return "x" }), repeatLines(30000, func(int) string { return "y" })...)
	yx := append(repeatLines(30000, func(int) string { return "y" }), repeatLines(30000, func(int) string { return "x" })...)
	start := time.Now()
	_, kind := bodyDiff(xy, yx, MaxRecipeLiterals)
	el := time.Since(start)
	t.Logf("30000x/30000y reversed: %v", el)
	if kind != bodyDiffTooBig {
		t.Fatalf("kind %d, want tooBig", kind)
	}
	if el > time.Second {
		t.Errorf("took %v", el)
	}
}

// A valid recipe exists here (two literals), and the round limit dmax is far
// beyond where the search stops, so tooBig can only come from MaxDiffWork.
func TestBodyDiffWorkBudgetOneSided(t *testing.T) {
	cur := append([]string{"a"}, repeatLines(300000, func(int) string { return "x" })...)
	cur = append(cur, "b")
	prev := append([]string{"b"}, repeatLines(3000, func(int) string { return "x" })...)
	prev = append(prev, "a")
	start := time.Now()
	_, kind := bodyDiff(cur, prev, MaxRecipeLiterals)
	el := time.Since(start)
	t.Logf("one-sided 300002 vs 3002: %v", el)
	if kind != bodyDiffTooBig {
		t.Fatalf("kind %d, want tooBig", kind)
	}
	if el > time.Second {
		t.Errorf("took %v", el)
	}
}

func TestBodyDiffLiteralCap(t *testing.T) {
	cur := []string{"top", "bottom"}
	for _, n := range []int{1000, 1001} {
		prev := []string{"top"}
		for i := 0; i < n; i++ {
			prev = append(prev, fmt.Sprintf("new %d", i))
		}
		prev = append(prev, "bottom")
		steps, kind := bodyDiff(cur, prev, MaxRecipeLiterals)
		if n == 1000 {
			if kind != bodyDiffOK || len(steps) != 1002 {
				t.Errorf("1000 literals: kind %d, %d steps", kind, len(steps))
			}
		} else if kind != bodyDiffTooBig {
			t.Errorf("1001 literals: kind %d, want tooBig", kind)
		}
	}
}

func TestComputeDiffOverCapIsNullBody(t *testing.T) {
	var prev strings.Builder
	for i := 0; i < 1001; i++ {
		fmt.Fprintf(&prev, "removed line %d\r\n", i)
	}
	prev.WriteString("kept\r\n")
	r, err := ComputeDiff(nil, []byte(prev.String()), nil, []byte("kept\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r == nil || !r.BodyNull || r.Body != nil {
		t.Fatalf("want BodyNull and no steps, got %+v", r)
	}
	enc, err := encodeRecipe(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(enc) != `{"b":null}` {
		t.Errorf("encoded %s, want {\"b\":null}", enc)
	}
	parsed, err := parseRecipe(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.BodyNull || parsed.Body != nil {
		t.Errorf("round trip lost the null body: %+v", parsed)
	}

	// Just under the cap: a real recipe that undoes to the previous body.
	under := strings.SplitN(prev.String(), "\r\n", 2)[1]
	r, err = ComputeDiff(nil, []byte(under), nil, []byte("kept\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r.BodyNull || len(r.Body) != 2 {
		t.Fatalf("under cap: got %+v", r)
	}
	enc, _ = encodeRecipe(r)
	parsed, err = parseRecipe(enc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := undoBodyRecipe([]byte("kept\r\n"), parsed.Body)
	if err != nil || string(got) != under {
		t.Errorf("under cap round trip failed: %v", err)
	}
}

func TestComputeDiffWithOptionsSmallCap(t *testing.T) {
	prev := []byte("one\r\ntwo\r\nthree\r\nkept\r\n")
	cur := []byte("kept\r\n")
	r, err := ComputeDiffWithOptions(nil, prev, nil, cur, ComputeDiffOptions{MaxLiterals: 2})
	if err != nil {
		t.Fatal(err)
	}
	if r == nil || !r.BodyNull || r.Body != nil {
		t.Fatalf("cap 2: want BodyNull, got %+v", r)
	}
	r, err = ComputeDiffWithOptions(nil, prev, nil, cur, ComputeDiffOptions{MaxLiterals: 3})
	if err != nil {
		t.Fatal(err)
	}
	if r == nil || r.BodyNull || len(r.Body) != 2 {
		t.Fatalf("cap 3: want a recipe, got %+v", r)
	}
	// A cap above the default is honoured: 1001 literals fit under 5000.
	var big strings.Builder
	for i := 0; i < MaxRecipeLiterals+1; i++ {
		fmt.Fprintf(&big, "l%d\r\n", i)
	}
	r, err = ComputeDiffWithOptions(nil, []byte(big.String()), nil, nil, ComputeDiffOptions{MaxLiterals: 5000})
	if err != nil {
		t.Fatal(err)
	}
	if r == nil || r.BodyNull || len(r.Body) != 1 {
		t.Fatalf("cap 5000: want one literal step, got %+v", r)
	}
}

func TestComputeDiffEmptyPreviousBody(t *testing.T) {
	r, err := ComputeDiff(nil, nil, nil, []byte("added\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := encodeRecipe(r)
	if string(enc) != `{"b":[]}` {
		t.Errorf("encoded %s, want {\"b\":[]}", enc)
	}
}
