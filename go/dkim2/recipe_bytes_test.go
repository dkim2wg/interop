package dkim2

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// Tests for the agreed extension to spec-06 §5: "b" (base64 octet) literal
// steps, and the verifier actually enforcing the "c" range rules (two
// integers, 1 <= start <= end <= item count, ascending and non-overlapping
// across the list) as "PERMERROR Message-Instance m=<N> has a malformed
// Recipe".

const (
	bytesTestHop1Key = "sel1._domainkey.test1.dkim2.com.pem"
	bytesTestHop2Key = "sel1._domainkey.test2.dkim2.com.pem"
)

// bytesTestOriginal is the pre-signing message: a Latin-1 Subject and an
// EUC-KR-ish body line, neither of them valid UTF-8.
var bytesTestOriginal = []byte("From: sender@test1.dkim2.com\r\n" +
	"To: user@test2.dkim2.com\r\n" +
	"Subject: caf\xe9\r\n" +
	"Date: Thu, 20 Feb 2025 00:00:00 +0000\r\n" +
	"Message-ID: <bytes-test@test1.dkim2.com>\r\n" +
	"\r\n" +
	"hello\r\n" +
	"\xb1\xa4 world\r\n" +
	"bye\r\n")

// twoHopWithRecipe signs original as test1 (m=1), then plays a second hop
// that replaces the Subject value and body line 2 with newSubject/newLine2,
// carries recipe on its m=2 Message-Instance, and signs as test2. recipe nil
// means "compute it with ComputeDiff". Returns hop1 and hop2.
func twoHopWithRecipe(t *testing.T, original []byte, newSubject, newLine2 string, recipe *Recipe) (hop1, hop2 []byte) {
	t.Helper()
	hop1 = signHop(t, original, bytesTestHop1Key, "sel1", "test1.dkim2.com",
		"sender@test1.dkim2.com", []string{"user@test2.dkim2.com"}, 1740000000)

	headers, bodyReader, err := parseHeaders(bytes.NewReader(hop1))
	if err != nil {
		t.Fatal(err)
	}
	beforeBody := new(bytes.Buffer)
	beforeBody.ReadFrom(bodyReader)

	after := make([]Header, len(headers))
	copy(after, headers)
	for i, h := range after {
		if lowerName(h.Name) == "subject" {
			after[i] = Header{Name: h.Name, Value: newSubject, Raw: h.Name + ": " + newSubject + "\r\n"}
		}
	}
	lines := splitLines(beforeBody.Bytes())
	lines[1] = newLine2
	afterBody := []byte(strings.Join(lines, "\r\n") + "\r\n")

	if recipe == nil {
		recipe, err = ComputeDiff(headers, beforeBody.Bytes(), after, afterBody)
		if err != nil {
			t.Fatal(err)
		}
		if recipe == nil {
			t.Fatal("ComputeDiff saw no change")
		}
	}

	hHash, err := hashHeaders(after, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	bHash, err := hashBody(bytes.NewReader(afterBody), "sha256")
	if err != nil {
		t.Fatal(err)
	}
	mi2 := &MessageInstance{Version: 2, Recipe: recipe, Hashes: []HashSet{{
		Alg:        "sha256",
		HeaderHash: base64.StdEncoding.EncodeToString(hHash),
		BodyHash:   base64.StdEncoding.EncodeToString(bHash),
	}}}

	var modified bytes.Buffer
	modified.WriteString(mi2.String() + "\r\n")
	for _, h := range after {
		modified.WriteString(h.Raw)
	}
	modified.WriteString("\r\n")
	modified.Write(afterBody)

	// Sign sees the grafted m=2 with hashes equal to its own and reuses it.
	hop2 = signHop(t, modified.Bytes(), bytesTestHop2Key, "sel1", "test2.dkim2.com",
		"user@test2.dkim2.com", []string{"dest@test3.dkim2.com"}, 1740000100)
	if n := len(logicalHeaders(string(hop2), "Message-Instance")); n != 2 {
		t.Fatalf("fixture should carry exactly m=1 and m=2, got %d Message-Instances", n)
	}
	return hop1, hop2
}

// verifyFullError runs VerifyFull and returns the first error text (top-level
// or per-result), "" for a clean pass.
func verifyFullError(t *testing.T, msg []byte) string {
	t.Helper()
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	results, err := VerifyFull(bytes.NewReader(msg), f, VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		return err.Error()
	}
	for _, r := range results {
		if r.Error != nil {
			return r.Error.Error()
		}
	}
	return ""
}

func TestRecipeBytesRoundTripVerifies(t *testing.T) {
	hop1, hop2 := twoHopWithRecipe(t, bytesTestOriginal, "changed subject", "changed line", nil)

	// The m=2 recipe must carry the two 8-bit literals as "b" items.
	mi2 := logicalHeaders(string(hop2), "Message-Instance")[0]
	mi, err := parseMI(mi2)
	if err != nil {
		t.Fatal(err)
	}
	if mi.Version != 2 || mi.Recipe == nil {
		t.Fatalf("expected the m=2 instance with a Recipe on top, got %s", mi2)
	}
	wantSubj := base64.StdEncoding.EncodeToString([]byte("caf\xe9"))
	wantLine := base64.StdEncoding.EncodeToString([]byte("\xb1\xa4 world"))
	subj := mi.Recipe.Headers["subject"]
	if len(subj) != 1 || subj[0].Data != nil || len(subj[0].Bytes) != 1 || subj[0].Bytes[0] != wantSubj {
		t.Errorf("subject recipe: want one b step [%s], got %+v", wantSubj, subj)
	}
	var sawLine bool
	for _, s := range mi.Recipe.Body {
		if s.Data != nil && strings.Contains(strings.Join(s.Data, "\n"), "\xb1") {
			t.Errorf("8-bit body line leaked into a d step: %q", s.Data)
		}
		if len(s.Bytes) == 1 && s.Bytes[0] == wantLine {
			sawLine = true
		}
	}
	if !sawLine {
		t.Errorf("body recipe: want a b step [%s], got %+v", wantLine, mi.Recipe.Body)
	}

	// Through the real entry point (Verify + Undo-based chain validation).
	if got := verifyFullError(t, hop2); got != "" {
		t.Fatalf("two-hop message with b-step recipe failed: %s", got)
	}

	// And the undone m=1 is byte-for-byte the first hop: the decoded octets
	// reached the hash (and the output) unmodified.
	var undone bytes.Buffer
	if err := Undo(bytes.NewReader(hop2), &undone, 1); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(undone.Bytes(), hop1) {
		t.Errorf("undo to m=1 does not reproduce hop 1\ngot:\n%q\nwant:\n%q", undone.Bytes(), hop1)
	}
}

// Structurally malformed Recipes are caught when the Message-Instance is
// parsed, so Verify itself rejects them, with the exact PERMERROR text.
func TestVerifyRejectsMalformedRecipe(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"descending c ranges", `{"b":[{"c":[3,3]},{"c":[1,1]}]}`},
		{"overlapping c ranges", `{"b":[{"c":[1,2]},{"c":[2,3]}]}`},
		{"adjacent equal start", `{"b":[{"c":[1,1]},{"c":[1,1]}]}`},
		{"start 0", `{"b":[{"c":[0,1]}]}`},
		{"negative start", `{"b":[{"c":[-1,1]}]}`},
		{"start after end", `{"b":[{"c":[2,1]}]}`},
		{"string bounds", `{"b":[{"c":["1","1"]}]}`},
		{"fractional bound", `{"b":[{"c":[1.5,2]}]}`},
		{"exponent bound", `{"b":[{"c":[1e0,2]}]}`},
		{"one bound", `{"b":[{"c":[1]}]}`},
		{"three bounds", `{"b":[{"c":[1,2,3]}]}`},
		{"c not an array", `{"b":[{"c":1}]}`},
		{"two keys in a step", `{"b":[{"c":[1,1],"d":["x"]}]}`},
		{"unknown step key", `{"b":[{"x":["y"]}]}`},
		{"empty step", `{"b":[{}]}`},
		{"empty d", `{"b":[{"d":[]}]}`},
		{"d not strings", `{"b":[{"d":[1]}]}`},
		{"invalid base64 in b", `{"b":[{"b":["!!!!"]}]}`},
		{"unpadded base64 in b", `{"b":[{"b":["YQ"]}]}`},
		{"whitespace inside base64", `{"b":[{"b":["YQ ==" ]}]}`},
		{"CR inside d", `{"b":[{"d":["a\rb"]}]}`},
		{"LF inside d", `{"b":[{"d":["a\nb"]}]}`},
		{"CRLF inside d, second item", `{"b":[{"d":["ok","a\r\nb"]}]}`},
		{"CR inside header d", `{"h":{"subject":[{"d":["a\rb"]}]}}`},
		{"LF inside header d", `{"h":{"subject":[{"d":["a\nb"]}]}}`},
		{"CR inside decoded b", `{"b":[{"b":["` + base64.StdEncoding.EncodeToString([]byte("a\rb")) + `"]}]}`},
		{"LF inside decoded b", `{"b":[{"b":["` + base64.StdEncoding.EncodeToString([]byte("a\nb")) + `"]}]}`},
		{"descending header c ranges", `{"h":{"subject":[{"c":[2,2]},{"c":[1,1]}]}}`},
		{"header start 0", `{"h":{"subject":[{"c":[0,0]}]}}`},
		{"header invalid base64", `{"h":{"subject":[{"b":["*"]}]}}`},
	}

	msg := string(buildSignedMsg(t))
	want := "PERMERROR Message-Instance m=1 has a malformed Recipe"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base64.StdEncoding.EncodeToString([]byte(tc.json))
			tampered := strings.Replace(msg, "Message-Instance: m=1; ",
				"Message-Instance: m=1; r="+r+"; ", 1)
			if tampered == msg {
				t.Fatal("failed to inject r= into the Message-Instance header")
			}
			f := &JSONKeyFetcher{Path: "../../dns.json"}
			_, err := Verify(strings.NewReader(tampered), f, VerifyOptions{SkipTimestampCheck: true})
			if err == nil {
				t.Fatalf("%s: expected rejection, got a pass", tc.json)
			}
			if err.Error() != want {
				t.Errorf("%s: got %q, want exactly %q", tc.json, err.Error(), want)
			}
			if got := verifyFullError(t, []byte(tampered)); got != want {
				t.Errorf("VerifyFull: got %q, want exactly %q", got, want)
			}
		})
	}
}

// Valid JSON of the wrong shape above step level keeps the §11.2 "contains
// invalid JSON" classification; and a well-formed Recipe still parses.
func TestMalformedRecipeStaysDistinctFromInvalidJSON(t *testing.T) {
	msg := string(buildSignedMsg(t))
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	inject := func(j string) string {
		r := base64.StdEncoding.EncodeToString([]byte(j))
		return strings.Replace(msg, "Message-Instance: m=1; ", "Message-Instance: m=1; r="+r+"; ", 1)
	}
	_, err := Verify(strings.NewReader(inject(`{"h":5}`)), f, VerifyOptions{SkipTimestampCheck: true})
	if err == nil || err.Error() != "PERMERROR Message-Instance m=1 contains invalid JSON" {
		t.Errorf(`{"h":5}: got %v, want the invalid-JSON PERMERROR`, err)
	}
	if _, err := parseRecipe([]byte(`{"h":{"subject":[{"c":[1,2]},{"b":["YQ=="]},{"c":[3,3]}]},"b":[{"d":["x"]},{"c":[1,1]}]}`)); err != nil {
		t.Errorf("well-formed recipe rejected: %v", err)
	}
}

// A "c" range that is fine on its own but runs past the number of current
// items can only be caught when the Recipe is applied; VerifyFull (the
// entry point cmd/dkim2verify uses) must reject it with the same PERMERROR,
// for both the body and a header field.
func TestVerifyFullRejectsCopyBeyondCount(t *testing.T) {
	// The fixture body has 3 lines; the Subject has 1 instance.
	c1_99 := [2]int{1, 99}
	c1_2 := [2]int{1, 2}
	cases := []struct {
		name   string
		recipe *Recipe
	}{
		{"body end beyond line count", &Recipe{Body: []RecipeStep{{Copy: &c1_99}}}},
		{"header end beyond instance count", &Recipe{Headers: map[string][]RecipeStep{"subject": {{Copy: &c1_2}}}}},
	}
	want := "PERMERROR Message-Instance m=2 has a malformed Recipe"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, hop2 := twoHopWithRecipe(t, bytesTestOriginal, "changed subject", "changed line", tc.recipe)
			if got := verifyFullError(t, hop2); got != want {
				t.Errorf("got %q, want exactly %q", got, want)
			}
		})
	}
}

// Generation: 8-bit literals come out as "b", ASCII as "d", runs coalesce
// per kind and a mixed run alternates.
func TestComputeDiffEmits8BitLiteralsAsBytes(t *testing.T) {
	before := []byte("ascii one\r\nascii two\r\ncaf\xe9\r\n\xb1\xa4\r\nascii three\r\nkept\r\n")
	after := []byte("kept\r\n")
	r, err := ComputeDiff(nil, before, nil, after)
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	want := []RecipeStep{
		{Data: []string{"ascii one", "ascii two"}},
		{Bytes: []string{b64("caf\xe9"), b64("\xb1\xa4")}},
		{Data: []string{"ascii three"}},
		{Copy: &[2]int{1, 1}},
	}
	if len(r.Body) != len(want) {
		t.Fatalf("want %d steps, got %d: %+v", len(want), len(r.Body), r.Body)
	}
	for i := range want {
		if !recipeStepsEqual(r.Body[i], want[i]) {
			t.Errorf("step %d: got %+v, want %+v", i, r.Body[i], want[i])
		}
	}
	// The encoded JSON must carry the exact octets (no U+FFFD anywhere).
	enc, err := encodeRecipe(r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, []byte("�")) || !bytes.Contains(enc, []byte(`"b":["`+b64("caf\xe9")+`"`)) {
		t.Errorf("encoded recipe lost the octets: %s", enc)
	}
	// And it round-trips through our own apply code to the exact bytes.
	parsed, err := parseRecipe(enc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := undoBodyRecipe(after, parsed.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, before) {
		t.Errorf("round trip: got %q, want %q", got, before)
	}

	// Header side: a Latin-1 value is a "b" step, an ASCII one a "d" step.
	hb := []Header{{Name: "Subject", Value: "caf\xe9", Raw: "Subject: caf\xe9\r\n"},
		{Name: "X-Note", Value: "x", Raw: "X-Note: x\r\n"},
		{Name: "Comments", Value: "plain", Raw: "Comments: plain\r\n"}}
	ha := []Header{{Name: "Subject", Value: "new", Raw: "Subject: new\r\n"},
		{Name: "Comments", Value: "other", Raw: "Comments: other\r\n"}}
	r, err = ComputeDiff(hb, nil, ha, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s := r.Headers["subject"]; len(s) != 1 || s[0].Data != nil || len(s[0].Bytes) != 1 || s[0].Bytes[0] != b64("caf\xe9") {
		t.Errorf("subject: want b step, got %+v", s)
	}
	if s := r.Headers["comments"]; len(s) != 1 || len(s[0].Data) != 1 || s[0].Data[0] != "plain" || s[0].Bytes != nil {
		t.Errorf("comments: want d step, got %+v", s)
	}
}

func recipeStepsEqual(a, b RecipeStep) bool {
	if (a.Copy == nil) != (b.Copy == nil) || (a.Copy != nil && *a.Copy != *b.Copy) {
		return false
	}
	return equalStringSlices(a.Data, b.Data) && equalStringSlices(a.Bytes, b.Bytes)
}

// Generation: reordered duplicate header instances (and body lines) never
// produce a "c" range that violates the ascending rule, and the Recipe still
// undoes to the exact previous state.
func TestRecipeGenerationNeverDescends(t *testing.T) {
	mk := func(vals ...string) []Header {
		hs := make([]Header, len(vals))
		for i, v := range vals {
			hs[i] = Header{Name: "Received-Note", Value: v, Raw: "Received-Note: " + v + "\r\n"}
		}
		return hs
	}
	headerCases := []struct{ before, after []Header }{
		{mk("A", "B"), mk("B", "A")},
		{mk("A", "B", "C"), mk("C", "B", "A")},
		{mk("A", "B", "C", "D"), mk("B", "D", "A", "C")},
		{mk("A", "A", "B"), mk("B", "A", "A")},
		{mk("caf\xe9", "B"), mk("B", "caf\xe9")},
	}
	for _, tc := range headerCases {
		steps := headerRecipeSteps(tc.before, tc.after)
		if err := validateRecipeSteps(steps, len(tc.after)); err != nil {
			t.Errorf("%v -> %v: generated an invalid recipe %+v: %v", vals(tc.before), vals(tc.after), steps, err)
			continue
		}
		enc, err := encodeRecipe(&Recipe{Headers: map[string][]RecipeStep{"received-note": steps}})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parseRecipe(enc)
		if err != nil {
			t.Errorf("%s: own recipe rejected by parser: %v", enc, err)
			continue
		}
		got, err := applyHeaderRecipe(tc.after, "Received-Note", parsed.Headers["received-note"])
		if err != nil {
			t.Errorf("%s: apply failed: %v", enc, err)
			continue
		}
		if !equalHeaderSlices(got, tc.before) {
			t.Errorf("%s: undo gave %v, want %v", enc, vals(got), vals(tc.before))
		}
	}

	bodyCases := []struct{ before, after []string }{
		{[]string{"a", "b"}, []string{"b", "a"}},
		{[]string{"a", "b", "c"}, []string{"c", "b", "a"}},
		{[]string{"a", "a", "b", "c"}, []string{"c", "a", "b", "a"}},
	}
	for _, tc := range bodyCases {
		steps, _ := bodyRecipeSteps(tc.before, tc.after, MaxRecipeLiterals)
		if err := validateRecipeSteps(steps, len(tc.after)); err != nil {
			t.Errorf("%v -> %v: generated an invalid recipe %+v: %v", tc.before, tc.after, steps, err)
			continue
		}
		got, err := undoBodyRecipe([]byte(strings.Join(tc.after, "\r\n")+"\r\n"), steps)
		if err != nil {
			t.Errorf("%v -> %v: apply failed: %v", tc.before, tc.after, err)
			continue
		}
		if want := strings.Join(tc.before, "\r\n") + "\r\n"; string(got) != want {
			t.Errorf("%v -> %v: undo gave %q", tc.before, tc.after, got)
		}
	}
}

func vals(hs []Header) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = h.Value
	}
	return out
}
