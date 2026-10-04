package dkim2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// RecipeStep is one step in a body or header Recipe. Exactly one of the
// three fields is set:
//
//   - Copy  {"c": [start, end]}: copy current items start..end inclusive.
//   - Data  {"d": [str, ...]}:   literal lines/values as UTF-8 JSON text.
//   - Bytes {"b": [b64, ...]}:   literal lines/values whose raw octets are
//     base64 (RFC 4648 §4) inside the JSON string, for values that JSON text
//     cannot carry (Latin-1, EUC-KR, any non-UTF-8 octets). Applied exactly
//     like "d" after decoding. Agreed extension to spec-06 §5 (proposed to
//     the WG).
type RecipeStep struct {
	Copy  *[2]int  `json:"c,omitempty"`
	Data  []string `json:"d,omitempty"`
	Bytes []string `json:"b,omitempty"`
}

// Recipe describes changes made to a message at one hop.
type Recipe struct {
	Headers map[string][]RecipeStep `json:"h,omitempty"`
	Body    []RecipeStep            `json:"b,omitempty"`

	// BodyNull records that "b" was present and JSON null: §12.1.1's "null
	// Recipe", the hop declaring that the previous body cannot be put back.
	// It is deliberately distinct from an absent "b" (the body was not
	// modified), which unmarshals to a nil Body just the same. Not encoded —
	// nothing here signs a null Recipe, it is only ever read.
	BodyNull bool `json:"-"`
}

// errMalformedRecipe marks a Recipe that is well-formed JSON but breaks the
// §5 step rules: a "c" step that is not two integers, bounds out of range or
// not ascending/non-overlapping, a step with other than exactly one known
// key, an empty literal list, a "d" item containing CR or LF, or a "b" item
// that is not base64 or decodes to octets containing CR or LF. Test with errors.Is; the §11.2-style report is
// malformedRecipeError.
var errMalformedRecipe = errors.New("malformed Recipe")

func malformedRecipe(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errMalformedRecipe}, args...)...)
}

// malformedRecipeError is the PERMERROR a verifier reports for a Recipe on
// Message-Instance m=M that breaks the §5 rules (shape follows the §11.2
// list; "has a malformed Recipe" is the agreed extension). The message is
// not accepted. It is self-describing, so Verify/VerifyFull return it
// verbatim rather than wrapping it.
type malformedRecipeError struct{ m int }

func (e *malformedRecipeError) Error() string {
	return fmt.Sprintf("PERMERROR Message-Instance m=%d has a malformed Recipe", e.m)
}

// UnmarshalJSON rejects every step shape the §5 schema does not allow:
// anything but an object with exactly one key from {c, d, b}; a "c" whose
// value is not an array of exactly two JSON integers (strings, 1.5 and the
// like are rejected here, not silently coerced); an empty or non-string "d"
// or "b" list. Range and base64 checks live in validateRecipeSteps so they
// also cover programmatically built steps.
func (s *RecipeStep) UnmarshalJSON(data []byte) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return malformedRecipe("step is not a JSON object")
	}
	if len(obj) != 1 {
		return malformedRecipe("step must have exactly one key, got %d", len(obj))
	}
	*s = RecipeStep{}
	for k, v := range obj {
		switch k {
		case "c":
			var bounds []json.RawMessage
			if err := json.Unmarshal(v, &bounds); err != nil || len(bounds) != 2 {
				return malformedRecipe(`"c" must be an array of exactly two integers`)
			}
			var c [2]int
			for i, b := range bounds {
				n, err := strconv.ParseInt(string(b), 10, strconv.IntSize)
				if err != nil {
					return malformedRecipe(`"c" bound %s is not a JSON integer`, string(b))
				}
				c[i] = int(n)
			}
			s.Copy = &c
		case "d":
			var d []string
			if err := json.Unmarshal(v, &d); err != nil || len(d) == 0 {
				return malformedRecipe(`"d" must be a non-empty array of strings`)
			}
			s.Data = d
		case "b":
			var b []string
			if err := json.Unmarshal(v, &b); err != nil || len(b) == 0 {
				return malformedRecipe(`"b" must be a non-empty array of base64 strings`)
			}
			s.Bytes = b
		default:
			return malformedRecipe("unknown step key %q", k)
		}
	}
	return nil
}

// decodeRecipeBytes decodes one "b" item: standard-alphabet base64 (RFC 4648
// §4, padded; nothing outside the alphabet, not even whitespace) whose
// decoded octets contain neither CR nor LF. The result is returned as a Go
// string so it flows down the same path as a "d" value; Go strings hold
// arbitrary octets and nothing on the hashing path validates UTF-8.
func decodeRecipeBytes(b64 string) (string, error) {
	for i := 0; i < len(b64); i++ {
		c := b64[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '+', c == '/', c == '=':
		default:
			return "", malformedRecipe(`"b" item is not standard base64`)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", malformedRecipe(`"b" item is not standard base64`)
	}
	if bytes.ContainsAny(raw, "\r\n") {
		return "", malformedRecipe(`"b" item decodes to octets containing CR or LF`)
	}
	return string(raw), nil
}

// literals returns the literal values a "d" or "b" step emits (decoded for
// "b"); nil for a "c" step. A "d" value containing CR or LF is rejected
// (§5.1/§5.2: "The text strings MUST NOT contain CR or LF characters").
func (s RecipeStep) literals() ([]string, error) {
	if s.Data != nil {
		for _, v := range s.Data {
			if strings.ContainsAny(v, "\r\n") {
				return nil, malformedRecipe(`"d" item contains CR or LF`)
			}
		}
		return s.Data, nil
	}
	if s.Bytes == nil {
		return nil, nil
	}
	out := make([]string, len(s.Bytes))
	for i, b64 := range s.Bytes {
		v, err := decodeRecipeBytes(b64)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

// validateRecipeSteps checks one step list against the §5.1/§5.2 rules:
// every step is exactly one of c/d/b; each "c" has 1 <= start <= end, and
// its start is greater than the end of every preceding "c" (ascending,
// non-overlapping); no "d" item contains CR or LF; every "b" item decodes.
// count is the number of current
// items (header instances of the name, or body lines) the Recipe is being
// applied to, so that end <= count can be checked too; pass -1 at parse
// time when it is not yet known.
func validateRecipeSteps(steps []RecipeStep, count int) error {
	lastEnd := 0
	for i, s := range steps {
		set := 0
		if s.Copy != nil {
			set++
		}
		if s.Data != nil {
			set++
		}
		if s.Bytes != nil {
			set++
		}
		if set != 1 {
			return malformedRecipe("step %d must be exactly one of c/d/b", i)
		}
		if s.Copy != nil {
			start, end := s.Copy[0], s.Copy[1]
			if start < 1 || end < start {
				return malformedRecipe(`"c" [%d,%d] needs 1 <= start <= end`, start, end)
			}
			if start <= lastEnd {
				return malformedRecipe(`"c" [%d,%d] does not ascend past the previous end %d`, start, end, lastEnd)
			}
			if count >= 0 && end > count {
				return malformedRecipe(`"c" [%d,%d] exceeds the %d current items`, start, end, count)
			}
			lastEnd = end
		}
		if _, err := s.literals(); err != nil {
			return err
		}
	}
	return nil
}

func parseRecipe(data []byte) (*Recipe, error) {
	// draft-06 §5.1: an explicit JSON null for "h" is no longer permitted
	// (distinct from an absent "h", which means the headers were unchanged).
	var r Recipe
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err == nil {
		if v, ok := probe["h"]; ok && string(v) == "null" {
			return nil, errors.New("null header recipe not permitted (draft-06 §5.1)")
		}
		if v, ok := probe["b"]; ok && string(v) == "null" {
			r.BodyNull = true
		}
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	for name, steps := range r.Headers {
		if err := validateRecipeSteps(steps, -1); err != nil {
			return nil, fmt.Errorf("header %q: %w", name, err)
		}
	}
	if err := validateRecipeSteps(r.Body, -1); err != nil {
		return nil, fmt.Errorf("body: %w", err)
	}
	return &r, nil
}

func encodeRecipe(r *Recipe) ([]byte, error) {
	// spec-06 §5.1: header field names in the JSON Recipes MUST be lower
	// case (matching against the message stays case-insensitive).
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

// isASCII reports whether no byte of s is >= 0x80.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// appendLiteral appends one literal value to steps: as a "d" item when it is
// pure ASCII, otherwise as a "b" item carrying the exact octets (encoding/json
// would turn any non-UTF-8 byte in a "d" string into U+FFFD). Consecutive
// literals of the same kind coalesce into one step; a mixed run alternates
// d and b steps.
func appendLiteral(steps []RecipeStep, val string) []RecipeStep {
	n := len(steps)
	if isASCII(val) {
		if n > 0 && steps[n-1].Data != nil {
			steps[n-1].Data = append(steps[n-1].Data, val)
			return steps
		}
		return append(steps, RecipeStep{Data: []string{val}})
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(val))
	if n > 0 && steps[n-1].Bytes != nil {
		steps[n-1].Bytes = append(steps[n-1].Bytes, b64)
		return steps
	}
	return append(steps, RecipeStep{Bytes: []string{b64}})
}

// recipeSteps builds the step list that turns the current items (afterKeys,
// numbered 1..n in the order given) back into the previous ones. Items are
// matched by key; beforeVals[i] is the literal emitted for before item i
// when it cannot be copied. Each before item is copied from the
// lowest-numbered unused after item with the same key that still keeps the
// "c" ranges ascending and non-overlapping (§5.1/§5.2); when there is none
// -- the item is gone, or only occurrences at or below the last copied index
// remain, as with reordered instances -- its literal is emitted instead (via
// appendLiteral, so 8-bit values become "b" items). Indices already passed
// can never be copied again, so they are discarded rather than consumed.
func recipeSteps(beforeKeys, beforeVals, afterKeys []string) []RecipeStep {
	afterIdx := make(map[string][]int)
	for i, k := range afterKeys {
		afterIdx[k] = append(afterIdx[k], i+1)
	}

	var steps []RecipeStep
	lastEnd := 0
	for i, k := range beforeKeys {
		idxs := afterIdx[k]
		for len(idxs) > 0 && idxs[0] <= lastEnd {
			idxs = idxs[1:]
		}
		if len(idxs) > 0 {
			c := [2]int{idxs[0], idxs[0]}
			steps = append(steps, RecipeStep{Copy: &c})
			lastEnd = idxs[0]
			idxs = idxs[1:] // consume the used index
		} else {
			steps = appendLiteral(steps, beforeVals[i])
		}
		afterIdx[k] = idxs
	}
	return steps
}

// diffLines builds the body Recipe (lines numbered top-down, §5.2).
func diffLines(before, after []string) []RecipeStep {
	return recipeSteps(before, before, after)
}

// headerRecipeSteps builds the Recipe for one header field name. Both sides
// are taken bottom-up (§5.1: instance 1 is the last occurrence); instances
// are matched on Raw (the folded form actually present) and a literal is
// the unfolded Value.
func headerRecipeSteps(before, after []Header) []RecipeStep {
	afterRaw := make([]string, len(after))
	for i, h := range after {
		afterRaw[len(after)-1-i] = h.Raw
	}
	beforeRaw := make([]string, len(before))
	beforeVal := make([]string, len(before))
	for i, h := range before {
		beforeRaw[len(before)-1-i] = h.Raw
		beforeVal[len(before)-1-i] = h.Value
	}
	return recipeSteps(beforeRaw, beforeVal, afterRaw)
}
