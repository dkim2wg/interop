package dkim2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// RecipeStep is one step in a body or header Recipe (§5.1, §5.2). Exactly
// one of the three fields is set:
//
//   - Copy  {"c": [start, end]}: copy current items start..end inclusive.
//   - Data  {"d": [str, ...]}:   literal lines/values as UTF-8 JSON text.
//   - Bytes {"u": [b64, ...]}:   literal lines/values whose raw octets are
//     canonical base64 inside the JSON string, for values that are not valid
//     UTF-8 (Latin-1, EUC-KR, ...). Applied exactly like "d" after decoding.
type RecipeStep struct {
	Copy  *[2]int  `json:"c,omitempty"`
	Data  []string `json:"d,omitempty"`
	Bytes []string `json:"u,omitempty"`
}

// Recipe describes changes made to a message at one hop.
type Recipe struct {
	Headers map[string][]RecipeStep `json:"h,omitempty"`
	Body    []RecipeStep            `json:"b,omitempty"`

	// BodyNull records that "b" was present and JSON null: §5.2's "null
	// Recipe", the hop declaring that the previous body cannot be put back.
	// It is deliberately distinct from an absent "b" (the body was not
	// modified), which unmarshals to a nil Body just the same. ComputeDiff
	// sets it when the body diff exceeds MaxRecipeLiterals/MaxDiffWork, and
	// MarshalJSON then emits "b": null.
	BodyNull bool `json:"-"`
}

// MarshalJSON encodes "b" as JSON null when BodyNull is set, as the step
// list when Body is non-nil (an empty list is the empty previous body), and
// omits it when Body is nil (body unchanged).
func (r Recipe) MarshalJSON() ([]byte, error) {
	var w struct {
		Headers map[string][]RecipeStep `json:"h,omitempty"`
		Body    any                     `json:"b,omitempty"`
	}
	w.Headers = r.Headers
	switch {
	case r.BodyNull:
		w.Body = json.RawMessage("null")
	case r.Body != nil:
		w.Body = r.Body
	}
	return json.Marshal(&w)
}

// errMalformedRecipe marks a Recipe that breaks the §5 schema or step
// rules: a "c" step that is not two integers, bounds out of range or not
// ascending/non-overlapping, a step with other than exactly one known key, an
// empty literal list, a "d" item containing CR or LF or not valid UTF-8, or a
// "u" item that is not canonical base64 or decodes to octets containing CR or
// LF. Test with errors.Is; the §14.2 report is malformedRecipeError.
var errMalformedRecipe = errors.New("malformed Recipe")

func malformedRecipe(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errMalformedRecipe}, args...)...)
}

// malformedRecipeError is the PERMERROR a verifier reports for a Recipe on
// Message-Instance m=M that is not valid JSON, or breaks the §5 schema or
// step rules (whether that shows when it is parsed or only when it is
// applied to the message): §14.2's "contains invalid JSON". The message is
// not accepted. It is self-describing, so Verify/VerifyFull return it
// verbatim rather than wrapping it.
type malformedRecipeError struct{ m int }

func (e *malformedRecipeError) Error() string {
	return fmt.Sprintf("PERMERROR: Message-Instance m=%d contains invalid JSON", e.m)
}

// UnmarshalJSON rejects every step shape the §5 schema does not allow:
// anything but an object with exactly one key from {c, d, u}; a "c" whose value is not an array of exactly two
// JSON integers (strings, 1.5 and the like are rejected here, not silently
// coerced); an empty or non-string "d" or "u" list. Range and base64 checks
// live in validateRecipeSteps so they also cover programmatically built
// steps.
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
		case "u":
			var b []string
			if err := json.Unmarshal(v, &b); err != nil || len(b) == 0 {
				return malformedRecipe(`"u" must be a non-empty array of base64 strings`)
			}
			s.Bytes = b
		default:
			return malformedRecipe("unknown step key %q", k)
		}
	}
	return nil
}

// The three patterns the §5 schema's "base64-line" must match: alphabet and
// padding, whole quanta, and zero pad bits ("QR==" is not canonical).
var (
	reB64Alphabet = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	reB64Quanta   = regexp.MustCompile(`^(.{4})*$`)
	reB64PadBits  = regexp.MustCompile(`^([^=]*|.*[AQgw]==|.*[AEIMQUYcgkosw048]=)$`)
)

// decodeRecipeBytes decodes one "u" item: canonical base64 as the §5 schema
// patterns define it (standard alphabet, padded, zero pad bits, nothing else
// -- not even whitespace) whose decoded octets contain neither CR nor LF.
// The result is returned as a Go string so it flows down the same path as a
// "d" value; Go strings hold arbitrary octets and nothing on the hashing
// path validates UTF-8.
func decodeRecipeBytes(b64 string) (string, error) {
	if !reB64Alphabet.MatchString(b64) || !reB64Quanta.MatchString(b64) || !reB64PadBits.MatchString(b64) {
		return "", malformedRecipe(`"u" item is not canonical base64`)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil {
		return "", malformedRecipe(`"u" item is not canonical base64`)
	}
	if bytes.ContainsAny(raw, "\r\n") {
		return "", malformedRecipe(`"u" item decodes to octets containing CR or LF`)
	}
	return string(raw), nil
}

// literals returns the literal values a "d" or "u" step emits (decoded for
// "u"); nil for a "c" step. A "d" value containing CR or LF is rejected
// (§5.1/§5.2: "The text strings MUST NOT contain CR or LF characters"), and
// so is one that is not valid UTF-8 (that needs a "u" step).
func (s RecipeStep) literals() ([]string, error) {
	if s.Data != nil {
		for _, v := range s.Data {
			if strings.ContainsAny(v, "\r\n") {
				return nil, malformedRecipe(`"d" item contains CR or LF`)
			}
			if !utf8.ValidString(v) {
				return nil, malformedRecipe(`"d" item is not valid UTF-8`)
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
// every step is exactly one of c/d/u; each "c" has 1 <= start <= end, and
// its start is greater than the end of every preceding "c" (ascending,
// non-overlapping); every "d" item is UTF-8 without CR or LF; every "u" item
// decodes.
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
			return malformedRecipe("step %d must be exactly one of c/d/u", i)
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

// errDuplicateJSONKey is returned for Recipe JSON in which one object names
// a key twice (§5: keys MUST be unique): parsers disagree on which value
// wins, so {"b":[...],"b":null} would be a null body Recipe to some
// verifiers and signers and a real one to others.  errUppercaseJSONKey is
// returned for a key holding an ASCII capital, at any level: -08 keys are
// strictly lowercase (contract D10).
var (
	errDuplicateJSONKey = errors.New("duplicate JSON object key")
	errUppercaseJSONKey = errors.New("JSON object key is not lowercase")
)

// jsonDuplicateKey walks data's tokens and returns errDuplicateJSONKey for
// the first object that names a key twice (compared exactly, after
// unescaping), or errUppercaseJSONKey for the first key holding an ASCII
// capital A-Z (non-ASCII letters are not judged).  It returns nil for valid
// JSON without either; invalid JSON is left to json.Unmarshal to report.
func jsonDuplicateKey(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	type frame struct {
		keys    map[string]bool // nil for an array
		wantKey bool
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.keys != nil && top.wantKey {
			if k, ok := tok.(string); ok {
				if strings.ContainsAny(k, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
					return fmt.Errorf("%w %q", errUppercaseJSONKey, k)
				}
				if top.keys[k] {
					return fmt.Errorf("%w %q", errDuplicateJSONKey, k)
				}
				top.keys[k] = true
				top.wantKey = false
				continue
			}
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, &frame{keys: map[string]bool{}, wantKey: true})
			continue
		case json.Delim('['):
			stack = append(stack, &frame{})
			continue
		case json.Delim('}'), json.Delim(']'):
			stack = stack[:len(stack)-1]
		}
		// A value (or a closed container) completes a member of the object
		// below: its next string token is a key again.
		if len(stack) > 0 && stack[len(stack)-1].keys != nil {
			stack[len(stack)-1].wantKey = true
		}
	}
}

// jsonLoneSurrogate reports whether a JSON text escapes a UTF-16 surrogate
// that is not half of a pair ("\ud800"): encoding/json would quietly turn it
// into U+FFFD, but it is not a character, so the string is not valid UTF-8
// text.
func jsonLoneSurrogate(data []byte) bool {
	hex4 := func(i int) (rune, bool) {
		if i+6 > len(data) || data[i] != '\\' || data[i+1] != 'u' {
			return 0, false
		}
		var r rune
		for _, c := range data[i+2 : i+6] {
			switch {
			case c >= '0' && c <= '9':
				r = r<<4 | rune(c-'0')
			case c >= 'a' && c <= 'f':
				r = r<<4 | rune(c-'a'+10)
			case c >= 'A' && c <= 'F':
				r = r<<4 | rune(c-'A'+10)
			default:
				return 0, false
			}
		}
		return r, true
	}
	inString := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			inString = c == '"'
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			r, ok := hex4(i)
			if !ok {
				i++ // a two-character escape
				continue
			}
			switch {
			case r >= 0xd800 && r <= 0xdbff:
				lo, ok := hex4(i + 6)
				if !ok || lo < 0xdc00 || lo > 0xdfff {
					return true
				}
				i += 11
			case r >= 0xdc00 && r <= 0xdfff:
				return true
			default:
				i += 5
			}
		}
	}
	return false
}

// parseRecipe parses and checks a Recipe JSON object (§5).  parseMI reports
// every failure -- invalid JSON, a duplicate key, or a breach of the schema
// or step rules -- as "contains invalid JSON".  Keys are lowercase at every
// level, or the JSON is invalid (contract D10).
func parseRecipe(data []byte) (*Recipe, error) {
	if !utf8.Valid(data) || jsonLoneSurrogate(data) {
		return nil, malformedRecipe("not UTF-8 JSON text")
	}
	if err := jsonDuplicateKey(data); err != nil {
		return nil, err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	if probe == nil {
		return nil, malformedRecipe("the Recipe is not a JSON object")
	}
	var r Recipe
	var hasH, hasB bool
	for k, v := range probe {
		switch k {
		case "h":
			hasH = true
			// §5 schema: "h" is an object with at least one property, each
			// an array of steps.  An absent "h" means the header fields
			// were unchanged; null, {} or a non-array value is invalid.
			var h map[string]json.RawMessage
			if err := json.Unmarshal(v, &h); err != nil || h == nil {
				return nil, malformedRecipe(`"h" is not an object`)
			}
			if len(h) == 0 {
				return nil, malformedRecipe(`"h" names no header field`)
			}
			for name, steps := range h {
				if t := bytes.TrimLeft(steps, " \t\r\n"); len(t) == 0 || t[0] != '[' {
					return nil, malformedRecipe("header %q Recipe is not an array", name)
				}
			}
		case "b":
			hasB = true
			if string(bytes.TrimSpace(v)) == "null" {
				r.BodyNull = true
			}
		}
	}
	if !hasH && !hasB {
		return nil, malformedRecipe(`neither "h" nor "b" is present`)
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
	// §5: the JSON keys, header field names included, MUST be lower
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

// ComputeDiffOptions tunes ComputeDiffWithOptions.
type ComputeDiffOptions struct {
	// MaxLiterals caps the literal lines a body Recipe may carry; a diff
	// needing more yields the null body Recipe (BodyNull). Zero or negative
	// means the default, MaxRecipeLiterals.
	MaxLiterals int
}

// ComputeDiff computes the Recipe that describes how afterHeaders/afterBody
// differs from beforeHeaders/beforeBody, with the default literal cap
// (MaxRecipeLiterals). Returns nil if nothing changed.
func ComputeDiff(beforeHeaders []Header, beforeBody []byte,
	afterHeaders []Header, afterBody []byte) (*Recipe, error) {
	return ComputeDiffWithOptions(beforeHeaders, beforeBody, afterHeaders, afterBody, ComputeDiffOptions{})
}

// ComputeDiffWithOptions is ComputeDiff with tunables (see
// ComputeDiffOptions). When the body diff exceeds the literal cap or
// MaxDiffWork the Recipe has BodyNull set and no body steps.
func ComputeDiffWithOptions(beforeHeaders []Header, beforeBody []byte,
	afterHeaders []Header, afterBody []byte, opts ComputeDiffOptions) (*Recipe, error) {
	maxLiterals := opts.MaxLiterals
	if maxLiterals <= 0 {
		maxLiterals = MaxRecipeLiterals
	}
	r := &Recipe{}
	changed := false

	beforeLines := splitLines(beforeBody)
	afterLines := splitLines(afterBody)
	if !equalStringSlices(beforeLines, afterLines) {
		changed = true
		steps, tooBig := bodyRecipeSteps(beforeLines, afterLines, maxLiterals)
		if tooBig {
			r.BodyNull = true // §5.2 null Recipe: "b": null
		} else {
			r.Body = steps
		}
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
// valid UTF-8 (ASCII included), otherwise as a "u" item carrying the exact
// octets (§5.1/§5.2: "u" MUST be used when the value is not valid UTF-8 and
// SHOULD NOT be when "d" would do; encoding/json would turn any non-UTF-8
// byte in a "d" string into U+FFFD). Consecutive literals of the same kind
// coalesce into one step; a mixed run alternates d and u steps.
func appendLiteral(steps []RecipeStep, val string) []RecipeStep {
	n := len(steps)
	if utf8.ValidString(val) {
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
// appendLiteral, so non-UTF-8 values become "u" items). Indices already passed
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

// bodyRecipeSteps builds the body Recipe (lines numbered top-down, §5.2)
// that rebuilds the before lines from the after lines, using the capped
// Myers diff (bodyDiff) with at most maxLiterals literal lines. tooBig reports that no recipe
// within the cap exists, so the caller must emit the null body Recipe.
// Literal runs are grouped into "d"/"u" steps by appendLiteral. The steps are
// never nil unless tooBig: an empty previous body is the empty list.
func bodyRecipeSteps(before, after []string, maxLiterals int) (steps []RecipeStep, tooBig bool) {
	flat, kind := bodyDiff(after, before, maxLiterals)
	if kind == bodyDiffTooBig {
		return nil, true
	}
	steps = []RecipeStep{}
	for _, st := range flat {
		if st.Lit {
			steps = appendLiteral(steps, st.Line)
			continue
		}
		c := [2]int{st.From, st.To}
		steps = append(steps, RecipeStep{Copy: &c})
	}
	return steps, false
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
