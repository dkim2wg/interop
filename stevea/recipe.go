package dkim2

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/pkg/diff/myers"
	"github.com/pkg/diff/write"
)

type BodyReader struct {
	r      *bufio.Scanner
	lineno int
}

func (r *BodyReader) Scan() bool {
	r.lineno++
	return r.r.Scan()
}

func (r *BodyReader) Line() int {
	return r.lineno
}

func (r *BodyReader) Err() error {
	return r.r.Err()
}

func (r *BodyReader) Text() string {
	return r.r.Text()
}

func (r *BodyReader) Bytes() []byte {
	return r.r.Bytes()
}

func NewBodyReader(r io.Reader) *BodyReader {
	return &BodyReader{
		r:      bufio.NewScanner(r),
		lineno: 0,
	}
}

type RecipeCopyHeaderStep []int

func (s RecipeCopyHeaderStep) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string][]int{
		"c": s,
	})
}

// ApplyHeader applies the copy step to the list of headers given.
// old headers are in newer...older order, output headers in older...newer
func (s RecipeCopyHeaderStep) ApplyHeader(oldHeaders []string, newHeaders []string) ([]string, error) {
	if s[1] > len(oldHeaders) {
		return nil, fmt.Errorf("copy range outside header count")
	}
	for i := s[0]; i <= s[1]; i++ {
		newHeaders = append(newHeaders, oldHeaders[len(oldHeaders)-i])
	}
	return newHeaders, nil
}

type RecipeDataHeaderStep []string

func (s RecipeDataHeaderStep) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string][]string{
		"d": s,
	})
}

// ApplyHeader copies headers to the output.
// Output headers are in older...newer order
func (s RecipeDataHeaderStep) ApplyHeader(_ []string, newHeaders []string) ([]string, error) {
	newHeaders = append(newHeaders, s...)
	return newHeaders, nil
}

type RecipeCopyBodyStep []int

func (s RecipeCopyBodyStep) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string][]int{
		"c": s,
	})
}

func (s RecipeCopyBodyStep) ApplyBody(r *BodyReader, w io.Writer) error {
	for r.Line() < s[0] {
		if !r.Scan() {
			return r.Err()
		}
	}
	for r.Line() <= s[1] {
		_, err := io.WriteString(w, r.Text())
		if err != nil {
			return err
		}
		if !r.Scan() {
			return r.Err()
		}
		_, err = io.WriteString(w, "\r\n")
		if err != nil {
			return err
		}
	}
	return nil
}

type RecipeDataBodyStep []string

func (s RecipeDataBodyStep) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string][]string{
		"d": s,
	})
}

func (s RecipeDataBodyStep) ApplyBody(_ *BodyReader, w io.Writer) error {
	for _, v := range s {
		_, err := io.WriteString(w, v)
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "\r\n")
		if err != nil {
			return err
		}
	}
	return nil
}

type RecipeTruncatedBodyStep struct{}

func (s RecipeTruncatedBodyStep) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]bool{
		"z": true,
	})
}

func (s RecipeTruncatedBodyStep) ApplyBody(_ *BodyReader, w io.Writer) error {
	//TODO implement me
	panic("implement me")
}

type RecipeHeaderStep interface {
	ApplyHeader(oldHeaders []string, newHeaders []string) ([]string, error)
}

type RecipeBodyStep interface {
	ApplyBody(r *BodyReader, w io.Writer) error
}

type RecipeHeaderSteps []RecipeHeaderStep

func (r *RecipeHeaderSteps) UnmarshalJSON(data []byte) error {
	var steps []map[string]json.RawMessage
	if err := json.Unmarshal(data, &steps); err != nil {
		return err
	}
	if steps == nil {
		*r = nil
		return nil
	}
	*r = make([]RecipeHeaderStep, 0, len(steps))
	for _, step := range steps {
		if len(step) != 1 {
			return fmt.Errorf("invalid recipe step: %v", step)
		}
		var prevEnd int
		for k, v := range step {
			switch k {
			case "d":
				var s RecipeDataHeaderStep
				err := json.Unmarshal(v, &s)
				if err != nil {
					return fmt.Errorf("invalid recipe json: %w", err)
				}
				*r = append(*r, s)
			case "c":
				var s RecipeCopyHeaderStep
				err := json.Unmarshal(v, &s)
				if err != nil {
					return fmt.Errorf("invalid recipe json: %w", err)
				}
				if len(s) != 2 {
					return fmt.Errorf("recipe step should have two values: %v", s)
				}
				if s[0] > s[1] {
					return fmt.Errorf("recipe copy step should have end >= start: %v", s)
				}
				if s[0] < 1 {
					return fmt.Errorf("recipe copy step must have start >= 1: %v", s)
				}
				if s[0] <= prevEnd {
					return fmt.Errorf("recipe copy start (%d) must be > previous end (%d)", s[0], prevEnd)
				}
				prevEnd = s[1]
				*r = append(*r, s)

			default:
				return fmt.Errorf("invalid recipe step key: %q", k)
			}
		}
	}
	return nil
}

type RecipeBodySteps []RecipeBodyStep

func (r *RecipeBodySteps) UnmarshalJSON(data []byte) error {
	var steps []map[string]json.RawMessage
	if err := json.Unmarshal(data, &steps); err != nil {
		return err
	}
	if steps == nil {
		*r = nil
		return nil
	}
	*r = make([]RecipeBodyStep, 0, len(steps))
	for _, step := range steps {
		if len(step) != 1 {
			return fmt.Errorf("invalid recipe step: %v", step)
		}
		var prevEnd int
		for k, v := range step {
			switch k {
			case "d":
				var s RecipeDataBodyStep
				err := json.Unmarshal(v, &s)
				if err != nil {
					return fmt.Errorf("invalid recipe json: %w", err)
				}
				*r = append(*r, s)
			case "c":
				var s RecipeCopyBodyStep
				err := json.Unmarshal(v, &s)
				if err != nil {
					return fmt.Errorf("invalid recipe json: %w", err)
				}
				if len(s) != 2 {
					return fmt.Errorf("recipe step should have two values: %v", s)
				}
				if s[0] > s[1] {
					return fmt.Errorf("recipe copy step should have end >= start: %v", s)
				}
				if s[0] < 1 {
					return fmt.Errorf("recipe copy step must have start >= 1: %v", s)
				}
				if s[0] <= prevEnd {
					return fmt.Errorf("recipe copy start (%d) must be > previous end (%d)", s[0], prevEnd)
				}
				prevEnd = s[1]
				*r = append(*r, s)
			case "z":
				var b bool
				if err := json.Unmarshal(v, &b); err != nil {
					return fmt.Errorf("invalid recipe json: %w", err)
				}
				if !b {
					return fmt.Errorf("recipe step z is not true: %v", v)
				}
				*r = append(*r, RecipeTruncatedBodyStep{})
			default:
				return fmt.Errorf("invalid recipe step key: %q", k)
			}
		}
	}
	return nil
}

type RecipeHeaderMap map[string]RecipeHeaderSteps

type Recipe struct {
	HeaderRecipes *RecipeHeaderMap `json:"h,omitempty"`
	BodyRecipes   *RecipeBodySteps `json:"b,omitempty"`
}

func (r *Recipe) UnmarshalJSON(data []byte) error {
	var s struct {
		HeaderRecipes *RecipeHeaderMap `json:"h"`
		BodyRecipes   *RecipeBodySteps `json:"b"`
	}
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	r.HeaderRecipes = s.HeaderRecipes
	r.BodyRecipes = s.BodyRecipes
	if r.HeaderRecipes != nil {
		for k := range *r.HeaderRecipes {
			if strings.ToLower(k) != k {
				return fmt.Errorf("invalid header name (must be lower case): %q", k)
			}
		}
	}
	return nil
}

// Header applies the recipe to an email header represented as a map of string slices.
// The key of the map is the name of the header, folded to lower case. The slice is
// successive headers of that name from top to bottom.
func (r *Recipe) Header(current map[string][]string) (map[string][]string, error) {
	if r.HeaderRecipes == nil {
		// If there is no "h" field in the JSON object then there was no
		// modification to the header fields.
		return current, nil
	}
	if len(*r.HeaderRecipes) == 0 {
		// If the "h" field value is null (there are no recipes for
		// any header field) then the previous state of the header fields
		// cannot be recreated.
		return nil, nil
	}

	result := make(map[string][]string, len(current))
	for k, v := range current {
		// If a header field name is not present in the JSON object then all
		// header fields with that header field name are to be retained.
		_, ok := (*r.HeaderRecipes)[k]
		if !ok {
			result[k] = v
		}
	}

	for k, recipe := range *r.HeaderRecipes {
		oldHeaders := current[k]
		var newHeaders []string
		for _, step := range recipe {
			var err error
			newHeaders, err = step.ApplyHeader(oldHeaders, newHeaders)
			if err != nil {
				return nil, err
			}
		}
		if newHeaders != nil {
			// ApplyHeader appends the headers we add to the end of the newHeaders slice,
			// which is the reverse of what we want
			slices.Reverse(newHeaders)
			result[k] = newHeaders
		}
	}
	return result, nil
}

func (r *Recipe) Body(newBody io.Reader, w io.Writer) error {
	if r.BodyRecipes == nil {
		_, err := io.Copy(w, newBody)
		return err
	}

	reader := NewBodyReader(newBody)
	for _, step := range *r.BodyRecipes {
		err := step.ApplyBody(reader, w)
		if err != nil {
			return err
		}
	}
	return nil
}

// HeadersFromMailHeaders creates headers suitable for Recipe.Header() from a mail.Header,
// stripping out unwanted headers and normalizing the header payloads.

//
// *  Ignore some header fields
//
// When calculating the header field hash "Received" or "Return-Path"
// header fields MUST be ignored.
// These are Trace headers as described in [RFC5321]
// and serve only to document details of the SMTP transmission process.
//
// When calculating the header field hash any header field with
// a header field name starting with "X-" MUST be ignored.
// Currently deployed email systems use these fields as
// proprietary Trace headers which have no defined meaning for
// other systems and it considerably simplifies reporting
// on changes to header fields to ignore them.
//
// When calculating the header field hash any "Message-Instance" or
// "DKIM2-Signature" header fields MUST be ignored. These header
// fields will be included in the hash value that will be signed
// by a DKIM2-Signature header field and it simplifies implementations
// if they are not included twice, especially when determining
// whether all modifications to a message have been correctly declared.
//
// When calculating the header field hash any "DKIM-Signature" header
// fields and any header fields whose field name starts with "ARC-"
// MUST be ignored. Not including
// DKIM1 and ARC signatures means that systems that wish to add other
// types of signature as well as a DKIM2 signature are free to do this
// in any convenient order.
//
// *  Convert all header field names (not the header field values) to
// lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC".
//
// *  Unfold all header field continuation lines as described in
// [RFC5322]; in particular, lines with terminators embedded in
// continued header field values (that is, CRLF sequences followed by
// WSP) MUST be interpreted without the CRLF.  Implementations MUST
// NOT remove the CRLF at the end of the header field value.
//
// *  Convert all sequences of one or more WSP characters to a single SP
// character.  WSP characters here include those before and after a
// line folding boundary.
//
// *  Delete all WSP characters at the end of each unfolded header field
// value.
//
// *  Delete any WSP characters remaining before and after the colon
// separating the header field name from the header field value.  The
// colon separator MUST be retained.

func headersEqual(a, b map[string][]string) bool {
	for k := range b {
		_, ok := a[k]
		if !ok {
			return false
		}
	}
	for k, valuesA := range a {
		valuesB, ok := b[k]
		if !ok {
			return false
		}
		if len(valuesA) != len(valuesB) {
			return false
		}
		for i, payloadA := range valuesA {
			if payloadA != valuesB[i] {
				return false
			}
		}
	}
	return true
}

type headerPair struct {
	oldHeaders []string
	newHeaders []string
}

func (h headerPair) WriteATo(w io.Writer, ai int) (int, error) {
	return io.WriteString(w, h.newHeaders[ai])
}

func (h headerPair) WriteBTo(w io.Writer, bi int) (int, error) {
	return io.WriteString(w, h.oldHeaders[bi])
}

func (h headerPair) LenA() int {
	return len(h.newHeaders)
}

func (h headerPair) LenB() int {
	return len(h.oldHeaders)
}

func (h headerPair) Equal(ai, bi int) bool {
	return h.newHeaders[ai] == h.oldHeaders[bi]
}

var _ myers.Pair = headerPair{}
var _ write.Pair = headerPair{}

/*
// diffHeaders creates a recipe to convert from newHeader to oldHeader
func diffHeaders(ctx context.Context, oldHeader, newHeader map[string][]string) *RecipeHeaderMap {
	if headersEqual(oldHeader, newHeader) {
		return nil
	}
	res := RecipeHeaderMap{}
	for k, v := range oldHeader {
		slices.Reverse(v)
		nv, ok := newHeader[k]
		if !ok {
			// New doesn't have this header, so we need to add them all
			res[k] = []RecipeHeaderStep{RecipeDataHeaderStep(v)}
			continue
		}
		slices.Reverse(nv)
		script := myers.Diff(ctx, headerPair{v, nv})
		if script.IsIdentity() {
			// Old and new are the same, so we don't record any recipe for them
			continue
		}
		changes := []RecipeHeaderStep{}

		write.Unified(script, os.Stdout, headerPair{v, nv})

		// Not clear what order the edits come out of myers.Diff,
		// so sort by destination range start
		slices.SortFunc(script.Ranges, func(a, b edit.Range) int {
			return cmp.Compare(a.LowB, b.LowB)
		})
		for _, scriptRange := range script.Ranges {
			switch {
			case scriptRange.IsEqual():
				changes = append(changes, RecipeCopyHeaderStep{
					scriptRange.LowA + 1,
					scriptRange.HighA,
				})
			case scriptRange.IsInsert():
				changes = append(changes, RecipeDataHeaderStep(v[scriptRange.LowB:scriptRange.HighB]))
			}
		}
		res[k] = changes
	}

	for k := range newHeader {
		if _, ok := oldHeader[k]; !ok {
			// Delete all headers with this name
			res[k] = []RecipeHeaderStep{}
		}
	}
	return &res
}
*/
