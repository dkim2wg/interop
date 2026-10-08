package dkim2

import "fmt"

// ErrMissingTag is returned when parsing a DKIM2-Signature
// or Message-Instance header and a required tag is missing
type ErrMissingTag struct {
	Name string
	V    string
	Tag  string
}

func (e ErrMissingTag) Error() string {
	return fmt.Sprintf("Missing tag '%s' in %s header", e.Tag, e.Name)
}

// ErrInvalidTag is returned when parsing a DKIM2-Signature
// or Message-Instance header and a tag isn't valid.
type ErrInvalidTag struct {
	Name   string
	V      string
	Tag    string
	TagVal string
	Err    error
}

func (e ErrInvalidTag) Error() string {
	return fmt.Sprintf("Malformed tag %q in %s header: %s", e.TagVal, e.Name, e.Err)
}

func (e ErrInvalidTag) Unwrap() error {
	return e.Err
}

// ErrMalformedHeader is returned when failing to parse a
// DKIM2-Signature or Message-Instance header.
type ErrMalformedHeader struct {
	Name string
	V    string
	Err  error
	Idx  int
}

func (e ErrMalformedHeader) Error() string {
	return fmt.Sprintf("Malformed %s header %q: %s", e.Name, e.V, e.Err)
}

func (e ErrMalformedHeader) Unwrap() error {
	return e.Err
}

// ErrRequiresRecipe is returned when trying to add a signature
// to a previously signed message where the hash has changed
// and no recipe was provided.
type ErrRequiresRecipe struct{}

func (e ErrRequiresRecipe) Error() string {
	return "Message hash has changed and no recipe was provided"
}

// ErrDuplicateOrdering is returned when there are multiple
// headers with the same i= (DKIM2-Signature) or
//m= (Message-Instance)

type ErrDuplicateOrdering struct {
	Tag    string
	TagVal int
}

func (e ErrDuplicateOrdering) Error() string {
	return fmt.Sprintf("Duplicate ordering for tag %s=%d", e.Tag, e.TagVal)
}
