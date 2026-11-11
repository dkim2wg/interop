package dkim2

import (
	"cmp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type MessageInstance struct {
	Revision int
	Hashes   []HashSet
	Recipes  *Recipe
	Original string
}

var base64Regexp = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)

// ParseMessageInstance parses the contents of a Message-Instance header
func ParseMessageInstance(s string) (*MessageInstance, error) {
	tags, err := NewTags(hdrMessageInstance, s, "m")
	if err != nil {
		return nil, err
	}
	rev, ok := tags.Get("m")
	if !ok {
		return nil, ErrMissingTag{
			Name: hdrMessageInstance,
			V:    s,
			Tag:  "m",
		}
	}
	revI, err := strconv.ParseInt(rev, 10, 32)
	if err != nil {
		return nil, ErrInvalidTag{
			Name:   hdrMessageInstance,
			V:      s,
			Tag:    "m",
			TagVal: rev,
			Err:    err,
		}
	}

	ret := MessageInstance{
		Revision: int(revI),
		Original: s,
	}

	hashes, ok := tags.Get("h")
	if !ok {
		return nil, ErrMessageInstanceTagMissing{
			MInstance: ret.Revision,
			Tag:       "h",
			Header:    s,
		}
	}

	hashList := strings.Split(hashes, ",")
	for _, h := range hashList {
		parts := strings.Split(h, ":")
		if len(parts) != 3 {
			return nil, ErrMessageInstanceSyntaxError{
				MInstance: ret.Revision,
				Header:    s,
				Err: ErrInvalidTag{
					Name:   hdrMessageInstance,
					V:      s,
					Tag:    "h",
					TagVal: h,
					Err:    errors.New("should have three components"),
				},
			}
		}
		headerHash := removeWhitespace(parts[1])
		bodyHash := removeWhitespace(parts[2])
		hs := HashSet{
			Name: strings.TrimSpace(parts[0]),
		}
		hs.HeaderHash, err = base64.StdEncoding.Strict().DecodeString(headerHash)
		if err != nil {
			return nil, ErrMessageInstanceSyntaxError{
				MInstance: ret.Revision,
				Header:    s,
				Err: ErrInvalidTag{
					Name:   hdrMessageInstance,
					V:      s,
					Tag:    "h",
					TagVal: h,
					Err:    fmt.Errorf("in header hash: %w", err),
				},
			}
		}

		hs.BodyHash, err = base64.StdEncoding.Strict().DecodeString(bodyHash)
		if err != nil {
			return nil, ErrMessageInstanceSyntaxError{
				MInstance: ret.Revision,
				Header:    s,
				Err: ErrInvalidTag{
					Name:   hdrMessageInstance,
					V:      s,
					Tag:    "h",
					TagVal: h,
					Err:    fmt.Errorf("in body hash: %w", err),
				},
			}
		}
		ret.Hashes = append(ret.Hashes, hs)
	}

	encodedRecipes, ok := tags.Get("r")
	if !ok {
		return &ret, nil
	}

	encodedRecipes = removeWhitespace(encodedRecipes)
	//if !base64Regexp.MatchString(recipes) {
	//	return nil, ErrInvalidRTag{errors.New("recipe (r=) has invalid base64")}
	//}

	jsonRecipe, err := base64.StdEncoding.Strict().DecodeString(encodedRecipes)
	if err != nil {
		return nil, ErrMessageInstanceSyntaxError{
			MInstance: ret.Revision,
			Header:    s,
			Err: ErrInvalidTag{
				Name:   hdrMessageInstance,
				V:      s,
				Tag:    "r",
				TagVal: encodedRecipes,
				Err:    err,
			},
		}
	}
	var recipe Recipe
	err = json.Unmarshal(jsonRecipe, &recipe)
	if err != nil {
		return nil, ErrMessageInstanceSyntaxError{
			MInstance: ret.Revision,
			Header:    s,
			Err: ErrInvalidTag{
				Name:   hdrMessageInstance,
				V:      s,
				Tag:    "r",
				TagVal: encodedRecipes,
				Err:    err,
			},
		}
	}
	ret.Recipes = &recipe

	return &ret, nil
}

func (m MessageInstance) ToString() (string, error) {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "m=%d; h=", m.Revision)
	for i, h := range m.Hashes {
		if i != 0 {
			b.WriteString(",\r\n ")
		}
		b.WriteString(h.Name)
		b.WriteString(":")
		b.WriteString(base64.StdEncoding.EncodeToString(h.HeaderHash))
		b.WriteString(":")
		b.WriteString(base64.StdEncoding.EncodeToString(h.BodyHash))
	}
	//b.WriteString(";")
	if m.Recipes == nil {
		return b.String(), nil
	}
	b.WriteString(";\r\n r=")
	encoded, err := json.Marshal(m.Recipes)
	if err != nil {
		return "", ErrInvalidTag{
			Name:   hdrMessageInstance,
			V:      "",
			Tag:    "r",
			TagVal: "",
			Err:    err,
		}
	}
	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(encoded)))
	base64.StdEncoding.Encode(b64, encoded)
	var chunkLen = 70
	for len(b64) < chunkLen {
		b.Write(b64[:chunkLen])
		b.WriteString("\r\n ")
		b64 = b64[chunkLen:]
	}
	b.Write(b64)
	//b.WriteString(";")
	return b.String(), nil
}

// MessageInstanceHeaders parses a slice of Message-Instance header values
// and returns them as a list sorted by revision (m=)
func MessageInstanceHeaders(headers []string) ([]*MessageInstance, error) {
	miHeaders := make([]*MessageInstance, len(headers))
	for i, h := range headers {
		mi, err := ParseMessageInstance(h)
		if err != nil {
			return nil, err
		}
		miHeaders[i] = mi
	}
	slices.SortFunc(miHeaders, func(a, b *MessageInstance) int {
		return cmp.Compare(a.Revision, b.Revision)
	})
	return miHeaders, nil
}

var whitespaceRe = regexp.MustCompile(`\s+`)

func removeWhitespace(s string) string {
	return whitespaceRe.ReplaceAllLiteralString(s, "")
}

func NewMessageInstance(m *mail.Message) (*MessageInstance, error) {
	h := NormalizedHeaders(m.Header)

	// Find the highest revision. We don't fully parse or validate existing Message-Instance headers.
	revision := 1
	existingMIeaders, ok := h["message-instance"]
	if ok {
		for _, miHeader := range existingMIeaders {
			tags, err := NewTags(hdrMessageInstance, miHeader, "m")
			if err == nil {
				m, ok := tags.Get("m")
				if ok {
					rev, err := strconv.ParseInt(m, 10, 32)
					if err == nil && int(rev) >= revision {
						revision = int(rev) + 1
					}
				}
			}
		}
	}

	hashes, err := HashMessage(m.Body, NormalizedHeaders(m.Header))
	if err != nil {
		return nil, err
	}
	ret := &MessageInstance{
		Revision: revision,
		Hashes:   hashes,
	}
	return ret, nil
}

/*

A Message-Instance header field documents the current contents of
the message and, in the case of a Reviser, records any relevant
changes that have been made to the incoming message.

The Message-Instance header field is a list of tag values as described
below. The m= and h= tags MUST be present. The r= tag is optional.

The tag identifiers (before the = sign) MUST be treated as case
insignificant, the tag value (after the = sign) is case significant. The
tags may appear in any order, but MUST be only one of each kind. Unknown
tags, for extensions, MUST be ignored.

ABNF:

    mi-field    = "Message-Instance:" mi-tag-list
    mi-tag-list = *([FWS] mi-tag [FWS] ";" [FWS])
    mi-tag      = mi-m-tag / mi-h-tag / mi-r-tag / x-tag
    x-tag       = ALPHA *(ALPHA / DIGIT / "_") "=" %x21-3A / %x3C-7E
                  ; for extension

## m= the revision number of the Message-Instance header field

The Originator of a message uses the
value 1. Further Message-Instance header fields are added with a value one
more than the current highest numbered Message-Instance header field. Gaps
in the numbering MUST be treated as making the whole message impossible
to verify.

ABNF:

    mi-m-tag    = %x6d [FWS] "=" [FWS] 1*DIGIT

## r= recipes to recreate the previous instance of the message

The r= tag value is the base64 encoded version of the JSON object that
contains the recipes that allow the previous instance of the message
to be recreated (see {{JSONrecipe}}).

ABNF:

    mi-r-tag    = %x72 [FWS] "=" base64string

## h= the hash values for the message

The h= tag value contains the hash name, header hash value and body
hash value. Calculating the hash values is explained in {{messagehashes}}.

ABNF:

    mi-h-tag    = %x68 [FWS] "=" hash-set *("," hash-set )
    hash-set    = [FWS] hash-name [FWS] ":" header-hash ":" body-hash
    hash-name   = "sha256" / x-hash-name
    header-hash = base64string
    body-hash   = base64string
    x-hash-name = textstring ; for later expansion

*/
