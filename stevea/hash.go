package dkim2

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"net/mail"
	"slices"
	"strings"
)

type HashSet struct {
	Name       string
	HeaderHash []byte
	BodyHash   []byte
}

func (h HashSet) String() string {
	var b strings.Builder
	b.WriteString(h.Name)
	b.WriteRune(':')
	b.WriteString(base64.StdEncoding.EncodeToString(h.HeaderHash))
	b.WriteRune(':')
	b.WriteString(base64.StdEncoding.EncodeToString(h.BodyHash))
	return b.String()
}

func (h HashSet) Equal(other HashSet) bool {
	return bytes.Equal(h.HeaderHash, other.HeaderHash) &&
		bytes.Equal(h.BodyHash, other.BodyHash) &&
		h.Name == other.Name
}

func (h HashSet) ContainedBy(others []HashSet) bool {
	return slices.ContainsFunc(others, func(other HashSet) bool {
		return h.Equal(other)
	})
}

type ErrInvalidHashName struct {
	Name string
}

func (e ErrInvalidHashName) Error() string {
	return fmt.Sprintf("invalid hash name: %q", e.Name)
}

func HashMessage(body io.Reader, header map[string][]string, hashNames ...string) ([]HashSet, error) {
	// The function can perform multiple hashes, if DKIM2
	// ever supports them other than theoretically.
	_ = hashNames
	bodyHasher := sha256.New()
	headerHasher := sha256.New()
	HashHeaders(headerHasher, header)
	HashBody(bodyHasher, body)
	return []HashSet{{
		Name:       "sha256",
		HeaderHash: headerHasher.Sum(nil),
		BodyHash:   bodyHasher.Sum(nil),
	}}, nil
}

// HashHeaders hashes the headers of an email, after they have
// been normalized by NormalizedHeaders
func HashHeaders(hash io.Writer, headers map[string][]string) {
	for _, key := range slices.Sorted(maps.Keys(headers)) {
		lines := headers[key]
		for _, line := range slices.Backward(lines) {
			hash.Write([]byte(key))
			hash.Write([]byte(":"))
			hash.Write([]byte(line))
			hash.Write([]byte("\r\n"))
		}
	}
}

// HashBody hashes the content of the body, with line-endings
// converted to CRLF, any blank lines at the end of the body
// excluded and a trailing CRLF.
func HashBody(hash io.Writer, body io.Reader) {
	scanner := bufio.NewScanner(body)
	hasTrailingCRLF := false
	blankLinesCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			blankLinesCount++
			continue
		}
		for blankLinesCount > 0 {
			_, _ = hash.Write([]byte("\r\n"))
			blankLinesCount--
		}
		_, _ = hash.Write([]byte(line))
		_, _ = hash.Write([]byte("\r\n"))
		hasTrailingCRLF = true
	}
	if !hasTrailingCRLF {
		_, _ = hash.Write([]byte("\r\n"))
	}
}

// NormalizedHeaders returns the headers of an email,
// unfolded, with keys folded to lower case and with
// headers that should not be part of a signature removed.
func NormalizedHeaders(headers mail.Header) map[string][]string {
	ret := make(map[string][]string, len(headers))
	for k, v := range headers {
		k = strings.ToLower(k)
		switch k {
		case "received", "return-path", "message-instance", "dkim2-signature", "dkim-signature":
			continue
		}
		if strings.HasPrefix(k, "x-") || strings.HasPrefix(k, "arc-") {
			continue
		}
		values := make([]string, 0, len(v))
		for _, val := range v {
			values = append(values, strings.TrimSpace(whitespaceRe.ReplaceAllString(val, " ")))
		}
		ret[strings.ToLower(k)] = values
	}
	return ret
}
