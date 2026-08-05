package dkim2

import (
	"bufio"
	"crypto/sha256"
	"io"
	"sort"
	"strings"
)

// hashBody computes the SHA-256 of the canonicalised message body per §5.1.
// Canonicalisation: strip all trailing empty lines, ensure exactly one trailing CRLF.
// The pending-CRLF counter accumulates consecutive empty lines and flushes them
// only when a non-empty line follows, so trailing empty lines are discarded.
func hashBody(r io.Reader) ([]byte, error) {
	h := sha256.New()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1 MiB max line
	pendingCRLFs := 0
	hasContent := false

	for scanner.Scan() {
		line := scanner.Text() // strips the \n; may still have trailing \r
		line = strings.TrimRight(line, "\r")

		if line == "" {
			pendingCRLFs++
		} else {
			// Flush any accumulated empty lines before this non-empty line
			for i := 0; i < pendingCRLFs; i++ {
				h.Write([]byte("\r\n"))
			}
			pendingCRLFs = 0
			h.Write([]byte(line))
			h.Write([]byte("\r\n"))
			hasContent = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Trailing empty lines (and an all-blank body) are discarded.
	// The canonical form always ends with exactly one CRLF.
	if !hasContent {
		h.Write([]byte("\r\n"))
	}
	return h.Sum(nil), nil
}

var excludedHeaderNames = map[string]bool{
	"received": true, "return-path": true, "message-instance": true,
	"dkim2-signature": true, "dkim-signature": true,
	"authentication-results": true, "delivered-to": true,
}
var excludedHeaderPrefixes = []string{"x-", "arc-"}

func shouldExcludeHeader(name string) bool {
	lower := strings.ToLower(name)
	if excludedHeaderNames[lower] {
		return true
	}
	for _, p := range excludedHeaderPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func collapseWSP(s string) string {
	var b strings.Builder
	inWSP := false
	for _, c := range s {
		if c == ' ' || c == '\t' {
			if !inWSP {
				b.WriteRune(' ')
				inWSP = true
			}
		} else {
			b.WriteRune(c)
			inWSP = false
		}
	}
	return b.String()
}

func canonicalizeHeader(h Header) string {
	raw := h.Raw
	// Unfold: remove CRLF before WSP
	raw = strings.ReplaceAll(raw, "\r\n ", " ")
	raw = strings.ReplaceAll(raw, "\r\n\t", "\t")
	raw = strings.TrimRight(raw, "\r\n")

	colon := strings.IndexByte(raw, ':')
	var name, value string
	if colon >= 0 {
		name = raw[:colon]
		value = raw[colon+1:]
	} else {
		name = raw
	}

	name = collapseWSP(strings.ToLower(name))
	name = strings.TrimSpace(name)

	value = collapseWSP(value)
	value = strings.TrimRight(value, " \t")
	value = strings.TrimLeft(value, " \t")

	return name + ":" + value
}

// hashHeaders computes the SHA-256 of canonicalised, sorted headers per §5.2.
func hashHeaders(headers []Header) ([]byte, error) {
	type canonPair struct {
		name  string
		canon string
	}
	var pairs []canonPair
	for _, h := range headers {
		if shouldExcludeHeader(h.Name) {
			continue
		}
		canon := canonicalizeHeader(h)
		pairs = append(pairs, canonPair{strings.ToLower(h.Name), canon})
	}

	// Bottom-up ordering for duplicates: reverse slice before stable sort so
	// the last occurrence of a name sorts first within that name's group.
	for i, j := 0, len(pairs)-1; i < j; i, j = i+1, j-1 {
		pairs[i], pairs[j] = pairs[j], pairs[i]
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		return pairs[i].name < pairs[j].name
	})

	h := sha256.New()
	for i, p := range pairs {
		h.Write([]byte(p.canon))
		if i < len(pairs)-1 {
			h.Write([]byte("\r\n"))
		}
	}
	if len(pairs) > 0 {
		h.Write([]byte("\r\n"))
	}
	return h.Sum(nil), nil
}

// canonicalizeSigHeader applies §9.5 canonicalization: unfold, lowercase name,
// delete ALL WSP from value. Returns the canonical form ending in \r\n.
func canonicalizeSigHeader(raw string) []byte {
	// Unfold
	raw = strings.ReplaceAll(raw, "\r\n ", " ")
	raw = strings.ReplaceAll(raw, "\r\n\t", "\t")
	raw = strings.TrimRight(raw, "\r\n")

	colon := strings.IndexByte(raw, ':')
	var name, value string
	if colon >= 0 {
		name = raw[:colon]
		value = raw[colon+1:]
	} else {
		name = raw
	}

	name = strings.TrimSpace(strings.ToLower(name))

	var b strings.Builder
	for _, c := range value {
		if c != ' ' && c != '\t' {
			b.WriteRune(c)
		}
	}
	value = b.String()

	return []byte(name + ":" + value + "\r\n")
}
