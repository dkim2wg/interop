package dkim2

import (
	"bufio"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"sort"
	"strings"
)

// spec-05 §3.1: two hashing algorithms are defined. Verifiers MUST implement
// both; Signers MAY implement either or both (we default to sha256).
var hashAlgs = map[string]func() hash.Hash{
	"sha256": sha256.New,
	"sha512": sha512.New,
}

// HashAlg resolves a spec-05 §7.3 hash-name to its constructor. Matching is
// case-insensitive: RFC 5234 makes ABNF quoted strings case-insensitive.
func HashAlg(name string) (func() hash.Hash, bool) {
	f, ok := hashAlgs[strings.ToLower(name)]
	return f, ok
}

// writeCanonicalBody streams the §5.1 body canonicalisation of r into w:
// strip all trailing empty lines, ensure exactly one trailing CRLF. The
// pending-CRLF counter accumulates consecutive empty lines and flushes them
// only when a non-empty line follows, so trailing empty lines are discarded.
// w is written to exactly once per canonical line/CRLF; hash.Hash.Write never
// returns an error, so callers passing a hash (directly, or via io.MultiWriter
// fanning out to several) can ignore Write's return value the same way this
// function does.
func writeCanonicalBody(w io.Writer, r io.Reader) error {
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
				w.Write([]byte("\r\n"))
			}
			pendingCRLFs = 0
			w.Write([]byte(line))
			w.Write([]byte("\r\n"))
			hasContent = true
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// Trailing empty lines (and an all-blank body) are discarded.
	// The canonical form always ends with exactly one CRLF.
	if !hasContent {
		w.Write([]byte("\r\n"))
	}
	return nil
}

// hashBody computes the hash (per alg) of the canonicalised message body per §5.1.
func hashBody(r io.Reader, alg string) ([]byte, error) {
	newHash, ok := HashAlg(alg)
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm: %q", alg)
	}
	h := newHash()
	if err := writeCanonicalBody(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// hashBodyMulti computes the body hash for every algorithm in algs in a
// single streaming pass over r — the body is canonicalised once and fanned
// out to one hash.Hash per (deduplicated) algorithm via io.MultiWriter, so r
// is never buffered regardless of how many algorithms are requested. algs
// may be empty (r is still drained; an empty map is returned).
func hashBodyMulti(r io.Reader, algs []string) (map[string][]byte, error) {
	hashers := make(map[string]hash.Hash, len(algs))
	writers := make([]io.Writer, 0, len(algs))
	for _, alg := range algs {
		if _, exists := hashers[alg]; exists {
			continue
		}
		newHash, ok := HashAlg(alg)
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm: %q", alg)
		}
		h := newHash()
		hashers[alg] = h
		writers = append(writers, h)
	}
	if err := writeCanonicalBody(io.MultiWriter(writers...), r); err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(hashers))
	for alg, h := range hashers {
		out[alg] = h.Sum(nil)
	}
	return out, nil
}

// Unsigned header fields per spec-05 §4, §4.1.
var excludedHeaderNames = map[string]bool{
	"apparently-to": true, "arc-authentication-results": true,
	"arc-message-signature": true, "arc-seal": true,
	"authentication-results": true, "auto-submitted": true,
	"delivered-to": true, "dkim-signature": true,
	"dkim2-signature": true, "dl-expansion-history": true,
	"message-instance": true, "original-recipient": true,
	"received": true, "return-path": true, "sio-label-history": true,
	"vbr-info": true, "x400-received": true, "x400-trace": true,
}

// spec-05 §4 narrowed the ARC- prefix to three exact names (above) and added
// a Received-* prefix rule so future trace fields of that form need no change.
var excludedHeaderPrefixes = []string{"x-", "received-"}

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

// hashHeaders computes the hash (per alg) of canonicalised, sorted headers per §5.2.
func hashHeaders(headers []Header, alg string) ([]byte, error) {
	newHash, ok := HashAlg(alg)
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm: %q", alg)
	}
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

	h := newHash()
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
