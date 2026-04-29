package dkim2

import (
	"bufio"
	"crypto/sha256"
	"io"
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

	// Trailing empty lines are discarded.
	// For an empty body, write exactly one CRLF (the canonical form of an empty body).
	if !hasContent {
		h.Write([]byte("\r\n"))
	}
	return h.Sum(nil), nil
}
