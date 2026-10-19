package dkim2

import (
	"bufio"
	"bytes"
	"io"
	"strings"
)

// Header is one RFC 5322 header field with continuation lines joined.
type Header struct {
	Name  string // original case
	Value string // unfolded, leading WSP after colon stripped
	Raw   string // original folded form: "Name: value\r\n"
}

// parseHeaders reads headers from r up to the blank line separator.
// Returns the headers and the body, its line endings normalised to CRLF.
func parseHeaders(r io.Reader) ([]Header, *bytes.Buffer, error) {
	br := bufio.NewReader(r)
	headers, err := readHeaderFields(br)
	if err != nil {
		return nil, nil, err
	}
	body, err := readBody(br)
	if err != nil {
		return nil, nil, err
	}
	return headers, body, nil
}

// readHeaderFields reads the header fields from br up to and including the
// blank line that ends them, leaving br at the first byte of the body.
func readHeaderFields(br *bufio.Reader) ([]Header, error) {
	var rawLines []string // one entry per logical line (not yet joined)

	for {
		line, err := br.ReadString('\n')
		// Normalise line ending: strip \r\n or \n, we'll add \r\n back
		line = strings.TrimRight(line, "\r\n")

		if line == "" {
			// Blank line = end of headers
			if err == nil || err == io.EOF {
				break
			}
		}
		if line != "" {
			rawLines = append(rawLines, line)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	// Join continuation lines into Header structs
	var headers []Header
	var currentLines []string

	flush := func() {
		if len(currentLines) == 0 {
			return
		}
		// Raw = original folded form with CRLF endings
		raw := strings.Join(currentLines, "\r\n") + "\r\n"

		// Name: from first line up to colon
		first := currentLines[0]
		colon := strings.IndexByte(first, ':')
		var name, value string
		if colon >= 0 {
			name = strings.TrimSpace(first[:colon])
			// Unfold value: first line after colon + continuation lines
			value = strings.TrimLeft(first[colon+1:], " \t")
			for _, cont := range currentLines[1:] {
				value += " " + strings.TrimLeft(cont, " \t")
			}
			value = strings.TrimRight(value, " \t")
		} else {
			name = strings.TrimSpace(first)
		}
		headers = append(headers, Header{Name: name, Value: value, Raw: raw})
		currentLines = currentLines[:0]
	}

	for _, line := range rawLines {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			// Continuation line
			currentLines = append(currentLines, line)
		} else {
			flush()
			currentLines = append(currentLines, line)
		}
	}
	flush()
	return headers, nil
}

// readBody reads the rest of br as the body, each line's ending (LF, CRLF,
// any run of CRs before the LF, or none at all on the last line) normalised
// to CRLF.  chainPlan.Write splits a streamed body exactly the same way.
func readBody(br *bufio.Reader) (*bytes.Buffer, error) {
	raw := &bytes.Buffer{}
	if _, err := br.WriteTo(raw); err != nil {
		return nil, err
	}
	return bytes.NewBuffer(normalizeBody(raw.Bytes())), nil
}

// normalizeBody returns b with every line ending made CRLF, as readBody
// describes: b itself when every line already ends in exactly one CRLF,
// else a copy built from whole runs of b with only the endings rewritten.
func normalizeBody(b []byte) []byte {
	var out []byte    // nil until some line needs rewriting
	done, pos := 0, 0 // b[:done] is in out
	for pos < len(b) {
		lf := bytes.IndexByte(b[pos:], '\n')
		if lf < 0 {
			lf = len(b)
		} else {
			lf += pos
		}
		t := lf
		for t > pos && b[t-1] == '\r' {
			t--
		}
		if lf < len(b) && lf-t == 1 {
			pos = lf + 1
			continue
		}
		if out == nil {
			out = make([]byte, 0, len(b)+len(b)/8+2)
		}
		out = append(append(append(out, b[done:pos]...), b[pos:t]...), crlf...)
		pos = min(lf+1, len(b))
		done = pos
	}
	if out == nil {
		return b
	}
	return append(out, b[done:]...)
}
