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
// Returns the headers and an io.Reader positioned at the start of the body.
// Line endings are normalised to CRLF.
func parseHeaders(r io.Reader) ([]Header, io.Reader, error) {
	br := bufio.NewReader(r)

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
			return nil, nil, err
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

	// Rebuild body with normalised CRLF from whatever the bufio reader has left
	// plus any bytes still buffered in br.
	bodyBuf := &bytes.Buffer{}
	for {
		chunk, err := br.ReadString('\n')
		if len(chunk) > 0 {
			line := strings.TrimRight(chunk, "\r\n")
			bodyBuf.WriteString(line)
			bodyBuf.WriteString("\r\n") // intentional: DKIM2 always hashes CRLF-normalised bodies
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
	}

	return headers, bodyBuf, nil
}
