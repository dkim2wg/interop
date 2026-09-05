package dkim2

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

// VerifyFull verifies the signature chain and the top Message-Instance (via
// Verify), then validates every lower Message-Instance by reconstructing it
// with Undo (which checks that level's recorded header/body hashes). A
// reconstruction or hash failure is reported as an extra failing VerifyResult.
func VerifyFull(r io.Reader, fetcher KeyFetcher, opts ...VerifyOptions) ([]VerifyResult, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	results, err := Verify(bytes.NewReader(buf), fetcher, opts...)
	if err != nil {
		return results, err
	}

	// §12.1.2: with no body there is nothing to undo a lower instance into, so
	// Verify's top-instance header-hash check is as far as the chain walk goes.
	if len(opts) > 0 && opts[0].HeadersOnly {
		return results, nil
	}

	// Highest MI version present.
	headers, _, perr := parseHeaders(bytes.NewReader(buf))
	if perr != nil {
		return results, nil // Verify already covered parse-level issues
	}
	highest := 0
	for _, h := range headers {
		if strings.ToLower(h.Name) == "message-instance" {
			if mi, e := parseMI(h.Raw); e == nil && mi.Version > highest {
				highest = mi.Version
			}
		}
	}

	// Validate each lower instance. Undo(target) reconstructs highest..target
	// and verifies the target level's recorded hashes.
	for target := highest - 1; target >= 1; target-- {
		if err := Undo(bytes.NewReader(buf), io.Discard, target); err != nil {
			results = append(results, VerifyResult{
				Domain: fmt.Sprintf("MI-chain v=%d", target),
				Error:  fmt.Errorf("MI chain validation failed: %w", err),
			})
			break
		}
	}

	return results, nil
}
