package dkim2

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// VerifyFull verifies the signature chain and the top Message-Instance (as
// Verify does), then validates every lower Message-Instance against the
// version of the message its Recipes rebuild.  A Recipe or hash failure is
// reported as an extra failing VerifyResult ("MI-chain v=N"); a Recipe that
// breaks the §5 rules against the message is the verbatim PERMERROR.
//
// The lower instances are checked by the planned walk (plan.go): the message
// is read once, its body streamed in the chunks r delivers into one pass that
// hashes every instance's body at once, and nothing is rebuilt.  The undo
// walk -- rebuilding each previous message with Undo -- gives the same
// verdicts; it is used with UndoWalk set, with HeadersOnly, and for the rare
// message the plan declines (see newChainPlan).
//
// With real DNS keys every key the signatures name is looked up in the
// background as soon as the header fields are read (see prefetchKeys).
func VerifyFull(r io.Reader, fetcher KeyFetcher, opts ...VerifyOptions) ([]VerifyResult, error) {
	if len(opts) > 0 && (opts[0].UndoWalk || opts[0].HeadersOnly) {
		return verifyFullUndo(r, fetcher, opts...)
	}

	// Keep what is read until the plan is known: the undo walk needs it all.
	rec := &recordingReader{r: r}
	br := bufio.NewReader(rec)
	headers, err := readHeaderFields(br)
	if err != nil {
		return nil, err
	}
	fetcher = prefetchKeys(headers, fetcher, opts...)
	plan := newChainPlan(headers)
	if plan == nil {
		return verifyFullUndo(io.MultiReader(bytes.NewReader(rec.buf), r), fetcher, opts...)
	}
	rec.buf, rec.off = nil, true

	// The body: what br already holds, then the rest straight from r (in
	// one slice from a bytes.Reader, else in plan.ReadFrom's large pieces).
	if n := br.Buffered(); n > 0 {
		b, _ := br.Peek(n)
		plan.Write(b)
	}
	if _, err := io.Copy(plan, r); err != nil {
		return nil, err
	}
	plan.close()

	results, err := verifyFields(headers, plan.topHashes, fetcher, opts...)
	if err != nil {
		return results, err
	}
	return plan.walk(results)
}

// recordingReader keeps a copy of everything read through it until off.
type recordingReader struct {
	r   io.Reader
	buf []byte
	off bool
}

func (rr *recordingReader) Read(p []byte) (int, error) {
	n, err := rr.r.Read(p)
	if !rr.off {
		rr.buf = append(rr.buf, p[:n]...)
	}
	return n, err
}

// verifyFullUndo is VerifyFull by the undo walk: Verify, then each lower
// instance rebuilt with Undo, which checks that level's recorded hashes.
func verifyFullUndo(r io.Reader, fetcher KeyFetcher, opts ...VerifyOptions) ([]VerifyResult, error) {
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
		if err := undo(bytes.NewReader(buf), io.Discard, target, true); err != nil {
			// A Recipe that only fails against the real item counts is
			// found here, not in parseMI; report it the way Verify reports
			// a structurally malformed one -- the verbatim PERMERROR, as
			// the top-level error, and the message is not accepted.
			var mre *malformedRecipeError
			if errors.As(err, &mre) {
				return results, mre
			}
			results = append(results, VerifyResult{
				Domain: fmt.Sprintf("MI-chain v=%d", target),
				Error:  fmt.Errorf("MI chain validation failed: %w", err),
			})
			break
		}
	}

	return results, nil
}
