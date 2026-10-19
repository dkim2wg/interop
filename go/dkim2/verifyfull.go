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
// breaks the §5 rules against the message is the verbatim PERMERROR, ranked
// with §14.7 (contract C9).  The §14.8 From check comes last, when nothing
// else failed.
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
	results, err = plan.walk(results)
	return fromLast(headers, results, err, opts...)
}

// chainLevelError is the VerifyResult error for a lower Message-Instance
// that does not check out against the message its Recipes rebuild: a hash
// that does not match is the §14.7 FAIL itself; anything else keeps the
// walk's own wording, as a PERMERROR.  The planned and undo walks both use
// it, so they report the same.
func chainLevelError(err error) error {
	var hm *hashMismatchError
	if errors.As(err, &hm) {
		return hm
	}
	return fmt.Errorf("PERMERROR: MI chain validation failed: %w", err)
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

	headers, results, err := verifyNoFrom(bytes.NewReader(buf), fetcher, opts...)
	if err != nil {
		return results, err
	}

	// §16.3: with no body there is nothing to undo a lower instance into, so
	// Verify's top-instance header-hash check is as far as the chain walk goes.
	if len(opts) > 0 && opts[0].HeadersOnly {
		return fromLast(headers, results, nil, opts...)
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
			// found here, not in parseMI: the verbatim PERMERROR, as Verify
			// reports a structurally malformed one, but found by the walk,
			// so it ranks with §14.7 (C9) -- after the hash checks of the
			// instances above it.
			var mre *malformedRecipeError
			if errors.As(err, &mre) {
				results = append(results, VerifyResult{
					Domain:  fmt.Sprintf("MI-chain v=%d", mre.m),
					Error:   mre,
					section: 7,
				})
				break
			}
			results = append(results, VerifyResult{
				Domain: fmt.Sprintf("MI-chain v=%d", target),
				Error:  chainLevelError(err),
			})
			break
		}
	}

	return fromLast(headers, results, nil, opts...)
}
