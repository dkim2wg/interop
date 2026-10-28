package dkim2

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"testing"
)

// hashBodyMulti is the reference body hash the verifier's streaming pass
// (hashBodyStream, the planned walk's chainPlan) is checked against: the
// body is canonicalised line by line by writeCanonicalBody, the signer's
// canonicalisation, and fanned out to one hash.Hash per (deduplicated)
// algorithm.  Its input must already have CRLF line endings (readBody's).
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

// TestHashBodyStream: Verify's streaming body hash over the raw body, cut
// into two pieces at every point, matches the reference over readBody's
// CRLF-normalised copy -- for every mix of line endings, blank lines and an
// unterminated last line, and for bodies long enough to fill the rewrite
// buffer (bare LF) and the read buffer.
func TestHashBodyStream(t *testing.T) {
	algs := []string{"sha256", "sha512"}
	bodies := []string{
		"", "\r\n", "\n", "\r", "a", "a\r", "a\r\r", "a\r\n", "a\n", "a\r\r\n",
		"\r\n\r\n", "\n\n\r\n", "a\r\n\r\n", "a\n\n", "\r\na\r\n", "\na\n\n",
		"a\r\n\r\nb\r\n\r\n\r\n", "a\n\r\nb\r\r\n\n", "a\rb\r\nc\r\r\n\r\r\n",
		"x\r\ny\nz\r\n\r\n\nw", "\r\n\r\nx", "x\r\n\r\n\r", "lead\r\n\r\n\nmid\r\n\r\nend\r\n\r\n",
	}
	long := []string{
		strings.Repeat("bare LF line\n\n", 20000) + "end\n",
		strings.Repeat("CRLF line\r\n\r\n", 20000) + strings.Repeat("\n", 3),
		strings.Repeat("mixed\r\nlf\n\r\n\n", 30000),
	}
	check := func(name, body string, chunks [][]byte) {
		t.Helper()
		want, werr := hashBodyMulti(bytes.NewReader(mustReadBody(t, body)), algs)
		got, gerr := hashBodyStream(&chunkReader{chunks: chunks}, algs)
		if (werr == nil) != (gerr == nil) {
			t.Fatalf("%s: stream error %v, reference error %v", name, gerr, werr)
		}
		for _, alg := range algs {
			if !bytes.Equal(got[alg], want[alg]) {
				t.Errorf("%s: %s differs", name, alg)
			}
		}
	}
	for _, body := range bodies {
		b := []byte(body)
		for i := 0; i <= len(b); i++ {
			check(fmt.Sprintf("%q split %d", body, i), body, [][]byte{b[:i], b[i:]})
		}
	}
	for i, body := range long {
		b := []byte(body)
		check(fmt.Sprintf("long %d whole", i), body, [][]byte{b})
		check(fmt.Sprintf("long %d cycling", i), body, cyclingChunks(b))
		got, err := hashBodyStream(bytes.NewReader(b), algs) // one Write
		if want, _ := hashBodyMulti(bytes.NewReader(mustReadBody(t, body)), algs); err != nil || !bytes.Equal(got["sha256"], want["sha256"]) {
			t.Errorf("long %d from a bytes.Reader: %v", i, err)
		}
	}
	if _, err := hashBodyStream(strings.NewReader(strings.Repeat("y", maxCanonLine)+"\n"), algs); !errors.Is(err, bufio.ErrTooLong) {
		t.Errorf("over-long line: %v, want bufio.ErrTooLong", err)
	}
}

func mustReadBody(t *testing.T, body string) []byte {
	t.Helper()
	norm, err := readBody(bufio.NewReader(strings.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	return norm.Bytes()
}

// chunkReader delivers chunks one Read at a time (and is no WriterTo, so
// io.Copy hands it to ReadFrom).
type chunkReader struct{ chunks [][]byte }

func (c *chunkReader) Read(p []byte) (int, error) {
	for len(c.chunks) > 0 && len(c.chunks[0]) == 0 {
		c.chunks = c.chunks[1:]
	}
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.chunks[0])
	c.chunks[0] = c.chunks[0][n:]
	return n, nil
}

func TestDeliveredToExcluded(t *testing.T) {
	if !shouldExcludeHeader("delivered-to") {
		t.Fatal("Delivered-To must be excluded from header hash (§4.1)")
	}
}

func TestSpec05ExcludedNames(t *testing.T) {
	for _, n := range []string{
		"apparently-to", "dl-expansion-history",
		"original-recipient", "sio-label-history",
		"x400-received", "x400-trace",
	} {
		if !shouldExcludeHeader(n) {
			t.Errorf("%s must be excluded (§4)", n)
		}
	}
}

// -08 §4 (contract D1) took Auto-Submitted and VBR-Info off the list: they
// are hashed.
func TestSpec08AutoSubmittedVBRInfoHashed(t *testing.T) {
	for _, n := range []string{"auto-submitted", "Auto-Submitted", "vbr-info", "VBR-Info"} {
		if shouldExcludeHeader(n) {
			t.Errorf("%s must be hashed (-08 §4)", n)
		}
	}
}

func TestSpec05ReceivedPrefix(t *testing.T) {
	if !shouldExcludeHeader("Received-SPF") {
		t.Error("Received-SPF must be excluded (§4)")
	}
	if !shouldExcludeHeader("received-anything") {
		t.Error("any Received-* must be excluded (§4)")
	}
}

func TestSpec05ARCNarrowed(t *testing.T) {
	for _, n := range []string{"ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results"} {
		if !shouldExcludeHeader(n) {
			t.Errorf("%s must be excluded (§4)", n)
		}
	}
	if shouldExcludeHeader("ARC-Something-Else") {
		t.Error("the ARC- prefix match was removed (spec-05 §4); only the three RFC 8617 names are excluded")
	}
}

// Header values are sequences of octets (§6.2): bytes that are not
// valid UTF-8 -- a raw EUC-KR or Big5 Subject, as 2003-era spam and some
// current senders still emit -- must reach the hash unchanged. Iterating a
// Go string with `range` decodes runes and turns every such byte into U+FFFD,
// which is what collapseWSP used to do (found 2026-10-04 by
// util/charset-corpus.sh: Go and the other three native verifiers disagreed
// on three SpamAssassin-corpus messages).
func TestCanonicalizeHeaderKeepsInvalidUTF8Bytes(t *testing.T) {
	raw := "Subject:  \xc1\xd9\xa6b  \xa5\xce20%\t\xaa\xba  \r\n"
	got := canonicalizeHeader(Header{Name: "Subject", Raw: raw})
	want := "subject:\xc1\xd9\xa6b \xa5\xce20% \xaa\xba"
	if got != want {
		t.Fatalf("canonicalizeHeader mangled non-UTF-8 bytes:\n got  %q\n want %q", got, want)
	}
	sig := canonicalizeSigHeader("DKIM2-Signature: i=1; \xc1 \xd9\r\n")
	if string(sig) != "dkim2-signature:i=1;\xc1\xd9\r\n" {
		t.Fatalf("canonicalizeSigHeader mangled non-UTF-8 bytes: %q", sig)
	}
}
