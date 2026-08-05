package dkim2

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// A 5-instance chain exercises the full walk across many levels.
const fullChainVector = "../../brong/tests/expected/chain-hop5-final-delivery.eml"

func TestVerifyFullValidMultiHop(t *testing.T) {
	raw, err := os.ReadFile(fullChainVector)
	if err != nil {
		t.Skip("vector not found")
	}
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	results, err := VerifyFull(bytes.NewReader(raw), f, VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("VerifyFull error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("no results")
	}
	for _, r := range results {
		if r.Error != nil {
			t.Errorf("unexpected failure i=%d d=%s: %v", r.Sequence, r.Domain, r.Error)
		}
	}
}

func TestVerifyFullRejectsTamper(t *testing.T) {
	raw, err := os.ReadFile(fullChainVector)
	if err != nil {
		t.Skip("vector not found")
	}
	// Flip a letter in the body (after the header/body separator).
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		t.Fatal("no body")
	}
	tampered := append([]byte{}, raw...)
	flipped := false
	for i := idx + 4; i < len(tampered); i++ {
		c := tampered[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			tampered[i] ^= 0x20 // flip case
			flipped = true
			break
		}
	}
	if !flipped {
		t.Skip("no letter in body to flip")
	}
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	results, err := VerifyFull(bytes.NewReader(tampered), f, VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		return // a top-level error is also an acceptable rejection
	}
	failed := false
	for _, r := range results {
		if r.Error != nil {
			failed = true
		}
	}
	if !failed {
		t.Error("expected VerifyFull to reject a tampered message")
	}
}

func TestVerifyFullIgnoreTimestamps(t *testing.T) {
	raw, err := os.ReadFile(fullChainVector) // fixed 2026-02-20 timestamps (old now)
	if err != nil {
		t.Skip("vector not found")
	}
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	// Without skip: should fail on age.
	res, _ := VerifyFull(bytes.NewReader(raw), f)
	anyTSerr := false
	for _, r := range res {
		if r.Error != nil && strings.Contains(r.Error.Error(), "expired") {
			anyTSerr = true
		}
	}
	if !anyTSerr {
		t.Error("expected an expiry error without ignore-timestamps")
	}
	// With skip: should pass.
	res2, err := VerifyFull(bytes.NewReader(raw), f, VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("VerifyFull error: %v", err)
	}
	for _, r := range res2 {
		if r.Error != nil {
			t.Errorf("unexpected failure with skip: i=%d: %v", r.Sequence, r.Error)
		}
	}
}
