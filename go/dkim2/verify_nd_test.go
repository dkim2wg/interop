package dkim2

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// ndSignHop signs `in` (the message produced by the previous hop, or the raw
// fixture for the first hop) with the given key/Selector/domain, producing
// the next i=/m= layer. Exactly one of (mf/rt) or nd should be set per
// draft-06 §8 (nd= excludes mf=/rt=), matching the real Sign() constraint.
func ndSignHop(t *testing.T, in []byte, keyFile, sel, dom, mf string, rt []string, nd string) []byte {
	t.Helper()
	keyPEM, err := os.ReadFile("../../keys/" + keyFile)
	if err != nil {
		t.Skipf("key not found: %s", keyFile)
	}
	key, err := LoadPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("load key %s: %v", keyFile, err)
	}
	var out bytes.Buffer
	if err := Sign(bytes.NewReader(in), &out, key, SignOptions{
		Selector: sel, Domain: dom, MailFrom: mf, RcptTo: rt, NextDomain: nd,
		Timestamp: 1740000000,
	}); err != nil {
		t.Fatalf("sign hop d=%s: %v", dom, err)
	}
	return out.Bytes()
}

func ndTestFetcher(t *testing.T) KeyFetcher {
	t.Helper()
	return &JSONKeyFetcher{Path: "../../dns.json"}
}

func ndTestRaw(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../python/tests/emails/simple.eml")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestTopNdRejected builds a 2-hop chain whose HIGHEST (top) DKIM2-Signature
// carries nd= instead of mf=/rt=. Per local policy (stricter than spec-06),
// the only legitimate nd= producer emits the nd= signature together with the
// matching higher-i= signature at the same time, so nd= must never appear on
// the top signature. Verify must reject it.
func TestTopNdRejected(t *testing.T) {
	raw := ndTestRaw(t)

	// i=1: normal hop, origin sender.
	hop1 := ndSignHop(t, raw, "ed25519._domainkey.test1.dkim2.com.pem", "ed25519",
		"test1.dkim2.com", "sender@test1.dkim2.com", []string{"relay@test2.dkim2.com"}, "")

	// i=2 (top): carries nd= with nothing above it to fulfil the promise.
	top := ndSignHop(t, hop1, "ed25519._domainkey.test2.dkim2.com.pem", "ed25519",
		"test2.dkim2.com", "", nil, "test3.dkim2.com")

	_, err := Verify(bytes.NewReader(top), ndTestFetcher(t), VerifyOptions{SkipTimestampCheck: true})
	if err == nil || !strings.Contains(err.Error(), "unexpected nd= tag") {
		t.Fatalf("want unexpected nd= tag, got %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), "i=2") {
		t.Fatalf("want error to reference i=2, got %v", err)
	}
}

// TestNonTopNdChainVerifies builds a 3-hop chain where the middle signature
// (i=2, not the top) carries nd=, matching the d= of the following signature
// (i=3). This is the legitimate pattern and must still verify cleanly —
// checkChainOfCustody's existing adjacency handling must remain intact.
func TestNonTopNdChainVerifies(t *testing.T) {
	raw := ndTestRaw(t)

	hop1 := ndSignHop(t, raw, "ed25519._domainkey.test1.dkim2.com.pem", "ed25519",
		"test1.dkim2.com", "sender@test1.dkim2.com", []string{"relay@test2.dkim2.com"}, "")

	hop2 := ndSignHop(t, hop1, "ed25519._domainkey.test2.dkim2.com.pem", "ed25519",
		"test2.dkim2.com", "", nil, "test3.dkim2.com")

	hop3 := ndSignHop(t, hop2, "ed25519._domainkey.test3.dkim2.com.pem", "ed25519",
		"test3.dkim2.com", "recipient@test3.dkim2.com", []string{"final@test3.dkim2.com"}, "")

	results, err := Verify(bytes.NewReader(hop3), ndTestFetcher(t), VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	for _, r := range results {
		if r.Error != nil {
			t.Errorf("i=%d: %v", r.Sequence, r.Error)
		}
	}
}

// TestBridgeFromUnrelatedDomainRejected is the §9.3 requirement behind the
// case above: the extra DKIM2-Signature has to be made with a key for a domain
// in the RCPT TO the message arrived with. Here the bridge is signed by
// test4.dkim2.com, which the message never reached, so the chain must fail.
func TestBridgeFromUnrelatedDomainRejected(t *testing.T) {
	raw := ndTestRaw(t)

	hop1 := ndSignHop(t, raw, "ed25519._domainkey.test1.dkim2.com.pem", "ed25519",
		"test1.dkim2.com", "sender@test1.dkim2.com", []string{"relay@test2.dkim2.com"}, "")

	hop2 := ndSignHop(t, hop1, "ed25519._domainkey.test4.dkim2.com.pem", "ed25519",
		"test4.dkim2.com", "", nil, "test3.dkim2.com")

	hop3 := ndSignHop(t, hop2, "ed25519._domainkey.test3.dkim2.com.pem", "ed25519",
		"test3.dkim2.com", "recipient@test3.dkim2.com", []string{"final@test3.dkim2.com"}, "")

	_, err := Verify(bytes.NewReader(hop3), ndTestFetcher(t), VerifyOptions{SkipTimestampCheck: true})
	if err == nil {
		t.Fatal("a bridge from a domain the mail never reached was accepted")
	}
	if !strings.Contains(err.Error(), "i=2 nd= hop d=test4.dkim2.com did not match RCPT TO") {
		t.Fatalf("err = %v, want the nd= hop d= mismatch", err)
	}
}

// TestUnbridgedForwardBreaksCustody: without the bridge, the same forward from
// a different domain breaks the chain of custody — which is what the bridge is
// for.
func TestUnbridgedForwardBreaksCustody(t *testing.T) {
	raw := ndTestRaw(t)

	hop1 := ndSignHop(t, raw, "ed25519._domainkey.test1.dkim2.com.pem", "ed25519",
		"test1.dkim2.com", "sender@test1.dkim2.com", []string{"relay@test2.dkim2.com"}, "")

	hop2 := ndSignHop(t, hop1, "ed25519._domainkey.test3.dkim2.com.pem", "ed25519",
		"test3.dkim2.com", "recipient@test3.dkim2.com", []string{"final@test3.dkim2.com"}, "")

	_, err := Verify(bytes.NewReader(hop2), ndTestFetcher(t), VerifyOptions{SkipTimestampCheck: true})
	if err == nil {
		t.Fatal("an unbridged forward from another domain kept custody")
	}
	if !strings.Contains(err.Error(), "did not match") {
		t.Fatalf("err = %v, want a chain-of-custody failure", err)
	}
}

// TestDoubledNonTopNdChainVerifies extends the above to a doubled run of
// consecutive non-top nd= hops (i=2 and i=3), still topped by a normal (i=4)
// signature. Must still verify with no error.
func TestDoubledNonTopNdChainVerifies(t *testing.T) {
	raw := ndTestRaw(t)

	hop1 := ndSignHop(t, raw, "ed25519._domainkey.test1.dkim2.com.pem", "ed25519",
		"test1.dkim2.com", "sender@test1.dkim2.com", []string{"relay@test2.dkim2.com"}, "")

	hop2 := ndSignHop(t, hop1, "ed25519._domainkey.test2.dkim2.com.pem", "ed25519",
		"test2.dkim2.com", "", nil, "test3.dkim2.com")

	hop3 := ndSignHop(t, hop2, "ed25519._domainkey.test3.dkim2.com.pem", "ed25519",
		"test3.dkim2.com", "", nil, "test4.dkim2.com")

	hop4 := ndSignHop(t, hop3, "ed25519._domainkey.test4.dkim2.com.pem", "ed25519",
		"test4.dkim2.com", "recipient@test4.dkim2.com", []string{"final@test4.dkim2.com"}, "")

	results, err := Verify(bytes.NewReader(hop4), ndTestFetcher(t), VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	for _, r := range results {
		if r.Error != nil {
			t.Errorf("i=%d: %v", r.Sequence, r.Error)
		}
	}
}
