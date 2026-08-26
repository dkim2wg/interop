package dkim2

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestHashAlgRegistry(t *testing.T) {
	for _, n := range []string{"sha256", "sha512", "SHA256", "SHA512"} {
		if _, ok := HashAlg(n); !ok {
			t.Errorf("HashAlg(%q) must be supported (spec-05 §3)", n)
		}
	}
	if _, ok := HashAlg("x-whirlpool"); ok {
		t.Error("unknown algorithms must not resolve")
	}
}

func TestParseHashSets(t *testing.T) {
	got := parseHashSets("sha256:AAA:BBB,sha512:CCC:DDD")
	if len(got) != 2 {
		t.Fatalf("got %d hash-sets, want 2", len(got))
	}
	if got[0].Alg != "sha256" || got[0].HeaderHash != "AAA" || got[0].BodyHash != "BBB" {
		t.Errorf("first hash-set wrong: %+v", got[0])
	}
	if got[1].Alg != "sha512" {
		t.Errorf("second alg = %q, want sha512", got[1].Alg)
	}
}

func TestParseHashSetsLowercasesAlg(t *testing.T) {
	got := parseHashSets("SHA512:AAA:BBB")
	if got[0].Alg != "sha512" {
		t.Errorf("alg = %q, want sha512 (RFC 5234 quoted strings are case-insensitive)", got[0].Alg)
	}
}

func TestParseMIWithBothAlgorithms(t *testing.T) {
	raw := "Message-Instance: m=1; h=sha256:AAA:BBB,sha512:CCC:DDD;"
	mi, err := parseMI(raw)
	if err != nil {
		t.Fatalf("parseMI: %v", err)
	}
	if len(mi.Hashes) != 2 {
		t.Fatalf("got %d hash-sets, want 2", len(mi.Hashes))
	}
}

// --- Review round 1 findings (Finding 2: verifyMIHashes/Verify coverage) ---

// TestVerifyMIHashesFailsClosedOnUnimplementedAlgorithm covers the §3.4
// fail-closed path: an h= tag naming only an algorithm this build does not
// implement must be rejected with the exact spec-05 message, not silently
// accepted (which is what happens if the "usable == 0" check is ever lost).
func TestVerifyMIHashesFailsClosedOnUnimplementedAlgorithm(t *testing.T) {
	mi := &MessageInstance{
		Version: 1,
		Hashes:  []HashSet{{Alg: "x-whirlpool", HeaderHash: "AAAA", BodyHash: "AAAA"}},
	}
	headers := []Header{{Name: "From", Value: "a@b.com", Raw: "From: a@b.com\r\n"}}

	err := verifyMIHashes(mi, headers, []byte("x\r\n"))
	if err == nil {
		t.Fatal("expected a fail-closed error, got nil (pass)")
	}
	want := "Message-Instance m=1 no supported hash algorithm"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

// TestVerifyMIHashesWrongSha512Fails covers the all-must-pass rule: a
// correct sha256 hash-set alongside a wrong sha512 one must still fail, and
// the error must name the algorithm that actually mismatched.
func TestVerifyMIHashesWrongSha512Fails(t *testing.T) {
	headers := []Header{{Name: "From", Value: "a@b.com", Raw: "From: a@b.com\r\n"}}
	body := []byte("x\r\n")

	goodH256, err := hashHeaders(headers, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	goodB256, err := hashBody(bytes.NewReader(body), "sha256")
	if err != nil {
		t.Fatal(err)
	}

	mi := &MessageInstance{
		Version: 1,
		Hashes: []HashSet{
			{Alg: "sha256", HeaderHash: base64.StdEncoding.EncodeToString(goodH256),
				BodyHash: base64.StdEncoding.EncodeToString(goodB256)},
			{Alg: "sha512", HeaderHash: "AAAA", BodyHash: "AAAA"},
		},
	}

	err = verifyMIHashes(mi, headers, body)
	if err == nil {
		t.Fatal("expected an error for the wrong sha512 hash-set")
	}
	if !strings.Contains(err.Error(), "sha512") {
		t.Errorf("error = %q, want it to name sha512", err.Error())
	}
}

// TestVerifyMIHashesWrongSha256Fails is the mirror of the above: correct
// sha512 alongside a wrong sha256 must also fail (naming sha256), confirming
// the check isn't only exercised for whichever algorithm sorts/parses first.
func TestVerifyMIHashesWrongSha256Fails(t *testing.T) {
	headers := []Header{{Name: "From", Value: "a@b.com", Raw: "From: a@b.com\r\n"}}
	body := []byte("x\r\n")

	goodH512, err := hashHeaders(headers, "sha512")
	if err != nil {
		t.Fatal(err)
	}
	goodB512, err := hashBody(bytes.NewReader(body), "sha512")
	if err != nil {
		t.Fatal(err)
	}

	mi := &MessageInstance{
		Version: 1,
		Hashes: []HashSet{
			{Alg: "sha256", HeaderHash: "AAAA", BodyHash: "AAAA"},
			{Alg: "sha512", HeaderHash: base64.StdEncoding.EncodeToString(goodH512),
				BodyHash: base64.StdEncoding.EncodeToString(goodB512)},
		},
	}

	err = verifyMIHashes(mi, headers, body)
	if err == nil {
		t.Fatal("expected an error for the wrong sha256 hash-set")
	}
	if !strings.Contains(err.Error(), "sha256") {
		t.Errorf("error = %q, want it to name sha256", err.Error())
	}
}

// TestVerifyEndToEndBothAlgorithms signs with -hash both (SignOptions.HashAlgs
// = [sha256, sha512]) and verifies the full round trip through Verify(),
// exercising the streaming multi-algorithm body-hash path in verify.go end to
// end, not just the unit-level verifyMIHashes helper above.
func TestVerifyEndToEndBothAlgorithms(t *testing.T) {
	signed := signTestMessage(t, SignOptions{HashAlgs: []string{"sha256", "sha512"}})
	// Check the h= tag specifically: the DKIM2-Signature's s= algorithm field
	// ("ed25519-sha256") also contains the substring "sha256:", so a bare
	// substring check on the whole message would be a false positive/negative.
	if !strings.Contains(signed, "h=sha256:") || !strings.Contains(signed, ",sha512:") {
		t.Fatalf("signed message is missing an expected h= algorithm:\n%s", signed)
	}

	results, err := Verify(strings.NewReader(signed), testFetcher(t), VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(results) != 1 || results[0].Error != nil {
		t.Fatalf("results = %+v, want a single passing result", results)
	}
}

// TestVerifyEndToEndSha512Only signs with -hash sha512 (no sha256 hash-set at
// all) and verifies the full round trip through Verify().
func TestVerifyEndToEndSha512Only(t *testing.T) {
	signed := signTestMessage(t, SignOptions{HashAlgs: []string{"sha512"}})
	// h=sha512: with no h=sha256: hash-set at all; ignore the unrelated
	// "ed25519-sha256" algorithm field in the DKIM2-Signature's s= tag.
	if !strings.Contains(signed, "h=sha512:") {
		t.Fatalf("signed message is missing the expected h=sha512 hash-set:\n%s", signed)
	}
	if strings.Contains(signed, "h=sha256:") {
		t.Fatalf("signed message unexpectedly contains a sha256 hash-set:\n%s", signed)
	}

	results, err := Verify(strings.NewReader(signed), testFetcher(t), VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(results) != 1 || results[0].Error != nil {
		t.Fatalf("results = %+v, want a single passing result", results)
	}
}
