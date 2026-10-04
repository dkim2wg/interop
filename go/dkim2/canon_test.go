package dkim2

import "testing"

func TestDeliveredToExcluded(t *testing.T) {
	if !shouldExcludeHeader("delivered-to") {
		t.Fatal("Delivered-To must be excluded from header hash (draft-06 §4.1)")
	}
}

func TestSpec05ExcludedNames(t *testing.T) {
	for _, n := range []string{
		"apparently-to", "auto-submitted", "dl-expansion-history",
		"original-recipient", "sio-label-history", "vbr-info",
		"x400-received", "x400-trace",
	} {
		if !shouldExcludeHeader(n) {
			t.Errorf("%s must be excluded (spec-06 §4)", n)
		}
	}
}

func TestSpec05ReceivedPrefix(t *testing.T) {
	if !shouldExcludeHeader("Received-SPF") {
		t.Error("Received-SPF must be excluded (spec-06 §4)")
	}
	if !shouldExcludeHeader("received-anything") {
		t.Error("any Received-* must be excluded (spec-06 §4)")
	}
}

func TestSpec05ARCNarrowed(t *testing.T) {
	for _, n := range []string{"ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results"} {
		if !shouldExcludeHeader(n) {
			t.Errorf("%s must be excluded (spec-06 §4)", n)
		}
	}
	if shouldExcludeHeader("ARC-Something-Else") {
		t.Error("the ARC- prefix match was removed in spec-06 §4; only the three RFC 8617 names are excluded")
	}
}

// Header values are sequences of octets (spec-06 §6.2): bytes that are not
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
