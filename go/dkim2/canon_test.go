package dkim2

import "testing"

func TestDeliveredToExcluded(t *testing.T) {
	if !shouldExcludeHeader("delivered-to") {
		t.Fatal("Delivered-To must be excluded from header hash (draft-04 §4.1)")
	}
}

func TestSpec05ExcludedNames(t *testing.T) {
	for _, n := range []string{
		"apparently-to", "auto-submitted", "dl-expansion-history",
		"original-recipient", "sio-label-history", "vbr-info",
		"x400-received", "x400-trace",
	} {
		if !shouldExcludeHeader(n) {
			t.Errorf("%s must be excluded (spec-05 §4)", n)
		}
	}
}

func TestSpec05ReceivedPrefix(t *testing.T) {
	if !shouldExcludeHeader("Received-SPF") {
		t.Error("Received-SPF must be excluded (spec-05 §4)")
	}
	if !shouldExcludeHeader("received-anything") {
		t.Error("any Received-* must be excluded (spec-05 §4)")
	}
}

func TestSpec05ARCNarrowed(t *testing.T) {
	for _, n := range []string{"ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results"} {
		if !shouldExcludeHeader(n) {
			t.Errorf("%s must be excluded (spec-05 §4)", n)
		}
	}
	if shouldExcludeHeader("ARC-Something-Else") {
		t.Error("the ARC- prefix match was removed in spec-05 §4; only the three RFC 8617 names are excluded")
	}
}
