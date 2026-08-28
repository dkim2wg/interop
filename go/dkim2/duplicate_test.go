package dkim2

import "strings"
import "testing"

func TestCleanSignatureListHasNoErrors(t *testing.T) {
	errs := checkSignatureDuplicates([]SigItem{
		{Selector: "sel1", Algorithm: "rsa-sha256"},
		{Selector: "sel2", Algorithm: "ed25519-sha256"},
	}, 1)
	if len(errs) != 0 {
		t.Errorf("got %v, want no errors", errs)
	}
}

func TestDuplicateSelectorIsPermerror(t *testing.T) {
	errs := checkSignatureDuplicates([]SigItem{
		{Selector: "sel1", Algorithm: "rsa-sha256"},
		{Selector: "sel1", Algorithm: "ed25519-sha256"},
	}, 3)
	want := "PERMERROR DKIM2-Signature i=3 has a duplicate selector"
	if len(errs) != 1 || errs[0] != want {
		t.Errorf("got %v, want [%q]", errs, want)
	}
}

func TestDuplicateSelectorIsCaseInsensitive(t *testing.T) {
	errs := checkSignatureDuplicates([]SigItem{
		{Selector: "Sel1", Algorithm: "rsa-sha256"},
		{Selector: "sel1", Algorithm: "ed25519-sha256"},
	}, 1)
	if len(errs) != 1 || !strings.Contains(errs[0], "has a duplicate selector") {
		t.Errorf("got %v, want a duplicate-selector PERMERROR", errs)
	}
}

func TestSameAlgorithmTwiceAllowed(t *testing.T) {
	errs := checkSignatureDuplicates([]SigItem{
		{Selector: "sel1", Algorithm: "rsa-sha256"},
		{Selector: "sel2", Algorithm: "rsa-sha256"},
	}, 1)
	if len(errs) != 0 {
		t.Errorf("spec-06 §8.9 allows one additional same-algorithm signature with a distinct Selector; got %v", errs)
	}
}

func TestThreeSameAlgorithmHasExcessSelectors(t *testing.T) {
	errs := checkSignatureDuplicates([]SigItem{
		{Selector: "sel1", Algorithm: "rsa-sha256"},
		{Selector: "sel2", Algorithm: "rsa-sha256"},
		{Selector: "sel3", Algorithm: "rsa-sha256"},
	}, 2)
	if len(errs) != 1 || !strings.Contains(errs[0], "has more selectors than allowed") {
		t.Errorf("got %v, want an excess-selector PERMERROR", errs)
	}
}

func TestDuplicateSelectorAndExcessSelectorAreIndependent(t *testing.T) {
	// two sigs sharing an algorithm AND a Selector is a duplicate-selector
	// error but NOT an excess-selector error (the count is 2, not 3+)
	errs := checkSignatureDuplicates([]SigItem{
		{Selector: "sel1", Algorithm: "rsa-sha256"},
		{Selector: "sel1", Algorithm: "rsa-sha256"},
	}, 1)
	foundDup := false
	foundExcess := false
	for _, e := range errs {
		if strings.Contains(e, "duplicate selector") {
			foundDup = true
		}
		if strings.Contains(e, "more selectors than allowed") {
			foundExcess = true
		}
	}
	if !foundDup || foundExcess {
		t.Errorf("got %v, want only duplicate-selector error", errs)
	}
}

func TestDuplicateHashAlgorithmIsPermerror(t *testing.T) {
	_, err := parseMI("Message-Instance: m=4; h=sha256:AAA:BBB,sha256:CCC:DDD;")
	if err == nil || !strings.Contains(err.Error(), "has a duplicate hash algorithm") {
		t.Errorf("got %v, want a duplicate-hash-algorithm PERMERROR (spec-06 §7.3)", err)
	}
}
