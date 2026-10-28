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
	want := "PERMERROR: DKIM2-Signature i=3 has a duplicate selector"
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
		t.Errorf("§10.9 allows one additional same-algorithm signature with a distinct Selector; got %v", errs)
	}
}

// -08 §10.9 allows any number of one algorithm with distinct Selectors.
func TestThreeSameAlgorithmAllowed(t *testing.T) {
	errs := checkSignatureDuplicates([]SigItem{
		{Selector: "sel1", Algorithm: "rsa-sha256"},
		{Selector: "sel2", Algorithm: "rsa-sha256"},
		{Selector: "sel3", Algorithm: "rsa-sha256"},
	}, 2)
	if len(errs) != 0 {
		t.Errorf("got %v, want none", errs)
	}
}

// The local limit (contract D3): at most 8 items, checked after duplicates.
func TestMoreThanEightSignatures(t *testing.T) {
	var items []SigItem
	for i := 0; i < 9; i++ {
		items = append(items, SigItem{Selector: string(rune('a' + i)), Algorithm: "rsa-sha256"})
	}
	if errs := checkSignatureDuplicates(items[:8], 1); len(errs) != 0 {
		t.Errorf("eight: got %v", errs)
	}
	want := "PERMERROR: DKIM2-Signature i=1 has more than 8 signatures"
	if errs := checkSignatureDuplicates(items, 1); len(errs) != 1 || errs[0] != want {
		t.Errorf("nine: got %v, want [%q]", errs, want)
	}
	items[8].Selector = "a"
	want = "PERMERROR: DKIM2-Signature i=1 has a duplicate selector"
	if errs := checkSignatureDuplicates(items, 1); len(errs) != 1 || errs[0] != want {
		t.Errorf("nine with a duplicate: got %v, want [%q]", errs, want)
	}
}

func TestDuplicateHashAlgorithmIsPermerror(t *testing.T) {
	_, err := parseMI("Message-Instance: m=4; h=sha256:AAAA:BBBB,sha256:CCCC:DDDD;")
	if err == nil || !strings.Contains(err.Error(), "has a duplicate hash algorithm") {
		t.Errorf("got %v, want a duplicate-hash-algorithm PERMERROR (§9.3)", err)
	}
}
