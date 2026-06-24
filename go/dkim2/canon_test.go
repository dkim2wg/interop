package dkim2

import "testing"

func TestDeliveredToExcluded(t *testing.T) {
	if !shouldExcludeHeader("delivered-to") {
		t.Fatal("Delivered-To must be excluded from header hash (draft-03 §4.1)")
	}
}
