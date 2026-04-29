package dkim2

import (
	"testing"
)

func TestTagValueList(t *testing.T) {
	tvl := parseTagValueList("m=1; h=sha256:abc:def; r=xyz;")
	if got := tvl.get("m"); got != "1" {
		t.Errorf("m= got %q want %q", got, "1")
	}
	if got := tvl.get("h"); got != "sha256:abc:def" {
		t.Errorf("h= got %q want %q", got, "sha256:abc:def")
	}
	if got := tvl.get("r"); got != "xyz" {
		t.Errorf("r= got %q want %q", got, "xyz")
	}
	if got := tvl.get("missing"); got != "" {
		t.Errorf("missing key got %q want empty", got)
	}
	want := "m=1; h=sha256:abc:def; r=xyz;"
	if got := tvl.String(); got != want {
		t.Errorf("String() got %q want %q", got, want)
	}
}

func TestTagValueListEmpty(t *testing.T) {
	tvl := parseTagValueList("")
	if got := tvl.get("m"); got != "" {
		t.Errorf("empty got %q", got)
	}
	if got := tvl.String(); got != "" {
		t.Errorf("empty String() got %q", got)
	}
}
