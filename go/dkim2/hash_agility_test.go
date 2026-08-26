package dkim2

import "testing"

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
