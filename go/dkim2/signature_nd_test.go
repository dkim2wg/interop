package dkim2

import (
	"strings"
	"testing"
)

func parseSigHdr(s string) (*DKIM2Signature, error) {
	return parseSig("DKIM2-Signature:" + s)
}

func TestNDParsed(t *testing.T) {
	s, err := parseSigHdr(" i=2; m=2; t=1; d=fwd.example; nd=mx.dest.example; s=sel:rsa-sha256:AAAA")
	if err != nil {
		t.Fatal(err)
	}
	if s.NextDomain != "mx.dest.example" {
		t.Fatalf("nd=%q, want mx.dest.example", s.NextDomain)
	}
}

func TestNDAndMFMutuallyExclusive(t *testing.T) {
	_, err := parseSigHdr(" i=2; m=2; t=1; d=fwd.example; nd=mx.dest.example; mf=PA==; rt=PA==; s=sel:rsa-sha256:AAAA")
	if err == nil {
		t.Fatal("nd= together with mf=/rt= must be rejected")
	}
}

func TestMissingChainTags(t *testing.T) {
	_, err := parseSigHdr(" i=2; m=2; t=1; d=fwd.example; s=sel:rsa-sha256:AAAA")
	if err == nil {
		t.Fatal("must require nd= or both mf=+rt=")
	}
}

func TestRequiredCoreTags(t *testing.T) {
	// missing i=
	if _, err := parseSigHdr(" m=2; t=1; d=fwd.example; nd=x.example; s=sel:rsa-sha256:AAAA"); err == nil {
		t.Fatal("must require i=")
	}
	// missing t=
	if _, err := parseSigHdr(" i=2; m=2; d=fwd.example; nd=x.example; s=sel:rsa-sha256:AAAA"); err == nil {
		t.Fatal("must require t=")
	}
}

func TestMFRTStillValid(t *testing.T) {
	s, err := parseSigHdr(" i=2; m=2; t=1; d=fwd.example; mf=PA==; rt=PA==; s=sel:rsa-sha256:AAAA")
	if err != nil {
		t.Fatalf("mf=/rt= form must remain valid: %v", err)
	}
	if s.NextDomain != "" {
		t.Fatalf("NextDomain should be empty, got %q", s.NextDomain)
	}
}

func TestNDChainMatch(t *testing.T) {
	// i=1 declares nd=mx.dest.example; i=2 is signed by that domain → OK.
	sigs := []*DKIM2Signature{
		{Sequence: 1, Domain: "fwd.example", NextDomain: "mx.dest.example"},
		{Sequence: 2, Domain: "mx.dest.example", MailFrom: "a@x.example",
			RcptTo: []string{"b@y.example"}},
	}
	if err := checkChainOfCustody(sigs); err != nil {
		t.Fatalf("matching nd= chain should verify: %v", err)
	}
}

func TestNDChainMismatch(t *testing.T) {
	sigs := []*DKIM2Signature{
		{Sequence: 1, Domain: "fwd.example", NextDomain: "mx.dest.example"},
		{Sequence: 2, Domain: "other.example"},
	}
	err := checkChainOfCustody(sigs)
	if err == nil || !strings.Contains(err.Error(), "nd= does not match") {
		t.Fatalf("mismatched nd= chain must fail with nd= error, got: %v", err)
	}
}

func TestNDSerialized(t *testing.T) {
	sig := &DKIM2Signature{
		Sequence: 2, MIVersion: 2, Timestamp: 1, Domain: "fwd.example",
		NextDomain: "mx.dest.example",
		Sigs:       []SigItem{{Selector: "sel", Algorithm: "rsa-sha256"}},
	}
	out := sig.String()
	if !strings.Contains(out, "nd=mx.dest.example") {
		t.Fatalf("serialized form missing nd=: %s", out)
	}
	if strings.Contains(out, "mf=") || strings.Contains(out, "rt=") {
		t.Fatalf("nd= signature must not serialize mf=/rt=: %s", out)
	}
}
