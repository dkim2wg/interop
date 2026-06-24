package dkim2

import (
	"strings"
	"testing"
)

func TestFeedhereFlagParsed(t *testing.T) {
	s, err := parseSig("DKIM2-Signature: i=1; m=1; t=1; d=ex.example; " +
		"mf=PA==; rt=PA==; f=feedback,feedhere; s=sel:rsa-sha256:AAAA")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Flags) != 2 || s.Flags[0] != "feedback" || s.Flags[1] != "feedhere" {
		t.Fatalf("flags = %v, want [feedback feedhere]", s.Flags)
	}
}

func TestFlagsRoundTrip(t *testing.T) {
	sig := &DKIM2Signature{
		Sequence: 1, MIVersion: 1, Timestamp: 1, Domain: "ex.example",
		MailFrom: "a@x.example", RcptTo: []string{"b@y.example"},
		Flags: []string{"donotmodify", "feedhere"},
		Sigs:  []SigItem{{Selector: "sel", Algorithm: "rsa-sha256"}},
	}
	out := sig.String()
	if !strings.Contains(out, "f=donotmodify,feedhere") {
		t.Fatalf("serialized form missing flags: %s", out)
	}
}
