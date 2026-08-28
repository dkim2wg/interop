package dkim2

import (
	"strings"
	"testing"
)

// TestVerifyReportsMIParseError asserts that when a Message-Instance header
// cannot be parsed, the verifier reports *that* failure rather than silently
// dropping the header and inferring a bogus MI-numbering complaint.
//
// The MI here carries r={"h":null}, which parseRecipe rejects per draft-06
// §5.1. Skipping it while computing the topmost MI version leaves the top
// signature (m=1) apparently covering "MI m=0", which is a misleading
// diagnostic for a message whose real defect is the null header Recipe.
func TestVerifyReportsMIParseError(t *testing.T) {
	msg := string(buildSignedMsg(t))

	// eyJoIjpudWxsfQ== is base64 of {"h":null}
	tampered := strings.Replace(msg,
		"Message-Instance: m=1; ",
		"Message-Instance: m=1; r=eyJoIjpudWxsfQ==; ", 1)
	if tampered == msg {
		t.Fatal("failed to inject r= into the Message-Instance header")
	}

	f := &JSONKeyFetcher{Path: "../../dns.json"}
	results, err := Verify(strings.NewReader(tampered), f, VerifyOptions{SkipTimestampCheck: true})

	got := ""
	if err != nil {
		got = err.Error()
	} else {
		for _, r := range results {
			if r.Error != nil {
				got = r.Error.Error()
				break
			}
		}
	}
	if got == "" {
		t.Fatal("expected a failure for a null header recipe, got a pass")
	}

	if strings.Contains(got, "does not cover topmost MI") {
		t.Errorf("MI parse failure was swallowed and misreported as an MI-numbering problem: %s", got)
	}
	if !strings.Contains(got, "null header recipe") {
		t.Errorf("want error naming the null header recipe, got: %s", got)
	}
}
