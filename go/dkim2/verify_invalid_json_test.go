package dkim2

import (
	"strings"
	"testing"
)

// TestVerifyReportsInvalidRecipeJSON asserts that spec-05 §11.2 ("errors in
// a JSON object specifying Recipes should be called out specifically") is
// honoured end to end: feeding a complete, validly-signed message whose r=
// payload decodes to malformed JSON through the real verifier entry point
// (Verify, the same function VerifyFull and cmd/dkim2verify use) must reject
// it with the exact PERMERROR text, not a generic syntax error and not a
// silently-dropped/misreported failure (cf. TestVerifyReportsMIParseError
// and the C duplicate-h= lesson in commit 66bd3e6).
func TestVerifyReportsInvalidRecipeJSON(t *testing.T) {
	msg := string(buildSignedMsg(t))

	// eyJoIjog is base64 of `{"h": ` -- truncated, so it decodes to invalid
	// (incomplete) JSON rather than merely failing a semantic check.
	tampered := strings.Replace(msg,
		"Message-Instance: m=1; ",
		"Message-Instance: m=1; r=eyJoIjog; ", 1)
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
		t.Fatal("expected a failure for malformed recipe JSON, got a pass")
	}

	// Exact match at the outer boundary: Verify() used to re-wrap parseMI's
	// already-self-describing PERMERROR as
	// "Message-Instance: PERMERROR Message-Instance m=1 contains invalid
	// JSON" (a doubled prefix), which a Contains-only assertion would have
	// hidden. The injected r= is on m=1, the ONLY (bottom) Message-Instance
	// in buildSignedMsg's fixture, so this also confirms Go already flags a
	// malformed r= on the bottom instance, not just non-bottom ones.
	want := "PERMERROR Message-Instance m=1 contains invalid JSON"
	if got != want {
		t.Errorf("got %q, want exactly %q", got, want)
	}

	// Also exercise VerifyFull, the entry point cmd/dkim2verify actually
	// calls, to guard against the specific error being swallowed by the
	// full-chain MI validation added on top of Verify.
	fullResults, fullErr := VerifyFull(strings.NewReader(tampered), f, VerifyOptions{SkipTimestampCheck: true})
	got2 := ""
	if fullErr != nil {
		got2 = fullErr.Error()
	} else {
		for _, r := range fullResults {
			if r.Error != nil {
				got2 = r.Error.Error()
				break
			}
		}
	}
	if got2 != want {
		t.Errorf("VerifyFull: got %q, want exactly %q", got2, want)
	}
}

// TestVerifyReportsBadBase64RecipeAsSyntaxError asserts the §11.2 ruling
// that a bad-base64 r= value and a post-decode JSON parse failure are
// different errors: base64 failure -> "syntax error" (§11.2 lists this
// explicitly for malformed field content), never mislabelled as "contains
// invalid JSON" -- the payload never even reached JSON parsing.
func TestVerifyReportsBadBase64RecipeAsSyntaxError(t *testing.T) {
	msg := string(buildSignedMsg(t))

	// "!!!!" is not valid standard base64.
	tampered := strings.Replace(msg,
		"Message-Instance: m=1; ",
		"Message-Instance: m=1; r=!!!!; ", 1)
	if tampered == msg {
		t.Fatal("failed to inject r= into the Message-Instance header")
	}

	f := &JSONKeyFetcher{Path: "../../dns.json"}
	_, err := Verify(strings.NewReader(tampered), f, VerifyOptions{SkipTimestampCheck: true})
	if err == nil {
		t.Fatal("expected a failure for a bad-base64 recipe, got a pass")
	}

	want := "PERMERROR Message-Instance m=1 syntax error"
	if err.Error() != want {
		t.Errorf("got %q, want exactly %q", err.Error(), want)
	}
	if strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("bad base64 wrongly reported as invalid JSON: %v", err)
	}
}
