package dkim2

import (
	"bytes"
	"strings"
	"testing"
)

// TestVerifyCanonicalErrorStrings asserts that verify.go's custody/mismatch
// messages fire in the exact byte-for-byte spec-06 canonical forms (see
// docs/superpowers/plans/2026-07-05-dkim2-spec-04-upgrade.md, Task 3.3).
func TestVerifyCanonicalErrorStrings(t *testing.T) {
	t.Run("MAIL FROM mismatch", func(t *testing.T) {
		msg := buildSignedMsg(t) // signed with i=1, MailFrom sender@test1.dkim2.com
		f := &JSONKeyFetcher{Path: "../../dns.json"}
		_, err := Verify(bytes.NewReader(msg), f, VerifyOptions{
			SkipTimestampCheck: true,
			MailFrom:           "wrong@test1.dkim2.com",
		})
		want := "DKIM2-Signature i=1 MAIL FROM wrong@test1.dkim2.com did not match"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("want error containing %q, got %v", want, err)
		}
	})

	t.Run("RCPT TO mismatch", func(t *testing.T) {
		msg := buildSignedMsg(t)
		f := &JSONKeyFetcher{Path: "../../dns.json"}
		_, err := Verify(bytes.NewReader(msg), f, VerifyOptions{
			SkipTimestampCheck: true,
			RcptTo:             []string{"someone@else.com"},
		})
		want := "DKIM2-Signature i=1 RCPT TO someone@else.com did not match"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("want error containing %q, got %v", want, err)
		}
	})

	t.Run("d= vs mf= domain mismatch", func(t *testing.T) {
		msg := buildSignedMsg(t) // signed d=test1.dkim2.com, mf=sender@test1.dkim2.com
		// Tamper d= to a domain unrelated to the mf= domain (per §7.7).
		tampered := strings.ReplaceAll(string(msg), "d=test1.dkim2.com", "d=evil.com")
		f := &JSONKeyFetcher{Path: "../../dns.json"}
		results, err := Verify(strings.NewReader(tampered), f, VerifyOptions{SkipTimestampCheck: true})
		if err != nil {
			t.Fatalf("Verify error: %v", err)
		}
		if len(results) == 0 || results[0].Error == nil {
			t.Fatal("expected a per-signature error")
		}
		want := "DKIM2-Signature i=1 MAIL FROM and d= do not match"
		if !strings.Contains(results[0].Error.Error(), want) {
			t.Fatalf("want error containing %q, got %v", want, results[0].Error)
		}
	})

	t.Run("nd= adjacency mismatch (verbatim MAIL typo)", func(t *testing.T) {
		raw := ndTestRaw(t)

		// i=1: promises nd=wrong-nd.example.com, but the next hop won't honor it.
		hop1 := ndSignHop(t, raw, "ed25519._domainkey.test1.dkim2.com.pem", "ed25519",
			"test1.dkim2.com", "", nil, "wrong-nd.example.com")

		// i=2 (top): a normal hop signed as test2.dkim2.com, not matching nd=.
		top := ndSignHop(t, hop1, "ed25519._domainkey.test2.dkim2.com.pem", "ed25519",
			"test2.dkim2.com", "recipient@test2.dkim2.com", []string{"final@test2.dkim2.com"}, "")

		_, err := Verify(bytes.NewReader(top), ndTestFetcher(t), VerifyOptions{SkipTimestampCheck: true})
		want := "DKIM2-Signature i=1 MAIL nd= does not match"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("want error containing %q (verbatim spec-06 typo), got %v", want, err)
		}
	})
}

// TestSignatureParseErrorsCarryISequence asserts that signature.go's
// parse-time error messages carry the "DKIM2-Signature i=<x>" prefix
// wherever the sequence number is already known by that point in parsing,
// using the canonical "tag=<y> missing" / "tag=<y> syntax error" shapes.
// Two cases (no colon yet, and a malformed i= tag itself) genuinely cannot
// carry i=<x> since the sequence isn't parseable yet — those assert a
// sensible i=-less form instead.
func TestSignatureParseErrorsCarryISequence(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "no colon at all",
			raw:  "i=1; m=1; t=1;",
			want: "DKIM2-Signature: no colon found",
		},
		{
			name: "invalid i= (sequence itself malformed, no i= prefix possible)",
			raw:  "DKIM2-Signature: i=abc; m=1; t=1;",
			want: "DKIM2-Signature tag=i syntax error",
		},
		{
			name: "invalid m= (i= already known)",
			raw:  "DKIM2-Signature: i=1; m=abc; t=1;",
			want: "DKIM2-Signature i=1 tag=m syntax error",
		},
		{
			name: "invalid t= (i= already known)",
			raw:  "DKIM2-Signature: i=1; m=1; t=abc;",
			want: "DKIM2-Signature i=1 tag=t syntax error",
		},
		{
			name: "missing d= (i= already known)",
			raw:  "DKIM2-Signature: i=1; m=1; t=1;",
			want: "DKIM2-Signature i=1 tag=d missing",
		},
		{
			name: "missing s= (i= already known)",
			raw:  "DKIM2-Signature: i=1; m=1; t=1; d=test1.dkim2.com;",
			want: "DKIM2-Signature i=1 tag=s missing",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSig(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseSig(%q): want error containing %q, got %v", tc.raw, tc.want, err)
			}
		})
	}
}
