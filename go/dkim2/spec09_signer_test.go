package dkim2

// Contract E3.4 (docs/superpowers/specs/2026-11-03-dkim2-spec-09-design.md):
// a signer whose d= is below the From domain looks up the From domain's
// Domain Policy Record before it signs.

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func e34Key(t *testing.T) any {
	t.Helper()
	pemData, err := os.ReadFile("../../keys/sel1._domainkey.test2.dkim2.com.pem")
	if err != nil {
		t.Fatal(err)
	}
	key, err := LoadPrivateKey(pemData)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func e34Sign(t *testing.T, from, d string, policy PolicyFetcher) ([]byte, error) {
	t.Helper()
	msg := "From: A <a@" + from + ">\r\nTo: b@example.net\r\nSubject: s\r\n" +
		"Date: Tue, 3 Nov 2026 00:00:00 +0000\r\nMessage-ID: <x@" + from + ">\r\n\r\nbody\r\n"
	var out bytes.Buffer
	err := Sign(strings.NewReader(msg), &out, e34Key(t), SignOptions{
		Selector: "sel1", Domain: d, MailFrom: "bounce@" + d,
		RcptTo:  []string{"b@example.net"},
		Fetcher: &JSONKeyFetcher{Path: "../../dns.json"},
		Policy:  policy,
	})
	return out.Bytes(), err
}

func TestSpec09E34SignerUpwardOpenSigns(t *testing.T) {
	for _, x := range []string{"open", "noflag"} {
		out, err := e34Sign(t, x+".dkim2.com", "mail."+x+".dkim2.com", nil)
		if err != nil {
			t.Fatalf("%s: refused: %v", x, err)
		}
		results, err := VerifyFull(bytes.NewReader(out), &JSONKeyFetcher{Path: "../../dns.json"},
			VerifyOptions{SkipTimestampCheck: true})
		if err != nil {
			t.Fatalf("%s: does not verify: %v", x, err)
		}
		if r := PrimaryResult(results); r != nil {
			t.Fatalf("%s: does not verify: %v", x, r.Error)
		}
	}
}

func TestSpec09E34SignerUpwardRefused(t *testing.T) {
	for _, tc := range []struct{ x, reason string }{
		{"strict", "From strict.dkim2.com forbids subdomain signing"},
		{"strictlist", "From strictlist.dkim2.com forbids subdomain signing"},
		{"broken", "From broken.dkim2.com forbids subdomain signing"},
		{"multi", "multiple records for multi.dkim2.com policy"},
	} {
		out, err := e34Sign(t, tc.x+".dkim2.com", "mail."+tc.x+".dkim2.com", nil)
		want := "not signing: From header field is not Authentic for d=mail." + tc.x +
			".dkim2.com: " + tc.reason
		if err == nil || err.Error() != want || len(out) != 0 {
			t.Errorf("%s: want %q, got %v (%d bytes)", tc.x, want, err, len(out))
		}
	}
}

func TestSpec09E34SignerPolicyTemperror(t *testing.T) {
	p := &fakePolicy{temp: map[string]bool{"open.dkim2.com": true}}
	_, err := e34Sign(t, "open.dkim2.com", "mail.open.dkim2.com", p)
	want := "not signing: From header field is not Authentic for d=mail.open.dkim2.com: " +
		"policy for open.dkim2.com unavailable"
	if err == nil || err.Error() != want {
		t.Fatalf("want %q, got %v", want, err)
	}
	if p.calls["open.dkim2.com"] != 1 {
		t.Fatalf("lookups: %v", p.calls)
	}
}

func TestSpec09E34SignerPolicyHook(t *testing.T) {
	p := &fakePolicy{recs: map[string][]string{"open.dkim2.com": {"v=DKIM1; f=strict"}}}
	_, err := e34Sign(t, "open.dkim2.com", "mail.open.dkim2.com", p)
	if err == nil || !strings.HasSuffix(err.Error(), ": From open.dkim2.com forbids subdomain signing") {
		t.Fatalf("hook not used: %v", err)
	}
}

func TestSpec09E34SignerNoLookup(t *testing.T) {
	// Downward: From below d= signs with no lookup.
	p := &fakePolicy{}
	if _, err := e34Sign(t, "mail.strict.dkim2.com", "strict.dkim2.com", p); err != nil {
		t.Fatalf("downward refused: %v", err)
	}
	// Unrelated: the plain refusal, no lookup.
	_, err := e34Sign(t, "open.dkim2.com", "test2.dkim2.com", p)
	want := "not signing: From header field is not Authentic for d=test2.dkim2.com"
	if err == nil || err.Error() != want {
		t.Fatalf("want %q, got %v", want, err)
	}
	if len(p.calls) != 0 {
		t.Fatalf("lookups made: %v", p.calls)
	}
}
