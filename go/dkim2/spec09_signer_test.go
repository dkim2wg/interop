package dkim2

// Contract E3.4, revised (docs/superpowers/specs/2026-11-03-dkim2-spec-09-design.md):
// a signer whose d= is below the From domain asks SignOptions.ParentFrom;
// it looks no Domain Policy Record up.

import (
	"bytes"
	"crypto"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	e34DNS     = "../../dns.json"
	e34KeyPath = "../../keys/sel1._domainkey.test2.dkim2.com.pem"
	e34Refusal = "not signing: From header field is not Authentic for d=mail.open.dkim2.com"
)

func e34Key(t *testing.T) any {
	t.Helper()
	pemData, err := os.ReadFile(e34KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := LoadPrivateKey(pemData)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func e34Msg(from string) string {
	return "From: A <a@" + from + ">\r\nTo: b@example.net\r\nSubject: s\r\n" +
		"Date: Tue, 3 Nov 2026 00:00:00 +0000\r\nMessage-ID: <x@" + from + ">\r\n\r\nbody\r\n"
}

// e34Fetcher is dns.json that counts key and policy lookups.
type e34Fetcher struct {
	JSONKeyFetcher
	keys, policies int
}

func (f *e34Fetcher) FetchPublicKey(sel, dom string) (crypto.PublicKey, string, error) {
	f.keys++
	return f.JSONKeyFetcher.FetchPublicKey(sel, dom)
}

func (f *e34Fetcher) FetchPolicy(dom string) ([]string, error) {
	f.policies++
	return f.JSONKeyFetcher.FetchPolicy(dom)
}

// parentHook records the From domains it is asked about.
type parentHook struct {
	answer bool
	calls  []string
}

func (h *parentHook) fn(dom string) bool {
	h.calls = append(h.calls, dom)
	return h.answer
}

func e34Sign(t *testing.T, from, d string, f *e34Fetcher, pol PolicyFetcher,
	parent func(string) bool) ([]byte, error) {
	t.Helper()
	var out bytes.Buffer
	err := Sign(strings.NewReader(e34Msg(from)), &out, e34Key(t), SignOptions{
		Selector: "sel1", Domain: d, MailFrom: "bounce@" + d,
		RcptTo:     []string{"b@example.net"},
		Fetcher:    f,
		Policy:     pol,
		ParentFrom: parent,
	})
	return out.Bytes(), err
}

func e34Verifies(t *testing.T, out []byte) {
	t.Helper()
	results, err := VerifyFull(bytes.NewReader(out), &JSONKeyFetcher{Path: e34DNS},
		VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("does not verify: %v", err)
	}
	if r := PrimaryResult(results); r != nil {
		t.Fatalf("does not verify: %v", r.Error)
	}
}

func TestSpec09E34SignerUpwardNoHookRefuses(t *testing.T) {
	f := &e34Fetcher{JSONKeyFetcher: JSONKeyFetcher{Path: e34DNS}}
	p := &fakePolicy{}
	out, err := e34Sign(t, "open.dkim2.com", "mail.open.dkim2.com", f, p, nil)
	if err == nil || err.Error() != e34Refusal || len(out) != 0 {
		t.Fatalf("want %q, got %v (%d bytes)", e34Refusal, err, len(out))
	}
	if f.policies != 0 || len(p.calls) != 0 {
		t.Fatalf("policy lookups made: fetcher %d, Policy %v", f.policies, p.calls)
	}
}

func TestSpec09E34SignerUpwardHookTrueSigns(t *testing.T) {
	f := &e34Fetcher{JSONKeyFetcher: JSONKeyFetcher{Path: e34DNS}}
	h := &parentHook{answer: true}
	out, err := e34Sign(t, "open.dkim2.com", "mail.open.dkim2.com", f, nil, h.fn)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if len(h.calls) != 1 || h.calls[0] != "open.dkim2.com" {
		t.Fatalf("hook calls: %v", h.calls)
	}
	if f.policies != 0 {
		t.Fatalf("policy lookups made: %d", f.policies)
	}
	e34Verifies(t, out)
}

func TestSpec09E34SignerUpwardHookFalseRefuses(t *testing.T) {
	h := &parentHook{answer: false}
	out, err := e34Sign(t, "open.dkim2.com", "mail.open.dkim2.com", nil, nil, h.fn)
	if err == nil || err.Error() != e34Refusal || len(out) != 0 {
		t.Fatalf("want %q, got %v (%d bytes)", e34Refusal, err, len(out))
	}
	if len(h.calls) != 1 {
		t.Fatalf("hook calls: %v", h.calls)
	}
}

func TestSpec09E34SignerDownwardNeverCallsHook(t *testing.T) {
	h := &parentHook{answer: false}
	if _, err := e34Sign(t, "mail.open.dkim2.com", "open.dkim2.com", nil, nil, h.fn); err != nil {
		t.Fatalf("downward refused: %v", err)
	}
	// Unrelated: the plain refusal, hook not asked.
	_, err := e34Sign(t, "open.dkim2.com", "test2.dkim2.com", nil, nil, h.fn)
	want := "not signing: From header field is not Authentic for d=test2.dkim2.com"
	if err == nil || err.Error() != want {
		t.Fatalf("want %q, got %v", want, err)
	}
	if len(h.calls) != 0 {
		t.Fatalf("hook called: %v", h.calls)
	}
}

func TestSpec09E34ParentFromSet(t *testing.T) {
	f := ParentFromSet([]string{"Open.DKIM2.com."})
	if !f("open.dkim2.com") || f("dkim2.com") {
		t.Fatal("ParentFromSet mismatch")
	}
}

func TestSpec09E34CLIParentFrom(t *testing.T) {
	bin := t.TempDir() + "/dkim2sign"
	if b, err := exec.Command("go", "build", "-o", bin, "../cmd/dkim2sign").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	run := func(extra ...string) ([]byte, string, error) {
		args := append([]string{"-selector", "sel1", "-domain", "mail.open.dkim2.com",
			"-key", e34KeyPath, "-mail-from", "bounce@mail.open.dkim2.com",
			"-rcpt-to", "b@example.net", "-dns-json", e34DNS}, extra...)
		cmd := exec.Command(bin, args...)
		cmd.Stdin = strings.NewReader(e34Msg("open.dkim2.com"))
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		return stdout.Bytes(), stderr.String(), err
	}
	_, stderr, err := run()
	if err == nil || strings.TrimSpace(stderr) != "ERROR: "+e34Refusal {
		t.Fatalf("without -parent-from: err %v, stderr %q", err, stderr)
	}
	out, stderr, err := run("-parent-from", "example.org", "-parent-from", "OPEN.dkim2.com.")
	if err != nil {
		t.Fatalf("with -parent-from: %v: %s", err, stderr)
	}
	e34Verifies(t, out)
}
