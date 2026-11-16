package dkim2

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

// A header-section line that is not a field is a malformed header section
// (CVE-2026-129847): no Message-Instance hashes it, so it must never be
// read as something else or passed over in silence.

const malformedText = "PERMERROR: malformed header field"

var malformedLines = []struct {
	name, line string
	first      bool // the line opens the header section
}{
	{"no-colon", "NoColonHere", false},
	{"wsp-in-name", "Sub ject: x", false},
	{"empty-name", ":Empty: x", false},
	{"leading-wsp", " Subject: evil", true},
	{"leading-htab", "\tSubject: evil", true},
}

// withLine puts line into msg's header section: first, or last before the
// blank line.
func withLine(t *testing.T, msg []byte, line string, first bool) []byte {
	t.Helper()
	if first {
		return append([]byte(line+"\r\n"), msg...)
	}
	i := bytes.Index(msg, []byte("\r\n\r\n"))
	if i < 0 {
		t.Fatal("no header/body separator")
	}
	out := append([]byte{}, msg[:i+2]...)
	out = append(out, line+"\r\n"...)
	return append(out, msg[i+2:]...)
}

func signedPlain(t *testing.T) []byte {
	t.Helper()
	out, err := gateSign(t, []byte("From: a@test3.dkim2.com\r\nTo: b@test2.dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n"), false)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return out
}

func TestMalformedHeaderVerifyPermerror(t *testing.T) {
	signed := signedPlain(t)
	fetcher := &JSONKeyFetcher{Path: "../../dns.json"}
	entries := []struct {
		name string
		fn   func([]byte) ([]VerifyResult, error)
	}{
		{"Verify", func(m []byte) ([]VerifyResult, error) {
			return Verify(bytes.NewReader(m), fetcher, VerifyOptions{SkipTimestampCheck: true})
		}},
		{"VerifyFull", func(m []byte) ([]VerifyResult, error) {
			return VerifyFull(bytes.NewReader(m), fetcher, VerifyOptions{SkipTimestampCheck: true})
		}},
		{"VerifyFull/undo", func(m []byte) ([]VerifyResult, error) {
			return VerifyFull(bytes.NewReader(m), fetcher, VerifyOptions{SkipTimestampCheck: true, UndoWalk: true})
		}},
	}
	for _, ml := range malformedLines {
		msg := withLine(t, signed, ml.line, ml.first)
		for _, e := range entries {
			_, err := e.fn(msg)
			if err == nil || err.Error() != malformedText {
				t.Errorf("%s %s: err %v, want %q", ml.name, e.name, err, malformedText)
			}
		}
	}
}

// The malformed header section comes before every other check, the field
// counts (contract C9 step a) included.
func TestMalformedHeaderBeforeChainLength(t *testing.T) {
	var b strings.Builder
	for i := 0; i <= MaxChainLength; i++ {
		b.WriteString("Message-Instance: m=1; h=sha256:AAAA:AAAA\r\n")
	}
	b.WriteString("NoColonHere\r\nFrom: a@test3.dkim2.com\r\n\r\nbody\r\n")
	_, err := Verify(strings.NewReader(b.String()), &JSONKeyFetcher{Path: "../../dns.json"})
	if err == nil || err.Error() != malformedText {
		t.Fatalf("err %v, want %q", err, malformedText)
	}
}

// No DKIM2 field at all: there is no DKIM2 result to give, malformed or not.
func TestMalformedHeaderNoDKIM2IsNone(t *testing.T) {
	for _, ml := range malformedLines {
		msg := withLine(t, []byte("From: a@test3.dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n"), ml.line, ml.first)
		if _, err := VerifyFull(bytes.NewReader(msg), &JSONKeyFetcher{Path: "../../dns.json"}); !errors.Is(err, ErrNone) {
			t.Errorf("%s: err %v, want ErrNone", ml.name, err)
		}
	}
}

func TestMalformedHeaderSignRefused(t *testing.T) {
	plain := []byte("From: a@test3.dkim2.com\r\nTo: b@test2.dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n")
	for _, ml := range malformedLines {
		wantRefused(t, withLine(t, plain, ml.line, ml.first), false, "malformed header field")
		// Even with the upstream gate off: what would be signed is unhashed.
		key := loadKey(t, "../../keys/sel1._domainkey.test3.dkim2.com.pem")
		var out bytes.Buffer
		err := Sign(bytes.NewReader(withLine(t, signedPlain(t), ml.line, ml.first)), &out, key, SignOptions{
			Selector: "sel1", Domain: "test3.dkim2.com", SkipUpstreamCheck: true, SkipTimestampCheck: true,
		})
		if err == nil || !strings.Contains(err.Error(), "malformed header field") || out.Len() != 0 {
			t.Errorf("%s SkipUpstreamCheck: err %v, %d bytes out", ml.name, err, out.Len())
		}
	}
}

// What is a field: a name of no WSP or colon, then optional WSP, a colon.
func TestHeaderFieldShapes(t *testing.T) {
	for _, tc := range []struct {
		in        string
		malformed bool
	}{
		{"Subject: x\r\n", false},
		{"Subject \t: x\r\n", false},
		{"X-Empty:\r\n", false},
		{"Subject: x\r\n folded\r\n", false},
		{"NoColonHere\r\n", true},
		{"Sub ject: x\r\n", true},
		{":Empty: x\r\n", true},
		{" Subject: x\r\n", true},
		{"Subject\r\n : x\r\n", true}, // the colon must be on the name's own line
	} {
		h, err := readHeaderFields(bufio.NewReader(strings.NewReader(tc.in + "\r\n")))
		if err != nil {
			t.Fatal(err)
		}
		if got := malformedHeader(h); got != tc.malformed {
			t.Errorf("%q: malformed=%v, want %v", tc.in, got, tc.malformed)
		}
	}
}
