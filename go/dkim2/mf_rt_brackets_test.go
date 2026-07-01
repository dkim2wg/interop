package dkim2

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
)

// signTestMessage signs the shared simple.eml fixture with the given
// SignOptions (selector/domain/key follow the existing ed25519 test1.dkim2.com
// fixtures used throughout dkim2_test.go) and returns the full signed message.
func signTestMessage(t *testing.T, opts SignOptions) string {
	t.Helper()
	raw, err := os.ReadFile("../../python/tests/emails/simple.eml")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile("../../keys/ed25519._domainkey.test1.dkim2.com.pem")
	if err != nil {
		t.Fatal(err)
	}
	key, err := LoadPrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	if opts.Selector == "" {
		opts.Selector = "ed25519"
	}
	if opts.Domain == "" {
		opts.Domain = "test1.dkim2.com"
	}
	if opts.Timestamp == 0 {
		opts.Timestamp = 1740000000
	}

	var out bytes.Buffer
	if err := Sign(bytes.NewReader(raw), &out, key, opts); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// extractTag pulls a base64 tag value (e.g. "mf") out of the first
// DKIM2-Signature header found in msg.
func extractTag(msg, tag string) string {
	idx := strings.Index(msg, "DKIM2-Signature:")
	if idx < 0 {
		return ""
	}
	line := msg[idx:]
	if nl := strings.IndexAny(line, "\r\n"); nl >= 0 {
		line = line[:nl]
	}
	prefix := "; " + tag + "="
	ti := strings.Index(line, prefix)
	if ti < 0 {
		// Also allow the tag at the very start (immediately after the colon).
		prefix = " " + tag + "="
		ti = strings.Index(line, prefix)
		if ti < 0 {
			return ""
		}
	}
	rest := line[ti+len(prefix):]
	if semi := strings.IndexByte(rest, ';'); semi >= 0 {
		rest = rest[:semi]
	}
	return strings.TrimSpace(rest)
}

// testFetcher returns a KeyFetcher backed by the shared dns.json fixture used
// throughout dkim2_test.go.
func testFetcher(t *testing.T) KeyFetcher {
	t.Helper()
	return &JSONKeyFetcher{Path: "../../dns.json"}
}

func TestMFEncodesWithBrackets(t *testing.T) {
	signed := signTestMessage(t, SignOptions{MailFrom: "sender@test1.dkim2.com",
		RcptTo: []string{"rcpt@test2.dkim2.com"}})
	mf := extractTag(signed, "mf")
	dec, _ := base64.StdEncoding.DecodeString(mf)
	if string(dec) != "<sender@test1.dkim2.com>" {
		t.Fatalf("mf= = %q, want <sender@test1.dkim2.com>", dec)
	}
}

func TestBareMFFailsVerify(t *testing.T) {
	signed := signTestMessage(t, SignOptions{MailFrom: "sender@test1.dkim2.com",
		RcptTo: []string{"rcpt@test2.dkim2.com"}})
	bad := strings.Replace(signed,
		base64.StdEncoding.EncodeToString([]byte("<sender@test1.dkim2.com>")),
		base64.StdEncoding.EncodeToString([]byte("sender@test1.dkim2.com")), 1)
	res, _ := Verify(strings.NewReader(bad), testFetcher(t), VerifyOptions{SkipTimestampCheck: true})
	if len(res) == 0 || res[len(res)-1].Error == nil ||
		!strings.Contains(res[len(res)-1].Error.Error(), "7.5") {
		t.Fatalf("expected 7.5 bracket failure, got %+v", res)
	}
}

func TestBareRTFailsVerify(t *testing.T) {
	signed := signTestMessage(t, SignOptions{MailFrom: "sender@test1.dkim2.com",
		RcptTo: []string{"rcpt@test2.dkim2.com"}})
	bad := strings.Replace(signed,
		base64.StdEncoding.EncodeToString([]byte("<rcpt@test2.dkim2.com>")),
		base64.StdEncoding.EncodeToString([]byte("rcpt@test2.dkim2.com")), 1)
	res, _ := Verify(strings.NewReader(bad), testFetcher(t), VerifyOptions{SkipTimestampCheck: true})
	if len(res) == 0 || res[len(res)-1].Error == nil ||
		!strings.Contains(res[len(res)-1].Error.Error(), "7.6") {
		t.Fatalf("expected 7.6 bracket failure, got %+v", res)
	}
}

func TestNullMailFromEncodesAsEmptyBrackets(t *testing.T) {
	signed := signTestMessage(t, SignOptions{MailFrom: "",
		RcptTo: []string{"rcpt@test2.dkim2.com"}})
	mf := extractTag(signed, "mf")
	dec, _ := base64.StdEncoding.DecodeString(mf)
	if string(dec) != "<>" {
		t.Fatalf("mf= = %q, want <>", dec)
	}
}

func TestToRFC5321Path(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "<>"},
		{"sender@test1.dkim2.com", "<sender@test1.dkim2.com>"},
		{"<sender@test1.dkim2.com>", "<sender@test1.dkim2.com>"},
	}
	for _, tc := range cases {
		if got := toRFC5321Path(tc.in); got != tc.want {
			t.Errorf(fmt.Sprintf("toRFC5321Path(%q) = %q, want %q", tc.in, got, tc.want))
		}
	}
}
