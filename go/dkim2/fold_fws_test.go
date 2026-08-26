package dkim2

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Folding whitespace inside DKIM2 tag values (spec-05 §2.12): FWS may appear
// inside a base64 string and around the colons of an s= item, and "MUST be
// ignored when the value is used".
//
// Regression: we split the s= item on ':' before stripping FWS, so a fold
// landing between the Selector colon and the algorithm token left CRLF+TAB
// glued to the algorithm name.  Folded output from a conformant signer must
// verify.
var foldPoints = []struct {
	name    string
	pattern *regexp.Regexp
	repl    string
}{
	{"mf_base64", regexp.MustCompile(`(mf=)([A-Za-z0-9+/=]{6})`), "$1$2\r\n\t"},
	{"rt_base64", regexp.MustCompile(`(rt=)([A-Za-z0-9+/=]{6})`), "$1$2\r\n\t"},
	{"s_selector", regexp.MustCompile(`(s=[A-Za-z0-9_-]+:)`), "$1\r\n\t"},
	{"s_algorithm", regexp.MustCompile(`(:ed25519-sha256:)`), "$1\r\n\t"},
	{"h_hashes", regexp.MustCompile(`(h=sha256:)([A-Za-z0-9+/=]{6})`), "$1$2\r\n\t"},
}

// refold inserts a fold into the DKIM2-Signature / Message-Instance headers only.
func refold(msg string, re *regexp.Regexp, repl string) string {
	head, body, found := strings.Cut(msg, "\r\n\r\n")
	if !found {
		return msg
	}
	var out []string
	for _, h := range strings.Split(head, "\r\n") {
		name, _, _ := strings.Cut(strings.ToLower(h), ":")
		if name == "dkim2-signature" || name == "message-instance" {
			out = append(out, re.ReplaceAllString(h, repl))
		} else {
			out = append(out, h)
		}
	}
	return strings.Join(out, "\r\n") + "\r\n\r\n" + body
}

func signForFoldTest(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../python/tests/emails/simple.eml")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile("../../keys/ed25519._domainkey.test1.dkim2.com.pem")
	if err != nil {
		t.Skip("key not found")
	}
	key, err := LoadPrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	var signed bytes.Buffer
	if err := Sign(bytes.NewReader(raw), &signed, key, SignOptions{
		Selector: "ed25519", Domain: "test1.dkim2.com",
		MailFrom:  "sender@test1.dkim2.com",
		RcptTo:    []string{"recipient@example.com"},
		Timestamp: 1740000000,
	}); err != nil {
		t.Fatal(err)
	}
	return signed.String()
}

func TestFoldedTagValuesVerify(t *testing.T) {
	signed := signForFoldTest(t)
	verifyExpectPass(t, signed, "unfolded baseline")

	for _, fp := range foldPoints {
		folded := refold(signed, fp.pattern, fp.repl)
		if folded == signed {
			t.Errorf("%s: fold was not actually inserted", fp.name)
			continue
		}
		verifyExpectPass(t, folded, "fold in "+fp.name)
	}
}

func TestAllFoldsAtOnceVerify(t *testing.T) {
	msg := signForFoldTest(t)
	for _, fp := range foldPoints {
		msg = refold(msg, fp.pattern, fp.repl)
	}
	verifyExpectPass(t, msg, "every fold point at once")
}

// A folded f= flag list carries CRLF+WSP, not just spaces (§2.12). The signer
// can't emit f= yet, so check the parser directly.
func TestParseFoldedFlagList(t *testing.T) {
	raw := "DKIM2-Signature: i=1; m=1; t=1740000000; d=test1.dkim2.com;" +
		" mf=PHNlbmRlckB0ZXN0MS5ka2ltMi5jb20+;" +
		" rt=PHJjcHRAdGVzdDIuZGtpbTIuY29tPg==;" +
		" s=ed25519:ed25519-sha256:AAAA;" +
		" f=feedback,\r\n\tdonotmodify;\r\n"
	sig, err := parseSig(raw)
	if err != nil {
		t.Fatalf("parseSig: %v", err)
	}
	want := []string{"feedback", "donotmodify"}
	if len(sig.Flags) != len(want) {
		t.Fatalf("Flags = %q, want %q", sig.Flags, want)
	}
	for i := range want {
		if sig.Flags[i] != want[i] {
			t.Errorf("Flags[%d] = %q, want %q", i, sig.Flags[i], want[i])
		}
	}
}

func verifyExpectPass(t *testing.T, msg string, desc string) {
	t.Helper()
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	results, err := Verify(strings.NewReader(msg), f, VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Errorf("%s: Verify returned error: %v", desc, err)
		return
	}
	if len(results) == 0 {
		t.Errorf("%s: no signatures found", desc)
		return
	}
	for _, r := range results {
		if r.Error != nil {
			t.Errorf("%s: i=%d d=%s failed: %v", desc, r.Sequence, r.Domain, r.Error)
		}
	}
}
