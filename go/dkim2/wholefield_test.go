package dkim2

// Whole-field syntax and folding (follow-up review, F.1-F.6): see section F of
// docs/superpowers/specs/2026-10-09-verifier-strictness-review-fixes.md.

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

func wantOutcome(t *testing.T, got, want string) {
	t.Helper()
	if want == "" {
		if got != "" {
			t.Fatalf("want pass, got %q", got)
		}
		return
	}
	if !strings.Contains(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// F.1: every non-empty tag-list fragment must be a well-formed tag=value.
func TestWholeFieldF1_TagLists(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	tmpl := withS(t, sigLine, "sel1:rsa-sha256:{SIG}")
	const sigErr = "PERMERROR DKIM2-Signature i=1 syntax error"
	const miErr = "PERMERROR Message-Instance m=1 syntax error"
	cases := []struct {
		name, extra, want string
	}{
		{"empty fragments", " ;; ", ""},
		{"unknown tag", " x_1=foo bar;", ""},
		{"folded unknown value", " x=foo\r\n\tbar;", ""},
		{"FWS around =", " x = foo ;", ""},
		{"empty value", " x=;", ""},
		{"junk", " junk;", sigErr},
		{"name starts with digit", " 9bad=foo;", sigErr},
		{"no name", " =v;", sigErr},
		{"NUL in unknown value", " x=a\x00b;", sigErr},
		{"DEL in unknown value", " x=a\x7fb;", sigErr},
		{"8-bit in unknown value", " x=caf\xc3\xa9;", sigErr},
		{"NBSP in unknown value", " x=a\xc2\xa0;", sigErr},
		{"bare CR in value", " x=a\rb;", sigErr},
	}
	for _, tc := range cases {
		t.Run("sig/"+tc.name, func(t *testing.T) {
			msg := resign(t, tmpl+tc.extra, miLine, rest)
			wantOutcome(t, verifyOutcome(msg, jsonFetcher(), skipTS), tc.want)
		})
		t.Run("mi/"+tc.name, func(t *testing.T) {
			want := tc.want
			if want != "" {
				want = miErr
			}
			msg := resign(t, tmpl, miLine+tc.extra, rest)
			wantOutcome(t, verifyOutcome(msg, jsonFetcher(), skipTS), want)
		})
	}
	// A bad byte in a known tag's value is just as fatal.
	t.Run("sig/NUL in n=", func(t *testing.T) {
		msg := resign(t, tmpl+" n=ab\x00c;", miLine, rest)
		wantOutcome(t, verifyOutcome(msg, jsonFetcher(), skipTS), sigErr)
	})
}

// F.2: no FWS inside a selector or algorithm name; exactly three parts.
func TestWholeFieldF2_SItems(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	const sigErr = "PERMERROR DKIM2-Signature i=1 syntax error"
	cases := []struct {
		name, s, want string
	}{
		{"plain", "sel1:rsa-sha256:{SIG}", ""},
		{"FWS around colons", " sel1 : rsa-sha256 : {SIG}", ""},
		{"fold after colons", "sel1:\r\n\trsa-sha256:\r\n\t{SIG}", ""},
		{"fold before colons", "sel1\r\n\t:rsa-sha256\r\n :{SIG}", ""},
		{"FWS around comma", "sel1:rsa-sha256:{SIG} ,\r\n\tsel9:x-unknown:AAAA", ""},
		{"space in algorithm", "sel1:rsa- sha256:{SIG}", sigErr},
		{"fold in algorithm", "sel1:rsa-\r\n\tsha256:{SIG}", sigErr},
		{"space in selector", "se l1:rsa-sha256:{SIG}", sigErr},
		{"bad selector char", "sel/1:rsa-sha256:{SIG}", sigErr},
		{"empty selector label", "sel1..x:rsa-sha256:{SIG}", sigErr},
		{"bad algorithm char", "sel1:rsa.sha256:{SIG}", sigErr},
		{"two parts", "sel1:rsa-sha256:{SIG},sel2:rsa-sha256", sigErr},
		{"four parts", "sel1:rsa-sha256:{SIG}:x", sigErr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := resign(t, withS(t, sigLine, tc.s), miLine, rest)
			wantOutcome(t, verifyOutcome(msg, jsonFetcher(), skipTS), tc.want)
		})
	}
	// FWS inside the base64 signature value is removed.
	t.Run("fold inside signature value", func(t *testing.T) {
		msg := resign(t, withS(t, sigLine, "sel1:rsa-sha256:{SIG}"), miLine, rest)
		i := strings.Index(msg, "rsa-sha256:") + len("rsa-sha256:") + 20
		msg = msg[:i] + "\r\n\t" + msg[i:]
		wantOutcome(t, verifyOutcome(msg, jsonFetcher(), skipTS), "")
	})
}

// F.3: no FWS inside a hash name; both digests required.
func TestWholeFieldF3_HashSets(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	tmpl := withS(t, sigLine, "sel1:rsa-sha256:{SIG}")
	hval := miLine[strings.Index(miLine, "h=")+2 : len(miLine)-1] // sha256:H:B
	parts := strings.Split(hval, ":")
	hh, bh := parts[1], parts[2]
	const miErr = "PERMERROR Message-Instance m=1 syntax error"
	cases := []struct {
		name, h, want string
	}{
		{"plain", hval, ""},
		{"FWS around name", " sha256 :" + hh + ":" + bh, ""},
		{"fold beside colons", "sha256\r\n\t:\r\n\t" + hh + "\r\n\t:\r\n\t" + bh, ""},
		{"fold inside digests", "sha256:" + hh[:10] + "\r\n\t" + hh[10:] + ":" + bh[:5] + " " + bh[5:], ""},
		{"unknown second set", hval + ", x-hash:AAAA:AAAA", ""},
		{"space in name", "sha 256:" + hh + ":" + bh, miErr},
		{"fold in name", "sha\r\n\t256:" + hh + ":" + bh, miErr},
		{"bad name char", "sha.256:" + hh + ":" + bh, miErr},
		{"missing body digest", hval + ",sha512:AAAA", miErr},
		{"empty body digest", hval + ",sha512:AAAA:", miErr},
		{"four parts", hval + ":AAAA", miErr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mi := "Message-Instance: m=1; h=" + tc.h + ";"
			msg := resign(t, tmpl, mi, rest)
			wantOutcome(t, verifyOutcome(msg, jsonFetcher(), skipTS), tc.want)
		})
	}
}

// F.4: every key-record value, known or not, must match the value grammar.
func TestWholeFieldF4_KeyRecordValues(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	msg := sigLine + "\r\n" + miLine + "\r\n" + rest
	p := sel1P(t)
	const keyErr = "PERMERROR DKIM2-Signature i=1 public key sel1 has a syntax error"
	cases := []struct {
		name, rec, want string
	}{
		{"note with spaces", "v=DKIM1; n=a note here; p=" + p, ""},
		{"folded note", "v=DKIM1; n=a\r\n\tnote; p=" + p, ""},
		{"NUL in n=", "v=DKIM1; n=a\x00b; p=" + p, keyErr},
		{"DEL in unknown tag", "v=DKIM1; x=a\x7fb; p=" + p, keyErr},
		{"8-bit in n=", "v=DKIM1; n=caf\xc3\xa9; p=" + p, keyErr},
		{"NUL in k=", "v=DKIM1; k=rsa\x00; p=" + p, keyErr},
		{"semicolon-free junk in t=", "v=DKIM1; t=y\x01; p=" + p, keyErr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := verifyOutcome(msg, txtFetcher{"sel1": {{tc.rec}}}, skipTS)
			wantOutcome(t, got, tc.want)
		})
	}
}

// F.5: the signer never folds a Domain; a long d= signs and verifies.
func TestWholeFieldF5_LongDomainSigns(t *testing.T) {
	raw, err := os.ReadFile("../../python/tests/emails/simple.eml")
	if err != nil {
		t.Fatal(err)
	}
	domain := strings.Repeat("a", 40) + "." + strings.Repeat("b", 40) + ".example.com"
	var out bytes.Buffer
	if err := Sign(bytes.NewReader(raw), &out, strictKey(t, "sel1"), SignOptions{
		Selector:  "sel1",
		Domain:    domain,
		MailFrom:  "sender@" + domain,
		RcptTo:    []string{"recipient@example.com"},
		Timestamp: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	signed := out.String()
	head, _, _ := strings.Cut(signed, "\r\n\r\n")
	for _, line := range strings.Split(head, "\r\n") {
		if len(line) > 998 {
			t.Fatalf("header line of %d octets", len(line))
		}
	}
	if !strings.Contains(signed, "d="+domain+";") {
		t.Fatalf("d= not kept whole:\n%s", head)
	}
	p := sel1P(t)
	got := verifyOutcome(signed, txtFetcher{"sel1": {{"v=DKIM1; k=rsa; p=" + p}}}, VerifyOptions{})
	wantOutcome(t, got, "")
}
