package dkim2

// Tests for draft-ietf-dkim-dkim2-spec-08, item by item of the contract
// (docs/superpowers/specs/2026-10-28-dkim2-spec-08-design.md, D1-D13).
// They reuse the -07 suite's fake DNS and signing helpers (spec07_test.go).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"
)

// ---- D10: tag names and JSON keys are strictly lowercase ----

func TestSpec08D10TagNamesStrictLowercase(t *testing.T) {
	// An uppercase tag name is an unknown tag: ignored, never a duplicate.
	tvl := parseTagValueList("m=1; M=2")
	if tvl.duplicate != "" || tvl.get("m") != "1" {
		t.Fatalf(`"m=1; M=2": duplicate %q, m=%q`, tvl.duplicate, tvl.get("m"))
	}
	if parseTagValueList("M=1").has("m") {
		t.Fatal(`"M=1" has no m= tag`)
	}

	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	skip := VerifyOptions{SkipTimestampCheck: true}
	for _, tc := range []struct {
		name     string
		from, to string
		want     string
	}{
		{"D= is not d=", "d=example.com;", "D=example.com;", "PERMERROR: DKIM2-Signature i=1 tag=d missing"},
		{"M= is not m=", "Message-Instance: m=1;", "Message-Instance: M=1;", "PERMERROR: Message-Instance m= tag=m missing"},
		{"T= twin is not a duplicate", "t=1740000000;", "t=1740000000; T=1;", "FAIL: DKIM2-Signature i=1 selector s07 incorrect signature"},
	} {
		msg := bytes.Replace(hop1, []byte(tc.from), []byte(tc.to), 1)
		if got := primary07(t, msg, skip); got != tc.want {
			t.Errorf("%s: primary %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSpec08D10JSONKeysStrictLowercase(t *testing.T) {
	const invalid = "PERMERROR: Message-Instance m=2 contains invalid JSON"
	for _, js := range []string{
		`{"B":null}`,
		`{"H":{"subject":[{"c":[1,1]}]}}`,
		`{"h":{"Subject":[{"c":[1,1]}]}}`,
		`{"b":[{"C":[1,1]}]}`,
		`{"b":[{"D":["x"]}]}`,
		`{"b":[],"X":1}`,
		// Duplicates are compared exactly, after unescaping.
		`{"b":null,"b":null}`,
	} {
		if _, err := parseMI(miWithRecipe(2, js)); err == nil || err.Error() != invalid {
			t.Errorf("parseMI(%s) = %v, want %q", js, err, invalid)
		}
	}
	// Non-ASCII letters are not judged.
	if _, err := parseMI(miWithRecipe(2, `{"h":{"x-É":[{"d":["v"]}]}}`)); err != nil {
		t.Errorf("a non-ASCII capital in a key: %v", err)
	}
}

// ---- D6: "Recipe <path> is invalid" for one bad step ----

func TestSpec08D6RecipePathIsInvalid(t *testing.T) {
	const invalid = "PERMERROR: Message-Instance m=2 contains invalid JSON"
	step := func(path string) string { return "PERMERROR: Message-Instance m=2 Recipe " + path + " is invalid" }
	for _, tc := range []struct{ js, want string }{
		// One step the schema or §5.1/§5.2 rejects.
		{`{"b":[{"c":[3,4]},{"c":[1,2]}]}`, step("b[1]")},
		{`{"b":[{"c":[1,2]},{"c":[2,3]}]}`, step("b[1]")},
		{`{"b":[{"u":["QR=="]}]}`, step("b[0]")},
		{`{"b":[{"u":["YQ1i"]}]}`, step("b[0]")},
		{`{"b":[{"b":["eA=="]}]}`, step("b[0]")},
		{`{"b":[{"c":[1,1],"d":["x"]}]}`, step("b[0]")},
		{`{"b":[{}]}`, step("b[0]")},
		{`{"b":[5]}`, step("b[0]")},
		{`{"b":[null]}`, step("b[0]")},
		{`{"b":[{"c":[0,1]}]}`, step("b[0]")},
		{`{"b":[{"c":[2,1]}]}`, step("b[0]")},
		{`{"b":[{"c":[1]}]}`, step("b[0]")},
		{`{"b":[{"c":["1",2]}]}`, step("b[0]")},
		{`{"b":[{"d":[]}]}`, step("b[0]")},
		{`{"b":[{"d":"x"}]}`, step("b[0]")},
		{`{"b":[{"d":[null]}]}`, step("b[0]")},
		{`{"b":[{"d":["a\rb"]}]}`, step("b[0]")},
		{`{"b":[{"u":[1]}]}`, step("b[0]")},
		{`{"h":{"subject":[{"d":["x"]},{"c":[0,1]}]}}`, step("h.subject[1]")},
		{`{"h":{"subject":{"c":[1,1]}}}`, step("h.subject")},
		{`{"h":{"x café":[5]}}`, step(`h.x\x20caf\xC3\xA9[0]`)},
		// b first, then h names in byte order, then steps in order.
		{`{"h":{"a":[{"x":1}]},"b":[{"c":[1,1]},{"x":1}]}`, step("b[1]")},
		{`{"h":{"b":[{"x":1}],"a":[{"d":["v"]},{"x":1}]}}`, step("h.a[1]")},
		// Whole-document problems first.
		{`{"b":[{"x":1}],"h":[]}`, invalid},
		{`{"b":[{"x":1}],"h":{}}`, invalid},
		{`{"b":"x"}`, invalid},
		{`{"b":[{"c":[1e0,1]}]}`, invalid},
		{`{"b":[{"c":[1,1]}],"x":1.5}`, invalid},
		{`{"b":[{"x":1}],"B":null}`, invalid},
		{`{"b":[{"d":["\udc80"]}]}`, invalid},
		{`{"b":[{"x":1}],"x":"\udc80"}`, invalid},
	} {
		if _, err := parseMI(miWithRecipe(2, tc.js)); err == nil || err.Error() != tc.want {
			t.Errorf("parseMI(%s) = %v, want %q", tc.js, err, tc.want)
		}
	}
	// A copy past the end of the message is found when the Recipe is
	// applied, and is still "contains invalid JSON".
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	rev := revise07(t, hop1, nil, "", `{"b":[{"c":[1,5]}]}`)
	hop2 := must07(t, rev, "example.org", "list@lists.example.org", []string{"sub@example.net"}, "")
	if got := primary07(t, hop2, VerifyOptions{SkipTimestampCheck: true}); got != invalid {
		t.Errorf("copy past the end: primary %q, want %q", got, invalid)
	}
}

// ---- D7: a p= that is base64 but not a key of its type is malformed ----

func TestSpec08D7MalformedKeys(t *testing.T) {
	edPub := spec07Key(t).Public().(ed25519.PublicKey)
	edSPKI, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	small := new(big.Int).Lsh(big.NewInt(1), 511)
	small.Add(small, big.NewInt(1))
	smallSPKI, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: small, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString
	for _, tc := range []struct {
		name, txt string
		want      error
	}{
		{"ed25519 as SPKI DER", "v=DKIM1; k=ed25519; p=" + b64(edSPKI), ErrKeyMalformed},
		{"ed25519 31 octets", "v=DKIM1; k=ed25519; p=" + b64(edPub[:31]), ErrKeyMalformed},
		{"ed25519 33 octets", "v=DKIM1; k=ed25519; p=" + b64(append(append([]byte{}, edPub...), 0)), ErrKeyMalformed},
		{"rsa not a key", "v=DKIM1; k=rsa; p=AAAA", ErrKeyMalformed},
		{"rsa 512 bits", "v=DKIM1; k=rsa; p=" + b64(smallSPKI), ErrKeyMalformed},
		{"p= not base64", "v=DKIM1; k=ed25519; p=!!!!", ErrKeySyntax},
		{"ed25519 raw", "v=DKIM1; k=ed25519; p=" + b64(edPub), nil},
	} {
		_, _, err := parseDKIM1TXT(tc.txt)
		if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}

	// Verified: "public key <s> is malformed", PERMERROR.
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	results, err := VerifyFull(bytes.NewReader(hop1), &mapKeyFetcher{map[string]string{
		"s07._domainkey.example.com": "v=DKIM1; k=ed25519; p=" + b64(edSPKI)}},
		VerifyOptions{SkipTimestampCheck: true})
	want := "PERMERROR: DKIM2-Signature i=1 public key s07 is malformed"
	if p := PrimaryResult(results); err != nil || p == nil || p.Error.Error() != want {
		t.Errorf("SPKI ed25519 key: %v %v, want %q", err, results, want)
	}
}

// ---- D5: timestamps, Chain of Custody and From Authentic are FAIL ----

func TestSpec08D5FailNotPermerror(t *testing.T) {
	skip := VerifyOptions{SkipTimestampCheck: true}
	now := time.Now().Unix()
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	for _, tc := range []struct {
		name string
		msg  []byte
		opt  VerifyOptions
		want string
	}{
		{"expired", must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"b@example.org"}, "",
			func(o *SignOptions) { o.Timestamp = now - 15*86400 }),
			VerifyOptions{}, "FAIL: DKIM2-Signature i=1 signature expired"},
		{"future", must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"b@example.org"}, "",
			func(o *SignOptions) { o.Timestamp = now + 2*86400 }),
			VerifyOptions{}, "FAIL: DKIM2-Signature i=1 signature is from the future"},
		{"top nd", must07(t, []byte(spec07Base), "example.com", "", nil, "fwd.example.net"),
			skip, "FAIL: DKIM2-Signature i=1 unexpected nd= tag"},
		{"envelope MAIL FROM", hop1, VerifyOptions{SkipTimestampCheck: true, MailFrom: "b@example.com"},
			"FAIL: DKIM2-Signature i=1 MAIL FROM b@example.com did not match"},
		{"envelope RCPT TO", hop1, VerifyOptions{SkipTimestampCheck: true, RcptTo: []string{"x@example.org"}},
			"FAIL: DKIM2-Signature i=1 RCPT TO x@example.org did not match"},
		{"mf and d", must07(t, []byte(spec07Base), "example.com", "a@example.net", []string{"b@example.org"}, ""),
			skip, "FAIL: DKIM2-Signature i=1 MAIL FROM and d= do not match"},
		{"nd mismatch", ndChain07(t, "x@mail.example.org", "example.org", "other.example"),
			skip, "FAIL: DKIM2-Signature i=2 nd= does not match"},
		{"d and rt", must07(t, hop1, "other.net", "<>", []string{"a@example.com"}, ""),
			skip, "FAIL: DKIM2-Signature i=2 d= does not match the rt= of i=1"},
		{"mf and rt", must07(t, hop1, "example.net", "x@example.net", []string{"y@example.org"}, ""),
			skip, "FAIL: DKIM2-Signature i=2 mf= does not match the rt= of i=1"},
		{"From", fromChangeChain07(t, "x@elsewhere.net"),
			skip, "FAIL: DKIM2-Signature i=2 matching From is not authentic"},
	} {
		if got := primary07(t, tc.msg, tc.opt); got != tc.want {
			t.Errorf("%s: primary %q, want %q", tc.name, got, tc.want)
		}
	}
}
