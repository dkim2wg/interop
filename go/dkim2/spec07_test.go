package dkim2

// Shared behaviour tests for draft-ietf-dkim-dkim2-spec-07 (the U1..D1 table
// of the -07 upgrade plan).  The example.* domains these cases name live in
// this suite's own fake DNS (spec07Keys below): every one of them publishes
// the test1.dkim2.com Ed25519 key under the Selector "s07".

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

var spec07Domains = map[string]bool{
	"example.com": true, "example.org": true, "example.net": true,
	"other.net": true, "fwd.example.net": true, "other.example": true,
	"elsewhere.net": true, "lists.example.org": true, "mail.example.org": true,
	"xn--bcher-kva.example": true,
}

type spec07Keys struct{ pub crypto.PublicKey }

func (k spec07Keys) FetchPublicKey(sel, dom string) (crypto.PublicKey, string, error) {
	if sel == "s07" && spec07Domains[strings.ToLower(dom)] {
		return k.pub, "ed25519-sha256", nil
	}
	return nil, "", fmt.Errorf("%w: %s._domainkey.%s", ErrKeyNotFound, sel, dom)
}

func spec07Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	return loadKey(t, "../../keys/ed25519._domainkey.test1.dkim2.com.pem").(ed25519.PrivateKey)
}

func spec07Fetcher(t *testing.T) KeyFetcher {
	return spec07Keys{pub: spec07Key(t).Public()}
}

const spec07Base = "From: A <a@example.com>\r\nTo: list@lists.example.org\r\n" +
	"Subject: hello\r\n\r\nbody line\r\n"

// sign07 signs in as domain d.  Built chains skip the signer gate unless
// gate is set, so that broken chains can be made on purpose.
func sign07(t *testing.T, in []byte, d, mf string, rt []string, nd string, gate bool, mod ...func(*SignOptions)) ([]byte, error) {
	t.Helper()
	opts := SignOptions{
		Selector: "s07", Domain: d, MailFrom: mf, RcptTo: rt, NextDomain: nd,
		Timestamp: 1740000000, Fetcher: spec07Fetcher(t), SkipTimestampCheck: true,
		SkipUpstreamCheck: !gate,
	}
	for _, m := range mod {
		m(&opts)
	}
	var out bytes.Buffer
	err := Sign(bytes.NewReader(in), &out, spec07Key(t), opts)
	return out.Bytes(), err
}

func must07(t *testing.T, in []byte, d, mf string, rt []string, nd string, mod ...func(*SignOptions)) []byte {
	t.Helper()
	out, err := sign07(t, in, d, mf, rt, nd, false, mod...)
	if err != nil {
		t.Fatalf("sign d=%s: %v", d, err)
	}
	return out
}

// verify07 runs VerifyFull and returns every error text, "" for a pass.
func verify07(t *testing.T, msg []byte, opts ...VerifyOptions) string {
	t.Helper()
	opt := VerifyOptions{SkipTimestampCheck: true}
	if len(opts) > 0 {
		opt = opts[0]
	}
	results, err := VerifyFull(bytes.NewReader(msg), spec07Fetcher(t), opt)
	var got []string
	if err != nil {
		got = append(got, err.Error())
	}
	for _, r := range results {
		if r.Error != nil {
			got = append(got, r.Error.Error())
		}
	}
	return strings.Join(got, " | ")
}

func wantPass07(t *testing.T, msg []byte, opts ...VerifyOptions) {
	t.Helper()
	if got := verify07(t, msg, opts...); got != "" {
		t.Fatalf("want PASS, got %s", got)
	}
}

func wantErr07(t *testing.T, msg []byte, want string, opts ...VerifyOptions) {
	t.Helper()
	got := verify07(t, msg, opts...)
	if !strings.Contains(got, want) {
		t.Fatalf("want %q, got %q", want, got)
	}
}

// revise07 rewrites the content of a signed message with mutate (header
// fields) and newBody ("" keeps the body), and adds an UNSIGNED top
// Message-Instance carrying recipeJSON, or the ComputeDiff Recipe when
// recipeJSON is "".
func revise07(t *testing.T, in []byte, mutate func([]Header) []Header, newBody string, recipeJSON string) []byte {
	t.Helper()
	headers, bodyReader, err := parseHeaders(bytes.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	var before bytes.Buffer
	before.ReadFrom(bodyReader)
	var content []Header
	var chain []string
	top := 0
	for _, h := range headers {
		switch strings.ToLower(h.Name) {
		case "message-instance":
			chain = append(chain, h.Raw)
			if mi, err := parseMI(h.Raw); err == nil && mi.Version > top {
				top = mi.Version
			}
		case "dkim2-signature":
			chain = append(chain, h.Raw)
		default:
			content = append(content, h)
		}
	}
	after := content
	if mutate != nil {
		after = mutate(append([]Header{}, content...))
	}
	afterBody := before.Bytes()
	if newBody != "" {
		afterBody = []byte(newBody)
	}
	hh, err := hashHeaders(after, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	bh, err := hashBody(bytes.NewReader(afterBody), "sha256")
	if err != nil {
		t.Fatal(err)
	}
	mi := fmt.Sprintf("Message-Instance: m=%d; h=sha256:%s:%s;", top+1,
		base64.StdEncoding.EncodeToString(hh), base64.StdEncoding.EncodeToString(bh))
	if recipeJSON == "" {
		r, err := ComputeDiff(content, before.Bytes(), after, afterBody)
		if err != nil || r == nil {
			t.Fatalf("ComputeDiff: %v %v", r, err)
		}
		js, _ := encodeRecipe(r)
		recipeJSON = string(js)
	}
	mi += " r=" + base64.StdEncoding.EncodeToString([]byte(recipeJSON)) + ";"
	var b bytes.Buffer
	b.WriteString(mi + "\r\n")
	for _, c := range chain {
		b.WriteString(c)
	}
	for _, h := range after {
		b.WriteString(h.Raw)
	}
	b.WriteString("\r\n")
	b.Write(afterBody)
	return b.Bytes()
}

func setHeader(name, value string) func([]Header) []Header {
	return func(hs []Header) []Header {
		for i, h := range hs {
			if strings.EqualFold(h.Name, name) {
				hs[i] = Header{Name: h.Name, Value: value, Raw: h.Name + ": " + value + "\r\n"}
			}
		}
		return hs
	}
}

// recipeOf returns the decoded r= JSON of Message-Instance m=m.
func recipeOf(t *testing.T, msg []byte, m int) string {
	t.Helper()
	headers, _, _ := parseHeaders(bytes.NewReader(msg))
	for _, h := range headers {
		if strings.EqualFold(h.Name, "message-instance") {
			tvl := parseTagValueList(h.Raw[strings.IndexByte(h.Raw, ':')+1:])
			if tvl.get("m") == fmt.Sprint(m) {
				js, err := base64.StdEncoding.DecodeString(stripB64WSP(tvl.get("r")))
				if err != nil {
					t.Fatal(err)
				}
				return string(js)
			}
		}
	}
	t.Fatalf("no m=%d", m)
	return ""
}

func miWithRecipe(m int, recipeJSON string) string {
	return fmt.Sprintf("Message-Instance: m=%d; h=sha256:AAAA:AAAA; r=%s;", m,
		base64.StdEncoding.EncodeToString([]byte(recipeJSON)))
}

// ---- U: the "u" Recipe step (§5) ----

func TestSpec07U1UTF8HeaderIsDStep(t *testing.T) {
	in := []byte("From: A <a@example.com>\r\nSubject: café\r\n\r\nbody\r\n")
	hop1 := must07(t, in, "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	got := recipeOf(t, revise07(t, hop1, setHeader("Subject", "x"), "", ""), 2)
	if !strings.Contains(got, `"subject":[{"d":["café"]}]`) {
		t.Fatalf("recipe %s, want subject step {\"d\":[\"café\"]}", got)
	}
}

func TestSpec07U2NonUTF8BodyIsUStep(t *testing.T) {
	in := []byte("From: A <a@example.com>\r\nSubject: s\r\n\r\ncaf\xe9\r\nnaïve\r\n")
	hop1 := must07(t, in, "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	rev := revise07(t, hop1, nil, "x\r\ny\r\n", "")
	got := recipeOf(t, rev, 2)
	if !strings.Contains(got, `{"u":["Y2Fm6Q=="]}`) || !strings.Contains(got, `{"d":["naïve"]}`) {
		t.Fatalf("recipe %s, want {\"u\":[\"Y2Fm6Q==\"]} then {\"d\":[\"naïve\"]}", got)
	}
	hop2 := must07(t, rev, "example.org", "list@lists.example.org", []string{"sub@example.net"}, "")
	wantPass07(t, hop2)
}

func TestSpec07UStepSchema(t *testing.T) {
	const invalid = "PERMERROR: Message-Instance m=2 contains invalid JSON"
	for name, js := range map[string]string{
		"U3 nonzero pad bits":   `{"b":[{"u":["QR=="]}]}`,
		"U4 old b step":         `{"b":[{"b":["eA=="]}]}`,
		"U4 two keys":           `{"b":[{"c":[1,1],"d":["x"]}]}`,
		"U4 empty step":         `{"b":[{}]}`,
		"U5 u decodes to CR":    `{"b":[{"u":["YQ1i"]}]}`,
		"U5 empty h":            `{"h":{}}`,
		"U5 unknown step key":   `{"b":[{"x":1}]}`,
		"U5 neither h nor b":    `{"x":1}`,
		"u not a multiple of 4": `{"b":[{"u":["YWI"]}]}`,
		"u with whitespace":     `{"b":[{"u":["YW Jj"]}]}`,
		"u non-alphabet":        `{"b":[{"u":["YW-j"]}]}`,
		"d lone surrogate":      `{"b":[{"d":["\ud800"]}]}`,
		"d invalid UTF-8":       "{\"b\":[{\"d\":[\"caf\xe9\"]}]}",
		"K2 h key case dup":     `{"h":{"Subject":[],"subject":[]}}`,
		"top key case dup":      `{"b":[],"B":null}`,
		"step key case dup":     `{"b":[{"d":["x"],"D":["y"]}]}`,
		"null h any case":       `{"H":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseMI(miWithRecipe(2, js))
			if err == nil || err.Error() != invalid {
				t.Fatalf("parseMI(%s) = %v, want %q", js, err, invalid)
			}
		})
	}
	for name, js := range map[string]string{
		"u canonical":   `{"b":[{"u":["Y2Fm6Q=="]}]}`,
		"u one pad":     `{"b":[{"u":["YWI="]}]}`,
		"u empty":       `{"b":[{"u":[""]}]}`,
		"upper keys":    `{"B":[{"U":["YWI="]},{"D":["x"]},{"C":[1,1]}]}`,
		"pair escapes":  `{"b":[{"d":["\ud83d\ude00"]}]}`,
		"unknown top":   `{"b":[],"x":1}`,
		"null b upper":  `{"B":null}`,
		"d valid utf-8": `{"b":[{"d":["naïve"]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseMI(miWithRecipe(2, js)); err != nil {
				t.Fatalf("parseMI(%s) = %v, want ok", js, err)
			}
		})
	}
	mi, err := parseMI(miWithRecipe(2, `{"B":null}`))
	if err != nil || mi.Recipe == nil || !mi.Recipe.BodyNull {
		t.Fatalf(`{"B":null} is not the null body Recipe: %v %+v`, err, mi)
	}
}

// K1: keys match case-insensitively at every level.
func TestSpec07K1UppercaseKeysVerify(t *testing.T) {
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	for _, js := range []string{`{"h":{"subject":[{"c":[1,1]}]}}`, `{"H":{"Subject":[{"C":[1,1]}]}}`} {
		rev := revise07(t, hop1, nil, "", js)
		hop2 := must07(t, rev, "example.org", "list@lists.example.org", []string{"sub@example.net"}, "")
		wantPass07(t, hop2)
	}
}

// ---- F: flags (§10.10, §12.5) ----

func TestSpec07F1DonotmodifyIgnored(t *testing.T) {
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"list@lists.example.org"}, "",
		func(o *SignOptions) { o.Flags = []string{"donotmodify", "donotexplode"} })
	if !strings.Contains(string(hop1), "f=donotmodify,donotexplode;") {
		t.Fatalf("flags not emitted:\n%s", hop1)
	}
	rev := revise07(t, hop1, setHeader("Subject", "[list] hello"), "body line\r\nfooter\r\n", "")
	hop2 := must07(t, rev, "example.org", "list@lists.example.org", []string{"a@example.net", "b@example.net"}, "")
	wantPass07(t, hop2)
}

func sigFlags(t *testing.T, msg []byte, i int) []string {
	t.Helper()
	headers, _, _ := parseHeaders(bytes.NewReader(msg))
	for _, h := range headers {
		if strings.EqualFold(h.Name, "dkim2-signature") {
			if s, err := parseSig(h.Raw); err == nil && s.Sequence == i {
				return s.Flags
			}
		}
	}
	t.Fatalf("no i=%d", i)
	return nil
}

func hasFlag(fs []string, f string) bool {
	for _, x := range fs {
		if x == f {
			return true
		}
	}
	return false
}

func TestSpec07F2Exploded(t *testing.T) {
	exploded := func(o *SignOptions) { o.Exploded = true }
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com",
		[]string{"list@lists.example.org", "b@lists.example.org"}, "", exploded,
		func(o *SignOptions) { o.Flags = []string{"exploded", "feedback"} })
	if f := sigFlags(t, hop1, 1); hasFlag(f, "exploded") || !hasFlag(f, "feedback") {
		t.Fatalf("i=1 flags %v: exploded must never be set at i=1", f)
	}
	hop2 := must07(t, hop1, "example.org", "list@lists.example.org", []string{"sub@example.net"}, "", exploded)
	if f := sigFlags(t, hop2, 2); !hasFlag(f, "exploded") {
		t.Fatalf("i=2 flags %v: requested exploded missing", f)
	}
	wantPass07(t, hop2)
	hop2b := must07(t, hop1, "example.org", "list@lists.example.org", []string{"a@example.net", "b@example.net"}, "")
	if f := sigFlags(t, hop2b, 2); !hasFlag(f, "exploded") {
		t.Fatalf("i=2 flags %v: two rt= addresses need exploded", f)
	}
	hop2c := must07(t, hop1, "example.org", "list@lists.example.org", []string{"a@example.net"}, "")
	if f := sigFlags(t, hop2c, 2); hasFlag(f, "exploded") {
		t.Fatalf("i=2 flags %v: one rt=, not requested", f)
	}
}

// ---- C: Chain of Custody (§7.1 item 1, §14.4) ----

func TestSpec07C1NullMailFromHop(t *testing.T) {
	for _, rt := range []string{"list@lists.example.org", "<list@Lists.Example.ORG.>"} {
		hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{rt}, "")
		hop2 := must07(t, hop1, "example.org", "<>", []string{"a@example.com"}, "")
		wantPass07(t, hop2)
	}
}

func TestSpec07C1PostfixStyleDomains(t *testing.T) {
	hop1 := must07(t, []byte(spec07Base), "example.com", "<A@Example.COM.>", []string{"<list@Lists.Example.ORG.>"}, "")
	hop2 := must07(t, hop1, "example.org", "<list@LISTS.example.org.>", []string{"sub@example.net"}, "")
	wantPass07(t, hop2)
}

func TestSpec07C2NullMailFromWrongDomain(t *testing.T) {
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	hop2 := must07(t, hop1, "other.net", "<>", []string{"a@example.com"}, "")
	wantErr07(t, hop2, "PERMERROR: DKIM2-Signature i=2 d= does not match the rt= of i=1")
}

func ndChain07(t *testing.T, rt1, d2, d3 string) []byte {
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{rt1}, "")
	hop2 := must07(t, hop1, d2, "", nil, "fwd.example.net")
	return must07(t, hop2, d3, "b@"+d3, []string{"c@example.net"}, "")
}

func TestSpec07C3NdHop(t *testing.T) {
	wantPass07(t, ndChain07(t, "x@mail.example.org", "example.org", "fwd.example.net"))
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"x@example.org"}, "")
	hop2 := must07(t, hop1, "mail.example.org", "", nil, "fwd.example.net")
	hop3 := must07(t, hop2, "fwd.example.net", "b@fwd.example.net", []string{"c@example.net"}, "")
	wantErr07(t, hop3, "PERMERROR: DKIM2-Signature i=2 d= does not match the rt= of i=1")
}

func TestSpec07C4NdMismatch(t *testing.T) {
	wantErr07(t, ndChain07(t, "x@mail.example.org", "example.org", "other.example"),
		"PERMERROR: DKIM2-Signature i=2 nd= does not match")
}

func TestSpec07C5DomainLiteral(t *testing.T) {
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"x@[192.0.2.1]"}, "")
	hop2 := must07(t, hop1, "example.org", "y@[192.0.2.1]", []string{"c@example.net"}, "")
	got := verify07(t, hop2)
	for _, want := range []string{
		"PERMERROR: DKIM2-Signature i=2 mf= does not match the rt= of i=1",
		"PERMERROR: DKIM2-Signature i=2 MAIL FROM and d= do not match",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("want %q in %q", want, got)
		}
	}
}

func TestSpec07C6MailFromAndD(t *testing.T) {
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.net", []string{"list@lists.example.org"}, "")
	_, err := VerifyFull(bytes.NewReader(hop1), spec07Fetcher(t), VerifyOptions{SkipTimestampCheck: true})
	want := "PERMERROR: DKIM2-Signature i=1 MAIL FROM and d= do not match"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("want top-level %q, got %v", want, err)
	}
}

// ---- A: From must be Authentic (§11, §14.8) ----

func TestSpec07A1FromAuthentic(t *testing.T) {
	const notAuth = "PERMERROR: DKIM2-Signature i=1 matching From is not authentic"
	for _, tc := range []struct {
		from, d, want string
	}{
		{"A <a@example.com>", "example.com", ""},
		{"A <a@example.com>", "example.net", notAuth},
		{"a@sub.example.com", "example.com", ""},
		{"a@example.com, b@example.com", "example.com", notAuth},
		{"a@[192.0.2.1]", "example.com", notAuth},
		{"=?utf-8?q?Caf=C3=A9?=\r\n <a@example.com>", "example.com", ""},
		{"=?utf-8?q?Caf=C3=A9?=\r\n <a@example.com>", "example.net", notAuth},
		{"group: a@example.com;", "example.com", notAuth},
	} {
		in := []byte("From: " + tc.from + "\r\nSubject: s\r\n\r\nbody\r\n")
		hop1 := must07(t, in, tc.d, "a@"+tc.d, []string{"list@lists.example.org"}, "")
		got := verify07(t, hop1)
		if tc.want == "" && got != "" || !strings.Contains(got, tc.want) {
			t.Errorf("From %q d=%s: got %q, want %q", tc.from, tc.d, got, tc.want)
		}
	}
	// Two From fields are never Authentic.
	in := []byte("From: a@example.com\r\nFrom: a@example.com\r\nSubject: s\r\n\r\nbody\r\n")
	wantErr07(t, must07(t, in, "example.com", "a@example.com", []string{"list@lists.example.org"}, ""), notAuth)
}

func fromChangeChain07(t *testing.T, newFrom string) []byte {
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	rev := revise07(t, hop1, setHeader("From", newFrom), "", "")
	return must07(t, rev, "example.org", "list@lists.example.org", []string{"sub@example.net"}, "")
}

func TestSpec07A2ChangedFrom(t *testing.T) {
	wantPass07(t, fromChangeChain07(t, "List <list@lists.example.org>"))
	wantErr07(t, fromChangeChain07(t, "x@elsewhere.net"),
		"PERMERROR: DKIM2-Signature i=2 matching From is not authentic")
	// The From at state 1 is still checked against i=1.
	hop1 := must07(t, []byte(strings.Replace(spec07Base, "a@example.com", "a@elsewhere.net", 1)),
		"example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	rev := revise07(t, hop1, setHeader("From", "list@lists.example.org"), "", "")
	hop2 := must07(t, rev, "example.org", "list@lists.example.org", []string{"sub@example.net"}, "")
	wantErr07(t, hop2, "PERMERROR: DKIM2-Signature i=1 matching From is not authentic")
}

// ingress07 adds an unsigned Message-Instance m=1 (no Recipe) over in, as a
// list host stamps a post that arrived without DKIM2.
func ingress07(t *testing.T, in []byte) []byte {
	t.Helper()
	headers, bodyReader, err := parseHeaders(bytes.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	body.ReadFrom(bodyReader)
	hh, err := hashHeaders(headers, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	bh, err := hashBody(bytes.NewReader(body.Bytes()), "sha256")
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(fmt.Sprintf("Message-Instance: m=1; h=sha256:%s:%s;\r\n",
		base64.StdEncoding.EncodeToString(hh), base64.StdEncoding.EncodeToString(bh))), in...)
}

// Ruling 19: i=1 is checked against the From at state m(i=1).  An author's
// From in an unsigned ingress m=1 that the list rewrote in m=2 before
// signing i=1 over m=2 was never covered by a signature, so it is not
// checked; the From at state m(i=1) still is.
func TestSpec07A5FromBeforeFirstSignature(t *testing.T) {
	in := ingress07(t, []byte(strings.Replace(spec07Base, "a@example.com", "a@elsewhere.net", 1)))
	rev := revise07(t, in, setHeader("From", "List <list@lists.example.org>"), "", "")
	wantPass07(t, must07(t, rev, "example.org", "list@lists.example.org", []string{"sub@example.net"}, ""))

	in = ingress07(t, []byte(spec07Base))
	rev = revise07(t, in, setHeader("Subject", "[list] s"), "", "")
	wantErr07(t, must07(t, rev, "example.org", "list@lists.example.org", []string{"sub@example.net"}, ""),
		"PERMERROR: DKIM2-Signature i=1 matching From is not authentic")
}

func TestSpec07A3SignerRefusesInauthenticFrom(t *testing.T) {
	in := []byte("From: a@example.net\r\nSubject: s\r\n\r\nbody\r\n")
	out, err := sign07(t, in, "example.com", "a@example.com", []string{"b@example.org"}, "", true)
	want := "From header field is not Authentic for d=example.com"
	if err == nil || !strings.Contains(err.Error(), want) || len(out) != 0 {
		t.Fatalf("want refusal %q, got %v (%d bytes)", want, err, len(out))
	}
	if _, err := sign07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"b@example.org"}, "", true); err != nil {
		t.Fatalf("authentic From refused: %v", err)
	}
}

// An unsigned top Message-Instance that changed From: the gate signs when
// d= makes the new From Authentic, and refuses otherwise.
func TestSpec07A3GateUnsignedTopChangedFrom(t *testing.T) {
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	rev := revise07(t, hop1, setHeader("From", "List <list@lists.example.org>"), "", "")
	out, err := sign07(t, rev, "lists.example.org", "list@lists.example.org", []string{"sub@example.net"}, "", true)
	if err != nil {
		t.Fatalf("gate refused a matching d=: %v", err)
	}
	wantPass07(t, out)
	_, err = sign07(t, rev, "other.net", "x@other.net", []string{"sub@example.net"}, "", true)
	want := "From header field is not Authentic for d=other.net"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want refusal %q, got %v", want, err)
	}
	// An unchanged From under a fresh hop needs no match with the new d=.
	if _, err := sign07(t, hop1, "lists.example.org", "list@lists.example.org", []string{"sub@example.net"}, "", true); err != nil {
		t.Fatalf("forwarding hop refused: %v", err)
	}
}

// A top nd= signature: the gate signs when its own d= is the nd=; inbound
// verification of the same message reports the unexpected nd= tag.
func TestSpec07GateTopNd(t *testing.T) {
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"x@mail.example.org"}, "")
	hop2 := must07(t, hop1, "example.org", "", nil, "fwd.example.net")
	wantErr07(t, hop2, "PERMERROR: DKIM2-Signature i=2 unexpected nd= tag")
	out, err := sign07(t, hop2, "fwd.example.net", "b@fwd.example.net", []string{"c@example.net"}, "", true)
	if err != nil {
		t.Fatalf("gate refused d= == nd=: %v", err)
	}
	wantPass07(t, out)
}

func TestSpec07A4IDNFrom(t *testing.T) {
	in := []byte("From: u@bücher.example\r\nSubject: s\r\n\r\nbody\r\n")
	hop1 := must07(t, in, "xn--bcher-kva.example", "u@xn--bcher-kva.example", []string{"list@lists.example.org"}, "")
	wantPass07(t, hop1)
	out, err := sign07(t, in, "xn--bcher-kva.example", "u@bücher.example", []string{"list@lists.example.org"}, "", true)
	if err != nil {
		t.Fatalf("IDN From refused: %v", err)
	}
	if !strings.Contains(string(out), "mf="+base64.StdEncoding.EncodeToString([]byte("<u@xn--bcher-kva.example>"))) {
		t.Fatalf("mf= not recorded as an A-label:\n%s", out)
	}
	wantPass07(t, out)
}

// ---- T: timestamps (§14.3) ----

func TestSpec07T1FutureLimit(t *testing.T) {
	now := time.Now().Unix()
	ok := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"b@example.org"}, "",
		func(o *SignOptions) { o.Timestamp = now + 7200 })
	wantPass07(t, ok, VerifyOptions{})
	bad := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"b@example.org"}, "",
		func(o *SignOptions) { o.Timestamp = now + 172800 })
	wantErr07(t, bad, "PERMERROR: DKIM2-Signature i=1 signature is from the future", VerifyOptions{})
	old := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"b@example.org"}, "",
		func(o *SignOptions) { o.Timestamp = now - 1209600 - 3600 })
	wantErr07(t, old, "PERMERROR: DKIM2-Signature i=1 signature expired", VerifyOptions{})
}

// ---- -07 error strings ----

func TestSpec07ErrorStrings(t *testing.T) {
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	t.Run("none", func(t *testing.T) {
		_, err := VerifyFull(strings.NewReader("From: a@example.com\r\n\r\nhi\r\n"), spec07Fetcher(t))
		if err != ErrNone {
			t.Fatalf("want ErrNone, got %v", err)
		}
	})
	t.Run("not signed", func(t *testing.T) {
		rev := revise07(t, []byte(spec07Base), setHeader("Subject", "x"), "", "")
		wantErr07(t, rev, "PERMERROR: Message-Instance m=1 is not signed")
	})
	t.Run("body hash", func(t *testing.T) {
		wantErr07(t, bytes.Replace(hop1, []byte("body line"), []byte("body lime"), 1),
			"FAIL: Message-Instance m=1 body hash sha256 mismatch")
	})
	t.Run("header hash", func(t *testing.T) {
		wantErr07(t, bytes.Replace(hop1, []byte("Subject: hello"), []byte("Subject: jello"), 1),
			"FAIL: Message-Instance m=1 header hash sha256 mismatch")
	})
	t.Run("incorrect signature", func(t *testing.T) {
		bad := bytes.Replace(hop1, []byte("t=1740000000"), []byte("t=1740000001"), 1)
		wantErr07(t, bad, "FAIL: DKIM2-Signature i=1 selector s07 incorrect signature")
	})
	t.Run("missing key", func(t *testing.T) {
		bad := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"b@example.org"}, "",
			func(o *SignOptions) { o.Selector = "nokey" })
		wantErr07(t, bad, "PERMERROR: DKIM2-Signature i=1 public key nokey does not exist")
	})
	t.Run("duplicate tag", func(t *testing.T) {
		bad := bytes.Replace(hop1, []byte("t=1740000000;"), []byte("t=1740000000; T=1740000000;"), 1)
		wantErr07(t, bad, "PERMERROR: DKIM2-Signature i=1 syntax error")
	})
	t.Run("nd with mf", func(t *testing.T) {
		bad := bytes.Replace(hop1, []byte("d=example.com;"), []byte("d=example.com; nd=x.example;"), 1)
		wantErr07(t, bad, "PERMERROR: DKIM2-Signature i=1 tag=mf was unexpected")
	})
	t.Run("custody", func(t *testing.T) {
		hop2 := must07(t, hop1, "example.net", "x@example.net", []string{"y@example.org"}, "")
		wantErr07(t, hop2, "PERMERROR: DKIM2-Signature i=2 mf= does not match the rt= of i=1")
	})
	t.Run("envelope", func(t *testing.T) {
		wantErr07(t, hop1, "PERMERROR: DKIM2-Signature i=1 MAIL FROM b@example.com did not match",
			VerifyOptions{SkipTimestampCheck: true, MailFrom: "b@example.com"})
	})
}

// ---- D1: never a DSN for mf=<> ----

func TestSpec07D1NoDSNForNullMailFrom(t *testing.T) {
	const keys = "../../keys/"
	raw := []byte("From: postmaster@test1.dkim2.com\r\nTo: user@test2.dkim2.com\r\n" +
		"Subject: bounce\r\n\r\nbody line\r\n")
	hop1 := signOnce(t, raw, keys+"rsa1024._domainkey.test1.dkim2.com.pem",
		"rsa1024", "test1.dkim2.com", "<>", []string{"user@test2.dkim2.com"})
	hop2 := signOnce(t, hop1, keys+"rsa1024._domainkey.test2.dkim2.com.pem",
		"rsa1024", "test2.dkim2.com", "user@test2.dkim2.com", []string{"dest@test3.dkim2.com"})
	_, upstream, err := Propagate(wrapDSN(hop2), PropagateOptions{
		Key:      loadKey(t, keys+"ed25519._domainkey.test2.dkim2.com.pem"),
		Selector: "ed25519", Domain: "test2.dkim2.com", Timestamp: 1740000000,
		SkipAuthentication: true,
	})
	if err == nil {
		t.Fatalf("propagated a DSN to %q for an mf=<> message", upstream)
	}
	if !strings.Contains(err.Error(), "mf=<>") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func wrapDSN(orig []byte) []byte {
	const boundary = "BOUNDARY07"
	var dsn bytes.Buffer
	dsn.WriteString("From: postmaster@test3.dkim2.com\r\nTo: user@test2.dkim2.com\r\nSubject: failure\r\n")
	dsn.WriteString("Content-Type: multipart/report; report-type=delivery-status; boundary=\"" + boundary + "\"\r\n\r\n")
	dsn.WriteString("--" + boundary + "\r\nContent-Type: text/plain\r\n\r\ndelivery failed\r\n")
	dsn.WriteString("--" + boundary + "\r\nContent-Type: message/delivery-status\r\n\r\n")
	dsn.WriteString("Reporting-MTA: dns; test3.dkim2.com\r\n\r\nFinal-Recipient: rfc822; dest@test3.dkim2.com\r\nAction: failed\r\nStatus: 5.1.1\r\n")
	dsn.WriteString("--" + boundary + "\r\nContent-Type: message/rfc822\r\n\r\n")
	dsn.Write(orig)
	dsn.WriteString("\r\n--" + boundary + "--\r\n")
	return dsn.Bytes()
}
