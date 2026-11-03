package dkim2

// Tests for draft-ietf-dkim-dkim2-spec-09, item by item of the contract
// (docs/superpowers/specs/2026-11-03-dkim2-spec-09-design.md, E1-E6).
// They reuse the spec07_test.go fake DNS and signing helpers.

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// ---- E1: NONE ----

func TestSpec09E1None(t *testing.T) {
	for _, verify := range []func() ([]VerifyResult, error){
		func() ([]VerifyResult, error) {
			return Verify(strings.NewReader(spec07Base), spec07Fetcher(t))
		},
		func() ([]VerifyResult, error) {
			return VerifyFull(strings.NewReader(spec07Base), spec07Fetcher(t))
		},
	} {
		_, err := verify()
		if !errors.Is(err, ErrNone) || err.Error() != "No DKIM2 header fields found" {
			t.Errorf("got %v, want ErrNone %q", err, "No DKIM2 header fields found")
		}
	}
	// An instance with no signature is not NONE.
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	if _, err := VerifyFull(bytes.NewReader(dropAllSigs(t, hop1)), spec07Fetcher(t),
		VerifyOptions{SkipTimestampCheck: true}); errors.Is(err, ErrNone) {
		t.Error("a Message-Instance alone gave NONE")
	}
}

// ---- E2: a null Recipe is a PERMERROR ----

func TestSpec09E2NullRecipe(t *testing.T) {
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	hop2 := func(in []byte, body, recipe string) []byte {
		return must07(t, revise07(t, in, nil, body, recipe),
			"example.org", "list@lists.example.org", []string{"sub@example.net"}, "")
	}
	null2 := hop2(hop1, "changed\r\n", `{"b":null}`)
	wantErr07(t, null2, "PERMERROR: Message-Instance m=2 has a null recipe")

	// Verify (no lower walk) reports it too: it does not depend on the walk.
	if res, err := Verify(bytes.NewReader(null2), spec07Fetcher(t), VerifyOptions{SkipTimestampCheck: true}); err == nil ||
		err.Error() != "PERMERROR: Message-Instance m=2 has a null recipe" {
		t.Errorf("Verify: got %v %+v", err, res)
	}

	// Two nulls: the lowest m= is named.
	wantPrimary := func(msg []byte, want string) {
		t.Helper()
		if got := primary07(t, msg, VerifyOptions{SkipTimestampCheck: true}); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	wantPrimary(hop2(null2, "again\r\n", `{"b":null}`), "PERMERROR: Message-Instance m=2 has a null recipe")

	// A lower instance's own Recipe fault beats a higher null: m=2's
	// Recipe is swapped for a malformed one after the chain is built.
	const ok2 = `{"b":[{"d":["body line"]}]}`
	over := hop2(hop2(hop1, "changed\r\n", ok2), "again\r\n", `{"b":null}`)
	b64 := base64.StdEncoding.EncodeToString
	bad := bytes.Replace(over, []byte(b64([]byte(ok2))), []byte(b64([]byte(`{"b":[{"c":[3,3]},{"c":[1,1]}]}`))), 1)
	if bytes.Equal(bad, over) {
		t.Fatal("m=2 Recipe not found")
	}
	wantPrimary(over, "PERMERROR: Message-Instance m=3 has a null recipe")
	wantPrimary(bad, "PERMERROR: Message-Instance m=2 recipe b[1] is invalid")

	// The signer's own view skips an unsigned null, and the gate signs
	// over it; a signed null is refused.
	unsigned := revise07(t, hop1, nil, "changed\r\n", `{"b":null}`)
	if got := primary07(t, unsigned, VerifyOptions{SkipTimestampCheck: true, Outbound: true}); got != "" {
		t.Errorf("outbound unsigned null: got %q, want pass", got)
	}
	if _, err := sign07(t, unsigned, "example.org", "list@lists.example.org", []string{"sub@example.net"}, "", true); err != nil {
		t.Errorf("gate refused this hop's own null: %v", err)
	}
	if _, err := sign07(t, null2, "example.net", "sub@example.net", []string{"x@other.net"}, "", true); err == nil ||
		!strings.Contains(err.Error(), "has a null recipe") {
		t.Errorf("gate over a signed null: got %v, want a refusal", err)
	}
}

// ---- E3: Authentic From, upwards, and the Domain Policy Record ----

type fakePolicy struct {
	recs  map[string][]string
	temp  map[string]bool
	calls map[string]int
}

func (p *fakePolicy) FetchPolicy(dom string) ([]string, error) {
	if p.calls == nil {
		p.calls = map[string]int{}
	}
	p.calls[dom]++
	if p.temp[dom] {
		return nil, errors.New("SERVFAIL")
	}
	return p.recs[dom], nil
}

func TestSpec09E3PolicyRecord(t *testing.T) {
	for _, tc := range []struct {
		name string
		txts []string
		want int
	}{
		{"none", nil, policyAllowed},
		{"no flags", []string{"v=DKIM1"}, policyAllowed},
		{"empty f=", []string{"v=DKIM1; f="}, policyAllowed},
		{"strict", []string{"v=DKIM1; f=strict"}, policyStrict},
		{"strict in a list, FWS", []string{"v=DKIM1; f=foo : strict"}, policyStrict},
		{"other flags", []string{"v=DKIM1; f=foo:bar-2"}, policyAllowed},
		{"case-sensitive flag", []string{"v=DKIM1; f=STRICT"}, policyAllowed},
		{"WSP around =", []string{"  v = DKIM1 ; f=strict"}, policyStrict},
		{"empty member", []string{"v=DKIM1; f=strict:"}, policyStrict},
		{"doubled colon", []string{"v=DKIM1; f=a::b"}, policyStrict},
		{"not a hyphenated-word", []string{"v=DKIM1; f=a-"}, policyStrict},
		{"duplicate tag", []string{"v=DKIM1; f=strict; f=foo"}, policyStrict},
		{"unparseable", []string{"v=DKIM1; garbage"}, policyStrict},
		{"two records", []string{"v=DKIM1", "v=DKIM1; f=strict"}, policyMultiple},
		{"foreign records only", []string{"v=spf1 -all", "f=strict"}, policyAllowed},
		{"v=dkim1 is foreign", []string{"v=dkim1; f=strict"}, policyAllowed},
		{"V=DKIM1 is foreign", []string{"V=DKIM1; f=strict"}, policyAllowed},
		{"DKIM1 beside foreign", []string{"v=spf1 -all", "v=DKIM1; f=strict"}, policyStrict},
		{"long whitespace", []string{"v=DKIM1; f=strict" + strings.Repeat(" ", 65000) + "x"}, policyStrict},
	} {
		if got := policyOf(tc.txts); got != tc.want {
			t.Errorf("%s: policyOf = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestSpec09E3FromUpward(t *testing.T) {
	// d=mail.example.org signs for a From at its parent, example.org.
	sub := func(from string) []byte {
		in := []byte("From: " + from + "\r\nSubject: s\r\n\r\nbody\r\n")
		return must07(t, in, "mail.example.org", "a@mail.example.org", []string{"list@lists.example.org"}, "")
	}
	run := func(msg []byte, p *fakePolicy) string {
		t.Helper()
		return verify07(t, msg, VerifyOptions{SkipTimestampCheck: true, Policy: p})
	}
	up := sub("A <a@Example.ORG.>")
	for _, tc := range []struct {
		name string
		p    *fakePolicy
		want string
	}{
		{"no record", &fakePolicy{}, ""},
		{"no flags", &fakePolicy{recs: map[string][]string{"example.org": {"v=DKIM1"}}}, ""},
		{"strict", &fakePolicy{recs: map[string][]string{"example.org": {"v=DKIM1; f=strict"}}},
			"FAIL: DKIM2-Signature i=1 From example.org forbids subdomain signing"},
		{"malformed", &fakePolicy{recs: map[string][]string{"example.org": {"v=DKIM1; f=strict:"}}},
			"FAIL: DKIM2-Signature i=1 From example.org forbids subdomain signing"},
		{"multiple", &fakePolicy{recs: map[string][]string{"example.org": {"v=DKIM1", "v=DKIM1"}}},
			"PERMERROR: DKIM2-Signature i=1 multiple records for example.org policy"},
		{"temporary failure", &fakePolicy{temp: map[string]bool{"example.org": true}},
			"TEMPERROR: DKIM2-Signature i=1 policy for example.org unavailable"},
	} {
		if got := run(up, tc.p); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
		if tc.p.calls["example.org"] != 1 || len(tc.p.calls) != 1 {
			t.Errorf("%s: lookups %v, want one for example.org", tc.name, tc.p.calls)
		}
	}

	// The downward match needs no lookup; a sibling fails without one.
	strict := func() *fakePolicy {
		return &fakePolicy{recs: map[string][]string{
			"example.org": {"v=DKIM1; f=strict"}, "lists.example.org": {"v=DKIM1; f=strict"}}}
	}
	p := strict()
	if got := run(sub("a@x.mail.example.org"), p); got != "" || len(p.calls) != 0 {
		t.Errorf("downward: got %q, lookups %v", got, p.calls)
	}
	p = strict()
	if got := run(sub("a@lists.example.org"), p); got != "FAIL: DKIM2-Signature i=1 matching From is not authentic" || len(p.calls) != 0 {
		t.Errorf("sibling: got %q, lookups %v", got, p.calls)
	}
	// Never once an earlier error exists.
	p = strict()
	tampered := bytes.Replace(up, []byte("\r\n\r\nbody"), []byte("\r\n\r\nbodz"), 1)
	if got := run(tampered, p); !strings.Contains(got, "body hash") || len(p.calls) != 0 {
		t.Errorf("tampered: got %q, lookups %v", got, p.calls)
	}

	// The From classification (E3.1).
	for _, tc := range []struct{ from, want string }{
		{"a@example.org, b@example.org", "FAIL: DKIM2-Signature i=1 From has more than one address"},
		{"g: a@example.org, b@example.org;", "FAIL: DKIM2-Signature i=1 From has more than one address"},
		{`"x, y" <a@mail.example.org>`, ""},
		{"(x, y) a@mail.example.org", ""},
		{"g: a@mail.example.org;", "FAIL: DKIM2-Signature i=1 matching From is not authentic"},
		{"no address", "FAIL: DKIM2-Signature i=1 matching From is not authentic"},
		{"a@[192.0.2.1]", "FAIL: DKIM2-Signature i=1 From uses a domain literal"},
	} {
		if got := run(sub(tc.from), &fakePolicy{}); got != tc.want {
			t.Errorf("From %q: got %q, want %q", tc.from, got, tc.want)
		}
	}

	// One lookup per domain per verification.
	p = &fakePolicy{}
	c := newPolicyCache(p)
	c.get("example.org")
	c.get("example.org")
	if p.calls["example.org"] != 1 {
		t.Errorf("cache: %d lookups", p.calls["example.org"])
	}
}

// The dns.json policy source: the shared fixtures' "_domainkey" entries.
func TestSpec09E3JSONPolicy(t *testing.T) {
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	for dom, want := range map[string]int{
		"strict.dkim2.com": policyStrict, "strictlist.dkim2.com": policyStrict,
		"broken.dkim2.com": policyStrict, "multi.dkim2.com": policyMultiple,
		"noflag.dkim2.com": policyAllowed, "foreign.dkim2.com": policyAllowed,
		"test1.dkim2.com": policyAllowed,
	} {
		txts, err := f.FetchPolicy(dom)
		if err != nil {
			t.Fatal(err)
		}
		if got := policyOf(txts); got != want {
			t.Errorf("%s: %d, want %d", dom, got, want)
		}
	}
}

// ---- E4: foreign TXT records beside a key ----

func TestSpec09E4FirstTagV(t *testing.T) {
	for _, tc := range []struct {
		txt  string
		isV  bool
		want string
	}{
		{"v=DKIM1; p=x", true, "DKIM1"},
		{" \tv = DKIM1 ;", true, "DKIM1"},
		{"v=spf1 -all", true, "spf1 -all"},
		{"k=rsa; v=DKIM1", false, ""},
		{"V=DKIM1", false, ""},
		{"vv=DKIM1", false, ""},
		{"garbage", false, ""},
	} {
		if isV, v := firstTagV(tc.txt); isV != tc.isV || v != tc.want {
			t.Errorf("firstTagV(%q) = %v %q, want %v %q", tc.txt, isV, v, tc.isV, tc.want)
		}
	}
}

// ---- E5: an RSA key under 1024 bits is too short ----

type smallRSAFetcher struct{}

func (smallRSAFetcher) FetchPublicKey(sel, dom string) (crypto.PublicKey, string, error) {
	n := new(big.Int).Lsh(big.NewInt(1), 511)
	return &rsa.PublicKey{N: n.Add(n, big.NewInt(1)), E: 65537}, "rsa-sha256", nil
}

func TestSpec09E5RSATooShort(t *testing.T) {
	msg := signOnce(t, []byte("From: a@test1.dkim2.com\r\nSubject: s\r\n\r\nbody\r\n"),
		"../../keys/sel1._domainkey.test1.dkim2.com.pem", "sel1", "test1.dkim2.com",
		"a@test1.dkim2.com", []string{"b@test2.dkim2.com"})
	results, err := VerifyFull(bytes.NewReader(msg), smallRSAFetcher{}, VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	p := PrimaryResult(results)
	if p == nil || p.Error.Error() != "PERMERROR: DKIM2-Signature i=1 public key sel1 too short" {
		t.Errorf("got %+v", p)
	}
}

// ---- E6: strings and the exploded flag at i=1 ----

func TestSpec09E6ExplodedAtI1(t *testing.T) {
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	if bytes.Contains(hop1, []byte("; f=")) {
		t.Fatalf("i=1 already carries f=: %s", hop1)
	}
	for _, flags := range []string{"exploded", "foo, exploded"} {
		msg := bytes.Replace(hop1, []byte("DKIM2-Signature: i=1;"), []byte("DKIM2-Signature: i=1; f="+flags+";"), 1)
		if bytes.Equal(msg, hop1) {
			t.Fatal("no i=1 signature to edit")
		}
		// Before any key fetch: the fetcher here has no keys at all.
		results, err := VerifyFull(bytes.NewReader(msg), txtFetcher{}, VerifyOptions{SkipTimestampCheck: true})
		got := ""
		if err != nil {
			got = err.Error()
		} else if p := PrimaryResult(results); p != nil {
			got = p.Error.Error()
		}
		if got != "PERMERROR: DKIM2-Signature i=1 has an exploded flag" {
			t.Errorf("f=%s: got %q", flags, got)
		}
	}
}

func TestSpec09E6Strings(t *testing.T) {
	mi := "Message-Instance: m=1; h=sha256:AAAA:AAAA;"
	if _, err := chainStructure([]string{mi, mi}, nil, false); err == nil ||
		err.Error() != "PERMERROR: Message-Instance m=1 is duplicated" {
		t.Errorf("duplicate m=: %v", err)
	}
	sig := "DKIM2-Signature: i=1; m=1; d=example.com;"
	if _, err := chainStructure([]string{mi}, []string{sig, sig}, false); err == nil ||
		err.Error() != "PERMERROR: DKIM2-Signature i=1 is duplicated" {
		t.Errorf("duplicate i=: %v", err)
	}
	if _, err := parseMI(miWithRecipe(2, `{"b":[{"x":1}]}`)); err == nil ||
		err.Error() != "PERMERROR: Message-Instance m=2 recipe b[0] is invalid" {
		t.Errorf("recipe: %v", err)
	}
	in := []byte("From: a@example.com\r\nSubject: s\r\n\r\nbody\r\n")
	wantErr07(t, must07(t, in, "example.com", "a@example.net", []string{"list@lists.example.org"}, ""),
		"FAIL: DKIM2-Signature i=1 mf= and d= do not match")
}
