package dkim2

// Tests for draft-ietf-dkim-dkim2-spec-08, item by item of the contract
// (docs/superpowers/specs/2026-10-28-dkim2-spec-08-design.md, D1-D13).
// They reuse the -07 suite's fake DNS and signing helpers (spec07_test.go).

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
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

// ---- D2, D4: "|" and "," groups of hash-sets in h= ----

func TestSpec08D2HashGroupsParse(t *testing.T) {
	got, err := parseHashSets("sha256:AAAA:BBBB \r\n | sha512:CCCC:DDDD ,\tx-hash:EEEE:FFFF")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Group != 0 || got[1].Group != 1 || got[2].Group != 1 || got[2].Alg != "x-hash" {
		t.Fatalf("got %+v", got)
	}
	// Hash names are case sensitive (§9.3 %s"sha256"): SHA256 is unknown.
	if got, err := parseHashSets("SHA256:AAAA:BBBB"); err != nil || got[0].Alg != "SHA256" {
		t.Fatalf("SHA256: %+v %v", got, err)
	}
	for _, h := range []string{
		"sha256:AAAA:BBBB|", "|sha256:AAAA:BBBB", "sha256:AAAA:BBBB||sha512:AAAA:BBBB",
		"sha256:AAAA:BBBB,,sha512:AAAA:BBBB", "sha256:AAAA:BBBB, |sha512:AAAA:BBBB",
		// Every hash, of every set, is a non-empty padded base64string.
		"sha256:AAA:BBBB", "sha256:AAAA:", "x-hash:@@@@:AAAA", "sha256:AA=A:BBBB",
	} {
		if _, err := parseHashSets(h); err == nil {
			t.Errorf("parseHashSets(%q) accepted", h)
		}
	}
	// Duplicates count across the whole tag, compared exactly.
	if _, err := parseMI("Message-Instance: m=1; h=sha256:AAAA:BBBB|sha256:AAAA:BBBB;"); err == nil ||
		err.Error() != "PERMERROR: Message-Instance m=1 has a duplicate hash algorithm" {
		t.Errorf("duplicate across groups: %v", err)
	}
	if _, err := parseMI("Message-Instance: m=1; h=sha256:AAAA:BBBB,SHA256:AAAA:BBBB;"); err != nil {
		t.Errorf("sha256 and SHA256 are not duplicates: %v", err)
	}
	// The signer writes one "," group; String keeps the groups.
	mi := &MessageInstance{Version: 1, Hashes: []HashSet{{Alg: "sha256", HeaderHash: "AAAA", BodyHash: "BBBB"},
		{Alg: "sha512", HeaderHash: "CCCC", BodyHash: "DDDD", Group: 1}}}
	if s := mi.String(); s != "Message-Instance: m=1; h=sha256:AAAA:BBBB|sha512:CCCC:DDDD;" {
		t.Errorf("String() = %q", s)
	}
}

func TestSpec08D4HashCombine(t *testing.T) {
	headers := []Header{{Name: "From", Value: "a@b.com", Raw: "From: a@b.com\r\n"}}
	body := []byte("x\r\n")
	set := func(alg string, goodH, goodB bool, group int) HashSet {
		hs := HashSet{Alg: alg, HeaderHash: "AAAA", BodyHash: "AAAA", Group: group}
		if _, ok := HashAlg(alg); !ok {
			return hs
		}
		if goodH {
			h, _ := hashHeaders(headers, alg)
			hs.HeaderHash = base64.StdEncoding.EncodeToString(h)
		}
		if goodB {
			b, _ := hashBody(bytes.NewReader(body), alg)
			hs.BodyHash = base64.StdEncoding.EncodeToString(b)
		}
		return hs
	}
	const pfx = "Message-Instance m=1 "
	for _, tc := range []struct {
		name string
		sets []HashSet
		want string
	}{
		{"one good", []HashSet{set("sha256", true, true, 0)}, ""},
		{"unknown only", []HashSet{set("x-hash", true, true, 0)}, "PERMERROR: " + pfx + "algorithm x-hash unknown"},
		{"good, unknown", []HashSet{set("sha256", true, true, 0), set("x-hash", true, true, 0)},
			"PERMERROR: " + pfx + "algorithm x-hash unknown"},
		{"good | unknown", []HashSet{set("sha256", true, true, 0), set("x-hash", true, true, 1)}, ""},
		{"bad body | good", []HashSet{set("sha256", true, false, 0), set("sha512", true, true, 1)}, ""},
		{"bad body | bad header", []HashSet{set("sha256", true, false, 0), set("sha512", false, true, 1)},
			"FAIL: " + pfx + "no group of hashes passed"},
		{"bad header, bad body: h= order", []HashSet{set("sha512", false, true, 0), set("sha256", true, false, 0)},
			"FAIL: " + pfx + "header hash sha512 mismatch"},
		{"bad body, bad header: h= order", []HashSet{set("sha256", true, false, 0), set("sha512", false, true, 0)},
			"FAIL: " + pfx + "body hash sha256 mismatch"},
		{"header before body in a set", []HashSet{set("sha256", false, false, 0)},
			"FAIL: " + pfx + "header hash sha256 mismatch"},
		{"unknown, bad: FAIL wins", []HashSet{set("x-hash", true, true, 0), set("sha256", true, false, 0)},
			"FAIL: " + pfx + "body hash sha256 mismatch"},
		{"unknown | bad", []HashSet{set("x-hash", true, true, 0), set("sha256", true, false, 1)},
			"FAIL: " + pfx + "no group of hashes passed"},
		{"unknown | unknown", []HashSet{set("x-hash", true, true, 0), set("y-hash", true, true, 1)},
			"PERMERROR: " + pfx + "algorithm x-hash unknown"},
	} {
		mi := &MessageInstance{Version: 1, Hashes: tc.sets}
		got := ""
		if err := verifyMIHashes(mi, headers, body); err != nil {
			got = err.Error()
		}
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	// With no body (§16.4), a set passes when its header hash matches.
	mi := &MessageInstance{Version: 1, Hashes: []HashSet{set("sha256", true, false, 0)}}
	if err := verifyMIHeaderHashes(mi, headers); err != nil {
		t.Errorf("headers only: %v", err)
	}
}

// ---- D2, D3, D8: "|" and "," groups of signatures in s= ----

// resignSels is resign (strictness_test.go) for a template whose s= items
// carry {sel1}, {sel2} ...: each replaced by a real RSA signature with that
// test1.dkim2.com key over the signing input (every value blanked).
func resignSels(t *testing.T, sigTmpl, miLine, rest string, sels ...string) string {
	t.Helper()
	blank := sigTmpl
	for _, s := range sels {
		blank = strings.Replace(blank, "{"+s+"}", "", 1)
	}
	incomplete := (&DKIM2Signature{}).incompleteForm(blank)
	var input []byte
	input = append(input, canonicalizeSigHeader(miLine+"\r\n")...)
	input = append(input, canonicalizeSigHeader(incomplete+"\r\n")...)
	digest := sha256.Sum256(input)
	full := sigTmpl
	for _, s := range sels {
		sig, err := signDigest(strictKey(t, s), digest[:])
		if err != nil {
			t.Fatal(err)
		}
		full = strings.Replace(full, "{"+s+"}", base64.StdEncoding.EncodeToString(sig), 1)
	}
	return full + "\r\n" + miLine + "\r\n" + rest
}

// tempFetcher fails the lookup of Selector "tmp" as a DNS failure would.
type tempFetcher struct{ KeyFetcher }

func (f tempFetcher) FetchPublicKey(sel, dom string) (crypto.PublicKey, string, error) {
	if sel == "tmp" {
		return nil, "", errors.New("SERVFAIL")
	}
	return f.KeyFetcher.FetchPublicKey(sel, dom)
}

func TestSpec08D2SigGroupsParse(t *testing.T) {
	sig, err := parseSig("DKIM2-Signature: i=1; m=1; t=1; d=a.example; mf=PD4=; rt=PD4=; " +
		"s=a:rsa-sha256:AAAA \r\n | b:rsa-sha256:BBBB ,\tc:ed25519-sha256:CCCC;")
	if err != nil {
		t.Fatal(err)
	}
	if len(sig.Sigs) != 3 || sig.Sigs[0].Group != 0 || sig.Sigs[1].Group != 1 || sig.Sigs[2].Group != 1 {
		t.Fatalf("got %+v", sig.Sigs)
	}
	for _, s := range []string{
		"a:rsa-sha256:AAAA|", "|a:rsa-sha256:AAAA", "a:rsa-sha256:AAAA||b:rsa-sha256:AAAA",
		"a:rsa-sha256:AAAA,,b:rsa-sha256:AAAA", "a:rsa-sha256:AAAA,\t|b:rsa-sha256:AAAA",
		// Every value is a non-empty base64string, whatever the algorithm.
		"a:rsa-sha256:AAAA|x:future:@@@@", "a:rsa-sha256:AAAA,x:mldsa44:", "x:future:AAA",
	} {
		if _, err := parseSig("DKIM2-Signature: i=1; m=1; t=1; d=a.example; mf=PD4=; rt=PD4=; s=" + s + ";"); err == nil ||
			err.Error() != "PERMERROR: DKIM2-Signature i=1 syntax error" {
			t.Errorf("s=%s: %v, want a syntax error", s, err)
		}
	}
	// String keeps the groups.
	sig.Sigs = []SigItem{{Selector: "a", Algorithm: "rsa-sha256", Value: []byte{0}},
		{Selector: "b", Algorithm: "rsa-sha256", Value: []byte{0}, Group: 1}}
	if s := sig.String(); !strings.Contains(s, "s=a:rsa-sha256:AA==|b:rsa-sha256:AA==;") {
		t.Errorf("String() = %q", s)
	}
}

func TestSpec08D3SigCombine(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	const pfx = "DKIM2-Signature i=1 "
	for _, tc := range []struct {
		name, s string
		sels    []string
		want    string
		lookups int
	}{
		{"both pass", "sel1:rsa-sha256:{sel1},sel2:rsa-sha256:{sel2}", []string{"sel1", "sel2"}, "", 2},
		{"three of one algorithm", "sel1:rsa-sha256:{sel1},sel2:rsa-sha256:{sel2},sel3:rsa-sha256:{sel3}",
			[]string{"sel1", "sel2", "sel3"}, "", 3},
		{"good | bad", "sel1:rsa-sha256:{sel1}|sel2:rsa-sha256:AAAA", []string{"sel1"}, "", 2},
		{"bad | good", "sel2:rsa-sha256:AAAA|sel1:rsa-sha256:{sel1}", []string{"sel1"}, "", 2},
		{"good, bad", "sel1:rsa-sha256:{sel1},sel2:rsa-sha256:AAAA", []string{"sel1"},
			"FAIL: " + pfx + "selector sel2 incorrect signature", 2},
		{"bad | bad", "sel1:rsa-sha256:AAAA|sel2:rsa-sha256:AAAA", nil,
			"FAIL: " + pfx + "no group of signatures passed", 2},
		{"good, unknown", "sel1:rsa-sha256:{sel1},x:mldsa44:AAAA", []string{"sel1"},
			"PERMERROR: " + pfx + "selector x algorithm unknown", 1},
		{"good | unknown", "sel1:rsa-sha256:{sel1}|x:mldsa44:AAAA", []string{"sel1"}, "", 1},
		{"old composite only", "x:mldsa44-ed25519-sha512:AAAA", nil,
			"PERMERROR: " + pfx + "selector x algorithm unknown", 0},
		{"no key | good", "nokey:rsa-sha256:AAAA|sel1:rsa-sha256:{sel1}", []string{"sel1"}, "", 2},
		{"no key, bad: FAIL", "nokey:rsa-sha256:AAAA,sel2:rsa-sha256:AAAA", nil,
			"FAIL: " + pfx + "selector sel2 incorrect signature", 2},
		{"no key, good", "nokey:rsa-sha256:AAAA,sel1:rsa-sha256:{sel1}", []string{"sel1"},
			"PERMERROR: " + pfx + "public key nokey does not exist", 2},
		{"DNS failure, good", "tmp:rsa-sha256:AAAA,sel1:rsa-sha256:{sel1}", []string{"sel1"},
			"TEMPERROR: " + pfx + "public key tmp could not be fetched", 2},
		{"DNS failure, bad", "tmp:rsa-sha256:AAAA,sel2:rsa-sha256:AAAA", nil,
			"FAIL: " + pfx + "selector sel2 incorrect signature", 2},
		{"bad | DNS failure", "sel2:rsa-sha256:AAAA|tmp:rsa-sha256:AAAA", nil,
			"TEMPERROR: " + pfx + "public key tmp could not be fetched", 2},
		{"unknown | no key", "x:future:AAAA|nokey:rsa-sha256:AAAA", nil,
			"PERMERROR: " + pfx + "selector x algorithm unknown", 1},
	} {
		msg := resignSels(t, withS(t, sigLine, tc.s), miLine, rest, tc.sels...)
		f := &countingFetcher{inner: tempFetcher{jsonFetcher()}}
		if got := verifyOutcome(msg, f, skipTS); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
		if f.n != tc.lookups {
			t.Errorf("%s: %d key lookups, want %d", tc.name, f.n, tc.lookups)
		}
	}
}

func TestSpec08D3SelectorLimitAndDuplicates(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	items := func(n int) string {
		var s []string
		for i := 0; i < n; i++ {
			s = append(s, fmt.Sprintf("x%d:future:AAAA", i))
		}
		return strings.Join(s, ",")
	}
	for _, tc := range []struct{ name, s, want string }{
		{"nine", "sel1:rsa-sha256:{sel1}|" + items(8), "PERMERROR: DKIM2-Signature i=1 has more than 8 signatures"},
		{"eight", "sel1:rsa-sha256:{sel1}|" + items(7), ""},
		{"duplicate across groups", "sel1:rsa-sha256:{sel1}|sel1:rsa-sha256:AAAA",
			"PERMERROR: DKIM2-Signature i=1 has a duplicate selector"},
		{"duplicate before the limit", "sel1:rsa-sha256:{sel1}|" + items(8) + ",sel1:rsa-sha256:AAAA",
			"PERMERROR: DKIM2-Signature i=1 has a duplicate selector"},
	} {
		msg := resignSels(t, withS(t, sigLine, tc.s), miLine, rest, "sel1")
		f := &countingFetcher{inner: jsonFetcher()}
		if got := verifyOutcome(msg, f, skipTS); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
		if tc.want != "" && f.n != 0 {
			t.Errorf("%s: %d key lookups before the §14.2 check, want 0", tc.name, f.n)
		}
	}
}

// D3 amends C9: §14.5 and §14.6 are one step per signature, from i=1 up.
func TestSpec08D3KeyErrorAboveBadSignature(t *testing.T) {
	hop1 := must07(t, []byte(spec07Base), "example.com", "a@example.com", []string{"list@lists.example.org"}, "")
	hop2 := must07(t, hop1, "example.org", "list@lists.example.org", []string{"sub@example.net"}, "",
		func(o *SignOptions) { o.Selector = "nokey" })
	bad := bytes.Replace(hop2, []byte("i=1; m=1; t=1740000000"), []byte("i=1; m=1; t=1740000001"), 1)
	want := "FAIL: DKIM2-Signature i=1 selector s07 incorrect signature"
	if got := primary07(t, bad, VerifyOptions{SkipTimestampCheck: true}); got != want {
		t.Errorf("primary %q, want %q", got, want)
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
