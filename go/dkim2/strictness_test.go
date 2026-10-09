package dkim2

// Verifier strictness from the spec-06 review (R1, R3-R8): see
// docs/superpowers/specs/2026-10-09-verifier-strictness-review-fixes.md.
//   A. signature algorithms (§3.4, §8.9)
//   B. key records (§11.5, dns-00 §3.2/§3.4.1/§3.4.2.2)
//   C. Message-Instance tag case and repeats (§7)
//   D. t= syntax (§8.4, §11.2)

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// countingFetcher counts key lookups and delegates to an inner fetcher.
type countingFetcher struct {
	inner KeyFetcher
	n     int
}

func (f *countingFetcher) FetchPublicKey(selector, domain string) (crypto.PublicKey, string, error) {
	f.n++
	return f.inner.FetchPublicKey(selector, domain)
}

// txtFetcher serves raw TXT RRsets (each RR a list of character-strings)
// per selector, through the same record handling the real fetchers use.
type txtFetcher map[string][][]string

func (f txtFetcher) FetchPublicKey(selector, domain string) (crypto.PublicKey, string, error) {
	return keyFromTXTRecords(f[selector], selector+"._domainkey."+domain)
}

func strictKey(t *testing.T, name string) crypto.PrivateKey {
	t.Helper()
	pemBytes, err := os.ReadFile("../../keys/" + name + "._domainkey.test1.dkim2.com.pem")
	if err != nil {
		t.Skip("key not found")
	}
	key, err := LoadPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// strictSigned signs simple.eml with sel1 (RSA) at test1.dkim2.com and
// returns the message split into its DKIM2-Signature line, its
// Message-Instance line (both without CRLF) and the rest.
func strictSigned(t *testing.T, ts int64) (sigLine, miLine, rest string) {
	t.Helper()
	raw, err := os.ReadFile("../../python/tests/emails/simple.eml")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Sign(bytes.NewReader(raw), &out, strictKey(t, "sel1"), SignOptions{
		Selector:  "sel1",
		Domain:    "test1.dkim2.com",
		MailFrom:  "sender@test1.dkim2.com",
		RcptTo:    []string{"recipient@example.com"},
		Timestamp: ts,
	}); err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(out.String(), "\r\n", 3)
	if !strings.HasPrefix(parts[0], "DKIM2-Signature:") || !strings.HasPrefix(parts[1], "Message-Instance:") {
		t.Fatalf("unexpected signer output order: %q / %q", parts[0], parts[1])
	}
	return parts[0], parts[1], parts[2]
}

// resign builds a single-hop message from a DKIM2-Signature template whose s=
// items may carry "{SIG}" (replaced by a real RSA signature with sel1's key
// over the signing input) and a Message-Instance line used verbatim.
func resign(t *testing.T, sigTmpl, miLine, rest string) string {
	t.Helper()
	blank := strings.Replace(sigTmpl, "{SIG}", "", 1)
	incomplete := (&DKIM2Signature{}).incompleteForm(blank)
	var input []byte
	input = append(input, canonicalizeSigHeader(miLine+"\r\n")...)
	input = append(input, canonicalizeSigHeader(incomplete+"\r\n")...)
	digest := sha256.Sum256(input)
	sig, err := signDigest(strictKey(t, "sel1"), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	full := strings.Replace(sigTmpl, "{SIG}", base64.StdEncoding.EncodeToString(sig), 1)
	return full + "\r\n" + miLine + "\r\n" + rest
}

// withS replaces the s= tag (last tag the signer writes) of a signature line.
func withS(t *testing.T, sigLine, s string) string {
	t.Helper()
	i := strings.LastIndex(sigLine, "; s=")
	if i < 0 {
		t.Fatalf("no s= in %q", sigLine)
	}
	return sigLine[:i] + "; s=" + s + ";"
}

// verifyOutcome runs Verify and returns "" for a pass, else the error text.
func verifyOutcome(msg string, f KeyFetcher, opts VerifyOptions) string {
	results, err := Verify(strings.NewReader(msg), f, opts)
	if err != nil {
		return err.Error()
	}
	if len(results) == 0 {
		return "no results"
	}
	var errs []string
	for _, r := range results {
		if r.Error != nil {
			errs = append(errs, r.Error.Error())
		}
	}
	return strings.Join(errs, "; ")
}

var skipTS = VerifyOptions{SkipTimestampCheck: true}

func jsonFetcher() KeyFetcher { return &JSONKeyFetcher{Path: "../../dns.json"} }

// ---------------------------------------------------------------- A

func TestStrictA_UnknownAlgorithmNeverVerified(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	for _, alg := range []string{"future-alg", "RSA-SHA256", "rsa", "rsa-sha256x", "ed25519-sha256x"} {
		t.Run(alg, func(t *testing.T) {
			msg := resign(t, withS(t, sigLine, "sel1:"+alg+":{SIG}"), miLine, rest)
			f := &countingFetcher{inner: jsonFetcher()}
			got := verifyOutcome(msg, f, skipTS)
			if got == "" {
				t.Fatalf("RSA-signed item declaring %q passed", alg)
			}
			if want := "FAIL DKIM2-Signature i=1 has no signature with a supported algorithm"; !strings.Contains(got, want) {
				t.Errorf("error %q, want %q", got, want)
			}
			if f.n != 0 {
				t.Errorf("%d key lookups for an unknown algorithm, want 0", f.n)
			}
		})
	}
}

func TestStrictA_UnknownItemSkippedBeforeLookup(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	for name, s := range map[string]string{
		"base64 value":     "sel2:future-alg:AAAA,sel1:rsa-sha256:{SIG}",
		"non-base64 value": "sel2:future-alg:!!not base64!!,sel1:rsa-sha256:{SIG}",
	} {
		t.Run(name, func(t *testing.T) {
			msg := resign(t, withS(t, sigLine, s), miLine, rest)
			f := &countingFetcher{inner: jsonFetcher()}
			if got := verifyOutcome(msg, f, skipTS); got != "" {
				t.Fatalf("want pass, got %q", got)
			}
			if f.n != 1 {
				t.Errorf("%d key lookups, want exactly 1", f.n)
			}
		})
	}
}

func TestStrictA_ManyUnknownItemsLinear(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	var items []string
	for i := 0; i < 4000; i++ {
		items = append(items, fmt.Sprintf("u%d:future-alg-%d:AAAA", i, i))
	}
	items = append(items, "sel1:rsa-sha256:{SIG}")
	msg := resign(t, withS(t, sigLine, strings.Join(items, ",")), miLine, rest)
	f := &countingFetcher{inner: jsonFetcher()}
	got := verifyOutcome(msg, f, skipTS)
	if got != "" {
		t.Fatalf("want pass, got %q", got)
	}
	if f.n != 1 {
		t.Errorf("%d key lookups, want exactly 1", f.n)
	}
}

func TestStrictA_KnownAlgorithmBadValue(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	for name, s := range map[string]string{
		"empty":                     "sel1:rsa-sha256:",
		"not base64":                "sel1:rsa-sha256:!!!!",
		"unpadded":                  "sel1:rsa-sha256:AAA",
		"ed25519 empty beside good": "sel1:rsa-sha256:{SIG},ed25519:ed25519-sha256:",
	} {
		t.Run(name, func(t *testing.T) {
			msg := resign(t, withS(t, sigLine, s), miLine, rest)
			got := verifyOutcome(msg, jsonFetcher(), skipTS)
			if !strings.Contains(got, "PERMERROR DKIM2-Signature i=1 syntax error") {
				t.Errorf("got %q, want PERMERROR DKIM2-Signature i=1 syntax error", got)
			}
		})
	}
}

func TestStrictA_KeyTypeMismatch(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	// sel1 publishes an RSA key; an ed25519-sha256 item naming it mismatches.
	msg := resign(t, withS(t, sigLine, "sel1:ed25519-sha256:{SIG}"), miLine, rest)
	got := verifyOutcome(msg, jsonFetcher(), skipTS)
	want := "PERMERROR DKIM2-Signature i=1 public key sel1 algorithm mismatch"
	if !strings.Contains(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------- B

func sel1P(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../dns.json")
	if err != nil {
		t.Fatal(err)
	}
	var db map[string]map[string][][2]string
	if err := json.Unmarshal(data, &db); err != nil {
		t.Fatal(err)
	}
	txt := db["test1.dkim2.com"]["sel1._domainkey"][0][1]
	i := strings.Index(txt, "p=")
	return strings.TrimRight(strings.TrimSpace(txt[i+2:]), ";")
}

func TestStrictB_KeyRecords(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	msg := sigLine + "\r\n" + miLine + "\r\n" + rest
	p := sel1P(t)
	ed := "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=" // RFC 8463 example
	const pfx = "PERMERROR DKIM2-Signature i=1 public key sel1 "
	cases := []struct {
		name string
		rrs  [][]string
		want string // "" = pass
	}{
		{"plain", [][]string{{"v=DKIM1; k=rsa; p=" + p}}, ""},
		{"no v=, no k=", [][]string{{"p=" + p}}, ""},
		{"trailing ;", [][]string{{"v=DKIM1; k=rsa; p=" + p + ";"}}, ""},
		{"retired and unknown tags", [][]string{{"v=DKIM1; h=sha1; k=rsa; n=note; s=email; t=s; x_y=1; p=" + p}}, ""},
		{"FWS in p=", [][]string{{"v=DKIM1; k=rsa; p=" + p[:40] + " \t" + p[40:]}}, ""},
		{"one RR in two strings", [][]string{{"v=DKIM1; k=rsa; p=" + p[:100], p[100:]}}, ""},
		{"repeated p=", [][]string{{"v=DKIM1; p=; p=" + p}}, pfx + "has a syntax error"},
		{"bad v=", [][]string{{"v=garbage; p=" + p}}, pfx + "has a syntax error"},
		{"v= not first", [][]string{{"k=rsa; v=DKIM1; p=" + p}}, pfx + "has a syntax error"},
		{"no p=", [][]string{{"v=DKIM1; k=rsa"}}, pfx + "has a syntax error"},
		{"p= not base64", [][]string{{"v=DKIM1; k=rsa; p=!!!!"}}, pfx + "has a syntax error"},
		{"p= not a key", [][]string{{"v=DKIM1; k=rsa; p=AAAA"}}, pfx + "has a syntax error"},
		{"not a tag-list", [][]string{{"v=DKIM1; garbage; p=" + p}}, pfx + "has a syntax error"},
		{"bad tag name", [][]string{{"v=DKIM1; 1k=rsa; p=" + p}}, pfx + "has a syntax error"},
		{"upper-case P=", [][]string{{"v=DKIM1; k=rsa; P=" + p}}, pfx + "has a syntax error"},
		{"unknown k=", [][]string{{"v=DKIM1; k=unknown; p=" + p}}, pfx + "algorithm mismatch"},
		{"k=rsa-sha256", [][]string{{"v=DKIM1; k=rsa-sha256; p=" + p}}, pfx + "algorithm mismatch"},
		{"k=ed25519 for rsa-sha256", [][]string{{"v=DKIM1; k=ed25519; p=" + ed}}, pfx + "algorithm mismatch"},
		{"revoked", [][]string{{"v=DKIM1; k=rsa; p="}}, pfx + "has been revoked"},
		{"two identical RRs", [][]string{{"v=DKIM1; k=rsa; p=" + p}, {"v=DKIM1; k=rsa; p=" + p}}, pfx + "has multiple records"},
		{"two different RRs", [][]string{{"v=spf1 -all"}, {"v=DKIM1; k=rsa; p=" + p}}, pfx + "has multiple records"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := verifyOutcome(msg, txtFetcher{"sel1": tc.rrs}, skipTS)
			if tc.want == "" {
				if got != "" {
					t.Fatalf("want pass, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStrictB_JSONFetcherMultipleRecords(t *testing.T) {
	p := sel1P(t)
	db := map[string]map[string][][2]string{"ex.example": {"sel1._domainkey": {
		{"TXT", "v=DKIM1; k=rsa; p=" + p}, {"TXT", "v=DKIM1; k=rsa; p=" + p},
	}}}
	data, _ := json.Marshal(db)
	path := filepath.Join(t.TempDir(), "dns.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := (&JSONKeyFetcher{Path: path}).FetchPublicKey("sel1", "ex.example")
	if err == nil || !strings.Contains(err.Error(), "has multiple records") {
		t.Fatalf("got %v, want multiple records", err)
	}
}

// ---------------------------------------------------------------- C

func TestStrictC_MessageInstanceTagCase(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	tmpl := withS(t, sigLine, "sel1:rsa-sha256:{SIG}")
	// miLine is "Message-Instance: m=1; h=sha256:H:B;"
	hval := miLine[strings.Index(miLine, "h=")+2 : len(miLine)-1]
	cases := []struct {
		name, mi, want string
	}{
		{"H=", "Message-Instance: m=1; H=" + hval + ";", ""},
		{"M=", "Message-Instance: M=1; h=" + hval + ";", ""},
		{"h= twice", "Message-Instance: m=1; h=sha256:AAAA:AAAA; h=" + hval + ";",
			"PERMERROR Message-Instance m=1 syntax error"},
		{"h= then H=", "Message-Instance: m=1; h=" + hval + "; H=" + hval + ";",
			"PERMERROR Message-Instance m=1 syntax error"},
		{"m= then M=", "Message-Instance: m=1; M=1; h=" + hval + ";",
			"PERMERROR Message-Instance m=1 syntax error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := resign(t, tmpl, tc.mi, rest)
			got := verifyOutcome(msg, jsonFetcher(), skipTS)
			if tc.want == "" {
				if got != "" {
					t.Fatalf("want pass, got %q", got)
				}
				if res, err := VerifyFull(strings.NewReader(msg), jsonFetcher(), skipTS); err != nil {
					t.Fatalf("VerifyFull: %v", err)
				} else {
					for _, r := range res {
						if r.Error != nil {
							t.Fatalf("VerifyFull: %v", r.Error)
						}
					}
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------- D

func TestStrictD_TimestampSyntax(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	tmpl := withS(t, sigLine, "sel1:rsa-sha256:{SIG}")
	for _, tv := range []string{"garbage", "-5", "+5", "1e9", "0x10", "12 34", ""} {
		t.Run("t="+tv, func(t *testing.T) {
			msg := resign(t, strings.Replace(tmpl, "t=1740000000", "t="+tv, 1), miLine, rest)
			got := verifyOutcome(msg, jsonFetcher(), skipTS)
			if !strings.Contains(got, "PERMERROR DKIM2-Signature i=1 syntax error") {
				t.Errorf("got %q, want PERMERROR DKIM2-Signature i=1 syntax error", got)
			}
		})
	}
}

func TestStrictD_TimestampValues(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	tmpl := withS(t, sigLine, "sel1:rsa-sha256:{SIG}")
	now := time.Now().Unix()
	cases := []struct {
		tv   string
		opts VerifyOptions
		want string // "" = pass
	}{
		{"0", VerifyOptions{}, "expired"},
		{"0", skipTS, ""},
		{fmt.Sprint(now), VerifyOptions{}, ""},
		{" " + fmt.Sprint(now) + " ", VerifyOptions{}, ""},
		{"1000000000000", VerifyOptions{}, "future"},
		{"1000000000000", skipTS, ""},
		{"99999999999999999999999", VerifyOptions{}, "future"},
		{"99999999999999999999999", skipTS, ""},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("t=%s/skip=%v", tc.tv, tc.opts.SkipTimestampCheck), func(t *testing.T) {
			msg := resign(t, strings.Replace(tmpl, "t=1740000000", "t="+tc.tv, 1), miLine, rest)
			got := verifyOutcome(msg, jsonFetcher(), tc.opts)
			if tc.want == "" {
				if got != "" {
					t.Fatalf("want pass, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// The signer writes lower-case tag names.
func TestStrictSignerLowercaseTags(t *testing.T) {
	sigLine, miLine, _ := strictSigned(t, 1740000000)
	for _, line := range []string{sigLine, miLine} {
		v := line[strings.IndexByte(line, ':')+1:]
		for _, spec := range strings.Split(v, ";") {
			spec = strings.TrimSpace(spec)
			if spec == "" {
				continue
			}
			name := spec[:strings.IndexByte(spec, '=')]
			if name != strings.ToLower(name) {
				t.Errorf("tag %q in %q is not lower-case", name, line)
			}
		}
	}
}

// ---------------------------------------------------------------- E

// errFetcher fails every lookup as a DNS failure would.
type errFetcher struct{}

func (errFetcher) FetchPublicKey(selector, domain string) (crypto.PublicKey, string, error) {
	return nil, "", fmt.Errorf("SERVFAIL for %s._domainkey.%s", selector, domain)
}

func TestStrictE_ItemOutcomes(t *testing.T) {
	sigLine, miLine, rest := strictSigned(t, 1740000000)
	good := [][]string{{"v=DKIM1; k=rsa; p=" + sel1P(t)}}
	cases := []struct {
		name string
		s    string
		f    KeyFetcher
		want string // "" = pass
	}{
		{"unusable key beside a good item", "sel1:rsa-sha256:{SIG},sel2:rsa-sha256:AAAA",
			txtFetcher{"sel1": good, "sel2": {{"v=DKIM1; k=rsa; p="}}},
			"PERMERROR DKIM2-Signature i=1 public key sel2 has been revoked"},
		{"multiple records beside a good item", "sel2:rsa-sha256:AAAA,sel1:rsa-sha256:{SIG}",
			txtFetcher{"sel1": good, "sel2": {good[0], good[0]}},
			"PERMERROR DKIM2-Signature i=1 public key sel2 has multiple records"},
		{"absent key beside a good item", "sel9:rsa-sha256:AAAA,sel1:rsa-sha256:{SIG}",
			txtFetcher{"sel1": good}, ""},
		{"all keys absent", "sel9:rsa-sha256:AAAA,sel8:ed25519-sha256:{SIG},sel7:future-alg:AAAA",
			txtFetcher{"sel1": good},
			"PERMERROR DKIM2-Signature i=1 public key sel9 does not exist"},
		{"all keys absent (dns.json)", "sel9:rsa-sha256:{SIG}", jsonFetcher(),
			"PERMERROR DKIM2-Signature i=1 public key sel9 does not exist"},
		{"DNS failure", "sel1:rsa-sha256:{SIG}", errFetcher{},
			"TEMPERROR DKIM2-Signature i=1 public key sel1 could not be fetched"},
		{"bad signature", "sel1:rsa-sha256:AAAA", txtFetcher{"sel1": good},
			"FAIL DKIM2-Signature i=1 public key sel1"},
		{"bad signature beside a good one", "sel1:rsa-sha256:{SIG},ed25519:ed25519-sha256:AAAA",
			jsonFetcher(), "FAIL DKIM2-Signature i=1 public key ed25519"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := resign(t, withS(t, sigLine, tc.s), miLine, rest)
			got := verifyOutcome(msg, tc.f, skipTS)
			if tc.want == "" {
				if got != "" {
					t.Fatalf("want pass, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStrictE_KeyP_MustBePadded(t *testing.T) {
	_, _, err := parseDKIM1TXT("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if !errors.Is(err, ErrKeySyntax) {
		t.Fatalf("unpadded p=: got %v, want a syntax error", err)
	}
	if _, _, err := parseDKIM1TXT("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="); err != nil {
		t.Fatalf("padded p=: %v", err)
	}
}
