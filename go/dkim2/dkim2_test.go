package dkim2

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTagValueList(t *testing.T) {
	tvl := parseTagValueList("m=1; h=sha256:abc:def; r=xyz;")
	if got := tvl.get("m"); got != "1" {
		t.Errorf("m= got %q want %q", got, "1")
	}
	if got := tvl.get("h"); got != "sha256:abc:def" {
		t.Errorf("h= got %q want %q", got, "sha256:abc:def")
	}
	if got := tvl.get("r"); got != "xyz" {
		t.Errorf("r= got %q want %q", got, "xyz")
	}
	if got := tvl.get("missing"); got != "" {
		t.Errorf("missing key got %q want empty", got)
	}
	want := "m=1; h=sha256:abc:def; r=xyz;"
	if got := tvl.String(); got != want {
		t.Errorf("String() got %q want %q", got, want)
	}
}

func TestTagValueListEmpty(t *testing.T) {
	tvl := parseTagValueList("")
	if got := tvl.get("m"); got != "" {
		t.Errorf("empty got %q", got)
	}
	if got := tvl.String(); got != "" {
		t.Errorf("empty String() got %q", got)
	}
}

func TestParseHeaders(t *testing.T) {
	raw := "From: sender@example.com\r\nSubject: Test\r\n\r\nBody here\r\n"
	headers, bodyR, err := parseHeaders(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 2 {
		t.Fatalf("want 2 headers, got %d", len(headers))
	}
	if headers[0].Name != "From" || headers[0].Value != "sender@example.com" {
		t.Errorf("From: got name=%q value=%q", headers[0].Name, headers[0].Value)
	}
	if headers[0].Raw != "From: sender@example.com\r\n" {
		t.Errorf("From Raw: got %q", headers[0].Raw)
	}
	body, _ := io.ReadAll(bodyR)
	if string(body) != "Body here\r\n" {
		t.Errorf("body got %q", body)
	}
}

func TestParseHeadersContinuation(t *testing.T) {
	raw := "Subject: long\r\n subject continued\r\n\r\n"
	headers, _, err := parseHeaders(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 1 {
		t.Fatalf("want 1 header, got %d", len(headers))
	}
	if headers[0].Value != "long subject continued" {
		t.Errorf("value got %q", headers[0].Value)
	}
	if headers[0].Raw != "Subject: long\r\n subject continued\r\n" {
		t.Errorf("Raw got %q", headers[0].Raw)
	}
}

func TestParseHeadersLFOnly(t *testing.T) {
	raw := "From: a@b.com\nTo: c@d.com\n\nbody\n"
	headers, bodyR, err := parseHeaders(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 2 {
		t.Fatalf("want 2 headers, got %d", len(headers))
	}
	body, _ := io.ReadAll(bodyR)
	if string(body) != "body\r\n" {
		t.Errorf("body got %q", body)
	}
}

func TestParseHeadersNoBlankLine(t *testing.T) {
	raw := "From: a@b.com\r\nSubject: Hi\r\n"
	headers, bodyR, err := parseHeaders(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 2 {
		t.Fatalf("want 2 headers, got %d", len(headers))
	}
	body, _ := io.ReadAll(bodyR)
	if len(body) != 0 {
		t.Errorf("expected empty body, got %q", body)
	}
}

func TestHashHeaders(t *testing.T) {
	// Known good: header hash from python/tests/expected/simple-ed25519.eml
	// h= tag value: sha256:SLtzk6LO68CCaX4edrJ6yfpWbp3hwgvI8IdMBRLDk+Y=:...
	wantB64 := "SLtzk6LO68CCaX4edrJ6yfpWbp3hwgvI8IdMBRLDk+Y="

	// These are the content headers from python/tests/emails/simple.eml
	headers := []Header{
		{Name: "From", Value: "sender@test1.dkim2.com", Raw: "From: sender@test1.dkim2.com\r\n"},
		{Name: "To", Value: "recipient@example.com", Raw: "To: recipient@example.com\r\n"},
		{Name: "Subject", Value: "Simple test message", Raw: "Subject: Simple test message\r\n"},
		{Name: "Date", Value: "Sat, 01 Mar 2026 12:00:00 +0000", Raw: "Date: Sat, 01 Mar 2026 12:00:00 +0000\r\n"},
		{Name: "Message-ID", Value: "<test-simple@test1.dkim2.com>", Raw: "Message-ID: <test-simple@test1.dkim2.com>\r\n"},
	}
	got, err := hashHeaders(headers)
	if err != nil {
		t.Fatal(err)
	}
	gotB64 := base64.StdEncoding.EncodeToString(got)
	if gotB64 != wantB64 {
		t.Errorf("header hash got %s want %s", gotB64, wantB64)
	}
}

func TestHashHeadersExclusion(t *testing.T) {
	headers := []Header{
		{Name: "From", Value: "a@b.com", Raw: "From: a@b.com\r\n"},
		{Name: "Received", Value: "from x", Raw: "Received: from x\r\n"},
		{Name: "DKIM2-Signature", Value: "i=1", Raw: "DKIM2-Signature: i=1\r\n"},
		{Name: "Message-Instance", Value: "m=1", Raw: "Message-Instance: m=1\r\n"},
		{Name: "X-Custom", Value: "val", Raw: "X-Custom: val\r\n"},
		{Name: "ARC-Seal", Value: "val", Raw: "ARC-Seal: val\r\n"},
	}
	withExcluded, _ := hashHeaders(headers)

	headersOnly := []Header{headers[0]}
	withoutExcluded, _ := hashHeaders(headersOnly)

	if string(withExcluded) != string(withoutExcluded) {
		t.Error("excluded headers changed the hash")
	}
}

func TestHashHeadersDuplicateBottomUp(t *testing.T) {
	// Two From headers: first "a@b.com", second (bottom) "z@y.com".
	// Bottom-up ordering means the last occurrence (z@y.com) must sort first.
	// Hash input should be: "from:z@y.com\r\nfrom:a@b.com\r\n"
	headers := []Header{
		{Name: "From", Value: "a@b.com", Raw: "From: a@b.com\r\n"},
		{Name: "From", Value: "z@y.com", Raw: "From: z@y.com\r\n"},
	}
	got, err := hashHeaders(headers)
	if err != nil {
		t.Fatal(err)
	}
	want := "1JQe5BbA7apJ7348ocoxEM3ESwr3YUyXIdeRRYsnlGA="
	if base64.StdEncoding.EncodeToString(got) != want {
		t.Errorf("got %s want %s", base64.StdEncoding.EncodeToString(got), want)
	}
}

func TestCanonicalizeSigHeader(t *testing.T) {
	raw := "DKIM2-Signature: i=1; m=1; s=sel:alg:;\r\n"
	got := string(canonicalizeSigHeader(raw))
	want := "dkim2-signature:i=1;m=1;s=sel:alg:;\r\n"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestCanonicalizeSigHeaderFolded(t *testing.T) {
	raw := "DKIM2-Signature: i=1;\r\n m=1;\r\n s=sel:alg:;\r\n"
	got := string(canonicalizeSigHeader(raw))
	want := "dkim2-signature:i=1;m=1;s=sel:alg:;\r\n"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestRecipeRoundTrip(t *testing.T) {
	b64data := "eyJiIjpbeyJjIjpbMSwxXX1dfQ=="
	rJSON, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseRecipe(rJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Body) != 1 {
		t.Fatalf("want 1 body step, got %d", len(r.Body))
	}
	if r.Body[0].Copy == nil || r.Body[0].Copy[0] != 1 || r.Body[0].Copy[1] != 1 {
		t.Errorf("body step got %+v", r.Body[0])
	}
	got, err := encodeRecipe(r)
	if err != nil {
		t.Fatal(err)
	}
	if base64.StdEncoding.EncodeToString(got) != b64data {
		t.Errorf("re-encoded: got %s want %s",
			base64.StdEncoding.EncodeToString(got), b64data)
	}
}

func TestMessageInstanceRoundTrip(t *testing.T) {
	raw := "Message-Instance: m=1; h=sha256:SLtzk6LO68CCaX4edrJ6yfpWbp3hwgvI8IdMBRLDk+Y=:SgG5fNGEg1x24MwItCUYGDHQkWKng06W1/IvTGBdwzU=;"
	mi, err := parseMI(raw)
	if err != nil {
		t.Fatal(err)
	}
	if mi.Version != 1 {
		t.Errorf("Version got %d want 1", mi.Version)
	}
	if base64.StdEncoding.EncodeToString(mi.HeaderHash) != "SLtzk6LO68CCaX4edrJ6yfpWbp3hwgvI8IdMBRLDk+Y=" {
		t.Errorf("HeaderHash mismatch")
	}
	if base64.StdEncoding.EncodeToString(mi.BodyHash) != "SgG5fNGEg1x24MwItCUYGDHQkWKng06W1/IvTGBdwzU=" {
		t.Errorf("BodyHash mismatch")
	}
	if mi.Recipe != nil {
		t.Error("Recipe should be nil")
	}
	if got := mi.String(); got != raw {
		t.Errorf("String() got:\n  %q\nwant:\n  %q", got, raw)
	}
}

func TestMessageInstanceWithRecipe(t *testing.T) {
	raw := "Message-Instance: m=2; h=sha256:SLtzk6LO68CCaX4edrJ6yfpWbp3hwgvI8IdMBRLDk+Y=:DGv24YWxV2Z3AJ/C+rbwX078dNL59U5evazyN5MyTSE=; r=eyJiIjpbeyJjIjpbMSwxXX1dfQ==;"
	mi, err := parseMI(raw)
	if err != nil {
		t.Fatal(err)
	}
	if mi.Version != 2 {
		t.Errorf("Version got %d want 2", mi.Version)
	}
	if mi.Recipe == nil {
		t.Fatal("Recipe should not be nil")
	}
	if got := mi.String(); got != raw {
		t.Errorf("String() got:\n  %q\nwant:\n  %q", got, raw)
	}
}

func TestMessageInstanceBareTags(t *testing.T) {
	// parseMI must work without the "Message-Instance: " prefix
	bare := "m=1; h=sha256:SLtzk6LO68CCaX4edrJ6yfpWbp3hwgvI8IdMBRLDk+Y=:SgG5fNGEg1x24MwItCUYGDHQkWKng06W1/IvTGBdwzU=;"
	mi, err := parseMI(bare)
	if err != nil {
		t.Fatal(err)
	}
	if mi.Version != 1 {
		t.Errorf("Version got %d want 1", mi.Version)
	}
	if base64.StdEncoding.EncodeToString(mi.HeaderHash) != "SLtzk6LO68CCaX4edrJ6yfpWbp3hwgvI8IdMBRLDk+Y=" {
		t.Errorf("HeaderHash mismatch")
	}
}

func TestDiffLinesDuplicates(t *testing.T) {
	// "foo" appears twice in before but only once in after:
	// first should be a copy, second should be a data step
	before := []string{"foo", "foo"}
	after := []string{"foo", "bar"}
	steps := diffLines(before, after)
	if len(steps) != 2 {
		t.Fatalf("want 2 steps, got %d", len(steps))
	}
	// First: copy step (foo exists at index 1 in after)
	if steps[0].Copy == nil || steps[0].Copy[0] != 1 {
		t.Errorf("step 0: want Copy[1,1], got %+v", steps[0])
	}
	// Second: data step (index 1 was consumed, no more foo in after)
	if steps[1].Data == nil || len(steps[1].Data) == 0 || steps[1].Data[0] != "foo" {
		t.Errorf("step 1: want Data[foo], got %+v", steps[1])
	}
}

func TestComputeDiff(t *testing.T) {
	beforeHeaders := []Header{
		{Name: "From", Value: "a@b.com", Raw: "From: a@b.com\r\n"},
		{Name: "Subject", Value: "Old subject", Raw: "Subject: Old subject\r\n"},
	}
	afterHeaders := []Header{
		{Name: "From", Value: "a@b.com", Raw: "From: a@b.com\r\n"},
		{Name: "Subject", Value: "New subject", Raw: "Subject: New subject\r\n"},
	}
	beforeBody := []byte("Line 1\r\nLine 2\r\n")
	afterBody := []byte("Line 1\r\nLine 3\r\n")

	r, err := ComputeDiff(beforeHeaders, beforeBody, afterHeaders, afterBody)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("expected non-nil recipe")
	}
	// Body diff: Line 1 is copied, Line 2 is new data
	if len(r.Body) != 2 {
		t.Fatalf("body steps: want 2, got %d", len(r.Body))
	}
	if r.Body[0].Copy == nil {
		t.Errorf("body step 0: want Copy, got %+v", r.Body[0])
	}
	if r.Body[1].Data == nil || r.Body[1].Data[0] != "Line 2" {
		t.Errorf("body step 1: want Data[Line 2], got %+v", r.Body[1])
	}
	// Header diff: subject changed
	if r.Headers == nil {
		t.Fatal("expected header recipes")
	}
	if _, ok := r.Headers["subject"]; !ok {
		t.Error("expected recipe for subject header")
	}

	// No-change case returns nil
	r2, err := ComputeDiff(beforeHeaders, beforeBody, beforeHeaders, beforeBody)
	if err != nil {
		t.Fatal(err)
	}
	if r2 != nil {
		t.Error("unchanged message should return nil recipe")
	}
}

func TestJSONKeyFetcher(t *testing.T) {
	f := &JSONKeyFetcher{Path: "../../dns.json"}

	// Ed25519 key
	key, alg, err := f.FetchPublicKey("ed25519", "test1.dkim2.com")
	if err != nil {
		t.Fatal(err)
	}
	if alg != "ed25519-sha256" {
		t.Errorf("alg got %q want ed25519-sha256", alg)
	}
	if key == nil {
		t.Error("key is nil")
	}

	// RSA key
	key, alg, err = f.FetchPublicKey("sel1", "test1.dkim2.com")
	if err != nil {
		t.Fatal(err)
	}
	if alg != "rsa-sha256" {
		t.Errorf("alg got %q want rsa-sha256", alg)
	}
	if key == nil {
		t.Error("key is nil")
	}

	// Missing key
	_, _, err = f.FetchPublicKey("notexist", "test1.dkim2.com")
	if err == nil {
		t.Error("expected error for missing key")
	}
}

func TestHashBody(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string // base64 SHA-256
	}{
		{
			name: "simple",
			body: "Hello, this is a simple test message.\r\n",
			want: "SgG5fNGEg1x24MwItCUYGDHQkWKng06W1/IvTGBdwzU=",
		},
		{
			name: "empty",
			body: "",
			want: "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=",
		},
		{
			name: "trailing_blanks_stripped",
			// Three trailing blank lines — canonical is same as "Hello.\r\n"
			body: "Hello.\r\n\r\n\r\n\r\n",
			want: "yZQq1c8wjBl0fZ4Wc/oraMCAG1mZJv5v/hlvyFy+t6A=",
		},
		{
			name: "lf_only_normalised",
			body: "Hello.\n",
			want: "yZQq1c8wjBl0fZ4Wc/oraMCAG1mZJv5v/hlvyFy+t6A=",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := hashBody(strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			gotB64 := base64.StdEncoding.EncodeToString(got)
			if tc.want != "" && gotB64 != tc.want {
				t.Errorf("got %s want %s", gotB64, tc.want)
			}
		})
	}
}

func TestDKIM2SignatureRoundTrip(t *testing.T) {
	raw := "DKIM2-Signature: i=1; m=1; t=1740000000; d=test1.dkim2.com; mf=PHNlbmRlckB0ZXN0MS5ka2ltMi5jb20+; rt=PHJlY2lwaWVudEBleGFtcGxlLmNvbT4=; s=ed25519:ed25519-sha256:F//Dt+leS4H/m5LHwv0hWWCjq1UeVBgE0wrKI0GLcuN/iKhdiytBgPMqS+tIlbSNJmYnB9LldrQ9jPnTHRK2CA==;"
	sig, err := parseSig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Sequence != 1 { t.Errorf("i= got %d", sig.Sequence) }
	if sig.MIVersion != 1 { t.Errorf("m= got %d", sig.MIVersion) }
	if sig.Timestamp != 1740000000 { t.Errorf("t= got %d", sig.Timestamp) }
	if sig.Domain != "test1.dkim2.com" { t.Errorf("d= got %q", sig.Domain) }
	if sig.MailFrom != "<sender@test1.dkim2.com>" { t.Errorf("mf= got %q", sig.MailFrom) }
	if len(sig.RcptTo) != 1 || sig.RcptTo[0] != "<recipient@example.com>" {
		t.Errorf("rt= got %v", sig.RcptTo)
	}
	if len(sig.Sigs) != 1 || sig.Sigs[0].Selector != "ed25519" {
		t.Errorf("s= got %v", sig.Sigs)
	}
	if got := sig.String(); got != raw {
		t.Errorf("String() got:\n  %q\nwant:\n  %q", got, raw)
	}
}

func TestDKIM2SignatureIncompleteForm(t *testing.T) {
	raw := "DKIM2-Signature: i=1; m=1; t=1740000000; d=test1.dkim2.com; mf=PHNlbmRlckB0ZXN0MS5ka2ltMi5jb20+; rt=PHJlY2lwaWVudEBleGFtcGxlLmNvbT4=; s=ed25519:ed25519-sha256:F//Dt+leS4H/m5LHwv0hWWCjq1UeVBgE0wrKI0GLcuN/iKhdiytBgPMqS+tIlbSNJmYnB9LldrQ9jPnTHRK2CA==;"
	sig, _ := parseSig(raw)
	incomplete := sig.incompleteForm(raw)
	want := "DKIM2-Signature: i=1; m=1; t=1740000000; d=test1.dkim2.com; mf=PHNlbmRlckB0ZXN0MS5ka2ltMi5jb20+; rt=PHJlY2lwaWVudEBleGFtcGxlLmNvbT4=; s=ed25519:ed25519-sha256:;"
	if incomplete != want {
		t.Errorf("incompleteForm got:\n  %q\nwant:\n  %q", incomplete, want)
	}
}

func TestSignSimpleEd25519(t *testing.T) {
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

	var out bytes.Buffer
	err = Sign(bytes.NewReader(raw), &out, key, SignOptions{
		Selector:  "ed25519",
		Domain:    "test1.dkim2.com",
		MailFrom:  "sender@test1.dkim2.com",
		RcptTo:    []string{"recipient@example.com"},
		Timestamp: 1740000000,
	})
	if err != nil {
		t.Fatal(err)
	}

	expected, err := os.ReadFile("../../python/tests/expected/simple-ed25519.eml")
	if err != nil {
		t.Fatal(err)
	}
	// The expected file was generated via shell command substitution
	// (`result=$(...)`) which strips trailing newlines, so trim trailing
	// CR/LF from both sides to match the canonical bash equality semantics
	// used by the Python test runner.
	got := bytes.TrimRight(out.Bytes(), "\r\n")
	want := bytes.TrimRight(expected, "\r\n")
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from expected\ngot (first 500):\n%s\nwant (first 500):\n%s",
			truncate(string(got), 500), truncate(string(want), 500))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func verifyEML(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	// Skip timestamp check: test emails have fixed timestamps from 2026-02-20
	results, err := Verify(bytes.NewReader(raw), f, VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	for _, r := range results {
		if r.Error != nil {
			t.Errorf("i=%d: %v", r.Sequence, r.Error)
		}
	}
}

func TestVerifyAllPython(t *testing.T) {
	matches, err := filepath.Glob("../../python/tests/expected/*.eml")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Skip("no python expected files found")
	}
	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			verifyEML(t, path)
		})
	}
}

func TestVerifyAllBrong(t *testing.T) {
	matches, err := filepath.Glob("../../brong/tests/expected/*.eml")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Skip("no brong expected files found")
	}
	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			verifyEML(t, path)
		})
	}
}

func TestVerifySimpleEd25519(t *testing.T) {
	raw, err := os.ReadFile("../../python/tests/expected/simple-ed25519.eml")
	if err != nil {
		t.Fatal(err)
	}
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	results, err := Verify(bytes.NewReader(raw), f, VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Error != nil {
		t.Errorf("verify failed: %v", results[0].Error)
	}
}

func TestSignAllCases(t *testing.T) {
	cases := []struct {
		name     string
		email    string
		selector string
		domain   string
		keyFile  string
		mailFrom string
		rcptTo   []string
	}{
		{"simple-ed25519", "simple.eml", "ed25519", "test1.dkim2.com",
			"ed25519._domainkey.test1.dkim2.com.pem",
			"sender@test1.dkim2.com", []string{"recipient@example.com"}},
		{"simple-rsa1024", "simple.eml", "rsa1024", "test1.dkim2.com",
			"rsa1024._domainkey.test1.dkim2.com.pem",
			"sender@test1.dkim2.com", []string{"recipient@example.com"}},
		{"simple-rsa2048", "simple.eml", "sel1", "test1.dkim2.com",
			"sel1._domainkey.test1.dkim2.com.pem",
			"sender@test1.dkim2.com", []string{"recipient@example.com"}},
		{"multiheader-ed25519", "multiheader.eml", "ed25519", "test2.dkim2.com",
			"ed25519._domainkey.test2.dkim2.com.pem",
			"sender@test2.dkim2.com", []string{"recipient@example.com"}},
		{"trailingblank-ed25519", "trailingblank.eml", "ed25519", "test3.dkim2.com",
			"ed25519._domainkey.test3.dkim2.com.pem",
			"sender@test3.dkim2.com", []string{"recipient@example.com"}},
		{"emptybody-ed25519", "emptybody.eml", "ed25519", "test4.dkim2.com",
			"ed25519._domainkey.test4.dkim2.com.pem",
			"sender@test4.dkim2.com", []string{"recipient@example.com"}},
		{"multirecipient-ed25519", "multirecipient.eml", "ed25519", "test5.dkim2.com",
			"ed25519._domainkey.test5.dkim2.com.pem",
			"sender@test5.dkim2.com",
			[]string{"alice@example.com", "bob@example.com", "charlie@example.com"}},
		{"dsn-ed25519", "simple.eml", "ed25519", "test1.dkim2.com",
			"ed25519._domainkey.test1.dkim2.com.pem",
			"<>", []string{"recipient@example.com"}},
		{"simple-sel2", "simple.eml", "sel2", "test1.dkim2.com",
			"sel2._domainkey.test1.dkim2.com.pem",
			"sender@test1.dkim2.com", []string{"recipient@example.com"}},
		{"simple-sel3", "simple.eml", "sel3", "test1.dkim2.com",
			"sel3._domainkey.test1.dkim2.com.pem",
			"sender@test1.dkim2.com", []string{"recipient@example.com"}},
		{"dupheaders-ed25519", "dupheaders.eml", "ed25519", "test1.dkim2.com",
			"ed25519._domainkey.test1.dkim2.com.pem",
			"sender@test1.dkim2.com", []string{"recipient@example.com"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile("../../python/tests/emails/" + tc.email)
			if err != nil {
				t.Fatal(err)
			}
			keyPEM, err := os.ReadFile("../../keys/" + tc.keyFile)
			if err != nil {
				t.Skip("keyfile not found: " + tc.keyFile)
			}
			key, err := LoadPrivateKey(keyPEM)
			if err != nil {
				t.Fatal(err)
			}

			var out bytes.Buffer
			err = Sign(bytes.NewReader(raw), &out, key, SignOptions{
				Selector:  tc.selector,
				Domain:    tc.domain,
				MailFrom:  tc.mailFrom,
				RcptTo:    tc.rcptTo,
				Timestamp: 1740000000,
			})
			if err != nil {
				t.Fatal(err)
			}

			expectedPath := "../../python/tests/expected/" + tc.name + ".eml"
			expected, err := os.ReadFile(expectedPath)
			if err != nil {
				t.Fatal(err)
			}
			// Expected files were generated via bash $(...) which strips trailing newlines
			got := bytes.TrimRight(out.Bytes(), "\r\n")
			want := bytes.TrimRight(expected, "\r\n")
			if !bytes.Equal(got, want) {
				t.Errorf("output differs from %s\ngot (first 300):\n%s\nwant (first 300):\n%s",
					tc.name+".eml", truncate(string(got), 300), truncate(string(want), 300))
			}
		})
	}
}

// TestUndoNoRecipe: double-sign a message (no content change = no recipe),
// then Undo back to v=1 and compare with the original single-signed output.
func TestUndoNoRecipe(t *testing.T) {
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
	opts := SignOptions{
		Selector:  "ed25519",
		Domain:    "test1.dkim2.com",
		MailFrom:  "sender@test1.dkim2.com",
		RcptTo:    []string{"recipient@example.com"},
		Timestamp: 1740000000,
	}

	// Sign once.
	var signed1 bytes.Buffer
	if err := Sign(bytes.NewReader(raw), &signed1, key, opts); err != nil {
		t.Fatal(err)
	}

	// Sign again without content change — MI v=2 will have no recipe.
	opts.Timestamp = 1740000001
	var signed2 bytes.Buffer
	if err := Sign(bytes.NewReader(signed1.Bytes()), &signed2, key, opts); err != nil {
		t.Fatal(err)
	}

	// Undo back to v=1.
	var undone bytes.Buffer
	if err := Undo(bytes.NewReader(signed2.Bytes()), &undone, -1); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(undone.Bytes(), signed1.Bytes()) {
		t.Errorf("undo result does not match single-signed message\ngot:\n%s\nwant:\n%s",
			truncate(string(undone.Bytes()), 500), truncate(string(signed1.Bytes()), 500))
	}
}

// TestUndoHeaderRecipesRoundTrip verifies that undoHeaderRecipes correctly
// reconstructs the "before" state using a recipe computed by ComputeDiff.
func TestUndoHeaderRecipesRoundTrip(t *testing.T) {
	before := []Header{
		{Name: "Subject", Value: "Hello World", Raw: "Subject: Hello World\r\n"},
		{Name: "From", Value: "alice@example.com", Raw: "From: alice@example.com\r\n"},
	}
	after := []Header{
		{Name: "Subject", Value: "Goodbye World", Raw: "Subject: Goodbye World\r\n"},
		{Name: "From", Value: "alice@example.com", Raw: "From: alice@example.com\r\n"},
	}
	body := []byte("Test body.\r\n")

	recipe, err := ComputeDiff(before, body, after, body)
	if err != nil {
		t.Fatal(err)
	}
	if recipe == nil || recipe.Headers == nil {
		t.Fatal("expected recipe with header changes, got nil")
	}

	result := undoHeaderRecipes(after, recipe.Headers)

	if len(result) != len(before) {
		t.Fatalf("got %d headers, want %d", len(result), len(before))
	}
	for i, h := range result {
		if h.Raw != before[i].Raw {
			t.Errorf("header[%d]: got %q, want %q", i, h.Raw, before[i].Raw)
		}
	}
}

func TestApplyHeaderRecipe(t *testing.T) {
	// Before: Subject: Hello. After: Subject: World.
	// Recipe has one Data step with the "before" value.
	steps := []RecipeStep{{Data: []string{"Hello"}}}
	current := []Header{
		{Name: "Subject", Value: "World", Raw: "Subject: World\r\n"},
	}
	got := applyHeaderRecipe(current, "Subject", steps)
	if len(got) != 1 || got[0].Value != "Hello" {
		t.Errorf("expected Subject: Hello, got %v", got)
	}
	if got[0].Raw != "Subject: Hello\r\n" {
		t.Errorf("unexpected Raw: %q", got[0].Raw)
	}
}

func TestApplyHeaderRecipeCopy(t *testing.T) {
	// Before had [Subject: A, Subject: B]; after has only [Subject: B] (A removed).
	// headerRecipeSteps produces steps in before-bottom-up order:
	//   beforeBottomUp = [B, A]; B is found at afterIdx 1, A is not found.
	//   → [Copy{1,1}, Data["A"]]
	// Applying to current=[B]:
	//   bottomUp=[B]; Copy{1,1}→B, Data["A"]→A; emitted=[B,A]; reversed=[A,B].
	c1 := [2]int{1, 1}
	steps := []RecipeStep{{Copy: &c1}, {Data: []string{"A"}}}
	current := []Header{
		{Name: "Subject", Value: "B", Raw: "Subject: B\r\n"},
	}
	got := applyHeaderRecipe(current, "Subject", steps)
	if len(got) != 2 || got[0].Value != "A" || got[1].Value != "B" {
		t.Errorf("expected [A, B], got %v", got)
	}
}

func TestVerifyGap3DomainSuffix(t *testing.T) {
	// Build a signed message and tamper the d= domain to a non-suffix value.
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
		Selector:  "ed25519",
		Domain:    "test1.dkim2.com",
		MailFrom:  "sender@test1.dkim2.com",
		RcptTo:    []string{"recipient@example.com"},
		Timestamp: 1740000000,
	}); err != nil {
		t.Fatal(err)
	}
	// Replace d=test1.dkim2.com with d=evil.com in the signed output
	tampered := strings.ReplaceAll(signed.String(), "d=test1.dkim2.com", "d=evil.com")
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	results, err := Verify(strings.NewReader(tampered), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Error == nil {
		t.Error("expected domain suffix mismatch error")
	}
}

func TestVerifyGap3SubdomainOK(t *testing.T) {
	// d=sub.test1.dkim2.com is a valid suffix of mf= sender@test1.dkim2.com — NOT
	// wait, the check is that d= is a suffix of mf='s domain. So if mf=sender@sub.test1.dkim2.com
	// and d=test1.dkim2.com, that should PASS (d is a suffix of the mf domain).
	// Build directly using Sign with subdomain mf.
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
	// mf= sender@sub.test1.dkim2.com, d= test1.dkim2.com → should verify OK
	if err := Sign(bytes.NewReader(raw), &signed, key, SignOptions{
		Selector:  "ed25519",
		Domain:    "test1.dkim2.com",
		MailFrom:  "sender@sub.test1.dkim2.com",
		RcptTo:    []string{"recipient@example.com"},
		Timestamp: 1740000000,
	}); err != nil {
		t.Fatal(err)
	}
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	results, err := Verify(bytes.NewReader(signed.Bytes()), f, VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Error != nil {
		t.Errorf("expected pass for subdomain mf=, got: %v", results[0].Error)
	}
}

func buildSignedMsg(t *testing.T) []byte {
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
	var out bytes.Buffer
	if err := Sign(bytes.NewReader(raw), &out, key, SignOptions{
		Selector:  "ed25519",
		Domain:    "test1.dkim2.com",
		MailFrom:  "sender@test1.dkim2.com",
		RcptTo:    []string{"recipient@example.com"},
		Timestamp: 1740000000,
	}); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// verifyExpectFail checks that Verify rejects the message (either top-level error
// or at least one failing result). Timestamp check is skipped so tests are
// isolated to the specific failure mode being tested.
func verifyExpectFail(t *testing.T, msg string, desc string) {
	t.Helper()
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	results, err := Verify(strings.NewReader(msg), f, VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		return // top-level error — expected
	}
	for _, r := range results {
		if r.Error != nil {
			return // at least one failing result — expected
		}
	}
	t.Errorf("expected failure for %s, but all results passed", desc)
}

func TestVerifyGap5NonContiguousSig(t *testing.T) {
	msg := buildSignedMsg(t)
	// Replace i=1 with i=2 in the DKIM2-Signature header to create a gap (no i=1)
	tampered := strings.ReplaceAll(string(msg), "i=1;", "i=99;")
	verifyExpectFail(t, tampered, "non-contiguous i= sequence")
}

func TestVerifyGap5NonContiguousMI(t *testing.T) {
	msg := buildSignedMsg(t)
	// Replace m=1 in the Message-Instance header to m=99 (no m=1 MI exists)
	lines := strings.Split(string(msg), "\r\n")
	tampered := make([]string, len(lines))
	for i, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "message-instance:") {
			line = strings.ReplaceAll(line, "m=1;", "m=99;")
		}
		tampered[i] = line
	}
	verifyExpectFail(t, strings.Join(tampered, "\r\n"), "non-contiguous m= sequence")
}

func TestVerifyGap6OrphanMI(t *testing.T) {
	// Build a double-signed message then strip the outer sig,
	// leaving m=2 orphaned (referenced by no sig).
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
	opts := SignOptions{
		Selector: "ed25519", Domain: "test1.dkim2.com",
		MailFrom: "sender@test1.dkim2.com", RcptTo: []string{"recipient@example.com"},
		Timestamp: 1740000000,
	}
	var signed1 bytes.Buffer
	if err := Sign(bytes.NewReader(raw), &signed1, key, opts); err != nil {
		t.Fatal(err)
	}
	opts.Timestamp = 1740000001
	var signed2 bytes.Buffer
	if err := Sign(bytes.NewReader(signed1.Bytes()), &signed2, key, opts); err != nil {
		t.Fatal(err)
	}
	// Strip the outer DKIM2-Signature (i=2) — leave m=2 but no sig referencing it
	lines := strings.Split(signed2.String(), "\r\n")
	var kept []string
	skipNext := false
	for _, line := range lines {
		if skipNext {
			if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
				continue // continuation line
			}
			skipNext = false
		}
		if strings.HasPrefix(strings.ToLower(line), "dkim2-signature:") && strings.Contains(line, "i=2;") {
			skipNext = true
			continue
		}
		kept = append(kept, line)
	}
	verifyExpectFail(t, strings.Join(kept, "\r\n"), "orphan MI (m=2 with no referencing sig)")
}

// TestVerifyMultipleSigsAllChecked verifies that when a DKIM2-Signature contains
// multiple s= items, ALL of them are checked — a bad second item causes failure
// even when the first item passes.
func TestVerifyMultipleSigsAllChecked(t *testing.T) {
	msg := buildSignedMsg(t)
	// Inject a second (invalid) sig item into the s= tag.
	// The first item is valid; the second has a garbage signature value.
	// If we only check item[0], we'd incorrectly PASS.
	tampered := strings.Replace(string(msg),
		";", // first semicolon (end of i=1)
		";",  // no change to i= tag
		1)
	// Replace s=sel:alg:VALUE; with s=sel:alg:VALUE,sel:alg:BADVALUE;
	tampered = strings.Replace(string(msg),
		"s=ed25519:ed25519-sha256:",
		"s=ed25519:ed25519-sha256:",
		1)
	// Actually, let's splice in the bad item after the real sig value
	// Find the s= tag and add a comma + bad item before the trailing semicolon
	idx := strings.Index(string(msg), "; s=ed25519:ed25519-sha256:")
	if idx < 0 {
		t.Skip("could not find s= tag in signed message")
	}
	// Find end of s= value (the semicolon after the base64)
	sTagStart := idx + len("; s=")
	rest := string(msg)[sTagStart:]
	semiIdx := strings.Index(rest, ";")
	if semiIdx < 0 {
		t.Skip("no trailing semicolon found")
	}
	// Build tampered: original up through end of s= value, then add bad item
	prefix := string(msg)[:sTagStart+semiIdx]
	suffix := string(msg)[sTagStart+semiIdx:]
	tampered = prefix + ",sel2:ed25519-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" + suffix

	verifyExpectFail(t, tampered, "bad second s= item should cause failure")
}

// TestVerifyMultipleSigsNoVerifiable verifies that when no sig items can be key-fetched,
// the result is a failure (not a silent pass).
func TestVerifyMultipleSigsNoVerifiable(t *testing.T) {
	msg := buildSignedMsg(t)
	// Replace the selector with one that doesn't exist in dns.json
	tampered := strings.ReplaceAll(string(msg), "s=ed25519:ed25519-sha256:", "s=nonexistent:ed25519-sha256:")
	verifyExpectFail(t, tampered, "no verifiable sig items (unknown selector)")
}

func buildDoubleSignedMsg(t *testing.T) ([]byte, []byte) {
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
	opts1 := SignOptions{
		Selector: "ed25519", Domain: "test1.dkim2.com",
		MailFrom: "sender@test1.dkim2.com", RcptTo: []string{"relay@test2.dkim2.com"},
		Timestamp: 1740000000,
	}
	var signed1 bytes.Buffer
	if err := Sign(bytes.NewReader(raw), &signed1, key, opts1); err != nil {
		t.Fatal(err)
	}

	key2PEM, err := os.ReadFile("../../keys/ed25519._domainkey.test2.dkim2.com.pem")
	if err != nil {
		t.Skip("key2 not found")
	}
	key2, err := LoadPrivateKey(key2PEM)
	if err != nil {
		t.Fatal(err)
	}
	opts2 := SignOptions{
		Selector: "ed25519", Domain: "test2.dkim2.com",
		MailFrom: "relay@test2.dkim2.com", RcptTo: []string{"recipient@example.com"},
		Timestamp: 1740000001,
	}
	var signed2 bytes.Buffer
	if err := Sign(bytes.NewReader(signed1.Bytes()), &signed2, key2, opts2); err != nil {
		t.Fatal(err)
	}
	return signed1.Bytes(), signed2.Bytes()
}

func TestVerifyChainCustodyPass(t *testing.T) {
	_, doubleMsg := buildDoubleSignedMsg(t)
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	results, err := Verify(bytes.NewReader(doubleMsg), f, VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	for _, r := range results {
		if r.Error != nil {
			t.Errorf("i=%d: %v", r.Sequence, r.Error)
		}
	}
}

func TestVerifyChainCustodyBreak(t *testing.T) {
	_, doubleMsg := buildDoubleSignedMsg(t)
	// Tamper i=2's mf= to be a domain that doesn't match any rt= of i=1.
	// i=1 has rt=relay@test2.dkim2.com; replace mf of i=2 (relay@test2.dkim2.com)
	// with mf=attacker@evil.com (base64 of the bracketed RFC5321 path).
	original := base64.StdEncoding.EncodeToString([]byte("<relay@test2.dkim2.com>"))
	replacement := base64.StdEncoding.EncodeToString([]byte("<attacker@evil.com>"))
	// Only replace the FIRST occurrence of this base64 (which is in i=2's mf= tag,
	// since i=2 is at the top of the message)
	tampered := strings.Replace(string(doubleMsg), "mf="+original+";", "mf="+replacement+";", 1)
	if tampered == string(doubleMsg) {
		t.Skip("could not find mf= to tamper (base64 may differ)")
	}
	verifyExpectFail(t, tampered, "chain-of-custody break")
}

func TestVerifyEnvelopeMatchPass(t *testing.T) {
	msg := buildSignedMsg(t)
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	results, err := Verify(bytes.NewReader(msg), f, VerifyOptions{
		SkipTimestampCheck: true,
		MailFrom:           "sender@test1.dkim2.com",
		RcptTo:             []string{"recipient@example.com"},
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	for _, r := range results {
		if r.Error != nil {
			t.Errorf("i=%d: %v", r.Sequence, r.Error)
		}
	}
}

func TestVerifyEnvelopeMailFromMismatch(t *testing.T) {
	msg := buildSignedMsg(t)
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	_, err := Verify(bytes.NewReader(msg), f, VerifyOptions{
		SkipTimestampCheck: true,
		MailFrom:           "wrong@test1.dkim2.com",
	})
	if err == nil {
		t.Error("expected error for mismatched MAIL FROM")
	}
}

func TestVerifyEnvelopeRcptToMismatch(t *testing.T) {
	msg := buildSignedMsg(t)
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	_, err := Verify(bytes.NewReader(msg), f, VerifyOptions{
		SkipTimestampCheck: true,
		RcptTo:             []string{"someone@else.com"},
	})
	if err == nil {
		t.Error("expected error for RCPT TO not in rt=")
	}
}

func TestVerifyTimestampExpired(t *testing.T) {
	// A message signed with timestamp 1740000000 (2026-02-20) is >14 days old.
	raw, err := os.ReadFile("../../python/tests/expected/simple-ed25519.eml")
	if err != nil {
		t.Fatal(err)
	}
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	// Without SkipTimestampCheck the old test email should be rejected.
	results, err := Verify(bytes.NewReader(raw), f)
	if err != nil {
		t.Fatal(err) // top-level error is not expected
	}
	if len(results) == 0 || results[0].Error == nil {
		t.Error("expected expiry error for old test email")
	}
}

func TestVerifyNonceTooLong(t *testing.T) {
	msg := string(buildSignedMsg(t))
	// Inject an n= tag with 65 characters before the s= tag.
	nonce65 := strings.Repeat("a", 65)
	tampered := strings.Replace(msg, "; s=", "; n="+nonce65+"; s=", 1)
	verifyExpectFail(t, tampered, "n= nonce exceeding 64 characters")
}

func TestUndoBodyRecipe(t *testing.T) {
	body := []byte("line1\r\nline2\r\nline3\r\n")
	c1 := [2]int{1, 1}
	c3 := [2]int{3, 3}
	steps := []RecipeStep{
		{Copy: &c1},
		{Data: []string{"inserted"}},
		{Copy: &c3},
	}
	got := undoBodyRecipe(body, steps)
	want := []byte("line1\r\ninserted\r\nline3\r\n")
	if !bytes.Equal(got, want) {
		t.Errorf("got %q want %q", got, want)
	}
}
