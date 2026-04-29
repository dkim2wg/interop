package dkim2

import (
	"encoding/base64"
	"io"
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
