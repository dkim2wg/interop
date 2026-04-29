package dkim2

import (
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
