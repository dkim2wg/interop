package dkim2

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
)

// Spec-06: a null "b" Recipe means the previous BODY cannot be recreated; the
// header Recipe is mandatory, so the header history below it still can be, and
// must still be checked. These tests build chains whose top instance carries a
// null body Recipe over a genuinely signed lower chain.

// nullHop appends a new top Message-Instance (highest+1) carrying recipe JSON
// to the signed message in, after mutate has rewritten the content headers,
// and signs it as the list hop.
func nullHop(t *testing.T, in []byte, mutate func([]Header) []Header, body, recipe string) []byte {
	t.Helper()
	const keys = "../../keys/"
	headers, _, err := parseHeaders(bytes.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	var content []Header
	var miRaws, sigRaws []string
	top := 0
	for _, h := range headers {
		switch strings.ToLower(h.Name) {
		case "message-instance":
			miRaws = append(miRaws, h.Raw)
			if mi, err := parseMI(h.Raw); err == nil && mi.Version > top {
				top = mi.Version
			}
		case "dkim2-signature":
			sigRaws = append(sigRaws, h.Raw)
		default:
			content = append(content, h)
		}
	}
	content = mutate(content)
	hh, err := hashHeaders(content, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	bh, err := hashBodyMulti(strings.NewReader(body), []string{"sha256"})
	if err != nil {
		t.Fatal(err)
	}
	mi := fmt.Sprintf("Message-Instance: m=%d; h=sha256:%s:%s; r=%s;\r\n", top+1,
		base64.StdEncoding.EncodeToString(hh), base64.StdEncoding.EncodeToString(bh["sha256"]),
		base64.StdEncoding.EncodeToString([]byte(recipe)))
	var b bytes.Buffer
	for _, s := range sigRaws {
		b.WriteString(s)
	}
	b.WriteString(mi)
	for _, m := range miRaws {
		b.WriteString(m)
	}
	for _, h := range content {
		b.WriteString(h.Raw)
	}
	b.WriteString("\r\n" + body)
	if top >= 2 {
		return signOnce(t, b.Bytes(), keys+"sel1._domainkey.test3.dkim2.com.pem",
			"sel1", "test3.dkim2.com", "dest@test3.dkim2.com", []string{"end@test4.dkim2.com"})
	}
	return signOnce(t, b.Bytes(), keys+"sel1._domainkey.test2.dkim2.com.pem",
		"sel1", "test2.dkim2.com", "user@test2.dkim2.com", []string{"dest@test3.dkim2.com"})
}

func nullHopBase(t *testing.T) []byte {
	raw := []byte("From: Sender <sender@test1.dkim2.com>\r\nTo: user@test2.dkim2.com\r\n" +
		"Subject: hello\r\n\r\nbody line\r\n")
	return signOnce(t, raw, "../../keys/sel1._domainkey.test1.dkim2.com.pem",
		"sel1", "test1.dkim2.com", "sender@test1.dkim2.com", []string{"user@test2.dkim2.com"})
}

func subjectTag(hs []Header) []Header {
	out := make([]Header, len(hs))
	copy(out, hs)
	for i, h := range out {
		if strings.EqualFold(h.Name, "subject") {
			out[i] = Header{Name: "Subject", Value: " [list] hello",
				Raw: "Subject: [list] hello\r\n"}
		}
	}
	return out
}

const subjRecipe = `{"h":{"subject":[{"d":["hello"]}]},"b":null}`

func fullVerify(t *testing.T, msg []byte) ([]VerifyResult, error) {
	t.Helper()
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	return VerifyFull(bytes.NewReader(msg), f, VerifyOptions{SkipTimestampCheck: true})
}

func expectPass(t *testing.T, msg []byte) {
	t.Helper()
	res, err := fullVerify(t, msg)
	if err != nil {
		t.Fatalf("VerifyFull error: %v", err)
	}
	for _, r := range res {
		if r.Error != nil {
			t.Errorf("%s i=%d failed: %v", r.Domain, r.Sequence, r.Error)
		}
	}
}

func expectFail(t *testing.T, msg []byte, want string) {
	t.Helper()
	res, err := fullVerify(t, msg)
	got := ""
	if err != nil {
		got = err.Error()
	}
	for _, r := range res {
		if r.Error != nil {
			got += " " + r.Error.Error()
		}
	}
	if got == "" {
		t.Fatal("verified, want failure")
	}
	if !strings.Contains(got, want) {
		t.Fatalf("failure %q does not contain %q", got, want)
	}
}

func TestNullBodyAtM2OverSignedM1Passes(t *testing.T) {
	expectPass(t, nullHop(t, nullHopBase(t), subjectTag, "new body\r\n", subjRecipe))
}

func TestNullBodyAtM3OverNormalM2Passes(t *testing.T) {
	m2 := nullHop(t, nullHopBase(t), subjectTag, "second body\r\n",
		`{"h":{"subject":[{"d":["hello"]}]},"b":[{"d":["body line"]}]}`)
	expectPass(t, nullHop(t, m2, func(h []Header) []Header { return h }, "third body\r\n",
		`{"h":{},"b":null}`))
}

func TestNullBodyForgedHistoryBelowNullFails(t *testing.T) {
	// To is changed but the header Recipe only mentions Subject.
	forge := func(hs []Header) []Header {
		hs = subjectTag(hs)
		for i, h := range hs {
			if strings.EqualFold(h.Name, "to") {
				hs[i] = Header{Name: "To", Value: " evil@example.com", Raw: "To: evil@example.com\r\n"}
			}
		}
		return hs
	}
	expectFail(t, nullHop(t, nullHopBase(t), forge, "new body\r\n", subjRecipe),
		"m=1: sha256 header hash mismatch")
}

func TestNullBodyHeaderRecipeNotApplyingFails(t *testing.T) {
	expectFail(t, nullHop(t, nullHopBase(t), subjectTag, "new body\r\n",
		`{"h":{"subject":[{"c":[1,9]}]},"b":null}`), "")
}

func TestUndoStillRefusesNullBody(t *testing.T) {
	m := nullHop(t, nullHopBase(t), subjectTag, "new body\r\n", subjRecipe)
	if err := Undo(bytes.NewReader(m), io.Discard, 1); err == nil {
		t.Fatal("standalone Undo rebuilt a body it cannot")
	}
}
