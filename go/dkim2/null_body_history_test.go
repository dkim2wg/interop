package dkim2

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
)

// A null "b" Recipe means the previous BODY cannot be recreated.  Signed, it
// is a PERMERROR (contract E2); in a signer's own view of an unsigned null
// the header history below it can still be checked, and is.  These tests
// build chains whose top instance carries a null body Recipe over a
// genuinely signed lower chain.

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

// -09 (contract E2): a null body Recipe is a PERMERROR naming its instance,
// ahead of anything the walk would find below it.
func TestNullBodyAtM2OverSignedM1IsPermerror(t *testing.T) {
	expectFail(t, nullHop(t, nullHopBase(t), subjectTag, "new body\r\n", subjRecipe),
		"PERMERROR: Message-Instance m=2 has a null recipe")
}

func TestNullBodyAtM3OverNormalM2IsPermerror(t *testing.T) {
	m2 := nullHop(t, nullHopBase(t), subjectTag, "second body\r\n",
		`{"h":{"subject":[{"d":["hello"]}]},"b":[{"d":["body line"]}]}`)
	expectFail(t, nullHop(t, m2, func(h []Header) []Header { return h }, "third body\r\n",
		`{"b":null}`), "PERMERROR: Message-Instance m=3 has a null recipe")
}

// outboundErr verifies msg as its next signer does (Outbound): an unsigned
// null top is the signer's own, so the walk below it still runs.
func outboundErr(t *testing.T, msg []byte) string {
	t.Helper()
	res, err := VerifyFull(bytes.NewReader(msg), &JSONKeyFetcher{Path: "../../dns.json"},
		VerifyOptions{SkipTimestampCheck: true, Outbound: true})
	if err != nil {
		return err.Error()
	}
	if p := PrimaryResult(res); p != nil {
		return p.Error.Error()
	}
	return ""
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
	m := nullHop(t, nullHopBase(t), forge, "new body\r\n", subjRecipe)
	// Signed, the null is the result; unsigned (the signer's view), the
	// forged history below it is.
	expectFail(t, m, "PERMERROR: Message-Instance m=2 has a null recipe")
	if got := outboundErr(t, dropTopSig(t, m)); !strings.Contains(got, "FAIL: Message-Instance m=1 header hash sha256 mismatch") {
		t.Fatalf("outbound: got %q", got)
	}
}

func TestNullBodyHeaderRecipeNotApplyingFails(t *testing.T) {
	m := nullHop(t, nullHopBase(t), subjectTag, "new body\r\n", `{"h":{"subject":[{"c":[1,9]}]},"b":null}`)
	expectFail(t, m, "PERMERROR: Message-Instance m=2 has a null recipe")
	if got := outboundErr(t, dropTopSig(t, m)); !strings.Contains(got, "contains invalid JSON") {
		t.Fatalf("outbound: got %q", got)
	}
}

func TestNullBodyUnsignedTopOutboundPasses(t *testing.T) {
	m := dropTopSig(t, nullHop(t, nullHopBase(t), subjectTag, "new body\r\n", subjRecipe))
	if got := outboundErr(t, m); got != "" {
		t.Fatalf("outbound: got %q, want pass", got)
	}
}

func TestUndoStillRefusesNullBody(t *testing.T) {
	m := nullHop(t, nullHopBase(t), subjectTag, "new body\r\n", subjRecipe)
	if err := Undo(bytes.NewReader(m), io.Discard, 1); err == nil {
		t.Fatal("standalone Undo rebuilt a body it cannot")
	}
}

func forgeTo(hs []Header) []Header {
	hs = subjectTag(hs)
	for i, h := range hs {
		if strings.EqualFold(h.Name, "to") {
			hs[i] = Header{Name: "To", Value: " evil@example.com", Raw: "To: evil@example.com\r\n"}
		}
	}
	return hs
}

func subjectTag2(hs []Header) []Header {
	out := make([]Header, len(hs))
	copy(out, hs)
	for i, h := range out {
		if strings.EqualFold(h.Name, "subject") {
			out[i] = Header{Name: "Subject", Value: " [x] [list] hello", Raw: "Subject: [x] [list] hello\r\n"}
		}
	}
	return out
}

const ordinaryOverNull = `{"h":{"subject":[{"d":["[list] hello"]}]}}`

func TestNullBelowOrdinaryInstanceIsPermerror(t *testing.T) {
	m2 := nullHop(t, nullHopBase(t), subjectTag, "new body\r\n", subjRecipe)
	expectFail(t, nullHop(t, m2, subjectTag2, "new body\r\n", ordinaryOverNull),
		"PERMERROR: Message-Instance m=2 has a null recipe")
}

func TestNullBelowOrdinaryInstanceForgedFails(t *testing.T) {
	m2 := dropTopSig(t, nullHop(t, nullHopBase(t), forgeTo, "new body\r\n", subjRecipe))
	m := dropTopSig(t, nullHop(t, m2, subjectTag2, "new body\r\n", ordinaryOverNull))
	if got := outboundErr(t, m); !strings.Contains(got, "FAIL: Message-Instance m=1 header hash sha256 mismatch") {
		t.Fatalf("outbound: got %q", got)
	}
}

func emptyBodyBase(t *testing.T) []byte {
	raw := []byte("From: Sender <sender@test1.dkim2.com>\r\nTo: user@test2.dkim2.com\r\n" +
		"Subject: hello\r\n\r\n")
	return signOnce(t, raw, "../../keys/sel1._domainkey.test1.dkim2.com.pem",
		"sel1", "test1.dkim2.com", "sender@test1.dkim2.com", []string{"user@test2.dkim2.com"})
}

const subjOnly = `{"h":{"subject":[{"d":["hello"]}]}}`

func TestEmptyBodyHeaderOnlyRecipePasses(t *testing.T) {
	expectPass(t, nullHop(t, emptyBodyBase(t), subjectTag, "", subjOnly))
}

func TestEmptyBodyHiddenHeaderChangeFails(t *testing.T) {
	expectFail(t, nullHop(t, emptyBodyBase(t), forgeTo, "", subjOnly),
		"FAIL: Message-Instance m=1 header hash sha256 mismatch")
}
