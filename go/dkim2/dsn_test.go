package dkim2

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func loadKey(t *testing.T, path string) interface{} {
	t.Helper()
	pem, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("key not found: %s", path)
	}
	k, err := LoadPrivateKey(pem)
	if err != nil {
		t.Fatalf("load key %s: %v", path, err)
	}
	return k
}

// signOnce wraps Sign for a single hop.
func signOnce(t *testing.T, in []byte, keyPath, sel, dom, mf string, rt []string) []byte {
	t.Helper()
	key := loadKey(t, keyPath)
	var out bytes.Buffer
	if err := Sign(bytes.NewReader(in), &out, key, SignOptions{
		Selector: sel, Domain: dom, MailFrom: mf, RcptTo: rt, Timestamp: 1740000000,
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return out.Bytes()
}

func TestPropagate(t *testing.T) {
	const keys = "../../keys/"
	raw := []byte("From: sender@origin.example\r\n" +
		"To: user@test1.dkim2.com\r\n" +
		"Subject: hello\r\n\r\nbody line\r\n")

	// hop 1: origin signs i=1 (mf=sender@origin.example)
	hop1 := signOnce(t, raw, keys+"rsa1024._domainkey.test1.dkim2.com.pem",
		"rsa1024", "test1.dkim2.com", "sender@origin.example",
		[]string{"user@test2.dkim2.com"})
	// hop 2: forwarder re-signs unchanged (i=2/m=2). Undo to v=1 reconstructs
	// trivially and drops the forwarder's signature.
	hop2 := signOnce(t, hop1, keys+"rsa1024._domainkey.test2.dkim2.com.pem",
		"rsa1024", "test2.dkim2.com", "user@test2.dkim2.com",
		[]string{"dest@test3.dkim2.com"})

	// Wrap hop2 as the message/rfc822 part of a multipart/report DSN.
	boundary := "BOUNDARY42"
	var dsn bytes.Buffer
	dsn.WriteString("From: postmaster@test3.dkim2.com\r\n")
	dsn.WriteString("To: user@test2.dkim2.com\r\n")
	dsn.WriteString("Subject: failure\r\n")
	dsn.WriteString("Content-Type: multipart/report; report-type=delivery-status; boundary=\"" + boundary + "\"\r\n")
	dsn.WriteString("\r\n")
	dsn.WriteString("--" + boundary + "\r\n")
	dsn.WriteString("Content-Type: text/plain\r\n\r\ndelivery failed\r\n")
	dsn.WriteString("--" + boundary + "\r\n")
	dsn.WriteString("Content-Type: message/delivery-status\r\n\r\n")
	dsn.WriteString("Reporting-MTA: dns; test3.dkim2.com\r\n\r\nFinal-Recipient: rfc822; dest@test3.dkim2.com\r\nAction: failed\r\nStatus: 5.1.1\r\n")
	dsn.WriteString("--" + boundary + "\r\n")
	dsn.WriteString("Content-Type: message/rfc822\r\n\r\n")
	dsn.Write(hop2)
	dsn.WriteString("\r\n--" + boundary + "--\r\n")

	out, upstream, err := Propagate(dsn.Bytes(), PropagateOptions{
		ForwarderDomain: "test2.dkim2.com",
		Key:             loadKey(t, keys+"ed25519._domainkey.test3.dkim2.com.pem"),
		Selector:        "ed25519", Domain: "test3.dkim2.com", Timestamp: 1740000000,
		SkipAuthentication: true,
	})
	if err != nil {
		t.Fatalf("Propagate: %v", err)
	}
	if upstream != "<sender@origin.example>" {
		t.Fatalf("upstream = %q, want <sender@origin.example>", upstream)
	}

	// The propagated DSN is a fresh one-hop message: one MI, one DKIM2-Signature.
	headers, _, err := parseHeaders(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	var nMI, nSig int
	var ctype string
	for _, h := range headers {
		switch strings.ToLower(h.Name) {
		case "message-instance":
			nMI++
		case "dkim2-signature":
			nSig++
		case "content-type":
			ctype = h.Raw
		}
	}
	if nMI != 1 || nSig != 1 {
		t.Fatalf("propagated DSN has %d MI / %d sig, want 1/1", nMI, nSig)
	}
	if !strings.Contains(strings.ToLower(ctype), "multipart/report") {
		t.Fatalf("propagated DSN is not multipart/report: %q", ctype)
	}
}

// TestPropagateRejectsMissingDeliveryStatus verifies that Propagate enforces
// the RFC 6522 three-part multipart/report structure: a multipart/report DSN
// with three (or more) parts but no message/delivery-status part must be
// rejected, even though it still has a leading text part and a trailing
// message/rfc822 part.
func TestPropagateRejectsMissingDeliveryStatus(t *testing.T) {
	const keys = "../../keys/"
	raw := []byte("From: sender@origin.example\r\n" +
		"To: user@test1.dkim2.com\r\n" +
		"Subject: hello\r\n\r\nbody line\r\n")

	hop1 := signOnce(t, raw, keys+"rsa1024._domainkey.test1.dkim2.com.pem",
		"rsa1024", "test1.dkim2.com", "sender@origin.example",
		[]string{"user@test2.dkim2.com"})
	hop2 := signOnce(t, hop1, keys+"rsa1024._domainkey.test2.dkim2.com.pem",
		"rsa1024", "test2.dkim2.com", "user@test2.dkim2.com",
		[]string{"dest@test3.dkim2.com"})

	// Three parts, but the middle part is NOT message/delivery-status.
	boundary := "BOUNDARY43"
	var dsn bytes.Buffer
	dsn.WriteString("From: postmaster@test3.dkim2.com\r\n")
	dsn.WriteString("To: user@test2.dkim2.com\r\n")
	dsn.WriteString("Subject: failure\r\n")
	dsn.WriteString("Content-Type: multipart/report; report-type=delivery-status; boundary=\"" + boundary + "\"\r\n")
	dsn.WriteString("\r\n")
	dsn.WriteString("--" + boundary + "\r\n")
	dsn.WriteString("Content-Type: text/plain\r\n\r\ndelivery failed\r\n")
	dsn.WriteString("--" + boundary + "\r\n")
	dsn.WriteString("Content-Type: application/octet-stream\r\n\r\nnot a delivery status\r\n")
	dsn.WriteString("--" + boundary + "\r\n")
	dsn.WriteString("Content-Type: message/rfc822\r\n\r\n")
	dsn.Write(hop2)
	dsn.WriteString("\r\n--" + boundary + "--\r\n")

	_, _, err := Propagate(dsn.Bytes(), PropagateOptions{
		ForwarderDomain: "test2.dkim2.com",
		Key:             loadKey(t, keys+"ed25519._domainkey.test3.dkim2.com.pem"),
		Selector:        "ed25519", Domain: "test3.dkim2.com", Timestamp: 1740000000,
		SkipAuthentication: true,
	})
	if err == nil {
		t.Fatalf("Propagate: expected error for missing message/delivery-status part, got success")
	}
	if !strings.Contains(err.Error(), "delivery-status") {
		t.Fatalf("Propagate error = %v, want mention of delivery-status", err)
	}
}

// TestPropagateEmitsAWellFormedReport checks the MIME the splice produces: the
// boundary delimiter line has to be terminated and the rebuilt part needs its
// own blank line, or the returned message is not a part at all — its headers
// end up glued onto the "--boundary" line, which no MIME parser will read.
func TestPropagateEmitsAWellFormedReport(t *testing.T) {
	const keys = "../../keys/"
	out, _, err := Propagate(dsnAround(t, verifiableTwoHop(t), false), PropagateOptions{
		ForwarderDomain: "test2.dkim2.com",
		Key:             loadKey(t, keys+"sel1._domainkey.test2.dkim2.com.pem"),
		Selector:        "sel1", Domain: "test2.dkim2.com", Timestamp: 1740000000,
		SkipAuthentication: true,
	})
	if err != nil {
		t.Fatalf("Propagate: %v", err)
	}
	rep, err := parseReport(out)
	if err != nil {
		t.Fatalf("parse propagated DSN: %v", err)
	}
	for i := 1; i < len(rep.segments)-1; i++ {
		if !strings.HasPrefix(rep.segments[i], "\r\n") {
			t.Fatalf("part %d does not start on its own line: %.60q", i, rep.segments[i])
		}
	}
	if !strings.Contains(string(out), "\r\n\r\nDKIM2-Signature: i=1;") {
		t.Fatal("the returned message does not begin after a blank line")
	}
}

// --- §12.1.1's null Recipe: an upstream that declares the previous body
// unrecoverable gets the header fields back, not a body we cannot rebuild. ---

// nullRecipeChain builds a two-hop message whose m=2 carries "b": null.
// buildMI has no way to emit one (ComputeDiff only ever produces a real,
// reversible Recipe), so the instance is assembled here from the digest
// primitives, then genuinely signed.
func nullRecipeChain(t *testing.T) []byte {
	t.Helper()
	const keys = "../../keys/"
	raw := []byte("From: Sender <sender@test1.dkim2.com>\r\n" +
		"To: user@test2.dkim2.com\r\n" +
		"Subject: hello\r\n\r\nbody line\r\n")
	hop1 := signOnce(t, raw, keys+"sel1._domainkey.test1.dkim2.com.pem",
		"sel1", "test1.dkim2.com", "sender@test1.dkim2.com",
		[]string{"user@test2.dkim2.com"})

	headers, bodyReader, err := parseHeaders(bytes.NewReader(hop1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(bodyReader); err != nil {
		t.Fatal(err)
	}
	body := []byte("replaced entirely\r\n")

	var content []Header
	var miRaws, sigRaws []string
	for _, h := range headers {
		switch strings.ToLower(h.Name) {
		case "message-instance":
			miRaws = append(miRaws, h.Raw)
		case "dkim2-signature":
			sigRaws = append(sigRaws, h.Raw)
		default:
			content = append(content, h)
		}
	}

	hh, err := hashHeaders(content, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	bodyHashes, err := hashBodyMulti(bytes.NewReader(body), []string{"sha256"})
	if err != nil {
		t.Fatal(err)
	}
	mi2 := fmt.Sprintf("Message-Instance: m=2; h=sha256:%s:%s; r=%s;\r\n",
		base64.StdEncoding.EncodeToString(hh),
		base64.StdEncoding.EncodeToString(bodyHashes["sha256"]),
		base64.StdEncoding.EncodeToString([]byte(`{"b":null}`)))

	var assembled bytes.Buffer
	for _, s := range sigRaws {
		assembled.WriteString(s)
	}
	assembled.WriteString(mi2)
	for _, m := range miRaws {
		assembled.WriteString(m)
	}
	for _, h := range content {
		assembled.WriteString(h.Raw)
	}
	assembled.WriteString("\r\n")
	assembled.Write(body)

	// Sign i=2 over that state, so every signature in the chain is genuine.
	return signOnce(t, assembled.Bytes(), keys+"sel1._domainkey.test2.dkim2.com.pem",
		"sel1", "test2.dkim2.com", "user@test2.dkim2.com",
		[]string{"dest@test3.dkim2.com"})
}

func TestUndoReportsANullRecipeAsUnrecoverable(t *testing.T) {
	err := Undo(bytes.NewReader(nullRecipeChain(t)), io.Discard, 1)
	if !errors.Is(err, ErrUnrecoverable) {
		t.Fatalf("err = %v, want it to wrap ErrUnrecoverable", err)
	}
}

func TestPropagateNullRecipeReturnsHeadersOnly(t *testing.T) {
	const keys = "../../keys/"
	out, upstream, err := Propagate(dsnAround(t, nullRecipeChain(t), false),
		PropagateOptions{
			ForwarderDomain: "test2.dkim2.com",
			Key:             loadKey(t, keys+"sel1._domainkey.test3.dkim2.com.pem"),
			Selector:        "sel1", Domain: "test3.dkim2.com", Timestamp: 1740000000,
			SkipAuthentication: true,
		})
	if err != nil {
		t.Fatalf("Propagate: %v", err)
	}
	if upstream != "<sender@test1.dkim2.com>" {
		t.Fatalf("upstream = %q, want <sender@test1.dkim2.com>", upstream)
	}
	if strings.Contains(string(out), "message/rfc822") {
		t.Fatal("propagated a body it could not reconstruct")
	}
	if !strings.Contains(string(out), "text/rfc822-headers") {
		t.Fatal("the returned original is not text/rfc822-headers")
	}

	// The forwarder's whole hop comes off: its instance goes with the
	// signature that covered it, or the returned message carries an instance
	// above its own top signature (§11 "is not signed") upstream.
	rep, err := parseReport(out)
	if err != nil {
		t.Fatalf("parse propagated DSN: %v", err)
	}
	_, inner := splitPartHeaders(rep.segments[rep.embeddedSeg])
	hdrs, _, err := parseHeaders(strings.NewReader(inner))
	if err != nil {
		t.Fatal(err)
	}
	var mis, sigs int
	for _, h := range hdrs {
		switch strings.ToLower(h.Name) {
		case "message-instance":
			mis++
			if mi, _ := parseMI(h.Raw); mi != nil && mi.Version != 1 {
				t.Errorf("returned message keeps m=%d", mi.Version)
			}
		case "dkim2-signature":
			sigs++
			if sig, _ := parseSig(h.Raw); sig != nil && sig.Sequence != 1 {
				t.Errorf("returned message keeps i=%d", sig.Sequence)
			}
		}
	}
	if mis != 1 || sigs != 1 {
		t.Fatalf("returned message has %d MI / %d sig, want 1/1", mis, sigs)
	}
}

func TestPropagateRefusesWhenUndoSimplyFails(t *testing.T) {
	const keys = "../../keys/"
	// A body that changed with no Recipe describing it: undo cannot get back
	// to the m=1 body and does not claim to. That is a defect, not a
	// declaration, so there is nothing truthful to return.
	chain := nullRecipeChain(t)
	broken := bytes.Replace(chain,
		[]byte(base64.StdEncoding.EncodeToString([]byte(`{"b":null}`))),
		[]byte(base64.StdEncoding.EncodeToString([]byte(`{}`))), 1)
	if bytes.Equal(chain, broken) {
		t.Fatal("fixture: the null Recipe was not replaced")
	}
	_, _, err := Propagate(dsnAround(t, broken, false), PropagateOptions{
		ForwarderDomain: "test2.dkim2.com",
		Key:             loadKey(t, keys+"sel1._domainkey.test3.dkim2.com.pem"),
		Selector:        "sel1", Domain: "test3.dkim2.com", Timestamp: 1740000000,
		SkipAuthentication: true,
	})
	if err == nil {
		t.Fatal("propagated a message it could not reconstruct")
	}
	if !strings.Contains(err.Error(), "hash mismatch after reconstruction") {
		t.Fatalf("err = %v, want the reconstruction mismatch", err)
	}
}

// --- Authenticate: §12.1.2, the returned original's chain must verify -------

// The fixtures above never verify (hop 1 signs d=test1.dkim2.com over a
// sender@origin.example envelope, which the d=/mf= rule rejects), which the
// Propagate tests never needed. Authenticate does, so build a chain that
// holds: test1 originates to a user at test2, who forwards to test3.
func verifiableTwoHop(t *testing.T) []byte {
	t.Helper()
	const keys = "../../keys/"
	raw := []byte("From: Sender <sender@test1.dkim2.com>\r\n" +
		"To: user@test2.dkim2.com\r\n" +
		"Subject: hello\r\n\r\nbody line\r\n")
	hop1 := signOnce(t, raw, keys+"rsa1024._domainkey.test1.dkim2.com.pem",
		"rsa1024", "test1.dkim2.com", "sender@test1.dkim2.com",
		[]string{"user@test2.dkim2.com"})
	return signOnce(t, hop1, keys+"rsa1024._domainkey.test2.dkim2.com.pem",
		"rsa1024", "test2.dkim2.com", "user@test2.dkim2.com",
		[]string{"dest@test3.dkim2.com"})
}

// dsnAround wraps a returned original in a three-part multipart/report, as
// either a message/rfc822 part or (headersOnly) a text/rfc822-headers part
// carrying the header block alone.
func dsnAround(t *testing.T, embedded []byte, headersOnly bool) []byte {
	t.Helper()
	part := "Content-Type: message/rfc822\r\n\r\n"
	payload := embedded
	if headersOnly {
		part = "Content-Type: text/rfc822-headers\r\n\r\n"
		headers, _, err := parseHeaders(bytes.NewReader(embedded))
		if err != nil {
			t.Fatalf("parse embedded headers: %v", err)
		}
		var hdrs bytes.Buffer
		for _, h := range headers {
			hdrs.WriteString(h.Raw)
		}
		payload = hdrs.Bytes()
	}

	boundary := "BOUNDARY44"
	var dsn bytes.Buffer
	dsn.WriteString("From: postmaster@test3.dkim2.com\r\n")
	dsn.WriteString("To: user@test2.dkim2.com\r\n")
	dsn.WriteString("Subject: failure\r\n")
	dsn.WriteString("Content-Type: multipart/report; report-type=delivery-status; boundary=\"" + boundary + "\"\r\n")
	dsn.WriteString("\r\n")
	dsn.WriteString("--" + boundary + "\r\n")
	dsn.WriteString("Content-Type: text/plain\r\n\r\ndelivery failed\r\n")
	dsn.WriteString("--" + boundary + "\r\n")
	dsn.WriteString("Content-Type: message/delivery-status\r\n\r\n")
	dsn.WriteString("Reporting-MTA: dns; test3.dkim2.com\r\n\r\nFinal-Recipient: rfc822; dest@test3.dkim2.com\r\nAction: failed\r\nStatus: 5.1.1\r\n")
	dsn.WriteString("--" + boundary + "\r\n")
	dsn.WriteString(part)
	dsn.Write(payload)
	dsn.WriteString("\r\n--" + boundary + "--\r\n")
	return dsn.Bytes()
}

func TestAuthenticateIntactTwoHop(t *testing.T) {
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	res, err := Authenticate(dsnAround(t, verifiableTwoHop(t), false), f,
		VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !res.OK {
		t.Fatalf("intact two-hop DSN did not authenticate: %v", res.Reason)
	}
	if res.HeadersOnly {
		t.Fatal("HeadersOnly set for a message/rfc822 DSN")
	}
	// The forwarder recognises i=2 as its own by d= (§12.1.2 point 2).
	if res.Top == nil || res.Top.Sequence != 2 || res.Top.Domain != "test2.dkim2.com" {
		t.Fatalf("Top = %+v, want i=2 d=test2.dkim2.com", res.Top)
	}
	if res.Top.MailFrom != "<user@test2.dkim2.com>" {
		t.Fatalf("Top.MailFrom = %q, want <user@test2.dkim2.com>", res.Top.MailFrom)
	}
}

func TestAuthenticateHeadersOnly(t *testing.T) {
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	res, err := Authenticate(dsnAround(t, verifiableTwoHop(t), true), f,
		VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !res.OK {
		t.Fatalf("headers-only DSN did not authenticate from the headers alone: %v", res.Reason)
	}
	if !res.HeadersOnly {
		t.Fatal("HeadersOnly not set for a text/rfc822-headers DSN")
	}
	if res.Top == nil || res.Top.Sequence != 2 {
		t.Fatalf("Top = %+v, want i=2", res.Top)
	}
}

// A returned original whose headers were changed after signing: the top
// instance's header hash no longer matches, with or without a body.
func TestAuthenticateRejectsTamperedHeaders(t *testing.T) {
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	tampered := bytes.Replace(verifiableTwoHop(t),
		[]byte("Subject: hello"), []byte("Subject: hullo"), 1)
	for _, headersOnly := range []bool{false, true} {
		res, err := Authenticate(dsnAround(t, tampered, headersOnly), f,
			VerifyOptions{SkipTimestampCheck: true})
		if err != nil {
			t.Fatalf("headersOnly=%v: Authenticate: %v", headersOnly, err)
		}
		if res.OK {
			t.Fatalf("headersOnly=%v: tampered returned message authenticated", headersOnly)
		}
		if res.Reason == nil || !strings.Contains(res.Reason.Error(), "header hash mismatch") {
			t.Fatalf("headersOnly=%v: Reason = %v, want header hash mismatch", headersOnly, res.Reason)
		}
	}
}

func TestAuthenticateUnsignedOriginal(t *testing.T) {
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	plain := []byte("From: a@b.example\r\nTo: c@d.example\r\nSubject: plain\r\n\r\nhi\r\n")
	res, err := Authenticate(dsnAround(t, plain, false), f)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.OK {
		t.Fatal("a DSN returning an unsigned message authenticated")
	}
	if res.Top != nil {
		t.Fatalf("Top = %+v, want nil for an unsigned original", res.Top)
	}
	// Reported as "no DKIM2-Signature", so a caller can tell an unsigned
	// original (fall back to legacy DSN handling) from a broken one.
	if res.Reason == nil || !strings.Contains(res.Reason.Error(), "no DKIM2-Signature") {
		t.Fatalf("Reason = %v, want no DKIM2-Signature", res.Reason)
	}
}

// --- Propagate: a Forwarder's §9.3 bridge goes with its hop ----------------

// bridgedChain: test1 -> user@test2; test2 bridges with nd= and sends the real
// hop from test3.
func bridgedChain(t *testing.T) []byte {
	t.Helper()
	const keys = "../../keys/"
	raw := []byte("From: Sender <sender@test1.dkim2.com>\r\n" +
		"To: user@test2.dkim2.com\r\n" +
		"Subject: bridged\r\n\r\nbody line\r\n")
	hop1 := signOnce(t, raw, keys+"sel1._domainkey.test1.dkim2.com.pem",
		"sel1", "test1.dkim2.com", "sender@test1.dkim2.com",
		[]string{"user@test2.dkim2.com"})
	hop2 := ndSignHop(t, hop1, "sel1._domainkey.test2.dkim2.com.pem", "sel1",
		"test2.dkim2.com", "", nil, "test3.dkim2.com")
	return signOnce(t, hop2, keys+"sel1._domainkey.test3.dkim2.com.pem",
		"sel1", "test3.dkim2.com", "srs0=x@bounce.test3.dkim2.com",
		[]string{"dest@test5.dkim2.com"})
}

func TestAuthenticateBridgedChain(t *testing.T) {
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	res, err := Authenticate(dsnAround(t, bridgedChain(t), false), f,
		VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !res.OK {
		t.Fatalf("a DSN returning a bridged chain did not authenticate: %v", res.Reason)
	}
	if res.Top == nil || res.Top.Sequence != 3 {
		t.Fatalf("Top = %+v, want i=3", res.Top)
	}
}

func TestPropagateStripsTheBridgeWithItsHop(t *testing.T) {
	const keys = "../../keys/"
	out, upstream, err := Propagate(dsnAround(t, bridgedChain(t), false), PropagateOptions{
		ForwarderDomain: "test3.dkim2.com",
		Key:             loadKey(t, keys+"sel1._domainkey.test2.dkim2.com.pem"),
		Selector:        "sel1", Domain: "test2.dkim2.com", Timestamp: 1740000000,
		Fetcher:            &JSONKeyFetcher{Path: "../../dns.json"},
		SkipTimestampCheck: true,
	})
	if err != nil {
		t.Fatalf("Propagate: %v", err)
	}
	// The report goes to the hop before both: the bridge is not a hop of its
	// own, and an nd= signature is never valid as the top of a chain.
	if upstream != "<sender@test1.dkim2.com>" {
		t.Fatalf("upstream = %q, want <sender@test1.dkim2.com>", upstream)
	}

	rep, err := parseReport(out)
	if err != nil {
		t.Fatalf("parse propagated DSN: %v", err)
	}
	_, inner := splitPartHeaders(rep.segments[rep.embeddedSeg])
	headers, _, err := parseHeaders(strings.NewReader(inner))
	if err != nil {
		t.Fatal(err)
	}
	var sigs []*DKIM2Signature
	for _, h := range headers {
		if strings.EqualFold(h.Name, "dkim2-signature") {
			sig, perr := parseSig(h.Raw)
			if perr != nil {
				t.Fatalf("parse returned-message signature: %v", perr)
			}
			sigs = append(sigs, sig)
		}
	}
	if len(sigs) != 1 {
		t.Fatalf("%d signatures left on the returned message, want 1", len(sigs))
	}
	if sigs[0].NextDomain != "" {
		t.Fatalf("the signature left is the nd= bridge (nd=%s)", sigs[0].NextDomain)
	}
}

// --- §12.1.2 point 1: the DSN's own signing domain must be aligned with the
// rt= of the returned message's top signature — i.e. the bounce came from the
// system we handed the message to. Checked only on a d= we have verified: an
// unverified d= is whatever the forger typed. -------------------------------

// signedDSNAround wraps embedded in a DSN and signs the DSN as a new message
// (as §12.1.1 makes it: MAIL FROM <>, one Message-Instance, one signature).
func signedDSNAround(t *testing.T, embedded []byte, domain string) []byte {
	t.Helper()
	return signOnce(t, dsnAround(t, embedded, false),
		"../../keys/sel1._domainkey."+domain+".pem", "sel1", domain,
		"", []string{"user@test2.dkim2.com"})
}

func TestAuthenticateAlignedDSN(t *testing.T) {
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	// verifiableTwoHop's top signature is i=2 rt=<dest@test3.dkim2.com>, so a
	// DSN for it must be signed by test3.dkim2.com.
	res, err := Authenticate(signedDSNAround(t, verifiableTwoHop(t), "test3.dkim2.com"), f,
		VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !res.OK {
		t.Fatalf("an aligned, fully-signed DSN did not authenticate: %v", res.Reason)
	}
	if res.DSNError != nil {
		t.Fatalf("the DSN's own chain did not verify: %v", res.DSNError)
	}
	if res.DSNSig == nil || res.DSNSig.Domain != "test3.dkim2.com" {
		t.Fatalf("DSNSig = %+v, want d=test3.dkim2.com", res.DSNSig)
	}
	if res.Alignment != "pass" {
		t.Fatalf("Alignment = %q (%s), want pass", res.Alignment, res.AlignDetail)
	}
	if !strings.Contains(res.AlignDetail, "dest@test3.dkim2.com") {
		t.Fatalf("AlignDetail = %q, want it to name the recipient", res.AlignDetail)
	}
}

func TestAuthenticateMisalignedDSN(t *testing.T) {
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	// Every signature verifies and the returned message is intact, so nothing
	// but point 1 can tell this is not a bounce from where we sent the mail.
	res, err := Authenticate(signedDSNAround(t, verifiableTwoHop(t), "test4.dkim2.com"), f,
		VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.DSNError != nil {
		t.Fatalf("the DSN's own chain should still verify: %v", res.DSNError)
	}
	if res.Alignment != "fail" {
		t.Fatalf("Alignment = %q (%s), want fail", res.Alignment, res.AlignDetail)
	}
	if res.OK {
		t.Fatal("a DSN from a domain the message was never sent to authenticated")
	}
	if !strings.Contains(res.AlignDetail, "d=test4.dkim2.com is not aligned") {
		t.Fatalf("AlignDetail = %q, want it to name the signing domain", res.AlignDetail)
	}
}

// TestCheckAlignmentDomainRelationships pins the direction question. Which
// domain relationships count as "aligned" is a decision about relaxed matching
// on its own, and the shared test DNS has keys for test1..test5.dkim2.com only
// — no subdomain and no parent — so there is no way to build a real signed DSN
// for either shape. Accept and reject through the real entry point are covered
// above.
func TestCheckAlignmentDomainRelationships(t *testing.T) {
	rtTest3 := &DKIM2Signature{RcptTo: []string{"<dest@test3.dkim2.com>"}}
	// §9.4's direction: labels come off the ADDRESS domain, so d= may be the
	// delivery domain or a parent of it.
	for _, d := range []string{"test3.dkim2.com", "dkim2.com"} {
		state, detail := checkAlignment(&DKIM2Signature{Domain: d}, rtTest3)
		if state != "pass" {
			t.Errorf("d=%s: state = %q (%s), want pass", d, state, detail)
		}
	}
	// Never a child of it: a system with a dedicated bounce domain signs as
	// its org domain and puts the bounce address on the subdomain, so this
	// shape has no legitimate producer.
	for _, d := range []string{"bounce.test3.dkim2.com", "test4.dkim2.com",
		"test3.dkim2.com.evil.example", "evil.example"} {
		if state, _ := checkAlignment(&DKIM2Signature{Domain: d}, rtTest3); state != "fail" {
			t.Errorf("d=%s: state = %q, want fail", d, state)
		}
	}
	// An nd= top signature on the returned message has no rt= to align with.
	ndTop := &DKIM2Signature{Domain: "test2.dkim2.com", NextDomain: "test3.dkim2.com"}
	state, detail := checkAlignment(&DKIM2Signature{Domain: "test3.dkim2.com"}, ndTop)
	if state != "none" || !strings.Contains(detail, "no rt=") {
		t.Fatalf("state = %q (%s), want none/no rt=", state, detail)
	}
}

func TestAuthenticateBrokenDSNSignature(t *testing.T) {
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	// A DSN whose own signature is broken claims DKIM2 and lies, so it must
	// not be propagated, and point 1 cannot be applied to a d= we cannot trust.
	tampered := bytes.Replace(signedDSNAround(t, verifiableTwoHop(t), "test3.dkim2.com"),
		[]byte("Subject: failure"), []byte("Subject: FAILURE"), 1)
	res, err := Authenticate(tampered, f, VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.DSNError == nil {
		t.Fatal("a tampered DSN's own signature still verified")
	}
	if res.Alignment != "none" {
		t.Fatalf("Alignment = %q, want none — an unverified d= must not be used", res.Alignment)
	}
	if res.OK {
		t.Fatal("a DSN whose own signature is broken authenticated")
	}
}

func TestAuthenticateUnsignedDSNIsReportedNotFailed(t *testing.T) {
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	// An unsigned DSN is not what §12.1.2 is about ("when a system receives a
	// DKIM2 signed DSN"), so it is reported, not failed.
	res, err := Authenticate(dsnAround(t, verifiableTwoHop(t), false), f,
		VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.DSNSig != nil {
		t.Fatalf("DSNSig = %+v, want nil for an unsigned DSN", res.DSNSig)
	}
	if res.Alignment != "none" {
		t.Fatalf("Alignment = %q, want none", res.Alignment)
	}
	if !res.OK {
		t.Fatalf("an unsigned DSN with an intact returned message did not authenticate: %v", res.Reason)
	}
}

// --- §12.1.2: "If the verification fails then the DSN MUST NOT be propagated
// any further" — Propagate enforces that itself. ---------------------------

func TestPropagateNeedsTheMeansToAuthenticate(t *testing.T) {
	const keys = "../../keys/"
	_, _, err := Propagate(dsnAround(t, verifiableTwoHop(t), false), PropagateOptions{
		ForwarderDomain: "test2.dkim2.com",
		Key:             loadKey(t, keys+"sel1._domainkey.test2.dkim2.com.pem"),
		Selector:        "sel1", Domain: "test2.dkim2.com", Timestamp: 1740000000,
	})
	if err == nil || !strings.Contains(err.Error(), "need a Fetcher to authenticate") {
		t.Fatalf("err = %v, want a refusal to propagate unauthenticated", err)
	}
}

func TestPropagateRefusesAMisalignedDSN(t *testing.T) {
	const keys = "../../keys/"
	_, _, err := Propagate(signedDSNAround(t, verifiableTwoHop(t), "test4.dkim2.com"),
		PropagateOptions{
			ForwarderDomain: "test2.dkim2.com",
			Key:             loadKey(t, keys+"sel1._domainkey.test2.dkim2.com.pem"),
			Selector:        "sel1", Domain: "test2.dkim2.com", Timestamp: 1740000000,
			Fetcher:            &JSONKeyFetcher{Path: "../../dns.json"},
			SkipTimestampCheck: true,
		})
	if err == nil || !strings.Contains(err.Error(), "not aligned") {
		t.Fatalf("err = %v, want a refusal for a misaligned DSN", err)
	}
}

func TestPropagateAFullyAuthenticatedDSN(t *testing.T) {
	const keys = "../../keys/"
	out, upstream, err := Propagate(
		signedDSNAround(t, verifiableTwoHop(t), "test3.dkim2.com"),
		PropagateOptions{
			ForwarderDomain: "test2.dkim2.com",
			Key:             loadKey(t, keys+"sel1._domainkey.test2.dkim2.com.pem"),
			Selector:        "sel1", Domain: "test2.dkim2.com", Timestamp: 1740000000,
			Fetcher:            &JSONKeyFetcher{Path: "../../dns.json"},
			SkipTimestampCheck: true,
		})
	if err != nil {
		t.Fatalf("Propagate: %v", err)
	}
	if upstream != "<sender@test1.dkim2.com>" {
		t.Fatalf("upstream = %q, want <sender@test1.dkim2.com>", upstream)
	}

	// The inbound DSN was itself signed — the only kind §12.1.2 is about — so
	// its own instance and signature must not survive into ours.
	headers, _, err := parseHeaders(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	var nMI int
	var sigs []*DKIM2Signature
	for _, h := range headers {
		switch strings.ToLower(h.Name) {
		case "message-instance":
			nMI++
		case "dkim2-signature":
			sig, perr := parseSig(h.Raw)
			if perr != nil {
				t.Fatalf("parse propagated signature: %v", perr)
			}
			sigs = append(sigs, sig)
		}
	}
	if nMI != 1 || len(sigs) != 1 {
		t.Fatalf("propagated DSN has %d MI / %d sig, want 1/1", nMI, len(sigs))
	}
	if sigs[0].Domain != "test2.dkim2.com" || sigs[0].MIVersion != 1 {
		t.Fatalf("propagated signature = d=%s m=%d, want d=test2.dkim2.com m=1",
			sigs[0].Domain, sigs[0].MIVersion)
	}
}

func TestAuthenticateRejectsNonDSN(t *testing.T) {
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	_, err := Authenticate([]byte("From: a@b.example\r\n\r\nnot a DSN\r\n"), f)
	if err == nil {
		t.Fatal("Authenticate accepted a message that is not a DSN")
	}
	if !strings.Contains(err.Error(), "multipart/report") {
		t.Fatalf("err = %v, want mention of multipart/report", err)
	}
}
