package dkim2

import (
	"bytes"
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
	})
	if err == nil {
		t.Fatalf("Propagate: expected error for missing message/delivery-status part, got success")
	}
	if !strings.Contains(err.Error(), "delivery-status") {
		t.Fatalf("Propagate error = %v, want mention of delivery-status", err)
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
