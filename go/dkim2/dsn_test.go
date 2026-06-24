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
	if upstream != "sender@origin.example" {
		t.Fatalf("upstream = %q, want sender@origin.example", upstream)
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
