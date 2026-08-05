package dkim2

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
)

// A hop that changes nothing adds no Message-Instance (spec-04 §9.1/§9.2.5); it
// signs against the existing top instance and reuses its m=.
//
// Regression: a transparent re-sign used to emit a fresh instance carrying
// hashes identical to the one below it and no recipe at all.  A recipe-less
// instance is legal to receive — it asserts no change — but nothing should
// produce one.

func signHop(t *testing.T, in []byte, keyName, selector, domain, mailFrom string,
	rcptTo []string, ts int64) []byte {
	t.Helper()
	keyPEM, err := os.ReadFile("../../keys/" + keyName)
	if err != nil {
		t.Skip("key not found: " + keyName)
	}
	key, err := LoadPrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Sign(bytes.NewReader(in), &out, key, SignOptions{
		Selector: selector, Domain: domain,
		MailFrom: mailFrom, RcptTo: rcptTo, Timestamp: ts,
	}); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// unchangedChain returns a message signed by test1 then relayed unchanged and
// re-signed by test2.
func unchangedChain(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../python/tests/emails/simple.eml")
	if err != nil {
		t.Fatal(err)
	}
	hop1 := signHop(t, raw, "rsa1024._domainkey.test1.dkim2.com.pem",
		"rsa1024", "test1.dkim2.com", "sender@test1.dkim2.com",
		[]string{"user@test2.dkim2.com"}, 1740000000)
	return signHop(t, hop1, "rsa1024._domainkey.test2.dkim2.com.pem",
		"rsa1024", "test2.dkim2.com", "user@test2.dkim2.com",
		[]string{"dest@test3.dkim2.com"}, 1740000100)
}

// logicalHeaders returns the named header fields with folded continuations joined.
func logicalHeaders(msg, name string) []string {
	head, _, _ := strings.Cut(msg, "\r\n\r\n")
	var logical []string
	for _, line := range strings.Split(head, "\r\n") {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && len(logical) > 0 {
			logical[len(logical)-1] += " " + strings.TrimLeft(line, " \t")
			continue
		}
		logical = append(logical, line)
	}
	var out []string
	for _, h := range logical {
		if strings.HasPrefix(strings.ToLower(h), strings.ToLower(name)+":") {
			out = append(out, h)
		}
	}
	return out
}

func TestUnchangedHopAddsNoMessageInstance(t *testing.T) {
	msg := string(unchangedChain(t))
	mis := logicalHeaders(msg, "Message-Instance")
	if len(mis) != 1 {
		t.Errorf("expected the single m=1 instance to be reused, got %d:\n%s",
			len(mis), strings.Join(mis, "\n"))
	}
}

func TestUnchangedHopSignaturePointsAtReusedInstance(t *testing.T) {
	msg := string(unchangedChain(t))
	sigs := logicalHeaders(msg, "DKIM2-Signature")
	if len(sigs) != 2 {
		t.Fatalf("expected two signatures, got %d", len(sigs))
	}
	reI := regexp.MustCompile(`i=(\d+)`)
	reM := regexp.MustCompile(`m=(\d+)`)
	for _, s := range sigs {
		i := reI.FindStringSubmatch(s)
		m := reM.FindStringSubmatch(s)
		if i == nil || m == nil {
			t.Fatalf("could not read i=/m= from %s", s)
		}
		if m[1] != "1" {
			t.Errorf("signature i=%s references m=%s, want m=1", i[1], m[1])
		}
	}
}

func TestUnchangedHopStillVerifies(t *testing.T) {
	verifyExpectPass(t, string(unchangedChain(t)), "reused-instance chain")
}

func TestRecipeLessInstanceFromUpstreamIsAccepted(t *testing.T) {
	raw, err := os.ReadFile("../../python/tests/emails/simple.eml")
	if err != nil {
		t.Fatal(err)
	}
	hop1 := signHop(t, raw, "rsa1024._domainkey.test1.dkim2.com.pem",
		"rsa1024", "test1.dkim2.com", "sender@test1.dkim2.com",
		[]string{"user@test2.dkim2.com"}, 1740000000)

	// Graft on a recipe-less m=2 with the same hashes, then re-sign so a
	// signature covers it.
	mi1 := logicalHeaders(string(hop1), "Message-Instance")[0]
	mi2 := strings.Replace(mi1, "m=1;", "m=2;", 1)
	if mi2 == mi1 {
		t.Fatalf("failed to build m=2 fixture from %s", mi1)
	}
	grafted := []byte(mi2 + "\r\n" + string(hop1))
	resigned := signHop(t, grafted, "rsa1024._domainkey.test2.dkim2.com.pem",
		"rsa1024", "test2.dkim2.com", "user@test2.dkim2.com",
		[]string{"dest@test3.dkim2.com"}, 1740000100)

	if n := len(logicalHeaders(string(resigned), "Message-Instance")); n != 2 {
		t.Fatalf("fixture should carry the recipe-less m=2 instance, got %d MIs", n)
	}
	verifyExpectPass(t, string(resigned), "recipe-less m=2 from upstream")
}
