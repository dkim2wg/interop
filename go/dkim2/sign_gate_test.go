package dkim2

import (
	"bytes"
	"strings"
	"testing"
)

// Signer gate: Sign verifies an existing chain before covering it.

func gateSign(t *testing.T, in []byte, allowNull bool) ([]byte, error) {
	t.Helper()
	key := loadKey(t, "../../keys/sel1._domainkey.test3.dkim2.com.pem")
	var out bytes.Buffer
	err := Sign(bytes.NewReader(in), &out, key, SignOptions{
		Selector: "sel1", Domain: "test3.dkim2.com",
		MailFrom: "<list@test3.dkim2.com>", RcptTo: []string{"<subscriber@test4.dkim2.com>"},
		Fetcher:             &JSONKeyFetcher{Path: "../../dns.json"},
		SkipTimestampCheck:  true,
		AllowNullBodyRecipe: allowNull,
	})
	return out.Bytes(), err
}

func wantSigned(t *testing.T, in []byte, allowNull bool) {
	t.Helper()
	out, err := gateSign(t, in, allowNull)
	if err != nil {
		t.Fatalf("Sign refused: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no output")
	}
}

func wantRefused(t *testing.T, in []byte, allowNull bool, sub string) {
	t.Helper()
	out, err := gateSign(t, in, allowNull)
	if err == nil {
		t.Fatal("Sign signed, want refusal")
	}
	if len(out) != 0 {
		t.Errorf("refused but wrote %d bytes", len(out))
	}
	if !strings.Contains(err.Error(), "not signing") || !strings.Contains(err.Error(), sub) {
		t.Errorf("error %q lacks %q / not signing", err, sub)
	}
}

// dropTopSig removes the highest DKIM2-Signature header, leaving the top
// Message-Instance unsigned: the shape a hop sees outbound.
func dropTopSig(t *testing.T, msg []byte) []byte {
	t.Helper()
	// Sign prepends, so the highest-i= signature is the first one.
	i := bytes.Index(msg, []byte("DKIM2-Signature:"))
	if i < 0 {
		t.Fatal("no sig")
	}
	j := i
	for {
		j += bytes.Index(msg[j:], []byte("\r\n")) + 2
		if msg[j] != ' ' && msg[j] != '\t' {
			break
		}
	}
	return append(append([]byte{}, msg[:i]...), msg[j:]...)
}

func TestGateFreshSigns(t *testing.T) {
	wantSigned(t, []byte("From: a@test1.dkim2.com\r\nTo: b@test2.dkim2.com\r\nSubject: hi\r\n\r\nbody\r\n"), false)
}

func TestGateValidChainSigns(t *testing.T) {
	wantSigned(t, nullHopBase(t), false)
}

func TestGateUnsignedTopMISigns(t *testing.T) {
	m := nullHop(t, nullHopBase(t), subjectTag, "new body\r\n", `{"h":{"subject":[{"d":["hello"]}]},"b":[{"d":["body line"]}]}`)
	wantSigned(t, dropTopSig(t, m), false)
}

func TestGateBrokenSignatureRefused(t *testing.T) {
	m := bytes.Replace(nullHopBase(t), []byte("sender@test1"), []byte("sendex@test1"), 1)
	wantRefused(t, m, false, "chain")
}

func TestGateBrokenMIChainRefused(t *testing.T) {
	m := nullHop(t, nullHopBase(t), subjectTag, "new body\r\n", `{"h":{"subject":[{"d":["hello"]}]},"b":[{"d":["body line"]}]}`)
	m = bytes.Replace(m, []byte("body line\r\n"), []byte("body lime\r\n"), 1)
	// the body of m=2 is "new body"; tamper that instead
	m = bytes.Replace(m, []byte("new body"), []byte("new bodz"), 1)
	wantRefused(t, dropTopSig(t, m), false, "")
}

func TestGateNullTopRefusedUnlessAllowed(t *testing.T) {
	m := nullHop(t, nullHopBase(t), subjectTag, "new body\r\n", subjRecipe)
	wantRefused(t, m, false, "null")
	wantRefused(t, dropTopSig(t, m), false, "null")
	wantSigned(t, m, true)
	wantSigned(t, dropTopSig(t, m), true)
}

func TestGateForgedNullTopRefusedEvenWithOption(t *testing.T) {
	m := nullHop(t, nullHopBase(t), forgeTo, "new body\r\n", subjRecipe)
	wantRefused(t, m, true, "")
	wantRefused(t, dropTopSig(t, m), true, "")
}

// A list host adds unsigned Message-Instances to an unsigned post; there is no
// DKIM2-Signature at all.  The signer still checks the MI chain.
func miOnly(t *testing.T, recipe, body string) []byte {
	t.Helper()
	orig := []byte("From: Sender <sender@test1.dkim2.com>\r\nTo: user@test2.dkim2.com\r\nSubject: hello\r\n\r\nbody line\r\n")
	m1 := dropAllSigs(t, signOnce(t, orig, "../../keys/sel1._domainkey.test1.dkim2.com.pem",
		"sel1", "test1.dkim2.com", "<sender@test1.dkim2.com>", []string{"<user@test2.dkim2.com>"}))
	return dropAllSigs(t, nullHop(t, m1, subjectTag, body, recipe))
}

func dropAllSigs(t *testing.T, msg []byte) []byte {
	t.Helper()
	for bytes.Contains(msg[:bytes.Index(msg, []byte("\r\n\r\n"))], []byte("DKIM2-Signature:")) {
		msg = dropTopSig(t, msg)
	}
	return msg
}

const ordRecipe = `{"h":{"subject":[{"d":["hello"]}]},"b":[{"d":["body line"]}]}`

func TestGateMIOnlySigns(t *testing.T) {
	wantSigned(t, miOnly(t, ordRecipe, "new body\r\n"), false)
}

func TestGateMIOnlyBrokenRefused(t *testing.T) {
	m := miOnly(t, ordRecipe, "new body\r\n")
	wantRefused(t, bytes.Replace(m, []byte("To: user@test2"), []byte("To: evil@test2"), 1), false, "")
	wantRefused(t, bytes.Replace(m, []byte("new body"), []byte("new bodz"), 1), false, "")
}

func TestGateMIOnlyNull(t *testing.T) {
	m := miOnly(t, subjRecipe, "new body\r\n")
	wantRefused(t, m, false, "null")
	wantSigned(t, m, true)
}

// nd= bridge: a top signature carrying nd= may be extended only by the
// domain it names.
func ndBridgeTop(t *testing.T, nd string) []byte {
	t.Helper()
	raw := ndTestRaw(t)
	hop1 := ndSignHop(t, raw, "ed25519._domainkey.test1.dkim2.com.pem", "ed25519",
		"test1.dkim2.com", "sender@test1.dkim2.com", []string{"relay@test2.dkim2.com"}, "")
	return ndSignHop(t, hop1, "ed25519._domainkey.test2.dkim2.com.pem", "ed25519",
		"test2.dkim2.com", "", nil, nd)
}

func TestGateNdToUsSigns(t *testing.T) {
	wantSigned(t, ndBridgeTop(t, "TEST3.dkim2.com"), false)
}

func TestGateNdToOtherRefused(t *testing.T) {
	wantRefused(t, ndBridgeTop(t, "test5.dkim2.com"), false, "names another domain")
}

// Spec-06 §11: only an MI whose m= is higher than every signature's is an
// error; a lower unreferenced MI is valid.
func TestVerifyUnreferencedLowerMIValid(t *testing.T) {
	raw := ndTestRaw(t)
	hop1 := ndSignHop(t, raw, "ed25519._domainkey.test1.dkim2.com.pem", "ed25519",
		"test1.dkim2.com", "sender@test1.dkim2.com", []string{"relay@test2.dkim2.com"}, "")
	unsigned := append(dropTopSig(t, hop1), []byte("changed\r\n")...) // m=1 with no signature, body now differs
	two := ndSignHop(t, unsigned, "ed25519._domainkey.test2.dkim2.com.pem", "ed25519",
		"test2.dkim2.com", "relay@test2.dkim2.com", []string{"x@test3.dkim2.com"}, "")
	_, err := Verify(bytes.NewReader(two), ndTestFetcher(t), VerifyOptions{SkipTimestampCheck: true})
	if err != nil && strings.Contains(err.Error(), "no referencing signature") {
		t.Fatalf("lower unreferenced MI rejected: %v", err)
	}
}
