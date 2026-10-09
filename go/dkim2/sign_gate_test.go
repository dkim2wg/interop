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

// An unsigned null top (i=1 covers only m=1) is one this hop would
// introduce: refused unless the option is set.
func TestGateNullTopRefusedUnlessAllowed(t *testing.T) {
	m := dropTopSig(t, nullHop(t, nullHopBase(t), subjectTag, "new body\r\n", subjRecipe))
	wantRefused(t, m, false, "unsigned top Message-Instance m=2 has a null body Recipe")
	wantSigned(t, m, true)
}

// A null top the upstream domain already signed (i=2, m=2) is extended
// without the option: a forwarder relaying a list post unchanged.
func TestGateSignedNullTopSigns(t *testing.T) {
	m := nullHop(t, nullHopBase(t), subjectTag, "new body\r\n", subjRecipe)
	wantSigned(t, m, false)
	wantSigned(t, m, true)
}

// A signature with m=k covers instances 1..k.  An unsigned null m=2 under an
// unsigned ordinary m=3 is not the top any more, but nothing covers it (the
// highest valid m= is 1): refused without the option, like a null top.
func TestGateNullBelowUnsignedTopRefusedUnlessAllowed(t *testing.T) {
	m2 := dropTopSig(t, nullHop(t, nullHopBase(t), subjectTag, "new body\r\n", subjRecipe))
	m := dropTopSig(t, nullHop(t, m2, subjectTag2, "new body\r\n", ordinaryOverNull))
	wantRefused(t, m, false, "unsigned Message-Instance m=2 has a null body Recipe")
	wantSigned(t, m, true)

	// The walk still checks the history under both unsigned instances.
	f2 := dropTopSig(t, nullHop(t, nullHopBase(t), forgeTo, "new body\r\n", subjRecipe))
	f := dropTopSig(t, nullHop(t, f2, subjectTag2, "new body\r\n", ordinaryOverNull))
	wantRefused(t, f, true, "")
}

// The null m=2 is covered by a valid i=2/m=2; only an ordinary m=3 is
// unsigned on top of it: no option needed.
func TestGateNullBelowSignedSigns(t *testing.T) {
	m2 := nullHop(t, nullHopBase(t), subjectTag, "new body\r\n", subjRecipe)
	m := dropTopSig(t, nullHop(t, m2, subjectTag2, "new body\r\n", ordinaryOverNull))
	wantSigned(t, m, false)
	wantSigned(t, m, true)
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

func TestVerifyDuplicateMIVersion(t *testing.T) {
	raw := ndTestRaw(t)
	hop1 := ndSignHop(t, raw, "ed25519._domainkey.test1.dkim2.com.pem", "ed25519",
		"test1.dkim2.com", "sender@test1.dkim2.com", []string{"relay@test2.dkim2.com"}, "")
	i := bytes.Index(hop1, []byte("Message-Instance:"))
	j := i + bytes.Index(hop1[i:], []byte("\r\n")) + 2
	for hop1[j] == ' ' || hop1[j] == '\t' {
		j += bytes.Index(hop1[j:], []byte("\r\n")) + 2
	}
	dup := append(append(append([]byte{}, hop1[:j]...), hop1[i:j]...), hop1[j:]...)
	_, err := Verify(bytes.NewReader(dup), ndTestFetcher(t), VerifyOptions{SkipTimestampCheck: true})
	if err == nil || !strings.Contains(err.Error(), "duplicate Message-Instance m=1") {
		t.Fatalf("want duplicate Message-Instance m=1, got %v", err)
	}
}

// A DKIM2-Signature naming m=2 that no verifier can key (no i=, i=0, i=abc,
// i=+1, the real i=1 signature with i= dropped and m= rewritten) is not
// coverage of an unsigned null m=2: Verify PERMERRORs on it, so the signer
// refuses with or without the option.
func TestGateFakeCoverageRefused(t *testing.T) {
	m := dropTopSig(t, nullHop(t, nullHopBase(t), subjectTag, "new body\r\n", subjRecipe))
	i := bytes.Index(m, []byte("DKIM2-Signature: i=1; m=1;"))
	if i < 0 {
		t.Fatal("no i=1 signature")
	}
	j := i
	for {
		j += bytes.Index(m[j:], []byte("\r\n")) + 2
		if m[j] != ' ' && m[j] != '\t' {
			break
		}
	}
	rewritten := bytes.Replace(m[i:j], []byte("i=1; m=1;"), []byte("m=2;"), 1)
	fakes := map[string][]byte{
		"no i=":       []byte("DKIM2-Signature: m=2; d=evil.example\r\n"),
		"empty i=":    []byte("DKIM2-Signature: i=; m=2; d=evil.example\r\n"),
		"i=0":         []byte("DKIM2-Signature: i=0; m=2; t=1; d=evil.example; s=sel1:rsa-sha256:AAAA\r\n"),
		"i=abc":       []byte("DKIM2-Signature: i=abc; m=2; d=evil.example\r\n"),
		"i=+1":        []byte("DKIM2-Signature: i=+1; m=2; d=evil.example\r\n"),
		"FWS m = 2":   []byte("DKIM2-Signature: m = 2 ; d=evil.example\r\n"),
		"m rewritten": rewritten,
	}
	for name, fake := range fakes {
		msg := append(append([]byte{}, fake...), m...)
		for _, allow := range []bool{false, true} {
			out, err := gateSign(t, msg, allow)
			if err == nil || len(out) != 0 {
				t.Errorf("%s allow=%v: signed, want refusal", name, allow)
				continue
			}
			// Refused by the gate's verifier (result=permerror) or, for an
			// i= present but not a chain number, by the signer's own parse.
			if !strings.Contains(err.Error(), "PERMERROR DKIM2-Signature has a missing or malformed i= tag") {
				t.Errorf("%s allow=%v: error %q", name, allow, err)
			}
		}
		_, err := Verify(bytes.NewReader(msg), &JSONKeyFetcher{Path: "../../dns.json"},
			VerifyOptions{SkipTimestampCheck: true})
		if err == nil || err.Error() != "PERMERROR DKIM2-Signature has a missing or malformed i= tag" {
			t.Errorf("%s: Verify err = %v", name, err)
		}
	}
}

func TestValidSequenceTag(t *testing.T) {
	for raw, want := range map[string]bool{
		"DKIM2-Signature: i=1; m=1":     true,
		"DKIM2-Signature: i = 12 ; m=1": true,
		"DKIM2-Signature: m=1":          false,
		"DKIM2-Signature: i=; m=1":      false,
		"DKIM2-Signature: i=0; m=1":     false,
		"DKIM2-Signature: i=-1; m=1":    false,
		"DKIM2-Signature: i=+1; m=1":    false,
		"DKIM2-Signature: i=abc; m=1":   false,
		"DKIM2-Signature: i=١; m=1":     false,
		"no colon at all":               false,
	} {
		if got := validSequenceTag(raw); got != want {
			t.Errorf("validSequenceTag(%q) = %v, want %v", raw, got, want)
		}
	}
}
