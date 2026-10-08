package dkim2

import (
	"bytes"
	"strings"
	"testing"
)

// Every DKIM2-Signature i= and m=, and every Message-Instance m=, is bounded
// by MaxChainLength (32): a larger value, or one longer than two digits, is a
// PERMERROR found before any contiguity check walks 1..max.

func TestChainNumberInRange(t *testing.T) {
	if MaxChainLength != 32 {
		t.Fatalf("MaxChainLength = %d", MaxChainLength)
	}
	for v, want := range map[string]bool{
		"1": true, "9": true, "32": true, "01": true,
		"33": false, "99": false, "001": false, "4294967297": false,
		"99999999999999999999": false,
	} {
		if got := chainNumberInRange(v); got != want {
			t.Errorf("chainNumberInRange(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestChainNumberBound(t *testing.T) {
	base := nullHopBase(t)
	const rng = "exceeds the maximum chain length of 32"
	cases := []struct {
		name, from, to, want string
		prepend              bool
	}{
		{"signature i=33", "DKIM2-Signature: i=1;", "DKIM2-Signature: i=33;", "PERMERROR DKIM2-Signature i= " + rng, false},
		{"signature i=huge", "DKIM2-Signature: i=1;", "DKIM2-Signature: i=99999999999999999999;", "PERMERROR DKIM2-Signature i= " + rng, false},
		{"signature i=2^32+1", "DKIM2-Signature: i=1;", "DKIM2-Signature: i=4294967297;", "PERMERROR DKIM2-Signature i= " + rng, false},
		{"signature m=huge", "DKIM2-Signature: i=1; m=1;", "DKIM2-Signature: i=1; m=99999999999999999999;", "PERMERROR DKIM2-Signature m= " + rng, false},
		{"instance m=huge", "Message-Instance: m=1;", "Message-Instance: m=99999999999999999999;", "PERMERROR Message-Instance m= " + rng, false},
		{"instance m=33", "Message-Instance: m=1;", "Message-Instance: m=33;", "PERMERROR Message-Instance m= " + rng, false},
		{"extra junk i=huge", "", "DKIM2-Signature: i=99999999999999999999; m=2; d=evil.example\r\n", "PERMERROR DKIM2-Signature i= " + rng, true},
	}
	for _, c := range cases {
		var msg []byte
		if c.prepend {
			msg = append([]byte(c.to), base...)
		} else {
			if !bytes.Contains(base, []byte(c.from)) {
				t.Fatalf("%s: fixture lacks %q", c.name, c.from)
			}
			msg = bytes.Replace(base, []byte(c.from), []byte(c.to), 1)
		}
		_, err := Verify(bytes.NewReader(msg), &JSONKeyFetcher{Path: "../../dns.json"},
			VerifyOptions{SkipTimestampCheck: true})
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: Verify err = %v, want %q", c.name, err, c.want)
		}
		_, err = VerifyFull(bytes.NewReader(msg), &JSONKeyFetcher{Path: "../../dns.json"},
			VerifyOptions{SkipTimestampCheck: true})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: VerifyFull err = %v, want %q", c.name, err, c.want)
		}
		for _, allow := range []bool{false, true} {
			wantRefused(t, msg, allow, c.want)
		}
	}
}
