package dkim2

import (
	"bytes"
	"strings"
	"testing"
)

// Every DKIM2-Signature i= and m=, and every Message-Instance m=, is a chain
// number: 1*DIGIT in ASCII (Atoi alone would take "+1"), at most three digits
// naming 1..MaxChainNumber (100), so "01" and "001" are 1; and no more than
// MaxChainLength (32). Anything else is a PERMERROR found before any
// contiguity check walks 1..max.

func TestChainNumberError(t *testing.T) {
	if MaxChainLength != 32 || MaxChainNumber != 100 {
		t.Fatalf("MaxChainLength = %d, MaxChainNumber = %d", MaxChainLength, MaxChainNumber)
	}
	for v, want := range map[string]string{
		"1": "", "9": "", "32": "", "01": "", "001": "", "032": "",
		"33": "ln", "99": "ln", "100": "ln",
		"101": "num", "0001": "num", "4294967297": "num", "99999999999999999999": "num",
		"": "mal", "0": "mal", "000": "mal", "abc": "mal", "1x": "mal", "4294967297x": "mal",
		"0_1": "mal", "\uff11": "mal", "+1": "mal", "-1": "mal",
	} {
		switch want {
		case "mal":
			want = "PERMERROR: Message-Instance m=" + strings.TrimSpace(v) + " syntax error"
		case "ln":
			want = "PERMERROR: Message-Instance m=" + v + " exceeds the maximum chain length of 32"
		case "num":
			want = "PERMERROR: Message-Instance m=" + v + " exceeds the maximum chain number of 100"
		}
		got := ""
		if err := chainNumberError("Message-Instance", "m", v, v, true); err != nil {
			got = err.Error()
		}
		if got != want {
			t.Errorf("chainNumberError(%q) = %q, want %q", v, got, want)
		}
	}
	if err := chainNumberError("Message-Instance", "m", "", "", false); err != nil {
		t.Errorf("missing m= is left to the callers, got %v", err)
	}
	if err := chainNumberError("DKIM2-Signature", "i", "abc", "abc", true); err == nil ||
		err.Error() != "PERMERROR: DKIM2-Signature i=abc syntax error" {
		t.Errorf("malformed i=: %v", err)
	}
	// A signature's m= is named by its i=.
	if err := chainNumberError("DKIM2-Signature", "m", "4294967297", "2", true); err == nil ||
		err.Error() != "PERMERROR: DKIM2-Signature i=2 m=4294967297 exceeds the maximum chain number of 100" {
		t.Errorf("signature m=: %v", err)
	}
}

func TestChainNumberBound(t *testing.T) {
	base := nullHopBase(t)
	const rng = "exceeds the maximum chain length of 32"
	const num = "exceeds the maximum chain number of 100"
	cases := []struct {
		name, from, to, want string
		prepend              bool
	}{
		{"signature i=33", "DKIM2-Signature: i=1;", "DKIM2-Signature: i=33;", "PERMERROR: DKIM2-Signature i=33 " + rng, false},
		{"signature i=101", "DKIM2-Signature: i=1;", "DKIM2-Signature: i=101;", "PERMERROR: DKIM2-Signature i=101 " + num, false},
		{"signature i=huge", "DKIM2-Signature: i=1;", "DKIM2-Signature: i=99999999999999999999;", "PERMERROR: DKIM2-Signature i=99999999999999999999 " + num, false},
		{"signature i=2^32+1", "DKIM2-Signature: i=1;", "DKIM2-Signature: i=4294967297;", "PERMERROR: DKIM2-Signature i=4294967297 " + num, false},
		{"signature m=huge", "DKIM2-Signature: i=1; m=1;", "DKIM2-Signature: i=1; m=99999999999999999999;", "PERMERROR: DKIM2-Signature i=1 m=99999999999999999999 " + num, false},
		{"signature m=4294967297x", "DKIM2-Signature: i=1; m=1;", "DKIM2-Signature: i=1; m=4294967297x;", "PERMERROR: DKIM2-Signature i=1 syntax error", false},
		{"signature m=abc", "DKIM2-Signature: i=1; m=1;", "DKIM2-Signature: i=1; m=abc;", "PERMERROR: DKIM2-Signature i=1 syntax error", false},
		{"signature m=+1", "DKIM2-Signature: i=1; m=1;", "DKIM2-Signature: i=1; m=+1;", "PERMERROR: DKIM2-Signature i=1 syntax error", false},
		{"instance m=huge", "Message-Instance: m=1;", "Message-Instance: m=99999999999999999999;", "PERMERROR: Message-Instance m=99999999999999999999 " + num, false},
		{"instance m=33", "Message-Instance: m=1;", "Message-Instance: m=33;", "PERMERROR: Message-Instance m=33 " + rng, false},
		{"instance m=101", "Message-Instance: m=1;", "Message-Instance: m=101;", "PERMERROR: Message-Instance m=101 " + num, false},
		{"instance m=+1", "Message-Instance: m=1;", "Message-Instance: m=+1;", "PERMERROR: Message-Instance m=+1 syntax error", false},
		{"instance m=4294967297x", "Message-Instance: m=1;", "Message-Instance: m=4294967297x;", "PERMERROR: Message-Instance m=4294967297x syntax error", false},
		{"extra junk i=huge", "", "DKIM2-Signature: i=99999999999999999999; m=2; d=evil.example\r\n", "PERMERROR: DKIM2-Signature i=99999999999999999999 " + num, true},
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
