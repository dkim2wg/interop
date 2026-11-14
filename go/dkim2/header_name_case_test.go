package dkim2

import (
	"bytes"
	"testing"
)

// Header field names are ASCII and compared without regard to ASCII case
// only. strings.ToLower and strings.EqualFold also fold Unicode: U+0130 (İ)
// lowers to "i" and the Kelvin sign U+212A folds to "k", so a field named
// "Authentİcation-Results" was hashed as authentication-results ... and one
// named "Receİved-Evil" was skipped as a Received- field, added after
// signing and still verifying. Python, Perl, JS and C keep such a name as the
// bytes it is.
func TestNonASCIIHeaderNamesAreNotFolded(t *testing.T) {
	raw := []byte("From: alice@test1.dkim2.com\r\nTo: bob@test2.dkim2.com\r\n" +
		"Subject: hello\r\n\r\nbody\r\n")
	signed := signOnce(t, raw, "../../keys/sel1._domainkey.test1.dkim2.com.pem",
		"sel1", "test1.dkim2.com", "alice@test1.dkim2.com", []string{"bob@test2.dkim2.com"})
	f := &JSONKeyFetcher{Path: "../../dns.json"}

	verify := func(msg []byte) error {
		res, err := Verify(bytes.NewReader(msg), f, VerifyOptions{SkipTimestampCheck: true})
		if err != nil {
			return err
		}
		if r := PrimaryResult(res); r != nil {
			return r.Error
		}
		return nil
	}
	if err := verify(signed); err != nil {
		t.Fatalf("the signed message: %v", err)
	}
	for _, added := range []string{
		"Receİved-Evil: x\r\n",                       // not a Received- field
		"X-Thİng: x\r\n",                             // an X- field: the prefix is ASCII
		"Authentİcation-Results: mx; dkim2=pass\r\n", // not ignored either way: hashed
		"Message-İnstance: m=9; h=sha256:AAAA:AAAA\r\n",
		"Keywords: x\r\n", // Kelvin sign: not "keywords"
	} {
		msg := append([]byte(added), signed...)
		err := verify(msg)
		if added[:2] == "X-" {
			if err != nil {
				t.Errorf("%q is an X- field, ignored: %v", added, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%q added after signing still verifies", added)
		}
	}
}
