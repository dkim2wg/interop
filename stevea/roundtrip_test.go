package dkim2

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRoundTrip(t *testing.T) {
	tests := map[string]struct {
		Input    string
		Selector string
		Domain   string
		Key      string
		MailFrom string
		RcptTo   []string
	}{
		// Test 1: Simple message with Ed25519
		"simple-ed25519": {
			Input:    "simple.eml",
			Selector: "ed25519",
			Domain:   "test1.dkim2.com",
			Key:      "ed25519._domainkey.test1.dkim2.com.pem",
			MailFrom: "sender@test1.dkim2.com",
			RcptTo:   []string{"recipient@example.com"},
		},
		// Test 2: Simple message with RSA-1024
		"simple-rsa1024": {
			Input:    "simple.eml",
			Selector: "rsa1024",
			Domain:   "test1.dkim2.com",
			Key:      "rsa1024._domainkey.test1.dkim2.com.pem",
			MailFrom: "sender@test1.dkim2.com",
			RcptTo:   []string{"recipient@example.com"},
		},
		// Test 3: Simple message with RSA-2048 (sel1)
		"simple-rsa2048": {
			Input:    "simple.eml",
			Selector: "sel1",
			Domain:   "test1.dkim2.com",
			Key:      "sel1._domainkey.test1.dkim2.com.pem",
			MailFrom: "sender@test1.dkim2.com",
			RcptTo:   []string{"recipient@example.com"},
		},
		// Test 4: Multi-header message with continuation lines, X- header excluded
		"multiheader-ed25519": {
			Input:    "multiheader.eml",
			Selector: "ed25519",
			Domain:   "test2.dkim2.com",
			Key:      "ed25519._domainkey.test2.dkim2.com.pem",
			MailFrom: "sender@test2.dkim2.com",
			RcptTo:   []string{"recipient@example.com"},
		},
		// Test 5: Message with trailing blank lines (body canonicalization)
		"trailingblank-ed25519": {
			Input:    "trailingblank.eml",
			Selector: "ed25519",
			Domain:   "test3.dkim2.com",
			Key:      "ed25519._domainkey.test3.dkim2.com.pem",
			MailFrom: "sender@test3.dkim2.com",
			RcptTo:   []string{"recipient@example.com"},
		},
		// Test 6: Empty body message
		"emptybody-ed25519": {
			Input:    "emptybody.eml",
			Selector: "ed25519",
			Domain:   "test4.dkim2.com",
			Key:      "ed25519._domainkey.test4.dkim2.com.pem",
			MailFrom: "sender@test4.dkim2.com",
			RcptTo:   []string{"recipient@example.com"},
		},
		// Test 7: Multiple recipients
		"multirecipient-ed25519": {
			Input:    "multirecipient.eml",
			Selector: "ed25519",
			Domain:   "test5.dkim2.com",
			Key:      "ed25519._domainkey.test5.dkim2.com.pem",
			MailFrom: "sender@test5.dkim2.com",
			RcptTo:   []string{"alice@example.com", "bob@example.com", "charlie@example.com"},
		},
		// Test 8: DSN (empty MAIL FROM)
		"dsn-ed25519": {
			Input:    "simple.eml",
			Selector: "ed25519",
			Domain:   "test1.dkim2.com",
			Key:      "ed25519._domainkey.test1.dkim2.com.pem",
			MailFrom: "<>",
			RcptTo:   []string{"recipient@example.com"},
		},
		// Test 9: Different selectors on same domain (sel2)
		"simple-sel2": {
			Input:    "simple.eml",
			Selector: "sel2",
			Domain:   "test1.dkim2.com",
			Key:      "sel2._domainkey.test1.dkim2.com.pem",
			MailFrom: "sender@test1.dkim2.com",
			RcptTo:   []string{"recipient@example.com"},
		},
		// Test 10: Different selectors on same domain (sel3)
		"simple-sel3": {
			Input:    "simple.eml",
			Selector: "sel3",
			Domain:   "test1.dkim2.com",
			Key:      "sel3._domainkey.test1.dkim2.com.pem",
			MailFrom: "sender@test1.dkim2.com",
			RcptTo:   []string{"recipient@example.com"},
		},
		// Test 11: Duplicate headers (bottom-up ordering)
		"simple-sel4": {
			Input:    "simple.eml",
			Selector: "ed25519",
			Domain:   "test1.dkim2.com",
			Key:      "ed25519._domainkey.test1.dkim2.com.pem",
			MailFrom: "sender@test1.dkim2.com",
			RcptTo:   []string{"recipient@example.com"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			input, _ := loadEmail(t, "testdata", "golden", "emails", tc.Input)
			key := loadPrivateKey(t, tc.Key)
			signOpts := SignOptions{
				Domain:    tc.Domain,
				Timestamp: 1740000000,
				Keys: []SigningKey{
					{
						Selector: tc.Selector,
						Signer:   key,
					},
				},
				MailFrom: tc.MailFrom,
				RcptTo:   tc.RcptTo,
			}
			var output bytes.Buffer
			err := Sign(&output, bytes.NewReader(input), signOpts)
			if err != nil {
				t.Fatal(err)
			}
			verifyOpts := VerifyOptions{
				IgnoreTimestamp: true,
				Resolver:        NewTestResolver(),
				MailFrom:        tc.MailFrom,
				RcptTo:          tc.RcptTo,
			}
			result := Verify(context.Background(),
				bytes.NewReader(output.Bytes()), verifyOpts)
			if result.State() != StatePass {
				t.Errorf("Verify() returned wrong state: %s", result.Err)
				t.Logf("Signed mail:\n---\n%s\n---", output.String())
			}
			resultAll := VerifyAll(context.Background(),
				bytes.NewReader(output.Bytes()), verifyOpts)
			if resultAll.State() != StatePass {
				t.Errorf("VerifyAll() returned wrong state: %s", resultAll.Err)
			}

			goldenFile := filepath.Join("testdata", "golden", "expected", name+".eml")
			_, set := os.LookupEnv("GENERATE")
			if set {
				err = os.WriteFile(goldenFile, output.Bytes(), 0644)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("Written golden file: %s", goldenFile)
			} else {
				want, err := os.ReadFile(goldenFile)
				if err != nil {
					t.Skipf("Golden file not present: %v", err)
				}
				if diff := cmp.Diff(string(want), string(output.Bytes())); diff != "" {
					t.Errorf("Golden file mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
