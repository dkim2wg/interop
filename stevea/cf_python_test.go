package dkim2

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPython_Verify(t *testing.T) {
	tests := map[string]struct {
		MailFrom string
		RcptTo   []string
	}{
		"simple-ed25519": {
			MailFrom: "sender@test1.dkim2.com",
			RcptTo:   []string{"recipient@example.com"},
		},
		"simple-rsa1024": {
			MailFrom: "sender@test1.dkim2.com",
			RcptTo:   []string{"recipient@example.com"},
		},
		"simple-rsa2048":         {},
		"simple-sel2":            {},
		"simple-sel3":            {},
		"dsn-ed25519":            {},
		"dupheaders-ed25519":     {},
		"emptybody-ed25519":      {},
		"multiheader-ed25519":    {},
		"trailingblank-ed25519":  {},
		"multirecipient-ed25519": {},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", "interop", "python", "expected", name+".eml"))
			if err != nil {
				t.Fatalf("Failed to open file: %v", err)
			}
			defer func(f *os.File) {
				_ = f.Close()
			}(f)
			result := Verify(context.Background(), f,
				VerifyOptions{
					IgnoreTimestamp: true,
					Resolver:        NewTestResolver(),
					MailFrom:        tc.MailFrom,
					RcptTo:          tc.RcptTo,
				})
			if result.State() != StatePass {
				t.Fatalf("Failed to verify message: %v", result.AuthenticationResult())
			}
		})
	}
}

func TestPython_VerifyAll(t *testing.T) {
	tests := map[string]struct {
		MailFrom string
		RcptTo   []string
	}{
		"multihop-3hop-dup-headers": {},
		"multihop-body-footer":      {},
		"multihop-dup-headers":      {},
		"multihop-header-add":       {},
		"multihop-header-replace":   {},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", "interop", "python", "expected", name+".eml"))
			if err != nil {
				t.Fatalf("Failed to open file: %v", err)
			}
			defer func(f *os.File) {
				_ = f.Close()
			}(f)
			result := VerifyAll(context.Background(), f,
				VerifyOptions{
					IgnoreTimestamp: true,
					Resolver:        NewTestResolver(),
					MailFrom:        tc.MailFrom,
					RcptTo:          tc.RcptTo,
				})
			if result.State() != StatePass {
				t.Fatalf("Failed to verify message: %v", result.AuthenticationResult())
			}
		})
	}
}
