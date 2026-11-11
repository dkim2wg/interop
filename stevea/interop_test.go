package dkim2

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

const dnsFile = "../dns.json"

func TestInterop_Python(t *testing.T) {
	emailDir := "../python/tests/expected"
	_, err := os.Stat(emailDir)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		t.Skipf("skipping test because %s does not exist", emailDir)
	}
	messages, err := filepath.Glob(filepath.Join(emailDir, "*.eml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range messages {
		name := filepath.Base(message)
		t.Run(name, func(t *testing.T) {
			if name == "emptybody-ed25519.eml" {
				t.Skipf("skipping %s as we fail on it due to bare CR", name)
			}
			f, err := os.Open(message)
			if err != nil {
				t.Fatal(err)
			}
			verifyOpts := VerifyOptions{
				Resolver:        NewTestResolver(dnsFile),
				IgnoreTimestamp: true,
			}
			result := Verify(context.Background(), f, verifyOpts)
			if result.State() != StatePass {
				t.Errorf("Verify() got %s (%v), want %s", result.Err, errors.Unwrap(result.Err), StatePass)

			}
		})
	}
}

func TestInterop_Brong(t *testing.T) {
	emailDir := "../brong/tests/expected"
	_, err := os.Stat(emailDir)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		t.Skipf("skipping test because %s does not exist", emailDir)
	}
	messages, err := filepath.Glob(filepath.Join(emailDir, "*.eml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range messages {
		name := filepath.Base(message)
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(message)
			if err != nil {
				t.Fatal(err)
			}
			verifyOpts := VerifyOptions{
				Resolver:        NewTestResolver(dnsFile),
				IgnoreTimestamp: true,
			}
			result := Verify(context.Background(), f, verifyOpts)
			if result.State() != StatePass {
				t.Errorf("Verify() got %s (%v), want %s", result.Err, errors.Unwrap(result.Err), StatePass)
			}
		})
	}
}
