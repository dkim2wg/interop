package dkim2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type TestResolver struct{}

func (t TestResolver) Resolve(_ context.Context, selector string, domain string) ([]string, error) {
	records := sync.OnceValue(
		func() map[string]map[string][][]string {
			f, err := os.Open(filepath.Join("testdata", "dns.json"))
			if err != nil {
				panic(err)
			}
			dec := json.NewDecoder(f)
			result := map[string]map[string][][]string{}
			err = dec.Decode(&result)
			if err != nil {
				panic(err)
			}
			return result
		})()
	dom, ok := records[domain]
	if !ok {
		return []string{}, nil
	}
	rec, ok := dom[selector+"._domainkey"]
	if !ok {
		return []string{}, nil
	}
	var results []string
	for _, rec := range rec {
		results = append(results, rec[1])
	}
	return results, nil
}

var _ KeyResolver = TestResolver{}

func NewTestResolver() TestResolver {
	return TestResolver{}
}

func loadPrivateKey(t testing.TB, name string) crypto.Signer {
	filename := filepath.Join("testdata", "keys", name)
	keyContent, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	key, err := parsePrivateKey(string(keyContent))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func parsePrivateKey(key string) (crypto.Signer, error) {
	keyfile := []byte(key)
	pemBlock, _ := pem.Decode(keyfile)
	if pemBlock != nil && pemBlock.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}

		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case ed25519.PrivateKey:
			return key, nil
		}
	}

	return nil, fmt.Errorf("failed to parse private key")
}

func loadEmail(t testing.TB, filename ...string) ([]byte, *mail.Message) {
	content, err := os.ReadFile(filepath.Join(filename...))
	if err != nil {
		t.Fatal(err)
	}
	//fmt.Printf("%q\n", content)
	msg, err := mail.ReadMessage(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	return content, msg
}

func splitTags(h string) (map[string]string, error) {
	ret := map[string]string{}
	h = strings.ReplaceAll(h, "\r\n", "")
	for kv := range strings.SplitAfterSeq(h, ";") {
		if strings.TrimSpace(kv) == "" {
			continue
		}
		k, v, found := strings.Cut(kv, "=")
		if !found {
			return nil, fmt.Errorf("no \"=\" found in %q", kv)
		}
		v = strings.TrimSuffix(v, ";")
		v = strings.TrimSpace(v)

		k = strings.TrimSpace(k)
		k = strings.ToLower(k)
		ret[k] = v
	}
	return ret, nil
}

func diffTags(t testing.TB, want, got []string) string {
	var wants, gots []map[string]string
	for _, w := range want {
		wantTags, err := splitTags(w)
		if err != nil {
			t.Fatal(err)
		}
		wants = append(wants, wantTags)
	}

	for _, g := range got {
		gotTags, err := splitTags(g)
		if err != nil {
			t.Fatal(err)
		}
		gots = append(gots, gotTags)
	}
	return cmp.Diff(wants, gots)
}
