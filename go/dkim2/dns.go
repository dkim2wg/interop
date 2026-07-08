package dkim2

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// KeyFetcher fetches DKIM2 public keys by selector and domain.
type KeyFetcher interface {
	// FetchPublicKey returns the public key, algorithm string, and error.
	// algorithm is "rsa-sha256" or "ed25519-sha256".
	FetchPublicKey(selector, domain string) (crypto.PublicKey, string, error)
}

// JSONKeyFetcher reads keys from a dns.json file.
type JSONKeyFetcher struct {
	Path string
}

func (f *JSONKeyFetcher) FetchPublicKey(selector, domain string) (crypto.PublicKey, string, error) {
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, "", fmt.Errorf("reading dns.json: %w", err)
	}
	// dns.json: map[domain]map[selectorKey][][2]string
	var db map[string]map[string][][2]string
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, "", fmt.Errorf("parsing dns.json: %w", err)
	}

	domainRecs, ok := db[domain]
	if !ok {
		return nil, "", fmt.Errorf("domain %q not found in dns.json", domain)
	}
	key := selector + "._domainkey"
	recs, ok := domainRecs[key]
	if !ok {
		return nil, "", fmt.Errorf("selector %q not found for %q in dns.json", key, domain)
	}
	for _, rec := range recs {
		if strings.ToLower(rec[0]) == "txt" {
			return parseDKIM1TXT(rec[1])
		}
	}
	return nil, "", fmt.Errorf("no TXT record for %s.%s", key, domain)
}

// parseDKIM1TXT parses a DKIM1 TXT record and returns the public key.
func parseDKIM1TXT(txt string) (crypto.PublicKey, string, error) {
	tags := make(map[string]string)
	for _, part := range strings.Split(txt, ";") {
		part = strings.TrimSpace(part)
		if eq := strings.IndexByte(part, '='); eq >= 0 {
			k := strings.TrimSpace(part[:eq])
			v := strings.TrimSpace(part[eq+1:])
			tags[k] = v
		}
	}

	keyType := tags["k"]
	if keyType == "" {
		keyType = "rsa"
	}
	pubB64 := tags["p"]
	pubBytes, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(pubB64, "="))
	if err != nil {
		return nil, "", fmt.Errorf("decoding public key: %w", err)
	}

	switch keyType {
	case "ed25519":
		if len(pubBytes) == 32 {
			return ed25519.PublicKey(pubBytes), "ed25519-sha256", nil
		}
		key, err := x509.ParsePKIXPublicKey(pubBytes)
		if err != nil {
			return nil, "", fmt.Errorf("parsing ed25519 public key: %w", err)
		}
		edKey, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, "", fmt.Errorf("expected ed25519 key, got %T", key)
		}
		return edKey, "ed25519-sha256", nil
	case "rsa", "rsa-sha256":
		key, err := x509.ParsePKIXPublicKey(pubBytes)
		if err != nil {
			// Some DKIM keys are published as bare PKCS#1 (RSAPublicKey)
			// rather than SubjectPublicKeyInfo; accept both.
			if k1, e1 := x509.ParsePKCS1PublicKey(pubBytes); e1 == nil {
				return k1, "rsa-sha256", nil
			}
			return nil, "", fmt.Errorf("parsing RSA public key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, "", fmt.Errorf("expected RSA key, got %T", key)
		}
		return rsaKey, "rsa-sha256", nil
	default:
		return nil, "", fmt.Errorf("unsupported key type: %q", keyType)
	}
}

// NetKeyFetcher looks up real DNS TXT records via net.LookupTXT.
type NetKeyFetcher struct{}

func (f *NetKeyFetcher) FetchPublicKey(selector, domain string) (crypto.PublicKey, string, error) {
	fqdn := selector + "._domainkey." + domain
	txts, err := net.DefaultResolver.LookupTXT(context.Background(), fqdn)
	if err != nil {
		return nil, "", fmt.Errorf("DNS lookup for %s: %w", fqdn, err)
	}
	for _, txt := range txts {
		if strings.Contains(txt, "v=DKIM1") {
			return parseDKIM1TXT(txt)
		}
	}
	return nil, "", fmt.Errorf("no DKIM1 TXT record at %s", fqdn)
}
