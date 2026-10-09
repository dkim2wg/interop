package dkim2

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
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
		return nil, "", fmt.Errorf("%w: domain %q not in dns.json", ErrKeyNotFound, domain)
	}
	key := selector + "._domainkey"
	recs, ok := domainRecs[key]
	if !ok {
		return nil, "", fmt.Errorf("%w: %q not in dns.json for %q", ErrKeyNotFound, key, domain)
	}
	// Each TXT entry is one RR (its strings already joined).
	var rrs [][]string
	for _, rec := range recs {
		if strings.ToLower(rec[0]) == "txt" {
			rrs = append(rrs, []string{rec[1]})
		}
	}
	return keyFromTXTRecords(rrs, key+"."+domain)
}

// Key-record outcomes (spec-06 §11.5).  A KeyFetcher wraps one of these
// (errors.Is): ErrKeyNotFound for an absent record (the item is skipped), the
// others for a record that is present but unusable ("PERMERROR
// DKIM2-Signature i=<x> public key <selector> <problem>").  Any other fetch
// error is a DNS failure: TEMPERROR ... could not be fetched.
var (
	// ErrKeyNotFound: no key record (NXDOMAIN, or no TXT RR at the name).
	ErrKeyNotFound = errors.New("does not exist")

	ErrKeyMultipleRecords   = errors.New("has multiple records")
	ErrKeySyntax            = errors.New("has a syntax error")
	ErrKeyRevoked           = errors.New("has been revoked")
	ErrKeyAlgorithmMismatch = errors.New("algorithm mismatch")
)

// keyRecordProblem returns the §11.5 wording for a key-record error, or "".
func keyRecordProblem(err error) string {
	for _, e := range []error{ErrKeyMultipleRecords, ErrKeySyntax, ErrKeyRevoked, ErrKeyAlgorithmMismatch} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return ""
}

// keyFromTXTRecords turns the TXT RRset at a key's name into a public key.
// Each RR is its list of character-strings, concatenated with nothing between
// them (dns-00 §3.4.2.2); more than one RR is an error.  An empty RRset keeps
// the "no record" behaviour of an absent key.
func keyFromTXTRecords(rrs [][]string, name string) (crypto.PublicKey, string, error) {
	switch len(rrs) {
	case 0:
		return nil, "", fmt.Errorf("%w: no TXT record at %s", ErrKeyNotFound, name)
	case 1:
		return parseDKIM1TXT(strings.Join(rrs[0], ""))
	default:
		return nil, "", fmt.Errorf("%w (%d TXT records at %s)", ErrKeyMultipleRecords, len(rrs), name)
	}
}

func isKeyWSP(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' }

// validKeyTagName: ALPHA *(ALPHA / DIGIT / "_") (dns-00 §3.2).
func validKeyTagName(n string) bool {
	if n == "" {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		alpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if i == 0 && !alpha {
			return false
		}
		if !alpha && !(c >= '0' && c <= '9') && c != '_' {
			return false
		}
	}
	return true
}

// parseDKIM1TXT validates a whole key record (dns-00 §3.2 tag-list, §3.4.1)
// and returns its public key and the signature algorithm that key serves.
// Tag names are case sensitive; a repeated tag, a v= that is not first or not
// exactly DKIM1, or a missing/undecodable p= is a syntax error; an empty p= is
// revoked; a k= other than rsa or ed25519 is an algorithm mismatch.  Unknown
// and retired tags (h=, n=, s=, t=) are ignored.
func parseDKIM1TXT(txt string) (crypto.PublicKey, string, error) {
	tags := make(map[string]string)
	idx := 0
	for _, spec := range strings.Split(txt, ";") {
		if strings.TrimFunc(spec, isKeyWSP) == "" {
			continue // empty spec, e.g. after a trailing ";"
		}
		eq := strings.IndexByte(spec, '=')
		if eq < 0 {
			return nil, "", fmt.Errorf("%w: %q is not a tag=value", ErrKeySyntax, spec)
		}
		name := strings.TrimFunc(spec[:eq], isKeyWSP)
		if !validKeyTagName(name) {
			return nil, "", fmt.Errorf("%w: bad tag name %q", ErrKeySyntax, name)
		}
		if _, dup := tags[name]; dup {
			return nil, "", fmt.Errorf("%w: repeated tag %s=", ErrKeySyntax, name)
		}
		val := strings.TrimFunc(spec[eq+1:], isKeyWSP)
		if name == "v" && (idx != 0 || val != "DKIM1") {
			return nil, "", fmt.Errorf("%w: v= must be the first tag and DKIM1", ErrKeySyntax)
		}
		tags[name] = val
		idx++
	}

	pubB64, ok := tags["p"]
	if !ok {
		return nil, "", fmt.Errorf("%w: no p= tag", ErrKeySyntax)
	}
	pubB64 = strings.Map(func(r rune) rune {
		if isKeyWSP(r) {
			return -1
		}
		return r
	}, pubB64)
	if pubB64 == "" {
		return nil, "", ErrKeyRevoked
	}

	keyType, ok := tags["k"]
	if !ok {
		keyType = "rsa"
	}
	if keyType != "rsa" && keyType != "ed25519" {
		return nil, "", fmt.Errorf("%w: unsupported key type k=%s", ErrKeyAlgorithmMismatch, keyType)
	}

	// A base64string, padded to a multiple of four (spec-06 §2.13).
	pubBytes, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return nil, "", fmt.Errorf("%w: p= is not padded base64", ErrKeySyntax)
	}

	switch keyType {
	case "ed25519":
		if len(pubBytes) == ed25519.PublicKeySize {
			return ed25519.PublicKey(pubBytes), "ed25519-sha256", nil
		}
		key, err := x509.ParsePKIXPublicKey(pubBytes)
		if err != nil {
			return nil, "", fmt.Errorf("%w: parsing ed25519 public key: %v", ErrKeySyntax, err)
		}
		edKey, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, "", fmt.Errorf("%w: k=ed25519 but p= is a %T", ErrKeySyntax, key)
		}
		return edKey, "ed25519-sha256", nil
	default: // rsa
		key, err := x509.ParsePKIXPublicKey(pubBytes)
		if err != nil {
			// Some DKIM keys are published as bare PKCS#1 (RSAPublicKey)
			// rather than SubjectPublicKeyInfo; accept both.
			if k1, e1 := x509.ParsePKCS1PublicKey(pubBytes); e1 == nil {
				return k1, "rsa-sha256", nil
			}
			return nil, "", fmt.Errorf("%w: parsing RSA public key: %v", ErrKeySyntax, err)
		}
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, "", fmt.Errorf("%w: k=rsa but p= is a %T", ErrKeySyntax, key)
		}
		return rsaKey, "rsa-sha256", nil
	}
}

// NetKeyFetcher looks up real DNS TXT records via net.LookupTXT.
type NetKeyFetcher struct{}

func (f *NetKeyFetcher) FetchPublicKey(selector, domain string) (crypto.PublicKey, string, error) {
	fqdn := selector + "._domainkey." + domain
	txts, err := net.DefaultResolver.LookupTXT(context.Background(), fqdn)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, "", fmt.Errorf("%w: %s", ErrKeyNotFound, fqdn)
		}
		return nil, "", fmt.Errorf("DNS lookup for %s: %w", fqdn, err)
	}
	// LookupTXT returns one string per RR, the RR's character-strings
	// already concatenated with nothing between them.
	rrs := make([][]string, len(txts))
	for i, txt := range txts {
		rrs[i] = []string{txt}
	}
	return keyFromTXTRecords(rrs, fqdn)
}
