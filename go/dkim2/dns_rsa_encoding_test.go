package dkim2

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"os"
	"testing"
)

// TestParseDKIM1TXTAcceptsBothRSAEncodings pins the RFC 6376 erratum 3017
// compatibility rule: a DKIM p= value may carry an RSA key either as a full
// SubjectPublicKeyInfo (what `openssl rsa -pubout` emits, and what every
// generator in this repo publishes) or as a bare PKCS#1 RSAPublicKey, which is
// what RFC 6376 §3.6.1 literally says. Verifiers must accept both, so removing
// the PKCS#1 fallback in parseDKIM1TXT must fail this test.
//
// See https://github.com/dkim2wg/interop/issues/9.
func TestParseDKIM1TXTAcceptsBothRSAEncodings(t *testing.T) {
	pemBytes, err := os.ReadFile("../../keys/sel1._domainkey.test1.dkim2.com.pem")
	if err != nil {
		t.Skip("key not found")
	}
	priv, err := LoadPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected an RSA test key, got %T", priv)
	}

	spki, err := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := x509.MarshalPKCS1PublicKey(&rsaPriv.PublicKey)

	for _, tc := range []struct {
		name string
		der  []byte
	}{
		{"SubjectPublicKeyInfo", spki},
		{"bare PKCS#1 RSAPublicKey", pkcs1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			txt := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(tc.der)
			key, alg, err := parseDKIM1TXT(txt)
			if err != nil {
				t.Fatalf("parseDKIM1TXT rejected a %s key: %v", tc.name, err)
			}
			if alg != "rsa-sha256" {
				t.Errorf("algorithm = %q, want rsa-sha256", alg)
			}
			got, ok := key.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("key type = %T, want *rsa.PublicKey", key)
			}
			if !got.Equal(&rsaPriv.PublicKey) {
				t.Error("parsed key does not match the original public key")
			}
		})
	}
}
