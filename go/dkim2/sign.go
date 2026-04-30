package dkim2

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Sign reads r, prepends a new Message-Instance and DKIM2-Signature header,
// and writes the complete signed message to w. Output uses CRLF line endings
// throughout (input line endings are normalised).
func Sign(r io.Reader, w io.Writer, key crypto.PrivateKey, opts SignOptions) error {
	ts := opts.Timestamp
	if ts == 0 {
		ts = time.Now().Unix()
	}

	// 1. Parse headers; buffer body for re-emission.
	headers, bodyReader, err := parseHeaders(r)
	if err != nil {
		return fmt.Errorf("parsing headers: %w", err)
	}
	bodyBuf := &bytes.Buffer{}
	if _, err := io.Copy(bodyBuf, bodyReader); err != nil {
		return fmt.Errorf("reading body: %w", err)
	}

	// 2. Body hash (over canonicalised body).
	bodyHash, err := hashBody(bytes.NewReader(bodyBuf.Bytes()))
	if err != nil {
		return fmt.Errorf("body hash: %w", err)
	}

	// 3. Collect existing MI / signature headers, find next m= and i= values.
	var existingMI []string
	var existingSigs []string
	for _, h := range headers {
		switch strings.ToLower(h.Name) {
		case "message-instance":
			existingMI = append(existingMI, h.Raw)
		case "dkim2-signature":
			existingSigs = append(existingSigs, h.Raw)
		}
	}

	miVersion := 1
	for _, raw := range existingMI {
		mi, err := parseMI(raw)
		if err == nil && mi.Version >= miVersion {
			miVersion = mi.Version + 1
		}
	}

	sigSeq := 1
	for _, raw := range existingSigs {
		sig, err := parseSig(raw)
		if err == nil && sig.Sequence >= sigSeq {
			sigSeq = sig.Sequence + 1
		}
	}

	// 4. Header hash (excludes MI/DKIM2-Sig/etc per §5.2).
	headerHash, err := hashHeaders(headers)
	if err != nil {
		return fmt.Errorf("header hash: %w", err)
	}

	// 5. Build new MI header.
	newMI := &MessageInstance{
		Version:    miVersion,
		HeaderHash: headerHash,
		BodyHash:   bodyHash,
	}
	newMIStr := newMI.String()

	// 6. Determine algorithm from key type.
	algorithm, err := algorithmForKey(key)
	if err != nil {
		return err
	}

	// 7. Build incomplete DKIM2-Signature (s= values empty per §8.5).
	incomplete := buildIncomplete(sigSeq, miVersion, ts,
		opts.Domain, opts.MailFrom, opts.RcptTo,
		opts.Selector, algorithm)

	// 8. Build the signing input: existing MIs (incl. new) ascending, existing
	//    sigs ascending, then the incomplete sig.
	sort.Slice(existingMI, func(i, j int) bool {
		a, errA := parseMI(existingMI[i])
		b, errB := parseMI(existingMI[j])
		if errA != nil || errB != nil {
			return false
		}
		return a.Version < b.Version
	})
	sort.Slice(existingSigs, func(i, j int) bool {
		a, errA := parseSig(existingSigs[i])
		b, errB := parseSig(existingSigs[j])
		if errA != nil || errB != nil {
			return false
		}
		return a.Sequence < b.Sequence
	})

	var sigInput []byte
	for _, mi := range existingMI {
		sigInput = append(sigInput, canonicalizeSigHeader(mi)...)
	}
	sigInput = append(sigInput, canonicalizeSigHeader(newMIStr+"\r\n")...)
	for _, s := range existingSigs {
		sigInput = append(sigInput, canonicalizeSigHeader(s)...)
	}
	sigInput = append(sigInput, canonicalizeSigHeader(incomplete+"\r\n")...)

	// 9. Hash signing input.
	digest := sha256.Sum256(sigInput)

	// 10. Sign the digest.
	sigBytes, err := signDigest(key, digest[:])
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}

	// 11. Build complete DKIM2-Signature header by inserting the sig bytes
	//     into the empty s= placeholder.
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)
	target := opts.Selector + ":" + algorithm + ":;"
	completeSig := strings.Replace(incomplete, target,
		opts.Selector+":"+algorithm+":"+sigB64+";", 1)
	if completeSig == incomplete {
		return fmt.Errorf("sign: s= placeholder %q not found in incomplete sig", target)
	}

	// 12. Write: complete sig + new MI + original headers + body.
	if _, err := fmt.Fprintf(w, "%s\r\n", completeSig); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s\r\n", newMIStr); err != nil {
		return err
	}
	for _, h := range headers {
		if _, err := io.WriteString(w, h.Raw); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "\r\n"); err != nil {
		return err
	}
	if _, err := w.Write(bodyBuf.Bytes()); err != nil {
		return err
	}

	return nil
}

func algorithmForKey(key crypto.PrivateKey) (string, error) {
	switch key.(type) {
	case ed25519.PrivateKey:
		return "ed25519-sha256", nil
	case *rsa.PrivateKey:
		return "rsa-sha256", nil
	default:
		return "", fmt.Errorf("unsupported key type: %T", key)
	}
}

func signDigest(key crypto.PrivateKey, digest []byte) ([]byte, error) {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return ed25519.Sign(k, digest), nil
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// LoadPrivateKey parses a PEM-encoded private key (PKCS#8 format).
func LoadPrivateKey(pemData []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	return key, nil
}
