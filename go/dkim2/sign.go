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

	raw, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading message: %w", err)
	}

	// 1. Parse headers; buffer body for re-emission.
	headers, bodyReader, err := parseHeaders(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("parsing headers: %w", err)
	}
	bodyBuf := &bytes.Buffer{}
	if _, err := io.Copy(bodyBuf, bodyReader); err != nil {
		return fmt.Errorf("reading body: %w", err)
	}

	// Out-of-range i=/m= are refused even with the gate bypassed: the next
	// i= and m= are computed from them below.
	{
		var mis, sigs []string
		for _, h := range headers {
			switch strings.ToLower(h.Name) {
			case "message-instance":
				mis = append(mis, h.Raw)
			case "dkim2-signature":
				sigs = append(sigs, h.Raw)
			}
		}
		if err := chainRangeError(mis, sigs); err != nil {
			return fmt.Errorf("not signing: %w", err)
		}
	}

	// Signer gate: never put our signature over a chain that does not check out.
	if !opts.SkipUpstreamCheck {
		if err := checkUpstream(raw, headers, opts); err != nil {
			return err
		}
	}

	// 2. Determine the hash algorithm(s) to sign with (spec-06 §3.1). Default
	// stays sha256-only: the signer default MUST NOT change.
	algs := opts.HashAlgs
	if len(algs) == 0 {
		algs = []string{"sha256"}
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
	var topMI *MessageInstance
	for _, raw := range existingMI {
		mi, err := parseMI(raw)
		if err == nil && mi.Version >= miVersion {
			miVersion = mi.Version + 1
			topMI = mi
		}
	}

	sigSeq := 1
	for _, raw := range existingSigs {
		sig, err := parseSig(raw)
		if err == nil && sig.Sequence >= sigSeq {
			sigSeq = sig.Sequence + 1
		}
	}

	// 4. Header/body hashes for every requested algorithm (excludes
	// MI/DKIM2-Sig/etc per §5.2; body per §5.1), in the requested order.
	var newHashes []HashSet
	for _, alg := range algs {
		hHash, err := hashHeaders(headers, alg)
		if err != nil {
			return fmt.Errorf("header hash: %w", err)
		}
		bHash, err := hashBody(bytes.NewReader(bodyBuf.Bytes()), alg)
		if err != nil {
			return fmt.Errorf("body hash: %w", err)
		}
		newHashes = append(newHashes, HashSet{
			Alg:        alg,
			HeaderHash: base64.StdEncoding.EncodeToString(hHash),
			BodyHash:   base64.StdEncoding.EncodeToString(bHash),
		})
	}

	// 5. Build new MI header — unless this hop changed nothing.
	//
	// draft-06 §9.1/§9.2.5: a forwarder that leaves both hashes unchanged adds
	// no new Message-Instance; it signs against the existing top instance and
	// reuses its m=.  An instance with identical hashes and no Recipe is not
	// forbidden, but §9.1 still calls it "most likely to be pointless and a
	// waste of time and energy"; this implementation avoids it by default,
	// and verifiers must still tolerate one from elsewhere.
	addMI := true
	if topMI != nil && hashSetsEqual(topMI.Hashes, newHashes) {
		addMI = false
		miVersion = topMI.Version
	}

	var newMIStr string
	if addMI {
		newMI := &MessageInstance{
			Version: miVersion,
			Hashes:  newHashes,
		}
		newMIStr = newMI.String()
	}

	// 6. Determine algorithm from key type.
	algorithm, err := algorithmForKey(key)
	if err != nil {
		return err
	}

	// 7. Build incomplete DKIM2-Signature (s= values empty per §8.5).
	incomplete := buildIncomplete(sigSeq, miVersion, ts,
		opts.Domain, opts.MailFrom, opts.RcptTo,
		opts.NextDomain, opts.Selector, algorithm)

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
	if addMI {
		sigInput = append(sigInput, canonicalizeSigHeader(newMIStr+"\r\n")...)
	}
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
	if addMI {
		if _, err := fmt.Fprintf(w, "%s\r\n", newMIStr); err != nil {
			return err
		}
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

// checkUpstream is the signer gate.  A message with no DKIM2 headers passes.
// Otherwise the existing chain is verified in outbound mode (an unsigned top
// Message-Instance is allowed) and, unless opts.AllowNullBodyRecipe, an
// UNSIGNED top Message-Instance (no DKIM2-Signature carries its m=) must not
// carry a null body Recipe.  A null top an upstream domain already signed is
// extended normally: that is a forwarder relaying, not this hop discarding.
func checkUpstream(raw []byte, headers []Header, opts SignOptions) error {
	var mis []*MessageInstance
	signedM := map[int]bool{}
	chain := false
	for _, h := range headers {
		switch strings.ToLower(h.Name) {
		case "dkim2-signature":
			chain = true
			// Only a signature with a valid i= can cover anything; the
			// verifier below PERMERRORs on any other.
			if sig, err := parseSig(h.Raw); err == nil && validSequenceTag(h.Raw) {
				signedM[sig.MIVersion] = true
			}
		case "message-instance":
			chain = true
			if mi, err := parseMI(h.Raw); err == nil {
				mis = append(mis, mi)
			}
		}
	}
	if !chain {
		return nil
	}
	fetcher := opts.Fetcher
	if fetcher == nil {
		fetcher = &NetKeyFetcher{}
	}
	results, err := VerifyFull(bytes.NewReader(raw), fetcher,
		VerifyOptions{SkipTimestampCheck: opts.SkipTimestampCheck, Outbound: true, Signer: opts.Domain})
	if err != nil {
		status := "fail"
		if strings.HasPrefix(err.Error(), "PERMERROR") {
			status = "permerror"
		}
		return fmt.Errorf("not signing: upstream DKIM2 chain result=%s: %w", status, err)
	}
	for _, r := range results {
		if r.Error == nil {
			continue
		}
		if strings.HasPrefix(r.Domain, "MI-chain") {
			return fmt.Errorf("not signing: Message-Instance chain does not undo cleanly: %w", r.Error)
		}
		return fmt.Errorf("not signing: upstream DKIM2 chain result=fail i=%d d=%s: %w", r.Sequence, r.Domain, r.Error)
	}
	var top *MessageInstance
	for _, mi := range mis {
		if top == nil || mi.Version > top.Version {
			top = mi
		}
	}
	if top != nil && top.Recipe != nil && top.Recipe.BodyNull && !signedM[top.Version] && !opts.AllowNullBodyRecipe {
		return fmt.Errorf("not signing: unsigned top Message-Instance m=%d has a null body Recipe (set allow-null-body-recipe to sign anyway)", top.Version)
	}
	return nil
}
