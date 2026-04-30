package dkim2

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Verify reads r and verifies all DKIM2-Signature headers.
// Returns one VerifyResult per signature. Body is never buffered.
func Verify(r io.Reader, fetcher KeyFetcher) ([]VerifyResult, error) {
	headers, bodyReader, err := parseHeaders(r)
	if err != nil {
		return nil, fmt.Errorf("parsing headers: %w", err)
	}

	// Stream body for hash — never buffer
	bodyHash, err := hashBody(bodyReader)
	if err != nil {
		return nil, fmt.Errorf("body hash: %w", err)
	}

	// Separate MI, sig, and content headers; preserve original Raw for signing input
	var miHeaders []string  // raw strings from h.Raw (include CRLF)
	var sigHeaders []string // raw strings from h.Raw (include CRLF)
	var contentHeaders []Header

	for _, h := range headers {
		switch strings.ToLower(h.Name) {
		case "message-instance":
			miHeaders = append(miHeaders, h.Raw)
		case "dkim2-signature":
			sigHeaders = append(sigHeaders, h.Raw)
		default:
			contentHeaders = append(contentHeaders, h)
		}
	}

	if len(sigHeaders) == 0 {
		return nil, fmt.Errorf("no DKIM2-Signature headers found")
	}
	if len(miHeaders) == 0 {
		return nil, fmt.Errorf("no Message-Instance headers found")
	}

	// Spec review note #3: top sig's m= must equal the count of MI headers
	maxMIVersion := 0
	for _, raw := range miHeaders {
		mi, err := parseMI(raw)
		if err == nil && mi.Version > maxMIVersion {
			maxMIVersion = mi.Version
		}
	}

	var topSig *DKIM2Signature
	for _, raw := range sigHeaders {
		s, err := parseSig(raw)
		if err == nil {
			if topSig == nil || s.Sequence > topSig.Sequence {
				topSig = s
			}
		}
	}

	if topSig != nil && topSig.MIVersion != maxMIVersion {
		return []VerifyResult{{
			Sequence: topSig.Sequence,
			Domain:   topSig.Domain,
			Error: fmt.Errorf("top signature i=%d m=%d does not cover topmost MI m=%d",
				topSig.Sequence, topSig.MIVersion, maxMIVersion),
		}}, nil
	}

	// Compute content header hash for MI hash verification
	contentHeaderHash, err := hashHeaders(contentHeaders)
	if err != nil {
		return nil, err
	}

	// Sort sigs ascending by sequence
	sort.Slice(sigHeaders, func(i, j int) bool {
		a, _ := parseSig(sigHeaders[i])
		b, _ := parseSig(sigHeaders[j])
		if a == nil || b == nil {
			return false
		}
		return a.Sequence < b.Sequence
	})

	// Sort MIs ascending by version
	sort.Slice(miHeaders, func(i, j int) bool {
		a, _ := parseMI(miHeaders[i])
		b, _ := parseMI(miHeaders[j])
		if a == nil || b == nil {
			return false
		}
		return a.Version < b.Version
	})

	var results []VerifyResult

	for idx, rawSig := range sigHeaders {
		sig, err := parseSig(rawSig)
		if err != nil {
			results = append(results, VerifyResult{Error: err})
			continue
		}

		res := VerifyResult{Sequence: sig.Sequence, Domain: sig.Domain}

		// Find the MI for this signature's MI version
		var thisMI *MessageInstance
		for _, raw := range miHeaders {
			mi, err := parseMI(raw)
			if err == nil && mi.Version == sig.MIVersion {
				thisMI = mi
				break
			}
		}
		if thisMI == nil {
			res.Error = fmt.Errorf("i=%d: no MI header with m=%d", sig.Sequence, sig.MIVersion)
			results = append(results, res)
			continue
		}

		// Verify MI header and body hashes only for the outermost (latest) MI.
		// Earlier MI versions recorded hashes from a prior message state;
		// an intermediary may have modified headers/body since then.
		if sig.MIVersion == maxMIVersion {
			if string(thisMI.HeaderHash) != string(contentHeaderHash) {
				res.Error = fmt.Errorf("i=%d: header hash mismatch", sig.Sequence)
				results = append(results, res)
				continue
			}
			if string(thisMI.BodyHash) != string(bodyHash) {
				res.Error = fmt.Errorf("i=%d: body hash mismatch", sig.Sequence)
				results = append(results, res)
				continue
			}
		}

		// Fetch public key
		item := sig.Sigs[0]
		pubKey, keyAlg, err := fetcher.FetchPublicKey(item.Selector, sig.Domain)
		if err != nil {
			res.Error = fmt.Errorf("i=%d: key fetch: %w", sig.Sequence, err)
			results = append(results, res)
			continue
		}

		// Check algorithm compatibility
		normAlg := strings.TrimSuffix(item.Algorithm, "-sha256")
		normKeyAlg := strings.TrimSuffix(keyAlg, "-sha256")
		if normAlg != normKeyAlg {
			res.Error = fmt.Errorf("i=%d: algorithm mismatch: sig=%s key=%s",
				sig.Sequence, item.Algorithm, keyAlg)
			results = append(results, res)
			continue
		}

		// Build signing input:
		// MI headers with m= <= this sig's MIVersion (ascending)
		// Sig headers with i= < this sig's Sequence (ascending, i.e. indices 0..idx-1)
		// Incomplete form of this sig
		var sigInput []byte
		for _, raw := range miHeaders {
			mi, err := parseMI(raw)
			if err == nil && mi.Version <= sig.MIVersion {
				sigInput = append(sigInput, canonicalizeSigHeader(raw)...)
			}
		}
		for i, raw := range sigHeaders {
			if i >= idx {
				break
			}
			sigInput = append(sigInput, canonicalizeSigHeader(raw)...)
		}
		// The incomplete form: strip signature values from this sig's raw header
		incomplete := sig.incompleteForm(strings.TrimRight(rawSig, "\r\n"))
		sigInput = append(sigInput, canonicalizeSigHeader(incomplete+"\r\n")...)

		digest := sha256.Sum256(sigInput)

		if err := verifyDigest(pubKey, keyAlg, digest[:], item.Value); err != nil {
			res.Error = fmt.Errorf("i=%d: %w", sig.Sequence, err)
		}
		results = append(results, res)
	}

	return results, nil
}

func verifyDigest(key crypto.PublicKey, alg string, digest, sig []byte) error {
	switch k := key.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(k, digest, sig) {
			return fmt.Errorf("ed25519 signature verification failed")
		}
		return nil
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig)
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
}
