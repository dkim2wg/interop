package dkim2

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Verify reads r and verifies all DKIM2-Signature headers.
// Returns one VerifyResult per signature. Body is never buffered.
// An optional VerifyOptions may be passed to enable §10.4 envelope matching.
func Verify(r io.Reader, fetcher KeyFetcher, opts ...VerifyOptions) ([]VerifyResult, error) {
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

	// Local policy (stricter than spec-04): the top (highest i=) signature
	// MUST NOT carry nd=. The only legitimate nd= producer emits the nd=
	// signature together with the matching higher-i= signature at the same
	// time, so nd= should never appear alone on the top signature. This is
	// distinct from checkChainOfCustody's adjacency handling below, which
	// still allows (and requires) nd= on non-top signatures.
	if topSig != nil && topSig.NextDomain != "" {
		return nil, fmt.Errorf("DKIM2-Signature i=%d unexpected nd= tag", topSig.Sequence)
	}

	if topSig != nil && topSig.MIVersion != maxMIVersion {
		return []VerifyResult{{
			Sequence: topSig.Sequence,
			Domain:   topSig.Domain,
			Error: fmt.Errorf("top signature i=%d m=%d does not cover topmost MI m=%d",
				topSig.Sequence, topSig.MIVersion, maxMIVersion),
		}}, nil
	}

	// §10.4 MUST: envelope exact-match against top sig if caller provided values
	if len(opts) > 0 && topSig != nil {
		opt := opts[0]
		if opt.MailFrom != "" {
			if normAddr(opt.MailFrom) != normAddr(topSig.MailFrom) {
				return nil, fmt.Errorf("DKIM2-Signature i=%d MAIL FROM %s did not match",
					topSig.Sequence, opt.MailFrom)
			}
		}
		if opt.RcptTo != nil {
			for _, delivered := range opt.RcptTo {
				found := false
				for _, rt := range topSig.RcptTo {
					if normAddr(delivered) == normAddr(rt) {
						found = true
						break
					}
				}
				if !found {
					return nil, fmt.Errorf("DKIM2-Signature i=%d RCPT TO %s did not match",
						topSig.Sequence, delivered)
				}
			}
		}
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

	// §7.1 MUST: i= values must be contiguous 1..N
	for idx, raw := range sigHeaders {
		sig, _ := parseSig(raw)
		if sig == nil || sig.Sequence != idx+1 {
			expected := idx + 1
			got := 0
			if sig != nil {
				got = sig.Sequence
			}
			return nil, fmt.Errorf("i= not contiguous: expected %d got %d", expected, got)
		}
	}
	// §7.1 MUST: m= values must be contiguous 1..N
	for idx, raw := range miHeaders {
		mi, _ := parseMI(raw)
		if mi == nil || mi.Version != idx+1 {
			expected := idx + 1
			got := 0
			if mi != nil {
				got = mi.Version
			}
			return nil, fmt.Errorf("m= not contiguous: expected %d got %d", expected, got)
		}
	}

	// §7.1 MUST: every MI must be referenced by at least one signature
	{
		miReferenced := make(map[int]bool)
		for _, raw := range sigHeaders {
			sig, _ := parseSig(raw)
			if sig != nil {
				miReferenced[sig.MIVersion] = true
			}
		}
		for _, raw := range miHeaders {
			mi, _ := parseMI(raw)
			if mi != nil && !miReferenced[mi.Version] {
				return nil, fmt.Errorf("Message-Instance m=%d has no referencing signature", mi.Version)
			}
		}
	}

	// §8.2/§11.4 MUST: chain-of-custody between consecutive signatures.
	if len(sigHeaders) > 1 {
		parsedSigs := make([]*DKIM2Signature, len(sigHeaders))
		for i, raw := range sigHeaders {
			parsedSigs[i], _ = parseSig(raw)
		}
		if err := checkChainOfCustody(parsedSigs); err != nil {
			return nil, err
		}
	}

	// §10.8 SHOULD: reject if a donotmodify or donotexplode request was violated
	{
		miByVersion := make(map[int]*MessageInstance)
		for _, raw := range miHeaders {
			mi, err := parseMI(raw)
			if err == nil {
				miByVersion[mi.Version] = mi
			}
		}
		for _, raw := range sigHeaders {
			sig, err := parseSig(raw)
			if err != nil {
				continue
			}
			for _, flag := range sig.Flags {
				switch flag {
				case "donotmodify":
					m := sig.MIVersion
					cur, hasCur := miByVersion[m]
					next, hasNext := miByVersion[m+1]
					if hasCur && hasNext {
						if !bytes.Equal(cur.BodyHash, next.BodyHash) || !bytes.Equal(cur.HeaderHash, next.HeaderHash) {
							return nil, fmt.Errorf("i=%d: message modified despite donotmodify request", sig.Sequence)
						}
					}
				case "donotexplode":
					for _, raw2 := range sigHeaders {
						sig2, err2 := parseSig(raw2)
						if err2 != nil || sig2.Sequence <= sig.Sequence {
							continue
						}
						for _, f2 := range sig2.Flags {
							if f2 == "exploded" {
								return nil, fmt.Errorf("i=%d: message exploded despite donotexplode request at i=%d", sig2.Sequence, sig.Sequence)
							}
						}
					}
				}
			}
		}
	}

	skipTS := len(opts) > 0 && opts[0].SkipTimestampCheck
	now := time.Now().Unix()

	var results []VerifyResult

	for idx, rawSig := range sigHeaders {
		sig, err := parseSig(rawSig)
		if err != nil {
			results = append(results, VerifyResult{Error: err})
			continue
		}

		res := VerifyResult{Sequence: sig.Sequence, Domain: sig.Domain}

		// §10.3 SHOULD: reject signatures more than 14 days old or in the future
		if !skipTS && sig.Timestamp > 0 {
			const tolerance = 300 // 5-minute clock-skew tolerance
			const maxAge = 14 * 24 * 3600
			if sig.Timestamp > now+tolerance {
				res.Error = fmt.Errorf("i=%d: timestamp is in the future", sig.Sequence)
				results = append(results, res)
				continue
			}
			if now > sig.Timestamp+maxAge {
				res.Error = fmt.Errorf("i=%d: signature has expired (age > 14 days)", sig.Sequence)
				results = append(results, res)
				continue
			}
		}

		// spec 7.5/7.6 MUST: mf=/rt= values must carry RFC5321 angle brackets.
		if sig.MailFrom != "" && !(strings.HasPrefix(sig.MailFrom, "<") && strings.HasSuffix(sig.MailFrom, ">")) {
			res.Error = fmt.Errorf("i=%d: mf= is not a bracketed RFC5321 reverse-path (spec 7.5)", sig.Sequence)
		}
		for _, r := range sig.RcptTo {
			if !(strings.HasPrefix(r, "<") && strings.HasSuffix(r, ">")) {
				res.Error = fmt.Errorf("i=%d: rt= entry is not a bracketed RFC5321 forward-path (spec 7.6)", sig.Sequence)
				break
			}
		}
		if res.Error != nil {
			results = append(results, res)
			continue
		}

		// §7.7 MUST: d= must be a suffix of (i.e. relaxed match against) the mf= domain
		if sig.MailFrom != "" && sig.MailFrom != "<>" {
			if mfDomain := domainFromAddr(sig.MailFrom); mfDomain != "" {
				if !relaxedDomainMatch(mfDomain, strings.ToLower(sig.Domain)) {
					res.Error = fmt.Errorf("DKIM2-Signature i=%d MAIL FROM and d= do not match",
						sig.Sequence)
					results = append(results, res)
					continue
				}
			}
		}

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

		// §10.6 MUST: verify ALL sig items; any crypto failure is an error
		var itemErr error
		verifiedAny := false
		for _, item := range sig.Sigs {
			pubKey, keyAlg, fetchErr := fetcher.FetchPublicKey(item.Selector, sig.Domain)
			if fetchErr != nil {
				if itemErr == nil {
					itemErr = fmt.Errorf("sel=%s: key fetch: %w", item.Selector, fetchErr)
				}
				continue
			}
			normAlg := strings.TrimSuffix(item.Algorithm, "-sha256")
			normKeyAlg := strings.TrimSuffix(keyAlg, "-sha256")
			if normAlg != normKeyAlg {
				itemErr = fmt.Errorf("sel=%s: algorithm mismatch: sig=%s key=%s",
					item.Selector, item.Algorithm, keyAlg)
				continue
			}
			if verr := verifyDigest(pubKey, keyAlg, digest[:], item.Value); verr != nil {
				itemErr = fmt.Errorf("sel=%s: %w", item.Selector, verr)
				continue // MUST check all remaining items even on failure
			}
			verifiedAny = true
		}
		if itemErr != nil {
			res.Error = fmt.Errorf("i=%d: %w", sig.Sequence, itemErr)
		} else if !verifiedAny {
			res.Error = fmt.Errorf("i=%d: no verifiable signature items", sig.Sequence)
		}
		results = append(results, res)
	}

	return results, nil
}

// normAddr normalises an email address for §10.4 exact-match comparison:
// surrounding RFC5321 angle brackets (if any) are stripped, domain part is
// lowercased, local-part case is preserved. VerifyOptions.MailFrom/RcptTo are
// bare SMTP-level addresses; topSig.MailFrom/RcptTo are bracketed per §7.5/7.6.
func normAddr(addr string) string {
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	at := strings.LastIndexByte(addr, '@')
	if at < 0 {
		return strings.ToLower(addr)
	}
	return addr[:at+1] + strings.ToLower(addr[at+1:])
}

// domainFromAddr extracts the domain from an email address (with or without angle brackets).
func domainFromAddr(addr string) string {
	addr = strings.TrimLeft(addr, "<")
	addr = strings.TrimRight(addr, ">")
	if at := strings.LastIndexByte(addr, '@'); at >= 0 {
		return strings.ToLower(addr[at+1:])
	}
	return ""
}

// checkChainOfCustody validates the §8.2/§11.4 chain across consecutive
// signatures (ascending i= order). For each adjacent pair, either the lower
// signature carries nd= (which MUST exactly match the higher signature's d=),
// or the higher signature's mf= domain MUST relaxed-match an rt= domain of the
// lower one. A null-sender (DSN) hop skips the mf=/rt= check.
func checkChainOfCustody(parsedSigs []*DKIM2Signature) error {
	for idx := 1; idx < len(parsedSigs); idx++ {
		cur := parsedSigs[idx]
		prev := parsedSigs[idx-1]
		if cur == nil || prev == nil {
			continue
		}
		if prev.NextDomain != "" {
			// draft-04 §11.4: nd= MUST exactly match the next sig's d=.
			if !strings.EqualFold(prev.NextDomain, cur.Domain) {
				return fmt.Errorf("DKIM2-Signature i=%d MAIL nd= does not match",
					prev.Sequence)
			}
			continue
		}
		curMFDomain := domainFromAddr(cur.MailFrom)
		if curMFDomain == "" {
			continue // null sender (DSN) — no chain check required
		}
		matched := false
		for _, rt := range prev.RcptTo {
			if rtDomain := domainFromAddr(rt); rtDomain != "" {
				if relaxedDomainMatch(curMFDomain, rtDomain) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return fmt.Errorf("DKIM2-Signature i=%d MAIL FROM %s did not match",
				cur.Sequence, cur.MailFrom)
		}
	}
	return nil
}

// relaxedDomainMatch reports whether d1 is equal to d2 or a subdomain of d2.
func relaxedDomainMatch(d1, d2 string) bool {
	d1 = strings.ToLower(d1)
	d2 = strings.ToLower(d2)
	return d1 == d2 || strings.HasSuffix(d1, "."+d2)
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
