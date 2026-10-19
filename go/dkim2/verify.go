package dkim2

import (
	"bufio"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Verify reads r and verifies all DKIM2-Signature headers.
// Returns one VerifyResult per signature. Body is never buffered: it is
// canonicalised in a single streaming pass, fanned out to one hash.Hash per
// implemented algorithm the topmost Message-Instance's h= tag names (see
// hashBodyStream), even when that names more than one algorithm.  It is
// read only when a body hash is needed.
// An optional VerifyOptions may be passed to enable §14.4 envelope matching.
//
// With real DNS keys (NetKeyFetcher) every key the signatures name is
// looked up in the background as soon as the header fields are read (see
// prefetchKeys), while the body is still being read and hashed.
func Verify(r io.Reader, fetcher KeyFetcher, opts ...VerifyOptions) ([]VerifyResult, error) {
	headers, results, err := verifyNoFrom(r, fetcher, opts...)
	return fromLast(headers, results, err, opts...)
}

// verifyNoFrom is Verify without the §14.8 From check, for VerifyFull's
// undo walk, which must check the lower instances (§14.7) before it.
func verifyNoFrom(r io.Reader, fetcher KeyFetcher, opts ...VerifyOptions) ([]Header, []VerifyResult, error) {
	br := bufio.NewReader(r)
	headers, err := readHeaderFields(br)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing headers: %w", err)
	}
	fetcher = prefetchKeys(headers, fetcher, opts...)
	results, err := verifyFields(headers, func(algs []string) (map[string][]byte, error) {
		return hashBodyStream(br, algs)
	}, fetcher, opts...)
	return headers, results, err
}

// fromLast finishes a verification with the §14.8 From check, which comes
// last in contract C9's order: only when nothing before it failed.
func fromLast(headers []Header, results []VerifyResult, err error, opts ...VerifyOptions) ([]VerifyResult, error) {
	if err != nil || PrimaryResult(results) != nil {
		return results, err
	}
	if ferr := verifyFrom(headers, opts...); ferr != nil {
		return nil, ferr
	}
	return results, nil
}

// verifyFields is Verify once the header fields are parsed.  bodyHashes
// returns the body hash for each algorithm named (those of the topmost
// Message-Instance this build implements); it is called at most once, and
// not at all with HeadersOnly or when an earlier check already failed.
func verifyFields(headers []Header, bodyHashes func(algs []string) (map[string][]byte, error),
	fetcher KeyFetcher, opts ...VerifyOptions) ([]VerifyResult, error) {
	var err error
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

	// A DKIM2-Signature whose i= is missing or not a positive integer cannot
	// be placed in the chain or keyed: PERMERROR, never silently skipped, so
	// a junk "DKIM2-Signature: m=2" can never pass for coverage of m=2.
	for _, raw := range sigHeaders {
		if !validSequenceTag(raw) {
			return nil, unkeyableSignatureError(raw)
		}
	}

	// Every i= and m= is a chain number (chainNumberError), before any 1..max walk.
	if err := chainRangeError(miHeaders, sigHeaders); err != nil {
		return nil, err
	}

	// No DKIM2 header fields at all is "none", not an error (-07 §14.2's
	// "No DKIM2 header fields found" is reported as dkim2=none).
	if len(sigHeaders) == 0 && len(miHeaders) == 0 {
		return nil, ErrNone
	}
	noSigsOutbound := len(sigHeaders) == 0 && len(opts) > 0 && opts[0].Outbound
	if len(sigHeaders) == 0 && !noSigsOutbound {
		return nil, fmt.Errorf("PERMERROR: Message-Instance m=%d is not signed", maxTagNumber(miHeaders, "m"))
	}
	if len(miHeaders) == 0 {
		return nil, fmt.Errorf("PERMERROR: Message-Instance m=%d missing", maxTagNumber(sigHeaders, "m"))
	}

	// Spec review note #3: top sig's m= must equal the count of MI headers.
	// Also track the topmost MI object itself: its hash-sets name the
	// algorithm(s) the body must be hashed with below.
	maxMIVersion := 0
	var topMI *MessageInstance
	for _, raw := range miHeaders {
		mi, err := parseMI(raw)
		if err != nil {
			// Report the parse failure rather than skipping the header. Skipping
			// silently lowers the apparent topmost version, which turns the real
			// defect into a bogus "does not cover topmost MI" complaint below.
			//
			// Every parseMI error is a self-describing §14.2 string.
			return nil, err
		}
		if mi.Version > maxMIVersion {
			maxMIVersion = mi.Version
			topMI = mi
		}
	}

	// §16.3: with HeadersOnly there is no body to hash — the caller handed us
	// the header fields alone, as echoed back in a DSN's text/rfc822-headers
	// part — so the body pass is skipped and only header hashes are checked.
	headersOnly := len(opts) > 0 && opts[0].HeadersOnly

	// Body is never buffered: hash it in a single streaming pass, fanned out
	// to every algorithm the topmost MI's h= tag names (that this build
	// implements — see hashBodyMulti/HashAlg, §3.5). Only the topmost MI's
	// hashes are ever checked against the body (see the per-signature loop
	// below), so that is the only hash-set that needs consulting here.
	var topBodyHashes map[string][]byte
	if !headersOnly {
		var neededAlgs []string
		if topMI != nil {
			neededAlgs = implementedAlgs(topMI.Hashes)
		}
		topBodyHashes, err = bodyHashes(neededAlgs)
		if err != nil {
			return nil, fmt.Errorf("PERMERROR: body hash: %w", err)
		}
	}

	// Outbound with no signature at all (a list host added unsigned
	// Message-Instances to an unsigned post): there is nothing to verify
	// cryptographically, but the top instance must still match the content;
	// VerifyFull then checks that the chain undoes.
	if noSigsOutbound {
		var mierr error
		if headersOnly {
			mierr = verifyMIHeaderHashes(topMI, contentHeaders)
		} else {
			mierr = verifyMIHashesPrecomputed(topMI, contentHeaders, topBodyHashes)
		}
		if mierr != nil {
			return []VerifyResult{{Domain: "MI-chain", Error: fmt.Errorf("unsigned top %w", mierr)}}, nil
		}
		return []VerifyResult{}, nil
	}

	// A signature that does not parse (bad t=, a missing tag, a known
	// algorithm's item without a base64 value) is the result, rather than a
	// knock-on "missing" once that signature drops out of the walk.
	for _, raw := range sigHeaders {
		if _, err := parseSig(raw); err != nil {
			return nil, err
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

	outbound := len(opts) > 0 && opts[0].Outbound
	// Outbound: an unsigned top instance is the one the next signer covers.
	// The signatures' own top instance is then an ordinary lower level (the
	// chain walk checks it); the unsigned one is checked against the content.
	unsignedTop := outbound && topSig != nil && topSig.MIVersion < maxMIVersion
	if unsignedTop && !headersOnly {
		if mierr := verifyMIHashesPrecomputed(topMI, contentHeaders, topBodyHashes); mierr != nil {
			return []VerifyResult{{
				Sequence: topSig.Sequence, Domain: topSig.Domain,
				Error: fmt.Errorf("i=%d: unsigned top %w", topSig.Sequence, mierr),
			}}, nil
		}
	} else if unsignedTop {
		if mierr := verifyMIHeaderHashes(topMI, contentHeaders); mierr != nil {
			return []VerifyResult{{
				Sequence: topSig.Sequence, Domain: topSig.Domain,
				Error: fmt.Errorf("i=%d: unsigned top %w", topSig.Sequence, mierr),
			}}, nil
		}
	}
	if topSig != nil && topSig.MIVersion != maxMIVersion && !unsignedTop {
		err := fmt.Errorf("PERMERROR: Message-Instance m=%d is not signed", maxMIVersion)
		if topSig.MIVersion > maxMIVersion {
			err = fmt.Errorf("PERMERROR: Message-Instance m=%d missing", topSig.MIVersion)
		}
		return []VerifyResult{{Sequence: topSig.Sequence, Domain: topSig.Domain, Error: err}}, nil
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

	// §14.2: i= values must be contiguous 1..N; the first gap is missing.
	for idx, raw := range sigHeaders {
		sig, _ := parseSig(raw)
		if sig == nil || sig.Sequence != idx+1 {
			return nil, fmt.Errorf("PERMERROR: DKIM2-Signature i=%d missing", idx+1)
		}
	}
	// A repeated m= is its own error, before the contiguity check.
	{
		seenM := make(map[int]bool)
		for _, raw := range miHeaders {
			if mi, _ := parseMI(raw); mi != nil {
				if seenM[mi.Version] {
					return nil, fmt.Errorf("PERMERROR: Message-Instance m=%d appears more than once", mi.Version)
				}
				seenM[mi.Version] = true
			}
		}
	}
	// §14.2: m= values must be contiguous 1..N; the first gap is missing.
	for idx, raw := range miHeaders {
		mi, _ := parseMI(raw)
		if mi == nil || mi.Version != idx+1 {
			return nil, fmt.Errorf("PERMERROR: Message-Instance m=%d missing", idx+1)
		}
	}

	// §14.2: a Message-Instance whose m= is higher than every
	// signature's is an error. A lower one no signature names is valid (a
	// list's unsigned m=1 under a signature on m=2).  Outbound, every
	// instance above the top signature is one the caller is about to cover
	// (its signature will name the top m=), so none of them is an error:
	// the chain walk still checks each against the content and undoes it.
	{
		maxSigM := 0
		for _, raw := range sigHeaders {
			sig, _ := parseSig(raw)
			if sig != nil && sig.MIVersion > maxSigM {
				maxSigM = sig.MIVersion
			}
		}
		for _, raw := range miHeaders {
			mi, _ := parseMI(raw)
			if mi != nil && mi.Version > maxSigM && !unsignedTop {
				return nil, fmt.Errorf("PERMERROR: Message-Instance m=%d is not signed", mi.Version)
			}
		}
	}

	parsedSigs := make([]*DKIM2Signature, len(sigHeaders))
	for i, raw := range sigHeaders {
		parsedSigs[i], _ = parseSig(raw)
	}

	// Contract C9: the checks run in -07 §14 section order, each over every
	// signature from i=1 up, so the first error found is the primary one.
	// §14.2: each signature field on its own.
	for _, sig := range parsedSigs {
		if err := sigFieldError(sig, miHeaders); err != nil {
			return nil, err
		}
	}

	// §14.3: not Validly Signed if made more than 14 days before delivery,
	// or more than one day after it.  t=0 is valid syntax and simply very
	// old.  Compared without adding to t=, which may be as large as
	// math.MaxInt64.
	if !(len(opts) > 0 && opts[0].SkipTimestampCheck) {
		now := time.Now().Unix()
		for _, sig := range parsedSigs {
			if sig.Timestamp > now+MaxFutureSkew {
				return nil, fmt.Errorf("PERMERROR: DKIM2-Signature i=%d signature is from the future", sig.Sequence)
			}
			if now-MaxSignatureAge > sig.Timestamp {
				return nil, fmt.Errorf("PERMERROR: DKIM2-Signature i=%d signature expired", sig.Sequence)
			}
		}
	}

	// §14.4: the top signature's nd=, the envelope, then the Chain of
	// Custody (every signature's mf= against its d=, and each signature
	// against the one below it).
	if err := topCustodyError(topSig, opts...); err != nil {
		return nil, err
	}
	if err := checkChainOfCustody(parsedSigs); err != nil {
		return nil, err
	}

	var results []VerifyResult

	for idx, rawSig := range sigHeaders {
		sig := parsedSigs[idx]
		res := VerifyResult{Sequence: sig.Sequence, Domain: sig.Domain}

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

		// §14.5 and §14.6: this signature's keys, then its signatures.
		res.Error = verifySigItems(sig, fetcher, digest[:])

		// §14.7: the MI header and body hashes, checked here only for the
		// outermost (latest) MI.  Earlier MI versions recorded hashes from
		// a prior message state; the chain walk checks those.  After the
		// crypto (C9): a signature that does not verify is the primary
		// error, whatever the hashes say.
		if res.Error == nil && sig.MIVersion == maxMIVersion {
			if headersOnly {
				res.Error = verifyMIHeaderHashes(topMI, contentHeaders)
			} else {
				res.Error = verifyMIHashesPrecomputed(topMI, contentHeaders, topBodyHashes)
			}
		}
		results = append(results, res)
	}

	return results, nil
}

// sigFieldError is the -07 §14.2 check of one DKIM2-Signature field on its
// own (contract C9 runs it for every signature before any §14.3 check): a
// duplicated tag, an mf=/rt= without its angle brackets (§10.5/§10.6), the
// §10.9 duplicate-selector and selector-count rules, and an m= naming a
// Message-Instance that is not there.
func sigFieldError(sig *DKIM2Signature, miHeaders []string) error {
	// §8: a tag name that occurs more than once makes the whole tag-list
	// invalid.
	if sig.Duplicate != "" {
		return sigSyntaxError(sig.Sequence)
	}
	if sig.MailFrom != "" && !(strings.HasPrefix(sig.MailFrom, "<") && strings.HasSuffix(sig.MailFrom, ">")) {
		return sigSyntaxError(sig.Sequence)
	}
	for _, r := range sig.RcptTo {
		if !(strings.HasPrefix(r, "<") && strings.HasSuffix(r, ">")) {
			return sigSyntaxError(sig.Sequence)
		}
	}
	if dupErrs := checkSignatureDuplicates(sig.Sigs, sig.Sequence); len(dupErrs) > 0 {
		return errors.New(dupErrs[0])
	}
	for _, raw := range miHeaders {
		if mi, err := parseMI(raw); err == nil && mi.Version == sig.MIVersion {
			return nil
		}
	}
	return fmt.Errorf("PERMERROR: Message-Instance m=%d missing", sig.MIVersion)
}

// topCustodyError is the start of §14.4: a top (highest i=) signature
// carrying nd= is "unexpected nd= tag" -- the signature that fulfils it has
// not been added -- and the envelope, when the caller gave one, must match
// the top signature's mf=/rt= exactly.  A signer's own gate (Outbound with
// Signer set) may extend a top nd= signature that names that signer -- its
// own d= is about to satisfy the nd= (§12.3 out-of-band arrangements); any
// other domain is refused.
func topCustodyError(topSig *DKIM2Signature, opts ...VerifyOptions) error {
	if topSig == nil {
		return nil
	}
	if topSig.NextDomain != "" {
		if len(opts) > 0 && opts[0].Outbound && opts[0].Signer != "" {
			if !strings.EqualFold(topSig.NextDomain, opts[0].Signer) {
				return fmt.Errorf("PERMERROR: DKIM2-Signature i=%d unexpected nd= tag (nd=%s names another domain than %s)",
					topSig.Sequence, topSig.NextDomain, opts[0].Signer)
			}
		} else {
			return fmt.Errorf("PERMERROR: DKIM2-Signature i=%d unexpected nd= tag", topSig.Sequence)
		}
	}
	if len(opts) == 0 {
		return nil
	}
	opt := opts[0]
	if opt.MailFrom != "" && normAddr(opt.MailFrom) != normAddr(topSig.MailFrom) {
		return fmt.Errorf("PERMERROR: DKIM2-Signature i=%d MAIL FROM %s did not match",
			topSig.Sequence, opt.MailFrom)
	}
	for _, delivered := range opt.RcptTo {
		found := false
		for _, rt := range topSig.RcptTo {
			if normAddr(delivered) == normAddr(rt) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("PERMERROR: DKIM2-Signature i=%d RCPT TO %s did not match",
				topSig.Sequence, delivered)
		}
	}
	return nil
}

// verifyFrom is §14.8 (§11), the last check in contract C9's order: run
// only once everything before it passed.  Outbound, the unsigned instances
// above the top signature are the signer's own to answer for (Sign checks
// them itself).
func verifyFrom(headers []Header, opts ...VerifyOptions) error {
	var content []Header
	var sigs []*DKIM2Signature
	mis := map[int]*MessageInstance{}
	top, topSigM, topSigI := 0, 0, 0
	for _, h := range headers {
		switch strings.ToLower(h.Name) {
		case "message-instance":
			if mi, err := parseMI(h.Raw); err == nil {
				mis[mi.Version] = mi
				if mi.Version > top {
					top = mi.Version
				}
			}
		case "dkim2-signature":
			if s, err := parseSig(h.Raw); err == nil {
				sigs = append(sigs, s)
				if s.Sequence > topSigI {
					topSigI, topSigM = s.Sequence, s.MIVersion
				}
			}
		default:
			content = append(content, h)
		}
	}
	if len(sigs) == 0 {
		return nil
	}
	sort.Slice(sigs, func(a, b int) bool { return sigs[a].Sequence < sigs[b].Sequence })
	limit := top
	if len(opts) > 0 && opts[0].Outbound && topSigM < top {
		limit = topSigM
	}
	return checkFromAuthentic(content, mis, top, limit, sigs)
}

// c9Section is the -07 §14 section an error string belongs to, for
// contract C9's ranking.  Anything not named here (syntax, missing,
// duplicate, "is not signed", Recipe errors, local limits) is §14.2.
func c9Section(text string) int {
	switch {
	case strings.HasSuffix(text, " signature expired") || strings.HasSuffix(text, " signature is from the future"):
		return 3
	case strings.HasPrefix(text, "TEMPERROR: ") || strings.Contains(text, " public key ") ||
		strings.Contains(text, " has no signature with a supported algorithm"):
		return 5
	case strings.HasPrefix(text, "FAIL: DKIM2-Signature "):
		return 6
	case strings.HasPrefix(text, "FAIL: Message-Instance "):
		return 7
	case strings.HasSuffix(text, " matching From is not authentic"):
		return 8
	}
	return 2
}

// PrimaryResult is the result whose error is the primary one (contract
// C9): the first in -07 §14 section order, the lowest i= first within a
// section; nil when every result passed.  Verify and VerifyFull return
// every signature's result in i= order (and the chain walk's after them);
// a caller reporting one reason, or one state, reports this one's.
func PrimaryResult(results []VerifyResult) *VerifyResult {
	var best *VerifyResult
	bestSec := 0
	for k := range results {
		r := &results[k]
		if r.Error == nil {
			continue
		}
		sec := r.section
		if sec == 0 {
			sec = c9Section(strings.SplitN(r.Error.Error(), "\n", 2)[0])
		}
		if best == nil || sec < bestSec || (sec == bestSec && sec != 7 && sec != 2 && r.Sequence < best.Sequence) {
			best, bestSec = r, sec
		}
	}
	return best
}

// maxTagNumber is the highest value of tag across raw header fields (name
// included), for an error that has to name one; chainRangeError has
// already checked that every one present is a chain number.
func maxTagNumber(raws []string, tag string) int {
	max := 0
	for _, raw := range raws {
		colon := strings.IndexByte(raw, ':')
		if colon < 0 {
			continue
		}
		if n, err := strconv.Atoi(parseTagValueList(raw[colon+1:]).get(tag)); err == nil && n > max {
			max = n
		}
	}
	return max
}

// verifySigItems decides one DKIM2-Signature's outcome from its s= items, in
// the order the behaviour spec (2026-10-09 review fixes, section E) gives:
//  1. unimplemented algorithms are ignored (§3.5); none left is PERMERROR;
//  2. (an implemented item's value is a padded base64string -- parseSig);
//  3. every implemented item's key is fetched: a DNS failure is TEMPERROR, a
//     record that is present but unusable is PERMERROR for the whole
//     signature (§14.5), an absent record skips the item;
//  4. every implemented item absent is PERMERROR "does not exist";
//  5. every item with a key is checked, and MUST verify (§14.6): when none
//     does, FAIL "selector <s1> incorrect signature"; when some pass and
//     some fail, FAIL "signature <s1> signature <s2> failed" (s1 passed).
func verifySigItems(sig *DKIM2Signature, fetcher KeyFetcher, digest []byte) error {
	type keyed struct {
		item SigItem
		key  crypto.PublicKey
	}
	var usable []keyed
	firstAbsent := ""
	implemented := 0
	for _, item := range sig.Sigs {
		if !KnownSigAlg(item.Algorithm) {
			continue
		}
		implemented++
		pubKey, keyAlg, err := fetcher.FetchPublicKey(item.Selector, sig.Domain)
		if err != nil {
			if errors.Is(err, ErrKeyNotFound) {
				if firstAbsent == "" {
					firstAbsent = item.Selector
				}
				continue
			}
			if problem := keyRecordProblem(err); problem != "" {
				return fmt.Errorf("PERMERROR: DKIM2-Signature i=%d public key %s %s",
					sig.Sequence, item.Selector, problem)
			}
			return fmt.Errorf("TEMPERROR: DKIM2-Signature i=%d public key %s could not be fetched",
				sig.Sequence, item.Selector)
		}
		// §10.9: the key's k= must be the item's algorithm.
		if keyAlg != item.Algorithm || !keyFitsAlg(pubKey, item.Algorithm) {
			return fmt.Errorf("PERMERROR: DKIM2-Signature i=%d public key %s algorithm mismatch",
				sig.Sequence, item.Selector)
		}
		// §3.2: RSA keys MUST be at least 1024 bits.
		if rk, ok := pubKey.(*rsa.PublicKey); ok && rk.N.BitLen() < 1024 {
			return fmt.Errorf("PERMERROR: DKIM2-Signature i=%d public key %s is too short (%d bits < 1024, §3.2)",
				sig.Sequence, item.Selector, rk.N.BitLen())
		}
		usable = append(usable, keyed{item, pubKey})
	}
	if implemented == 0 {
		return fmt.Errorf("PERMERROR: DKIM2-Signature i=%d has no signature with a supported algorithm", sig.Sequence)
	}
	if len(usable) == 0 {
		return fmt.Errorf("PERMERROR: DKIM2-Signature i=%d public key %s does not exist",
			sig.Sequence, firstAbsent)
	}
	passed, failed := "", ""
	for _, k := range usable {
		if err := verifyDigest(k.key, k.item.Algorithm, digest, k.item.Value); err != nil {
			if failed == "" {
				failed = k.item.Selector
			}
		} else if passed == "" {
			passed = k.item.Selector
		}
	}
	switch {
	case failed == "":
		return nil
	case passed == "":
		return fmt.Errorf("FAIL: DKIM2-Signature i=%d selector %s incorrect signature", sig.Sequence, failed)
	default:
		return fmt.Errorf("FAIL: DKIM2-Signature i=%d signature %s signature %s failed", sig.Sequence, passed, failed)
	}
}

// checkSignatureDuplicates enforces the §10.9 duplicate/limit rules for
// one DKIM2-Signature s= tag: a Selector MUST NOT appear more than once, and
// the same signing algorithm may appear at most twice, and only with
// distinct Selectors. Both comparisons are case-insensitive (a Selector is a
// Domain, §3.6; algorithm names are ABNF quoted strings, RFC 5234).
func checkSignatureDuplicates(items []SigItem, i int) []string {
	var errs []string

	seenSelectors := map[string]bool{}
	dupSelector := false
	for _, it := range items {
		sel := strings.ToLower(it.Selector)
		if seenSelectors[sel] {
			dupSelector = true
		}
		seenSelectors[sel] = true
	}
	if dupSelector {
		errs = append(errs, fmt.Sprintf("PERMERROR: DKIM2-Signature i=%d has a duplicate selector", i))
	}

	counts := map[string]int{}
	for _, it := range items {
		counts[strings.ToLower(it.Algorithm)]++
	}
	for _, n := range counts {
		if n > 2 {
			errs = append(errs, fmt.Sprintf("PERMERROR: DKIM2-Signature i=%d has more selectors than allowed", i))
			break
		}
	}

	return errs
}

// normAddr normalises an email address for the §14.4 exact match with the
// SMTP envelope: surrounding RFC 5321 angle brackets (if any) are stripped,
// the domain is lowercased and mapped to A-labels (§18), the local-part's
// case is preserved. VerifyOptions.MailFrom/RcptTo are bare SMTP-level
// addresses; topSig.MailFrom/RcptTo are bracketed per §10.5/§10.6.
func normAddr(addr string) string {
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	at := strings.LastIndexByte(addr, '@')
	if at < 0 {
		return strings.ToLower(addr)
	}
	d := strings.ToLower(addr[at+1:])
	if !strings.HasPrefix(d, "[") {
		d = toALabel(d)
	}
	return addr[:at+1] + d
}

// isNullPath reports whether a decoded mf= is the null reverse-path "<>".
func isNullPath(mf string) bool {
	return trimFWS(mf) == "<>"
}

// checkChainOfCustody is §14.4 over the signatures in ascending i= order
// (§7.1 items 1 and 2).  Every failure is PERMERROR; all of them are
// reported, joined, in the order found.
//
//   - Every signature S with a non-null mf= and no nd=: the mf= domain
//     relaxed-matches S's d=.
//   - For each S above i=1, with P the signature below it:
//     P has nd=: S's d= equals it (caseless), and nothing more is checked
//     for S; else S has nd= or a null mf=: some rt= domain of P
//     relaxed-matches S's d=; else S's mf= domain relaxed-matches some rt=
//     domain of P.
func checkChainOfCustody(sigs []*DKIM2Signature) error {
	var errs []error
	for idx, s := range sigs {
		if s == nil {
			continue
		}
		if idx > 0 && sigs[idx-1] != nil {
			p := sigs[idx-1]
			switch {
			case p.NextDomain != "":
				if !strings.EqualFold(p.NextDomain, s.Domain) {
					errs = append(errs, fmt.Errorf("PERMERROR: DKIM2-Signature i=%d nd= does not match", p.Sequence))
				}
			case s.NextDomain != "" || isNullPath(s.MailFrom):
				if !addrMatches(p.RcptTo, s.Domain) {
					errs = append(errs, fmt.Errorf("PERMERROR: DKIM2-Signature i=%d d= does not match the rt= of i=%d",
						s.Sequence, p.Sequence))
				}
			default:
				mf, lit := domainOf(s.MailFrom)
				matched := false
				for _, r := range p.RcptTo {
					if rd, rlit := domainOf(r); !lit && !rlit && relaxedMatch(mf, rd) {
						matched = true
						break
					}
				}
				if !matched {
					errs = append(errs, fmt.Errorf("PERMERROR: DKIM2-Signature i=%d mf= does not match the rt= of i=%d",
						s.Sequence, p.Sequence))
				}
			}
		}
		if s.NextDomain == "" && !isNullPath(s.MailFrom) {
			if mf, lit := domainOf(s.MailFrom); lit || !relaxedMatch(mf, s.Domain) {
				errs = append(errs, fmt.Errorf("PERMERROR: DKIM2-Signature i=%d MAIL FROM and d= do not match", s.Sequence))
			}
		}
	}
	return errors.Join(errs...)
}

// fromRecipe returns MI mi's header Recipe for From (its key matched
// without regard to case), and whether it has one.
func fromRecipe(mi *MessageInstance) ([]RecipeStep, bool) {
	if mi == nil || mi.Recipe == nil {
		return nil, false
	}
	for k, steps := range mi.Recipe.Headers {
		if lowerName(k) == "from" {
			return steps, true
		}
	}
	return nil, false
}

// checkFromAuthentic is §14.8 (§11), contract C5 as corrected by Ruling 19:
// the From in effect when each signature was made must be Authentic for it.
// State k is the message as it was when Message-Instance m=k was the highest:
// state top is the content as received, and state k-1 is state k with m=k's
// From Recipe undone.  The From at state m(i=1) is checked against i=1, and
// for each i >= 2 where some m=k with m(i-1) < k <= m(i) has a "from" key in
// its header Recipe, the From at state m(i) against i.  A From replaced
// before any signature covered it is never checked, nor are states above
// limit (outbound, the unsigned top instances: the signer checks those).  A
// From Recipe that cannot be applied stops the walk, and the states below it
// are not checked: the chain walk reports it.  sigs are in ascending i= order.
func checkFromAuthentic(content []Header, mis map[int]*MessageInstance, top, limit int, sigs []*DKIM2Signature) error {
	fromAt := map[int][]Header{}
	changed := map[int]bool{}
	from := fromFields(content)
	for k := top; k >= 1; k-- {
		fromAt[k] = from
		steps, ch := fromRecipe(mis[k])
		if !ch || k == 1 {
			continue
		}
		changed[k] = true
		prev, err := applyHeaderRecipe(from, "From", steps)
		if err != nil {
			break
		}
		from = prev
	}
	var errs []error
	prevM := 0
	for idx, s := range sigs {
		if s == nil {
			continue
		}
		due := s.Sequence == 1
		if s.Sequence >= 2 && idx > 0 {
			for k := prevM + 1; k <= s.MIVersion; k++ {
				if changed[k] {
					due = true
					break
				}
			}
		}
		prevM = s.MIVersion
		state, ok := fromAt[s.MIVersion]
		if !due || !ok || s.MIVersion > limit {
			continue
		}
		if !fromAuthentic(state, s.Domain) {
			errs = append(errs, fmt.Errorf("PERMERROR: DKIM2-Signature i=%d matching From is not authentic", s.Sequence))
		}
	}
	return errors.Join(errs...)
}

// keyFitsAlg reports whether key is of the type alg signs with.
func keyFitsAlg(key crypto.PublicKey, alg string) bool {
	switch key.(type) {
	case *rsa.PublicKey:
		return alg == "rsa-sha256"
	case ed25519.PublicKey:
		return alg == "ed25519-sha256"
	}
	return false
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
