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
	br := bufio.NewReader(r)
	headers, err := readHeaderFields(br)
	if err != nil {
		return nil, fmt.Errorf("parsing headers: %w", err)
	}
	fetcher = prefetchKeys(headers, fetcher, opts...)
	return verifyFields(headers, func(algs []string) (map[string][]byte, error) {
		return hashBodyStream(br, algs)
	}, fetcher, opts...)
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
			return nil, errUnkeyableSignature
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

	// §14.4: the top (highest i=) signature carrying nd= is "unexpected nd=
	// tag": the signature that fulfils it has not been added.  A signer's
	// own gate (Outbound with Signer set) may extend a top nd= signature
	// that names that signer -- its own d= is about to satisfy the nd=
	// (§12.3 out-of-band arrangements); any other domain is refused.
	if topSig != nil && topSig.NextDomain != "" {
		if len(opts) > 0 && opts[0].Outbound && opts[0].Signer != "" {
			if !strings.EqualFold(topSig.NextDomain, opts[0].Signer) {
				return nil, fmt.Errorf("PERMERROR: DKIM2-Signature i=%d unexpected nd= tag (nd=%s names another domain than %s)",
					topSig.Sequence, topSig.NextDomain, opts[0].Signer)
			}
		} else {
			return nil, fmt.Errorf("PERMERROR: DKIM2-Signature i=%d unexpected nd= tag", topSig.Sequence)
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

	// §14.4: envelope exact-match against top sig if caller provided values
	if len(opts) > 0 && topSig != nil {
		opt := opts[0]
		if opt.MailFrom != "" {
			if normAddr(opt.MailFrom) != normAddr(topSig.MailFrom) {
				return nil, fmt.Errorf("PERMERROR: DKIM2-Signature i=%d MAIL FROM %s did not match",
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
					return nil, fmt.Errorf("PERMERROR: DKIM2-Signature i=%d RCPT TO %s did not match",
						topSig.Sequence, delivered)
				}
			}
		}
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
					return nil, fmt.Errorf("PERMERROR: duplicate Message-Instance m=%d", mi.Version)
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

	// §14.4: the Chain of Custody, every signature's mf= against its d=
	// and each signature against the one below it.
	{
		parsedSigs := make([]*DKIM2Signature, len(sigHeaders))
		for i, raw := range sigHeaders {
			parsedSigs[i], _ = parseSig(raw)
		}
		if err := checkChainOfCustody(parsedSigs); err != nil {
			return nil, err
		}

		// §14.8: every From that the Recipes show, against its signature.
		// Outbound, the unsigned instances above the top signature are the
		// signer's own to answer for (Sign checks them itself).
		mis := make(map[int]*MessageInstance, len(miHeaders))
		for _, raw := range miHeaders {
			if mi, err := parseMI(raw); err == nil {
				mis[mi.Version] = mi
			}
		}
		limit := maxMIVersion
		if unsignedTop {
			limit = topSig.MIVersion
		}
		if err := checkFromAuthentic(contentHeaders, mis, maxMIVersion, limit, parsedSigs); err != nil {
			return nil, err
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

		// §8: a tag name that occurs more than once makes the whole
		// tag-list invalid.
		if sig.Duplicate != "" {
			res.Error = sigSyntaxError(sig.Sequence)
			results = append(results, res)
			continue
		}

		// §14.3: not Validly Signed if made more than 14 days before
		// delivery, or more than one day after it.  t=0 is valid syntax and
		// simply very old.  Compared without adding to t=, which may be as
		// large as math.MaxInt64.
		if !skipTS {
			if sig.Timestamp > now+MaxFutureSkew {
				res.Error = fmt.Errorf("PERMERROR: DKIM2-Signature i=%d signature is from the future", sig.Sequence)
				results = append(results, res)
				continue
			}
			if now-MaxSignatureAge > sig.Timestamp {
				res.Error = fmt.Errorf("PERMERROR: DKIM2-Signature i=%d signature expired", sig.Sequence)
				results = append(results, res)
				continue
			}
		}

		// §10.5/§10.6 MUST: mf=/rt= values carry RFC5321 angle brackets;
		// one that does not is a syntax error.
		if sig.MailFrom != "" && !(strings.HasPrefix(sig.MailFrom, "<") && strings.HasSuffix(sig.MailFrom, ">")) {
			res.Error = sigSyntaxError(sig.Sequence)
		}
		for _, r := range sig.RcptTo {
			if !(strings.HasPrefix(r, "<") && strings.HasSuffix(r, ">")) {
				res.Error = sigSyntaxError(sig.Sequence)
				break
			}
		}
		if res.Error != nil {
			results = append(results, res)
			continue
		}

		// §10.9: duplicate-selector and excess-selector checks must
		// run before any DNS lookup or crypto work.
		if dupErrs := checkSignatureDuplicates(sig.Sigs, sig.Sequence); len(dupErrs) > 0 {
			res.Error = fmt.Errorf("%s", strings.Join(dupErrs, "; "))
			results = append(results, res)
			continue
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
			res.Error = fmt.Errorf("PERMERROR: Message-Instance m=%d missing", sig.MIVersion)
			results = append(results, res)
			continue
		}

		// Verify MI header and body hashes only for the outermost (latest) MI.
		// Earlier MI versions recorded hashes from a prior message state;
		// an intermediary may have modified headers/body since then.
		if sig.MIVersion == maxMIVersion {
			var mierr error
			if headersOnly {
				mierr = verifyMIHeaderHashes(thisMI, contentHeaders)
			} else {
				mierr = verifyMIHashesPrecomputed(thisMI, contentHeaders, topBodyHashes)
			}
			if mierr != nil {
				res.Error = mierr
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

		res.Error = verifySigItems(sig, fetcher, digest[:])
		results = append(results, res)
	}

	return results, nil
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

// checkFromAuthentic is §14.8 (§11).  State k is the message as it was when
// Message-Instance m=k was the highest: state top is the content as received,
// and state k-1 is state k with m=k's From Recipe undone.  The From at state
// 1 must be Authentic for the i=1 signature, and for each k >= 2 whose header
// Recipe has a "from" key, the From at state k must be Authentic for the
// lowest i whose m= is k or more.  States above limit are not checked.  A
// From Recipe that cannot be applied stops the walk: the chain walk reports
// it.  sigs are in ascending i= order.
func checkFromAuthentic(content []Header, mis map[int]*MessageInstance, top, limit int, sigs []*DKIM2Signature) error {
	sigFor := func(k int) *DKIM2Signature {
		for _, s := range sigs {
			if s != nil && s.MIVersion >= k {
				return s
			}
		}
		return nil
	}
	failed := map[int]bool{}
	from := fromFields(content)
	for k := top; k >= 1; k-- {
		steps, changed := fromRecipe(mis[k])
		if k <= limit && (k == 1 || changed) {
			var s *DKIM2Signature
			if k == 1 {
				if len(sigs) > 0 && sigs[0] != nil && sigs[0].Sequence == 1 {
					s = sigs[0]
				}
			} else {
				s = sigFor(k)
			}
			if s != nil && !fromAuthentic(from, s.Domain) {
				failed[s.Sequence] = true
			}
		}
		if changed && k > 1 {
			prev, err := applyHeaderRecipe(from, "From", steps)
			if err != nil {
				break
			}
			from = prev
		}
	}
	var errs []error
	for _, s := range sigs {
		if s != nil && failed[s.Sequence] {
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
