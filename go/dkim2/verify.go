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
// Returns one VerifyResult per signature or, when the chain walk fails
// (contract C9: it comes before the signatures), the walk's failure alone,
// with the top signature's i=.  Body is never buffered: it is
// canonicalised in a single streaming pass, fanned out to one hash.Hash per
// implemented algorithm the topmost Message-Instance's h= tag names (see
// hashBodyStream), even when that names more than one algorithm.  It is
// read only when a body hash is needed.
// An optional VerifyOptions may be passed to enable §14.4 envelope matching.
//
// With real DNS keys (NetKeyFetcher) every key the signatures name is
// looked up in the background as soon as the header fields are read and
// the chain's structure checks out (see prefetchKeys), while the body is
// still being read and hashed.
func Verify(r io.Reader, fetcher KeyFetcher, opts ...VerifyOptions) ([]VerifyResult, error) {
	br := bufio.NewReader(r)
	headers, err := readHeaderFields(br)
	if err != nil {
		return nil, fmt.Errorf("parsing headers: %w", err)
	}
	cs, err := chainOf(headers, opts...)
	if err != nil {
		return nil, err
	}
	fetcher = prefetchKeys(cs.sigs, fetcher, opts...)
	results, err := verifyFields(cs, func(algs []string) (map[string][]byte, error) {
		return hashBodyStream(br, algs)
	}, nil, fetcher, opts...)
	return fromLast(headers, results, err, opts...)
}

// chainOf sorts headers into Message-Instances, DKIM2-Signatures and
// content, and runs the §14.2 structure check (chainStructure) over them:
// the first thing verified, before the body is read or any key looked up.
// No DKIM2 header fields at all is ErrNone (-07 §14.2's "No DKIM2 header
// fields found" is reported as dkim2=none).
func chainOf(headers []Header, opts ...VerifyOptions) (*chainShape, error) {
	var mis, sigs []string // raw fields, CRLF included
	var content []Header
	for _, h := range headers {
		switch strings.ToLower(h.Name) {
		case "message-instance":
			mis = append(mis, h.Raw)
		case "dkim2-signature":
			sigs = append(sigs, h.Raw)
		default:
			content = append(content, h)
		}
	}
	if len(sigs) == 0 && len(mis) == 0 {
		return nil, ErrNone
	}
	cs, err := chainStructure(mis, sigs, len(opts) > 0 && opts[0].Outbound)
	if err != nil {
		return nil, err
	}
	cs.content = content
	return cs, nil
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

// verifyFields is Verify once the chain's structure (cs) checks out.  bodyHashes
// returns the body hash for each algorithm named (those of the topmost
// Message-Instance this build implements); it is called at most once, and
// not at all with HeadersOnly or when an earlier check already failed.
// lower, when not nil, is the §14.7 walk of the instances below the top
// (VerifyFull's): run once the top instance's hashes match, it returns the
// walk's failure or nil.
//
// The checks run in contract C9's order, so the first error found is the
// primary one: (§14.2 structure, already checked by chainOf,) each
// Message-Instance's content by ascending m=, the §14.7 chain walk, each DKIM2-Signature's
// content by ascending i=, then §14.3, §14.4, and per signature §14.5 and
// §14.6.  A walk that fails is the result whatever the signatures say: no
// key is used and no signature verified before it passes.
func verifyFields(cs *chainShape, bodyHashes func(algs []string) (map[string][]byte, error),
	lower func() *VerifyResult, fetcher KeyFetcher, opts ...VerifyOptions) ([]VerifyResult, error) {
	var opt VerifyOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	miHeaders, sigHeaders, contentHeaders := cs.mis, cs.sigs, cs.content
	var err error

	// §14.2 content: each Message-Instance on its own, by ascending m=,
	// whether or not the walk reaches it.  Every parseMI error is a
	// self-describing §14.2 string.
	var topMI *MessageInstance
	for _, raw := range miHeaders {
		if topMI, err = parseMI(raw); err != nil {
			return nil, err
		}
	}

	// §16.3: with HeadersOnly there is no body to hash — the caller handed us
	// the header fields alone, as echoed back in a DSN's text/rfc822-headers
	// part — so the body pass is skipped and only header hashes are checked.
	headersOnly := opt.HeadersOnly

	// §14.7, the chain walk, top down.  The top instance is checked against
	// the content as received; the body is hashed in a single streaming pass
	// (never buffered), fanned out to every algorithm the topmost MI's h= tag
	// names that this build implements (see hashBodyStream, §3.5).  The
	// instances below it are lower's.  With no Message-Instance at all (the
	// signatures' m= tags are missing) there is nothing to walk.
	if topMI != nil {
		var mierr error
		if headersOnly {
			mierr = verifyMIHeaderHashes(topMI, contentHeaders)
		} else {
			topBodyHashes, err := bodyHashes(implementedAlgs(topMI.Hashes))
			if err != nil {
				return nil, fmt.Errorf("PERMERROR: body hash: %w", err)
			}
			mierr = verifyMIHashesPrecomputed(topMI, contentHeaders, topBodyHashes)
		}
		if mierr != nil {
			// Outbound, a top instance no signature covers yet is the
			// signer's own: "unsigned top", reported against the top
			// signature when there is one.
			switch {
			case len(sigHeaders) == 0:
				mierr = fmt.Errorf("unsigned top %w", mierr)
			case opt.Outbound && cs.maxSigM < topMI.Version:
				mierr = fmt.Errorf("i=%d: unsigned top %w", cs.topSigI, mierr)
			}
			res := VerifyResult{Sequence: cs.topSigI, Domain: cs.topSigD, Error: mierr}
			if len(sigHeaders) == 0 {
				res.Domain = "MI-chain"
			}
			return []VerifyResult{res}, nil
		}
		if lower != nil {
			if r := lower(); r != nil {
				r.Sequence = cs.topSigI // as the top instance's failure is
				return []VerifyResult{*r}, nil
			}
		}
	}

	// Outbound with no signature at all (a list host added unsigned
	// Message-Instances to an unsigned post): the walk was all there is.
	if len(sigHeaders) == 0 {
		return []VerifyResult{}, nil
	}

	// §14.2 content: each DKIM2-Signature on its own, by ascending i=.  A
	// signature that does not parse (bad t=, a missing tag, a known
	// algorithm's item without a base64 value) is the result.
	parsedSigs := make([]*DKIM2Signature, len(sigHeaders))
	for i, raw := range sigHeaders {
		if parsedSigs[i], err = parseSig(raw); err != nil {
			// §8: a duplicated tag is tag-list syntax, which ranks before
			// the missing or unexpected tags parseSig checks for.
			if colon := strings.IndexByte(raw, ':'); colon >= 0 && parseTagValueList(raw[colon+1:]).duplicate != "" {
				return nil, sigSyntaxError(i + 1)
			}
			return nil, err
		}
		if err := sigFieldError(parsedSigs[i], len(miHeaders)); err != nil {
			return nil, err
		}
	}
	topSig := parsedSigs[len(parsedSigs)-1]

	// §14.3: not Validly Signed if made more than 14 days before delivery,
	// or more than one day after it.  t=0 is valid syntax and simply very
	// old.  Compared without adding to t=, which may be as large as
	// math.MaxInt64.
	if !opt.SkipTimestampCheck {
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

	// §14.5 and §14.6: each signature's keys, then its signatures.
	results := make([]VerifyResult, 0, len(sigHeaders))
	for idx, rawSig := range sigHeaders {
		sig := parsedSigs[idx]

		// Build signing input:
		// MI headers with m= <= this sig's MIVersion (ascending)
		// Sig headers with i= < this sig's Sequence (ascending, i.e. indices 0..idx-1)
		// Incomplete form of this sig
		var sigInput []byte
		for k, raw := range miHeaders {
			if k+1 <= sig.MIVersion { // miHeaders are m=1..N in order
				sigInput = append(sigInput, canonicalizeSigHeader(raw)...)
			}
		}
		for _, raw := range sigHeaders[:idx] {
			sigInput = append(sigInput, canonicalizeSigHeader(raw)...)
		}
		// The incomplete form: strip signature values from this sig's raw header
		incomplete := sig.incompleteForm(strings.TrimRight(rawSig, "\r\n"))
		sigInput = append(sigInput, canonicalizeSigHeader(incomplete+"\r\n")...)

		digest := sha256.Sum256(sigInput)
		results = append(results, VerifyResult{Sequence: sig.Sequence, Domain: sig.Domain,
			Error: verifySigItems(sig, fetcher, digest[:])})
	}

	return results, nil
}

// chainShape is what chainStructure leaves for the checks after it: the
// fields in chain order, and the top (highest i=) signature's numbers.
type chainShape struct {
	mis, sigs []string // raw fields, by ascending m= and i= (1..N each)
	topSigI   int
	topSigM   int    // 0 when the top signature has no m=
	topSigD   string // its d= as written
	maxSigM   int    // the highest m= of any signature
	content   []Header
}

// chainStructure is -07 §14.2's structure check, contract C9 steps a..h:
// what the field names and their m=/i= numbers alone decide, before any
// field's content.  Each step is over every field, and the first that
// applies is the result:
//
//	a. more than MaxChainLength fields: Message-Instance, then
//	   DKIM2-Signature;
//	b. a Message-Instance with no usable m= (first top down);
//	c. an m= given twice (the lowest);
//	d. a DKIM2-Signature with no usable i=, or an i=/m= that is not a
//	   chain number (first top down);
//	e. an i= given twice (the lowest);
//	f. "m=<x> missing", the lowest x up to the higher of the highest m=
//	   and the top signature's m=;
//	g. the top Message-Instance not signed: above every signature's m=
//	   (allowed outbound: the next signer covers it);
//	h. "i=<x> missing", the lowest x.
func chainStructure(miHeaders, sigHeaders []string, outbound bool) (*chainShape, error) {
	tags := func(raw string) *tagValueList {
		if colon := strings.IndexByte(raw, ':'); colon >= 0 {
			raw = raw[colon+1:]
		}
		return parseTagValueList(raw)
	}
	// num is a value chainNumberError passed: 1..MaxChainLength in digits.
	num := func(v string) int {
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	}

	// a.
	if len(miHeaders) > MaxChainLength {
		return nil, fmt.Errorf("PERMERROR: more than %d Message-Instance fields", MaxChainLength)
	}
	if len(sigHeaders) > MaxChainLength {
		return nil, fmt.Errorf("PERMERROR: more than %d DKIM2-Signature fields", MaxChainLength)
	}

	// b, c.
	miAt := make([]string, MaxChainLength+1)
	maxM := 0
	for _, raw := range miHeaders {
		tvl := tags(raw)
		if !tvl.has("m") {
			return nil, errors.New("PERMERROR: Message-Instance m= tag=m missing")
		}
		if err := chainNumberError("Message-Instance", "m", tvl.get("m"), tvl.get("m"), true); err != nil {
			return nil, err
		}
	}
	for _, raw := range miHeaders {
		m := num(tags(raw).get("m"))
		if miAt[m] != "" {
			return nil, lowestTwice("Message-Instance m", miHeaders, tags, "m")
		}
		miAt[m] = raw
		if m > maxM {
			maxM = m
		}
	}

	// d, e.
	cs := &chainShape{}
	sigAt := make([]string, MaxChainLength+1)
	maxI := 0
	for _, raw := range sigHeaders {
		tvl := tags(raw)
		if !tvl.has("i") {
			return nil, errors.New("PERMERROR: DKIM2-Signature i= tag=i missing")
		}
		ident := tvl.get("i")
		if err := chainNumberError("DKIM2-Signature", "i", ident, ident, true); err != nil {
			return nil, err
		}
		if err := chainNumberError("DKIM2-Signature", "m", tvl.get("m"), ident, tvl.has("m")); err != nil {
			return nil, err
		}
	}
	for _, raw := range sigHeaders {
		tvl := tags(raw)
		i := num(tvl.get("i"))
		if sigAt[i] != "" {
			return nil, lowestTwice("DKIM2-Signature i", sigHeaders, tags, "i")
		}
		sigAt[i] = raw
		cs.maxSigM = max(cs.maxSigM, num(tvl.get("m")))
		if i > maxI {
			maxI = i
			cs.topSigI, cs.topSigM, cs.topSigD = i, num(tvl.get("m")), tvl.get("d")
		}
	}

	// f, g, h.
	for x := 1; x <= max(maxM, cs.topSigM); x++ {
		if miAt[x] == "" {
			return nil, fmt.Errorf("PERMERROR: Message-Instance m=%d missing", x)
		}
	}
	if maxM > cs.maxSigM && !outbound {
		return nil, fmt.Errorf("PERMERROR: Message-Instance m=%d is not signed", maxM)
	}
	for x := 1; x <= maxI; x++ {
		if sigAt[x] == "" {
			return nil, fmt.Errorf("PERMERROR: DKIM2-Signature i=%d missing", x)
		}
	}

	cs.mis, cs.sigs = miAt[1:maxM+1], sigAt[1:maxI+1]
	return cs, nil
}

// lowestTwice is "<who>=<n> appears more than once" for the lowest number
// tag gives more than one of raws (all chain numbers): steps c and e of
// chainStructure.
func lowestTwice(who string, raws []string, tags func(string) *tagValueList, tag string) error {
	var count [MaxChainLength + 1]int
	for _, raw := range raws {
		n, _ := strconv.Atoi(strings.TrimSpace(tags(raw).get(tag)))
		count[n]++
	}
	for n, c := range count {
		if c > 1 {
			return fmt.Errorf("PERMERROR: %s=%d appears more than once", who, n)
		}
	}
	return nil // not reached: the caller found one
}

// sigFieldError is the -07 §14.2 check of one DKIM2-Signature field on its
// own (contract C9 runs it for every signature, by ascending i=, after the
// chain walk and before any §14.3 check): a
// duplicated tag, an mf=/rt= without its angle brackets (§10.5/§10.6), the
// §10.9 duplicate-selector and selector-count rules, and an m= naming a
// Message-Instance that is not there.
func sigFieldError(sig *DKIM2Signature, top int) error {
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
	// chainStructure found m=1..top, and no others.
	if sig.MIVersion >= 1 && sig.MIVersion <= top {
		return nil
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

// c9Section is where an error string ranks in contract C9's order: the
// §14.7 chain walk (3), §14.3 (5), §14.5 (7), §14.6 (8), §14.8 (9).
// Anything else (§14.2, §14.4) is 2: those stop verification before
// anything that could be ranked against them is checked.
func c9Section(text string) int {
	switch {
	case strings.HasPrefix(text, "FAIL: Message-Instance "):
		return 3
	case strings.HasSuffix(text, " signature expired") || strings.HasSuffix(text, " signature is from the future"):
		return 5
	case strings.HasPrefix(text, "TEMPERROR: ") || strings.Contains(text, " public key ") ||
		strings.Contains(text, " has no signature with a supported algorithm"):
		return 7
	case strings.HasPrefix(text, "FAIL: DKIM2-Signature "):
		return 8
	case strings.HasSuffix(text, " matching From is not authentic"):
		return 9
	}
	return 2
}

// PrimaryResult is the result whose error is the primary one (contract
// C9): the first in its order, the lowest i= first within a section; nil
// when every result passed.  A chain walk that fails is the only result
// Verify and VerifyFull return; otherwise they return every signature's
// result in i= order.  A caller reporting one reason, or one state,
// reports this one's.
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
		if best == nil || sec < bestSec || (sec == bestSec && sec > 4 && r.Sequence < best.Sequence) {
			best, bestSec = r, sec
		}
	}
	return best
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
