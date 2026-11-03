package dkim2

import (
	"fmt"
	"strings"
)

// PolicyFetcher looks up the Domain Policy Record (§3.8; DKIMKEYS §6) of a
// From domain: the TXT records at _domainkey.<domain>, each RR's strings
// already joined.  None (NXDOMAIN, NODATA) is an empty slice and a nil
// error; any error is a temporary failure, reported as TEMPERROR.  The
// library does the filtering, counting and parsing (policyOf), so every
// PolicyFetcher gets the same semantics.  JSONKeyFetcher and NetKeyFetcher
// are PolicyFetchers.
type PolicyFetcher interface {
	FetchPolicy(domain string) ([]string, error)
}

// Domain Policy Record outcomes.
const (
	policyAllowed  = iota // no record, or one without the strict flag
	policyStrict          // f= holds "strict", or the record is malformed
	policyMultiple        // more than one v=DKIM1 record
	policyTemp            // the lookup failed for now
)

// policyOf is contract E3.2 over the TXT records at _domainkey.<dom>: only
// the records whose first tag is v=DKIM1 count; none is "allowed", more
// than one "multiple"; one is parsed as a key record's tag=value list, and
// is "strict" when its f= flag list holds "strict" or when the record, or
// its f= list, breaks the ABNF (fail closed).
func policyOf(txts []string) int {
	var recs []string
	for _, t := range txts {
		if isV, v := firstTagV(t); isV && v == "DKIM1" {
			recs = append(recs, t)
		}
	}
	switch len(recs) {
	case 0:
		return policyAllowed
	case 1:
	default:
		return policyMultiple
	}
	tags, err := parseKeyTags(recs[0])
	if err != nil {
		return policyStrict
	}
	f, ok := tags["f"]
	if !ok || f == "" {
		return policyAllowed
	}
	strict := false
	for _, m := range strings.Split(f, ":") {
		m = trimFWS(m)
		if !hyphenatedWord(m) {
			return policyStrict // an empty member, or not a flag at all
		}
		strict = strict || m == "strict"
	}
	if strict {
		return policyStrict
	}
	return policyAllowed
}

// hyphenatedWord: ALPHA *(ALPHA / DIGIT / "-"), not ending in "-".
func hyphenatedWord(s string) bool {
	if s == "" || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if i == 0 && !alpha {
			return false
		}
		if !alpha && !(c >= '0' && c <= '9') && c != '-' {
			return false
		}
	}
	return true
}

// policyCache looks each From domain's Domain Policy Record up at most once
// per verification, and only when asked: never in the key prefetch.
type policyCache struct {
	src  PolicyFetcher
	seen map[string]int
}

func newPolicyCache(src PolicyFetcher) *policyCache {
	return &policyCache{src: src, seen: map[string]int{}}
}

func (c *policyCache) get(dom string) int {
	if p, ok := c.seen[dom]; ok {
		return p
	}
	p := policyTemp
	if txts, err := c.src.FetchPolicy(dom); err == nil {
		p = policyOf(txts)
	}
	c.seen[dom] = p
	return p
}

// policySource is the Domain Policy Record source for a verification: the
// caller's VerifyOptions.Policy, else the key source when it is one too
// (dns.json, real DNS), else real DNS.
func policySource(fetcher KeyFetcher, opts ...VerifyOptions) PolicyFetcher {
	if len(opts) > 0 && opts[0].Policy != nil {
		return opts[0].Policy
	}
	if p, ok := fetcher.(PolicyFetcher); ok {
		return p
	}
	return &NetKeyFetcher{}
}

// commaOutsideQuotes reports whether a From value has a "," outside quoted
// strings and comments: a list of addresses, or a group of more than one.
func commaOutsideQuotes(v string) bool {
	depth, inQuote := 0, false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '\\' && (depth > 0 || inQuote):
			i++
		case inQuote:
			inQuote = c != '"'
		case c == '(':
			depth++
		case c == ')' && depth > 0:
			depth--
		case depth > 0:
		case c == '"':
			inQuote = true
		case c == ',':
			return true
		}
	}
	return false
}

// fromAuthenticError is §14.8 for one (signature, From fields) pair,
// contract E3.1: the first failing step's error, nil when the From is
// Authentic for the signature's d=.  The Domain Policy Record is looked up
// (through policies) only when the From domain is above d=.
func fromAuthenticError(froms []Header, s *DKIM2Signature, policies *policyCache) error {
	who := fmt.Sprintf("DKIM2-Signature i=%d", s.Sequence)
	notAuthentic := fmt.Errorf("FAIL: %s matching From is not authentic", who)
	if len(froms) > 1 || len(froms) == 1 && commaOutsideQuotes(froms[0].Value) {
		return fmt.Errorf("FAIL: %s From has more than one address", who)
	}
	if len(froms) == 0 {
		return notAuthentic
	}
	addr, ok := fromMailbox(froms[0].Value)
	if !ok {
		return notAuthentic
	}
	dom, lit := domainOf(addr)
	if lit {
		return fmt.Errorf("FAIL: %s From uses a domain literal", who)
	}
	d := toALabel(strings.TrimSuffix(strings.ToLower(trimFWS(s.Domain)), "."))
	if relaxedMatch(dom, d) {
		return nil
	}
	if !relaxedMatch(d, dom) {
		return notAuthentic
	}
	switch policies.get(dom) {
	case policyTemp:
		return fmt.Errorf("TEMPERROR: %s policy for %s unavailable", who, dom)
	case policyMultiple:
		return fmt.Errorf("PERMERROR: %s multiple records for %s policy", who, dom)
	case policyStrict:
		return fmt.Errorf("FAIL: %s From %s forbids subdomain signing", who, dom)
	}
	return nil
}
