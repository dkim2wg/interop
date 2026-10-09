package dkim2

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// DKIM2Signature is a parsed or constructed DKIM2-Signature header.
type DKIM2Signature struct {
	Sequence   int
	MIVersion  int
	Timestamp  int64
	Domain     string
	NextDomain string // nd= tag (draft-06 §8.7); empty if absent
	MailFrom   string
	RcptTo     []string
	Nonce      string   // n= tag (optional); max 64 ASCII chars per §8.3
	Flags      []string // f= tag (optional); comma-separated flags per §8.10
	Sigs       []SigItem
	Duplicate  string // lowercased tag name that appeared more than once (§8), if any
}

// toRFC5321Path wraps an address as an RFC5321 path for mf=/rt= (spec 7.5/7.6):
// angle brackets MUST be present. "" -> "<>"; already-bracketed unchanged.
func toRFC5321Path(a string) string {
	if a == "" {
		return "<>"
	}
	if strings.HasPrefix(a, "<") && strings.HasSuffix(a, ">") {
		return a
	}
	return "<" + a + ">"
}

// SigItem is one sel:alg:value entry in the s= tag.
type SigItem struct {
	Selector  string
	Algorithm string
	Value     []byte // nil means empty (signing input placeholder per §8.5)
}

// SignOptions carries per-message signing parameters.
type SignOptions struct {
	Selector   string
	Domain     string
	MailFrom   string
	RcptTo     []string
	NextDomain string // nd= (draft-06 §9.3); when set, emit nd= instead of mf=/rt=
	Timestamp  int64  // 0 = use time.Now()
	// HashAlgs selects the algorithm(s) used for the new Message-Instance's
	// h= tag (spec-06 §3.1/§7.3), in emission order. nil/empty means
	// []string{"sha256"} — the signer default, which MUST NOT change.
	HashAlgs []string

	// Signer gate: before signing a message that already carries a DKIM2
	// chain, Sign verifies that chain (outbound mode: an unsigned top
	// Message-Instance is the one this hop is about to cover) and refuses
	// if it does not check out.  Fetcher supplies the verification keys
	// (nil = real DNS); SkipTimestampCheck relaxes the §10.3 age check.
	Fetcher            KeyFetcher
	SkipTimestampCheck bool
	// AllowNullBodyRecipe lets Sign cover an UNSIGNED Message-Instance (its
	// m= above every valid upstream DKIM2-Signature's m=, top or not) whose
	// body Recipe is null ("b": null); by default that is refused.  A null
	// that an upstream signature already covers is signed without it.
	AllowNullBodyRecipe bool
	// SkipUpstreamCheck turns the gate off entirely (the caller built the
	// chain itself).
	SkipUpstreamCheck bool
}

// VerifyResult is the outcome for one DKIM2-Signature in the message.
type VerifyResult struct {
	Sequence int
	Domain   string
	Error    error // nil = pass
}

// VerifyOptions carries optional envelope values for §10.4 exact-match checking.
// Zero value means no envelope checks are performed.
type VerifyOptions struct {
	MailFrom           string   // SMTP MAIL FROM; empty = skip check
	RcptTo             []string // SMTP RCPT TO values; nil = skip check
	SkipTimestampCheck bool     // disable §10.3 14-day expiry check (for testing)

	// Outbound verifies a message as its next signer sees it: a top
	// Message-Instance that no signature covers yet (m= above every
	// signature's) is allowed, and is checked against the message content
	// instead.  Upstream signatures must still verify.
	Outbound bool

	// Signer is the domain about to sign, in Outbound mode: a top signature
	// whose nd= names it (a §9.3 bridge) is accepted; any other nd= is not.
	Signer string

	// HeadersOnly says the message has no body, as with the returned original
	// in a DSN's text/rfc822-headers part (spec-06 §12.1.2). Signatures and the
	// chain are checked as usual; of the Message-Instance content check, only
	// the topmost instance's header hash can be, so only that is.
	HeadersOnly bool
}

// errUnkeyableSignature is the PERMERROR for a DKIM2-Signature whose i= is
// missing or not a positive integer (or that has no tag-list at all).
var errUnkeyableSignature = errors.New("PERMERROR DKIM2-Signature has a missing or malformed i= tag")

// MaxChainLength is the most hops a chain may have: every i= and m= names
// one, so none may be larger.
const MaxChainLength = 32

// MaxChainNumber is the largest number an i= or m= may be written as (at
// most three digits).  Anything bigger is out of range before it is ever a
// chain number.
const MaxChainNumber = 100

func allASCIIDigits(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

// chainNumberError is the PERMERROR for an i= or m= value that is not a chain
// number, or nil (also when the tag is absent, which is left to the callers).
// 1*DIGIT in ASCII, else malformed (also zero): strconv.Atoi would take "+1".
// At most three digits and 1..MaxChainNumber, so "01" and "001" are 1 (and
// nothing is converted that could overflow), and no more than MaxChainLength.
func chainNumberError(field, tag, v string, present bool) error {
	if !present {
		return nil
	}
	v = strings.TrimSpace(v)
	if !allASCIIDigits(v) || strings.TrimLeft(v, "0") == "" {
		if tag == "i" {
			return fmt.Errorf("PERMERROR %s has a missing or malformed i= tag", field)
		}
		return fmt.Errorf("PERMERROR %s has a malformed %s= tag", field, tag)
	}
	if len(v) > 3 {
		return fmt.Errorf("PERMERROR %s %s= exceeds the maximum chain number of %d", field, tag, MaxChainNumber)
	}
	n, _ := strconv.Atoi(v)
	if n > MaxChainNumber {
		return fmt.Errorf("PERMERROR %s %s= exceeds the maximum chain number of %d", field, tag, MaxChainNumber)
	}
	if n > MaxChainLength {
		return fmt.Errorf("PERMERROR %s %s= exceeds the maximum chain length of %d", field, tag, MaxChainLength)
	}
	return nil
}

// chainRangeError is the PERMERROR for the first DKIM2-Signature i= or m=, or
// Message-Instance m=, that is not a chain number (chainNumberError), or nil.
// Raw fields, name included.  Checked before anything walks 1..max for gaps.
func chainRangeError(miHeaders, sigHeaders []string) error {
	type check struct {
		field, tag string
		raws       []string
	}
	for _, c := range []check{
		{"DKIM2-Signature", "i", sigHeaders},
		{"DKIM2-Signature", "m", sigHeaders},
		{"Message-Instance", "m", miHeaders},
	} {
		for _, raw := range c.raws {
			colon := strings.IndexByte(raw, ':')
			if colon < 0 {
				continue
			}
			tvl := parseTagValueList(raw[colon+1:])
			if err := chainNumberError(c.field, c.tag, tvl.get(c.tag), tvl.has(c.tag)); err != nil {
				return err
			}
		}
	}
	return nil
}

// validSequenceTag reports whether a raw DKIM2-Signature field carries an i=
// that is a positive integer written in ASCII digits.  strconv.Atoi would
// also take "+1", so only the digits are looked at.
func validSequenceTag(raw string) bool {
	colon := strings.IndexByte(raw, ':')
	if colon < 0 {
		return false
	}
	v := parseTagValueList(raw[colon+1:]).get("i")
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	// Positive: not all zeros.  Not converted, so a value too large for an
	// int is still a sequence number here; chainRangeError bounds it.
	return strings.TrimLeft(v, "0") != ""
}

// KnownSigAlg reports whether alg is a signature algorithm this verifier
// implements (spec-06 §3, §8.9).  Algorithm names are tag values, so they are
// case significant: "RSA-SHA256" is not "rsa-sha256".
func KnownSigAlg(alg string) bool {
	return alg == "rsa-sha256" || alg == "ed25519-sha256"
}

// sigSyntaxError is spec-06 §11.2's "PERMERROR DKIM2-Signature i=<x> syntax error".
func sigSyntaxError(i int) error {
	return fmt.Errorf("PERMERROR DKIM2-Signature i=%d syntax error", i)
}

func parseSig(raw string) (*DKIM2Signature, error) {
	colon := strings.IndexByte(raw, ':')
	if colon < 0 {
		// i= is not yet parsed at this point (the tag-value list hasn't even
		// been split off the field name), so no i=<x> prefix is available.
		return nil, fmt.Errorf("DKIM2-Signature: no colon found")
	}
	tvl := parseTagValueList(raw[colon+1:])
	sig := &DKIM2Signature{Duplicate: tvl.duplicate}

	if v := tvl.get("i"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			// The i= tag itself is malformed, so its value can't be trusted
			// to prefix this error.
			return nil, fmt.Errorf("DKIM2-Signature tag=i syntax error: %w", err)
		}
		sig.Sequence = n
	}
	if v := tvl.get("m"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("DKIM2-Signature i=%d tag=m syntax error: %w", sig.Sequence, err)
		}
		sig.MIVersion = n
	}
	if tvl.has("t") {
		// §8.4: sig-t-tag = %x74 [FWS] "=" [FWS] 1*DIGIT -- no sign, no
		// exponent, no hex.  Not constrained to 32 bits; anything beyond
		// int64 is saturated (it is far in the future either way).
		v := tvl.get("t")
		if !allASCIIDigits(v) {
			return nil, sigSyntaxError(sig.Sequence)
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			n = math.MaxInt64
		}
		sig.Timestamp = n
	}
	sig.Domain = tvl.get("d")
	sig.NextDomain = tvl.get("nd")
	if v := tvl.get("mf"); v != "" {
		b, err := base64.StdEncoding.DecodeString(stripB64WSP(v))
		if err != nil {
			return nil, fmt.Errorf("invalid mf=: %w", err)
		}
		sig.MailFrom = string(b)
	}
	if v := tvl.get("rt"); v != "" {
		for _, part := range strings.Split(v, ",") {
			b, err := base64.StdEncoding.DecodeString(stripB64WSP(part))
			if err != nil {
				return nil, fmt.Errorf("invalid rt= item: %w", err)
			}
			sig.RcptTo = append(sig.RcptTo, string(b))
		}
	}
	if v := tvl.get("s"); v != "" {
		for _, part := range strings.Split(v, ",") {
			// §2.12: strip folding whitespace before splitting, not after.
			// A fold may land between the Selector colon and the algorithm
			// token, in which case splitting first leaves the CRLF+WSP
			// attached to the algorithm name and the comparison fails.
			fields := strings.SplitN(stripB64WSP(part), ":", 3)
			if len(fields) != 3 {
				return nil, fmt.Errorf("invalid s= item: %q", part)
			}
			item := SigItem{Selector: fields[0], Algorithm: fields[1]}
			// §3.4: an item whose algorithm is not implemented is ignored
			// entirely, value included.  An implemented one MUST carry a
			// non-empty base64 signature.
			if KnownSigAlg(item.Algorithm) {
				b, err := base64.StdEncoding.DecodeString(fields[2])
				if fields[2] == "" || err != nil {
					return nil, sigSyntaxError(sig.Sequence)
				}
				item.Value = b
			}
			sig.Sigs = append(sig.Sigs, item)
		}
	}
	if v := tvl.get("n"); v != "" {
		if len(v) > 64 {
			return nil, fmt.Errorf("n= nonce exceeds 64 characters (%d)", len(v))
		}
		sig.Nonce = v
	}
	if v := tvl.get("f"); v != "" {
		// §2.12: a folded f= list carries CRLF+WSP, not just spaces.
		for _, part := range strings.Split(stripB64WSP(v), ",") {
			if part != "" {
				sig.Flags = append(sig.Flags, part)
			}
		}
	}
	// draft-06 §8: i= m= t= d= s= MUST be present; plus either nd= or both
	// mf= and rt=. nd= and mf=/rt= are mutually exclusive.
	if !tvl.has("i") || !tvl.has("m") || !tvl.has("t") {
		return nil, fmt.Errorf("DKIM2-Signature i=%d: missing required i=/m=/t= tag", sig.Sequence)
	}
	if sig.Domain == "" {
		return nil, fmt.Errorf("DKIM2-Signature i=%d tag=d missing", sig.Sequence)
	}
	if len(sig.Sigs) == 0 {
		return nil, fmt.Errorf("DKIM2-Signature i=%d tag=s missing", sig.Sequence)
	}
	hasND := tvl.has("nd")
	hasMF := tvl.has("mf")
	hasRT := tvl.has("rt")
	if hasND && (hasMF || hasRT) {
		return nil, fmt.Errorf("DKIM2-Signature i=%d tag=nd was unexpected: nd= excludes mf=/rt=", sig.Sequence)
	}
	if !hasND && !(hasMF && hasRT) {
		return nil, fmt.Errorf("DKIM2-Signature i=%d: missing chain tags (need nd= or both mf=+rt=)", sig.Sequence)
	}
	return sig, nil
}

// String returns the complete DKIM2-Signature header (with field name, no trailing CRLF).
// Format matches Python output exactly: single line, no folding.
func (sig *DKIM2Signature) String() string {
	mf := base64.StdEncoding.EncodeToString([]byte(toRFC5321Path(sig.MailFrom)))
	var rtParts []string
	for _, r := range sig.RcptTo {
		rtParts = append(rtParts, base64.StdEncoding.EncodeToString([]byte(toRFC5321Path(r))))
	}
	rt := strings.Join(rtParts, ",")

	var sParts []string
	for _, item := range sig.Sigs {
		val := base64.StdEncoding.EncodeToString(item.Value)
		sParts = append(sParts, item.Selector+":"+item.Algorithm+":"+val)
	}
	s := strings.Join(sParts, ",")

	// draft-06 §8: an nd= signature carries nd= instead of mf=/rt=.
	var chain string
	if sig.NextDomain != "" {
		chain = fmt.Sprintf("nd=%s", sig.NextDomain)
	} else {
		chain = fmt.Sprintf("mf=%s; rt=%s", mf, rt)
	}

	out := fmt.Sprintf(
		"DKIM2-Signature: i=%d; m=%d; t=%d; d=%s; %s; s=%s;",
		sig.Sequence, sig.MIVersion, sig.Timestamp, sig.Domain, chain, s,
	)
	// f= flags (draft-06 §8.10), e.g. feedback, feedhere — preserved verbatim.
	if len(sig.Flags) > 0 {
		out += " f=" + strings.Join(sig.Flags, ",") + ";"
	}
	return out
}

// reSTag matches the s= tag at a tag boundary — the start of the header value
// or after a ";" — case-insensitively and tolerating FWS around "=". This is
// independent of tag order (s= may be first) and case (S=), per spec-06 §8.
// Base64 cannot contain ";" so the value runs to the next ";".
var reSTag = regexp.MustCompile(`(?i)(^|;)\s*s\s*=`)

// incompleteForm takes the original raw header value (after the field name)
// and returns it with each s= item's signature value replaced by empty string
// (per §8.5), preserving every other byte — tag order, case, whitespace, and
// folding — so the reconstruction canonicalizes to exactly what was signed.
func (sig *DKIM2Signature) incompleteForm(rawHeader string) string {
	// Operate on the value after the field-name colon so a leading s= (no
	// preceding ";") is still matched by the "^" alternative.
	colon := strings.IndexByte(rawHeader, ':')
	if colon < 0 {
		return rawHeader
	}
	head, value := rawHeader[:colon+1], rawHeader[colon+1:]

	m := reSTag.FindStringIndex(value)
	if m == nil {
		return rawHeader
	}
	prefix := value[:m[1]] // through the "=" of the s tag (any order/case/WSP)
	rest := value[m[1]:]
	sval := rest
	suffix := ""
	if semi := strings.IndexByte(rest, ';'); semi >= 0 {
		sval, suffix = rest[:semi], rest[semi:]
	}

	// Blank the 3rd (signature) field of each comma-separated item, dropping
	// any folding within it.
	var stripped []string
	for _, item := range strings.Split(sval, ",") {
		f := strings.SplitN(item, ":", 3)
		if len(f) == 3 {
			stripped = append(stripped, f[0]+":"+f[1]+":")
		} else {
			stripped = append(stripped, item)
		}
	}
	return head + prefix + strings.Join(stripped, ",") + suffix
}

// buildIncomplete builds a fresh incomplete DKIM2-Signature header (s= values
// are empty per §8.5), for use as the signing input when creating a new sig.
func buildIncomplete(seq, miVer int, ts int64, domain, mailFrom string,
	rcptTo []string, nextDomain, selector, algorithm string) string {
	// draft-06 §9.3: an imaginary-hop signature carries nd= instead of mf=/rt=.
	var chain string
	if nextDomain != "" {
		chain = fmt.Sprintf("nd=%s", nextDomain)
	} else {
		mf := base64.StdEncoding.EncodeToString([]byte(toRFC5321Path(mailFrom)))
		var rtParts []string
		for _, r := range rcptTo {
			rtParts = append(rtParts, base64.StdEncoding.EncodeToString([]byte(toRFC5321Path(r))))
		}
		chain = fmt.Sprintf("mf=%s; rt=%s", mf, strings.Join(rtParts, ","))
	}
	return fmt.Sprintf(
		"DKIM2-Signature: i=%d; m=%d; t=%d; d=%s; %s; s=%s:%s:;",
		seq, miVer, ts, domain, chain, selector, algorithm,
	)
}
