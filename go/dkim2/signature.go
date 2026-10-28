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
	NextDomain string // nd= tag (§10.7); empty if absent
	MailFrom   string
	RcptTo     []string
	Nonce      string   // n= tag (optional); max 64 ASCII chars per §10.3
	Flags      []string // f= tag (optional); comma-separated flags per §10.10
	Sigs       []SigItem
	Duplicate  string // tag name that appeared more than once (§8), if any
}

// toRFC5321Path wraps an address as an RFC5321 path for mf=/rt= (§10.5,
// §10.6): angle brackets MUST be present. "" -> "<>"; already-bracketed
// unchanged.  A domain holding U-labels is recorded as A-labels (§18); the
// local part is left as it is.
func toRFC5321Path(a string) string {
	if a == "" {
		return "<>"
	}
	if !(strings.HasPrefix(a, "<") && strings.HasSuffix(a, ">")) {
		a = "<" + a + ">"
	}
	if at := strings.LastIndexByte(a, '@'); at >= 0 && !isASCII(a[at+1:]) {
		d := a[at+1 : len(a)-1]
		if !strings.HasPrefix(d, "[") {
			a = a[:at+1] + toALabel(d) + ">"
		}
	}
	return a
}

// SigItem is one sel:alg:value entry (sig-set) in the s= tag.
type SigItem struct {
	Selector  string
	Algorithm string
	Value     []byte // nil means empty (signing input placeholder per §10.9)
	// Group is the sig-all ("," list) the item belongs to, counting the
	// "|"-separated groups of s= from 0 (-08 §10.9).  Signers write one.
	Group int
}

// MaxSignatureItems is the most sig-sets one s= may hold (contract D3, a
// local limit: -08 dropped "more selectors than allowed", and every item
// can cost a key lookup and a verification).
const MaxSignatureItems = 8

// SignOptions carries per-message signing parameters.
type SignOptions struct {
	Selector   string
	Domain     string
	MailFrom   string
	RcptTo     []string
	NextDomain string // nd= (§12.3); when set, emit nd= instead of mf=/rt=
	Timestamp  int64  // 0 = use time.Now()
	// HashAlgs selects the algorithm(s) used for the new Message-Instance's
	// h= tag (§3.1/§9.3), in emission order. nil/empty means
	// []string{"sha256"} — the signer default, which MUST NOT change.
	HashAlgs []string

	// Signer gate: before signing a message that already carries a DKIM2
	// chain, Sign verifies that chain (outbound mode: an unsigned top
	// Message-Instance is the one this hop is about to cover) and refuses
	// if it does not check out.  Fetcher supplies the verification keys
	// (nil = real DNS); SkipTimestampCheck relaxes the §14.3 timestamp check.
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

	// Flags are emitted in f= (§10.10) as given, except that "exploded" is
	// never emitted at i=1 (§12.5).
	Flags []string
	// Exploded requests the "exploded" flag (§12.5): this hop sends copies
	// to more than one address.  It is also set, without the request, when
	// RcptTo holds more than one address; never at i=1.
	Exploded bool
}

// VerifyResult is the outcome for one DKIM2-Signature in the message.
type VerifyResult struct {
	Sequence int
	Domain   string
	Error    error // nil = pass

	// section is the -07 §14 section Error ranks in (contract C9), when its
	// text alone does not say: a Recipe that does not fit the message is
	// found by the §14.7 chain walk and ranks there, though its string is
	// §14.2's.  0: rank by the text (c9Section).
	section int
}

// VerifyOptions carries optional envelope values for the §14.4 exact-match check.
// Zero value means no envelope checks are performed.
type VerifyOptions struct {
	MailFrom           string   // SMTP MAIL FROM; empty = skip check
	RcptTo             []string // SMTP RCPT TO values; nil = skip check
	SkipTimestampCheck bool     // disable the §14.3 timestamp checks (for testing)

	// Outbound verifies a message as its next signer sees it: a top
	// Message-Instance that no signature covers yet (m= above every
	// signature's) is allowed, and is checked against the message content
	// instead.  Upstream signatures must still verify.
	Outbound bool

	// Signer is the domain about to sign, in Outbound mode: a top signature
	// whose nd= names it (a §12.3 bridge) is accepted; any other nd= is not.
	Signer string

	// HeadersOnly says the message has no body, as with the returned original
	// in a DSN's text/rfc822-headers part (§16.3). Signatures and the
	// chain are checked as usual; of the Message-Instance content check, only
	// the topmost instance's header hash can be, so only that is.
	HeadersOnly bool

	// UndoWalk makes VerifyFull check the lower Message-Instances by
	// rebuilding each previous version of the message (Undo), the
	// reference the default planned walk (plan.go) is held to.
	UndoWalk bool

	// NoKeyPrefetch turns off the background key lookups Verify and
	// VerifyFull start, with real DNS keys, once the header fields are read.
	NoKeyPrefetch bool
}

// ErrNone is returned by Verify and VerifyFull for a message with no DKIM2
// header fields at all: the result is "none" (Authentication-Results
// dkim2=none), not a PERMERROR, and it carries no error string of its own.
var ErrNone = errors.New("none")

// MaxFutureSkew and MaxSignatureAge are the §14.3 timestamp limits: a
// signature made more than one day after delivery, or more than 14 days
// before it, is not Validly Signed.
const (
	MaxFutureSkew   = 86400
	MaxSignatureAge = 1209600
)

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
// 1*DIGIT in ASCII, else a syntax error (also zero): strconv.Atoi would take
// "+1".  At most three digits and 1..MaxChainNumber, so "01" and "001" are 1
// (and nothing is converted that could overflow), and no more than
// MaxChainLength.  The field is named by its own number as written (a
// DKIM2-Signature by i=, a Message-Instance by m=, -07 §14.2): ident.
func chainNumberError(field, tag, v, ident string, present bool) error {
	if !present {
		return nil
	}
	v = strings.TrimSpace(v)
	identTag := "i"
	if field == "Message-Instance" {
		identTag = "m"
	}
	who := field + " " + identTag + "=" + strings.TrimSpace(ident)
	if !allASCIIDigits(v) || strings.TrimLeft(v, "0") == "" {
		return fmt.Errorf("PERMERROR: %s syntax error", who)
	}
	if tag != identTag {
		who += " " + tag + "=" + v
	}
	n := MaxChainNumber + 1
	if len(v) <= 3 {
		n, _ = strconv.Atoi(v)
	}
	if n > MaxChainNumber {
		return fmt.Errorf("PERMERROR: %s exceeds the maximum chain number of %d", who, MaxChainNumber)
	}
	if n > MaxChainLength {
		return fmt.Errorf("PERMERROR: %s exceeds the maximum chain length of %d", who, MaxChainLength)
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
			identTag := "i"
			if c.field == "Message-Instance" {
				identTag = "m"
			}
			if err := chainNumberError(c.field, c.tag, tvl.get(c.tag), tvl.get(identTag), tvl.has(c.tag)); err != nil {
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
// implements (§3, §10.9).  Algorithm names are tag values, so they are
// case significant: "RSA-SHA256" is not "rsa-sha256".  -08's mldsa44 (§3.4)
// is deferred (contract D8: Go keeps ML-DSA internal), so it, like the old
// mldsa44-ed25519-sha512 composite, is an unknown algorithm.
func KnownSigAlg(alg string) bool {
	return alg == "rsa-sha256" || alg == "ed25519-sha256"
}

// validToken: 1*(ALPHA / DIGIT / "_" / "-"), an algorithm or hash name
// (§9.3, §10.9) or one label of a selector.
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// validSelector: validToken labels joined by "." (§3.6 selector = Domain).
func validSelector(s string) bool {
	for _, label := range strings.Split(s, ".") {
		if !validToken(label) {
			return false
		}
	}
	return true
}

// sigSyntaxError is §14.2's "PERMERROR: DKIM2-Signature i=<x> syntax error".
func sigSyntaxError(i int) error {
	return fmt.Errorf("PERMERROR: DKIM2-Signature i=%d syntax error", i)
}

// sigTagError is §14.2's "PERMERROR: DKIM2-Signature i=<x> tag=<y> <what>"
// (what is "missing" or "was unexpected").
func sigTagError(i int, tag, what string) error {
	return fmt.Errorf("PERMERROR: DKIM2-Signature i=%d tag=%s %s", i, tag, what)
}

func parseSig(raw string) (*DKIM2Signature, error) {
	colon := strings.IndexByte(raw, ':')
	if colon < 0 {
		// i= is not yet parsed at this point (the tag-value list hasn't even
		// been split off the field name), so no i=<x> prefix is available.
		return nil, errors.New("PERMERROR: DKIM2-Signature syntax error (no colon found)")
	}
	tvl := parseTagValueList(raw[colon+1:])
	sig := &DKIM2Signature{Duplicate: tvl.duplicate}

	if v := tvl.get("i"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			// The i= tag itself is malformed: name it as written.
			return nil, fmt.Errorf("PERMERROR: DKIM2-Signature i=%s syntax error", strings.TrimSpace(v))
		}
		sig.Sequence = n
	}
	// §8: a fragment that is not a well-formed tag=value makes the whole
	// field a syntax error; it is never skipped to verify the rest.
	if tvl.syntaxErr {
		return nil, sigSyntaxError(sig.Sequence)
	}
	if v := tvl.get("m"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, sigSyntaxError(sig.Sequence)
		}
		sig.MIVersion = n
	}
	if tvl.has("t") {
		// §10.4: sig-t-tag = %x74 [FWS] "=" [FWS] 1*DIGIT -- no sign, no
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
			return nil, sigSyntaxError(sig.Sequence)
		}
		sig.MailFrom = string(b)
	}
	if v := tvl.get("rt"); v != "" {
		for _, part := range strings.Split(v, ",") {
			b, err := base64.StdEncoding.DecodeString(stripB64WSP(part))
			if err != nil {
				return nil, sigSyntaxError(sig.Sequence)
			}
			sig.RcptTo = append(sig.RcptTo, string(b))
		}
	}
	if v := tvl.get("s"); v != "" {
		// -08 §10.9: "|" groups of "," lists of sig-sets; an empty member
		// is a syntax error (contract D2).
		groups, ok := splitGroups(v)
		if !ok {
			return nil, sigSyntaxError(sig.Sequence)
		}
		for g, parts := range groups {
			for _, part := range parts {
				// §10.9 sig-set: exactly three parts.  FWS is allowed around
				// the separators and each colon (trimmed) and inside the
				// base64 value (removed), never inside the selector or
				// algorithm name: "rsa- sha256" is a syntax error, not a
				// fold to undo.
				fields := strings.Split(part, ":")
				if len(fields) != 3 {
					return nil, sigSyntaxError(sig.Sequence)
				}
				item := SigItem{Selector: trimFWS(fields[0]), Algorithm: trimFWS(fields[1]), Group: g}
				if !validSelector(item.Selector) || !validToken(item.Algorithm) {
					return nil, sigSyntaxError(sig.Sequence)
				}
				// Every item, whatever its algorithm, carries a non-empty
				// base64 signature (contract D3).
				value := stripB64WSP(fields[2])
				b, err := base64.StdEncoding.DecodeString(value)
				if value == "" || err != nil {
					return nil, sigSyntaxError(sig.Sequence)
				}
				item.Value = b
				sig.Sigs = append(sig.Sigs, item)
			}
		}
	}
	if v := tvl.get("n"); v != "" {
		if len(v) > 64 {
			return nil, fmt.Errorf("PERMERROR: DKIM2-Signature i=%d n= nonce exceeds 64 characters (%d)", sig.Sequence, len(v))
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
	// §10: i= m= t= d= s= MUST be present; plus either nd= or both
	// mf= and rt=. nd= and mf=/rt= are mutually exclusive.
	for _, tag := range []string{"i", "m", "t"} {
		if !tvl.has(tag) {
			return nil, sigTagError(sig.Sequence, tag, "missing")
		}
	}
	if sig.Domain == "" {
		return nil, sigTagError(sig.Sequence, "d", "missing")
	}
	if len(sig.Sigs) == 0 {
		return nil, sigTagError(sig.Sequence, "s", "missing")
	}
	hasND := tvl.has("nd")
	hasMF := tvl.has("mf")
	hasRT := tvl.has("rt")
	if hasND && hasMF {
		return nil, sigTagError(sig.Sequence, "mf", "was unexpected")
	}
	if hasND && hasRT {
		return nil, sigTagError(sig.Sequence, "rt", "was unexpected")
	}
	if !hasND && !hasMF {
		return nil, sigTagError(sig.Sequence, "mf", "missing")
	}
	if !hasND && !hasRT {
		return nil, sigTagError(sig.Sequence, "rt", "missing")
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

	var sb strings.Builder
	for i, item := range sig.Sigs {
		switch {
		case i == 0:
		case item.Group != sig.Sigs[i-1].Group:
			sb.WriteByte('|')
		default:
			sb.WriteByte(',')
		}
		sb.WriteString(item.Selector + ":" + item.Algorithm + ":" + base64.StdEncoding.EncodeToString(item.Value))
	}
	s := sb.String()

	// §10.7: an nd= signature carries nd= instead of mf=/rt=.
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
	// f= flags (§10.10), e.g. feedback, feedhere — preserved verbatim.
	if len(sig.Flags) > 0 {
		out += " f=" + strings.Join(sig.Flags, ",") + ";"
	}
	return out
}

// reSTag matches the s= tag at a tag boundary — the start of the header value
// or after a ";" — tolerating FWS around "=". This is independent of tag
// order (s= may be first); "S=" is an unknown tag, not s= (§8, D10).
// Base64 cannot contain ";" so the value runs to the next ";".
var reSTag = regexp.MustCompile(`(^|;)\s*s\s*=`)

// incompleteForm takes the original raw header value (after the field name)
// and returns it with each s= item's signature value replaced by empty string
// (per §14.6), preserving every other byte — tag order, case, whitespace, and
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

	// Blank the 3rd (signature) field of each item, dropping any folding
	// within it; every selector, algorithm name and ":" "," "|" stays
	// (-08 §12.8, contract D2).
	var out strings.Builder
	for gi, group := range strings.Split(sval, "|") {
		if gi > 0 {
			out.WriteByte('|')
		}
		for ii, item := range strings.Split(group, ",") {
			if ii > 0 {
				out.WriteByte(',')
			}
			if f := strings.SplitN(item, ":", 3); len(f) == 3 {
				out.WriteString(f[0] + ":" + f[1] + ":")
			} else {
				out.WriteString(item)
			}
		}
	}
	return head + prefix + out.String() + suffix
}

// buildIncomplete builds a fresh incomplete DKIM2-Signature header (s= values
// are empty per §14.6), for use as the signing input when creating a new sig.
func buildIncomplete(seq, miVer int, ts int64, domain, mailFrom string,
	rcptTo []string, nextDomain string, flags []string, selector, algorithm string) string {
	// §12.3: an imaginary-hop signature carries nd= instead of mf=/rt=.
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
	// f= (§10.10) goes before s=, so the s= placeholder stays last.
	if len(flags) > 0 {
		chain += "; f=" + strings.Join(flags, ",")
	}
	return fmt.Sprintf(
		"DKIM2-Signature: i=%d; m=%d; t=%d; d=%s; %s; s=%s:%s:;",
		seq, miVer, ts, domain, chain, selector, algorithm,
	)
}

// signFlags is the f= list a new signature at sequence seq carries (§10.10,
// §12.5): the caller's flags, each once, plus "exploded" when this hop
// sends copies to more than one address (requested, or rt= holds more than
// one); "exploded" is never set at i=1.
func signFlags(seq int, opts SignOptions) []string {
	var out []string
	seen := map[string]bool{}
	add := func(f string) {
		if f == "" || seen[f] || (f == "exploded" && seq == 1) {
			return
		}
		seen[f] = true
		out = append(out, f)
	}
	for _, f := range opts.Flags {
		add(strings.TrimSpace(f))
	}
	if opts.Exploded || len(opts.RcptTo) > 1 {
		add("exploded")
	}
	return out
}
