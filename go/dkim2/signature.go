package dkim2

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// DKIM2Signature is a parsed or constructed DKIM2-Signature header.
type DKIM2Signature struct {
	Sequence  int
	MIVersion int
	Timestamp int64
	Domain     string
	NextDomain string // nd= tag (draft-04 §8.7); empty if absent
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
	NextDomain string // nd= (draft-04 §9.3); when set, emit nd= instead of mf=/rt=
	Timestamp  int64  // 0 = use time.Now()
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
	if v := tvl.get("t"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("DKIM2-Signature i=%d tag=t syntax error: %w", sig.Sequence, err)
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
			fields := strings.SplitN(strings.TrimSpace(part), ":", 3)
			if len(fields) != 3 {
				return nil, fmt.Errorf("invalid s= item: %q", part)
			}
			item := SigItem{Selector: fields[0], Algorithm: fields[1]}
			if fields[2] != "" {
				b, err := base64.StdEncoding.DecodeString(stripB64WSP(fields[2]))
				if err != nil {
					return nil, fmt.Errorf("invalid sig value: %w", err)
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
		for _, part := range strings.Split(strings.ReplaceAll(v, " ", ""), ",") {
			if part != "" {
				sig.Flags = append(sig.Flags, part)
			}
		}
	}
	// draft-04 §8: i= m= t= d= s= MUST be present; plus either nd= or both
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

	// draft-04 §8: an nd= signature carries nd= instead of mf=/rt=.
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
	// f= flags (draft-04 §8.10), e.g. feedback, feedhere — preserved verbatim.
	if len(sig.Flags) > 0 {
		out += " f=" + strings.Join(sig.Flags, ",") + ";"
	}
	return out
}

// reSTag matches the s= tag at a tag boundary — the start of the header value
// or after a ";" — case-insensitively and tolerating FWS around "=". This is
// independent of tag order (s= may be first) and case (S=), per spec-04 §8.
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
	// draft-04 §9.3: an imaginary-hop signature carries nd= instead of mf=/rt=.
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
