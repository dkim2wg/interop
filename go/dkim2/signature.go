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
	Domain    string
	MailFrom  string
	RcptTo    []string
	Nonce     string   // n= tag (optional); max 64 ASCII chars per §7.3
	Flags     []string // f= tag (optional); comma-separated flags per §10.8
	Sigs      []SigItem
}

// SigItem is one sel:alg:value entry in the s= tag.
type SigItem struct {
	Selector  string
	Algorithm string
	Value     []byte // nil means empty (signing input placeholder per §8.5)
}

// SignOptions carries per-message signing parameters.
type SignOptions struct {
	Selector  string
	Domain    string
	MailFrom  string
	RcptTo    []string
	Timestamp int64 // 0 = use time.Now()
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
		return nil, fmt.Errorf("invalid DKIM2-Signature: no colon")
	}
	tvl := parseTagValueList(raw[colon+1:])
	sig := &DKIM2Signature{}

	if v := tvl.get("i"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid i=: %w", err)
		}
		sig.Sequence = n
	}
	if v := tvl.get("m"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid m=: %w", err)
		}
		sig.MIVersion = n
	}
	if v := tvl.get("t"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid t=: %w", err)
		}
		sig.Timestamp = n
	}
	sig.Domain = tvl.get("d")
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
	if sig.Domain == "" {
		return nil, fmt.Errorf("missing required d= tag in DKIM2-Signature")
	}
	if len(sig.Sigs) == 0 {
		return nil, fmt.Errorf("missing required s= tag in DKIM2-Signature")
	}
	return sig, nil
}

// String returns the complete DKIM2-Signature header (with field name, no trailing CRLF).
// Format matches Python output exactly: single line, no folding.
func (sig *DKIM2Signature) String() string {
	mf := base64.StdEncoding.EncodeToString([]byte(sig.MailFrom))
	var rtParts []string
	for _, r := range sig.RcptTo {
		rtParts = append(rtParts, base64.StdEncoding.EncodeToString([]byte(r)))
	}
	rt := strings.Join(rtParts, ",")

	var sParts []string
	for _, item := range sig.Sigs {
		val := base64.StdEncoding.EncodeToString(item.Value)
		sParts = append(sParts, item.Selector+":"+item.Algorithm+":"+val)
	}
	s := strings.Join(sParts, ",")

	return fmt.Sprintf(
		"DKIM2-Signature: i=%d; m=%d; t=%d; d=%s; mf=%s; rt=%s; s=%s;",
		sig.Sequence, sig.MIVersion, sig.Timestamp, sig.Domain, mf, rt, s,
	)
}

// reSTag matches "; s=" (semicolon followed by optional whitespace and s=).
// Base64 cannot contain semicolons, so this won't false-match inside a sig value.
var reSTag = regexp.MustCompile(`;\s*s=`)

// incompleteForm takes the original raw header and returns it with all
// signature values in the s= tag replaced by empty string (per §8.5).
func (sig *DKIM2Signature) incompleteForm(rawHeader string) string {
	m := reSTag.FindStringIndex(rawHeader)
	if m == nil {
		return rawHeader
	}
	prefix := rawHeader[:m[1]] // everything through "s="

	// Find the s= value's end: the next semicolon after the s= tag start
	rest := rawHeader[m[1]:]
	semiIdx := strings.IndexByte(rest, ';')
	var suffix string
	if semiIdx >= 0 {
		suffix = rest[semiIdx:] // from the closing ";" onward (including any trailing CRLF)
	}

	var stripped []string
	for _, item := range sig.Sigs {
		stripped = append(stripped, item.Selector+":"+item.Algorithm+":")
	}
	return prefix + strings.Join(stripped, ",") + suffix
}

// buildIncomplete builds a fresh incomplete DKIM2-Signature header (s= values
// are empty per §8.5), for use as the signing input when creating a new sig.
func buildIncomplete(seq, miVer int, ts int64, domain, mailFrom string,
	rcptTo []string, selector, algorithm string) string {
	mf := base64.StdEncoding.EncodeToString([]byte(mailFrom))
	var rtParts []string
	for _, r := range rcptTo {
		rtParts = append(rtParts, base64.StdEncoding.EncodeToString([]byte(r)))
	}
	rt := strings.Join(rtParts, ",")
	return fmt.Sprintf(
		"DKIM2-Signature: i=%d; m=%d; t=%d; d=%s; mf=%s; rt=%s; s=%s:%s:;",
		seq, miVer, ts, domain, mf, rt, selector, algorithm,
	)
}
