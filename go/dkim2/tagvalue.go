package dkim2

import "strings"

// stripB64WSP removes whitespace from a base64 string (needed when the value
// spans multiple folded header continuation lines).
func stripB64WSP(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
}

type tagValueList struct {
	order     []string
	vals      map[string]string
	duplicate string // lowercased tag name seen more than once (spec-06 §8), if any
	// syntaxErr: a non-empty fragment that is not [FWS] name [FWS] "="
	// [FWS] [value] [FWS] (spec-06 §7, §8 x-tag).  The whole field is then
	// a syntax error (§11.2); the fragment is never just skipped.
	syntaxErr bool
}

// trimFWS trims folding whitespace (SP, HTAB, CR, LF) -- and nothing else,
// unlike strings.TrimSpace, which would also eat NBSP, NEL, VT and FF.
func trimFWS(s string) string { return strings.Trim(s, " \t\r\n") }

func isWSPByte(c byte) bool { return c == ' ' || c == '\t' }

// validTagValue: tag-char *([FWS] tag-char), tag-char = %x21-3A / %x3C-7E
// (spec-06 §7 x-tag-value; RFC 6376 §3.2 tval/VALCHAR), for a value that
// trimFWS has already trimmed.  A CR or LF is only allowed as part of a
// fold (CRLF, or a bare LF, followed by WSP); any other control, DEL or
// 8-bit byte is a syntax error.
func validTagValue(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 0x21 && c <= 0x7e && c != ';':
		case isWSPByte(c):
		case c == '\r' && i+2 < len(v) && v[i+1] == '\n' && isWSPByte(v[i+2]):
			i++
		case c == '\n' && i+1 < len(v) && isWSPByte(v[i+1]):
		default:
			return false
		}
	}
	return true
}

// validTagName: ALPHA *(ALPHA / DIGIT / "_") (spec-06 §7 x-tag-name).
func validTagName(n string) bool {
	if n == "" {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		alpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if i == 0 && !alpha {
			return false
		}
		if !alpha && !(c >= '0' && c <= '9') && c != '_' {
			return false
		}
	}
	return true
}

func parseTagValueList(s string) *tagValueList {
	tvl := &tagValueList{vals: make(map[string]string)}
	seen := make(map[string]bool)
	// Tag names keep their ORIGINAL case and order so the header can be
	// re-serialized byte-for-byte for signing-input reconstruction; get/has
	// below do the case-insensitive lookup required by spec-06 §8.
	for _, part := range strings.Split(s, ";") {
		part = trimFWS(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			tvl.syntaxErr = true
			continue
		}
		k := trimFWS(part[:eq])
		v := trimFWS(part[eq+1:])
		if !validTagName(k) || !validTagValue(v) {
			tvl.syntaxErr = true
		}
		lk := strings.ToLower(k)
		if seen[lk] {
			tvl.duplicate = lk // §8: "there MUST be only one of each kind"
		}
		seen[lk] = true
		if _, exists := tvl.vals[k]; !exists {
			tvl.order = append(tvl.order, k)
		}
		tvl.vals[k] = v
	}
	return tvl
}

// get and has treat tag identifiers case-insensitively (spec-06 §8): exact
// match first (the common case), then a case-insensitive scan.
func (t *tagValueList) get(key string) string {
	if v, ok := t.vals[key]; ok {
		return v
	}
	lk := strings.ToLower(key)
	for k, v := range t.vals {
		if strings.ToLower(k) == lk {
			return v
		}
	}
	return ""
}

func (t *tagValueList) has(key string) bool {
	if _, ok := t.vals[key]; ok {
		return true
	}
	lk := strings.ToLower(key)
	for k := range t.vals {
		if strings.ToLower(k) == lk {
			return true
		}
	}
	return false
}

func (t *tagValueList) set(key, val string) {
	if _, exists := t.vals[key]; !exists {
		t.order = append(t.order, key)
	}
	t.vals[key] = val
}

func (t *tagValueList) String() string {
	if len(t.order) == 0 {
		return ""
	}
	parts := make([]string, 0, len(t.order))
	for _, k := range t.order {
		parts = append(parts, k+"="+t.vals[k])
	}
	return strings.Join(parts, "; ") + ";"
}
