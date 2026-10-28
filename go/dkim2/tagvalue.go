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
	duplicate string // tag name seen more than once (§8), if any
	// syntaxErr: a non-empty fragment that is not [FWS] name [FWS] "="
	// [FWS] [value] [FWS] (§8 tag-spec).  The whole field is then
	// a syntax error (§14.2); the fragment is never just skipped.
	syntaxErr bool
}

// trimFWS trims folding whitespace (SP, HTAB, CR, LF) -- and nothing else,
// unlike strings.TrimSpace, which would also eat NBSP, NEL, VT and FF.
func trimFWS(s string) string { return strings.Trim(s, " \t\r\n") }

func isWSPByte(c byte) bool { return c == ' ' || c == '\t' }

// validTagValue: tag-char *([FWS] tag-char), tag-char = %x21-3A / %x3C-7E
// (§8 tag-value; RFC 6376 §3.2 tval/VALCHAR), for a value that
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

// validTagName: ALPHA *(ALPHA / DIGIT / "_") (§8 tag-name).
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
	// Tag names are case sensitive (§8; contract D10, reversing -07's
	// "liberal in receive"): "M=1" is an unknown tag, not m=, and "m=1;
	// M=2" holds no duplicate.  Order is kept for re-serializing.
	parts := strings.Split(s, ";")
	for i, part := range parts {
		part = trimFWS(part)
		if part == "" {
			// §8: tag-spec *( ";" tag-spec ) [ ";" ] -- only the tag-list's
			// end may be empty (one optional trailing ";"); ";;" or a
			// leading ";" is a syntax error.
			if i != len(parts)-1 {
				tvl.syntaxErr = true
			}
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
		if _, exists := tvl.vals[k]; exists {
			tvl.duplicate = k // §8: a duplicate makes the whole tag-list invalid
		} else {
			tvl.order = append(tvl.order, k)
		}
		tvl.vals[k] = v
	}
	return tvl
}

// get and has look a tag up by its exact (lowercase) name (§8, D10).
func (t *tagValueList) get(key string) string { return t.vals[key] }

func (t *tagValueList) has(key string) bool {
	_, ok := t.vals[key]
	return ok
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
