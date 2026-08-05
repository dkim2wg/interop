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
	duplicate string // lowercased tag name seen more than once (spec-04 §8), if any
}

func parseTagValueList(s string) *tagValueList {
	tvl := &tagValueList{vals: make(map[string]string)}
	seen := make(map[string]bool)
	// Tag names keep their ORIGINAL case and order so the header can be
	// re-serialized byte-for-byte for signing-input reconstruction; get/has
	// below do the case-insensitive lookup required by spec-04 §8.
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(part[:eq])
		v := strings.TrimSpace(part[eq+1:])
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

// get and has treat tag identifiers case-insensitively (spec-04 §8): exact
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
