package dkim2

import "strings"

type tagValueList struct {
	order []string
	vals  map[string]string
}

func parseTagValueList(s string) *tagValueList {
	tvl := &tagValueList{vals: make(map[string]string)}
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
		if _, exists := tvl.vals[k]; !exists {
			tvl.order = append(tvl.order, k)
		}
		tvl.vals[k] = v
	}
	return tvl
}

func (t *tagValueList) get(key string) string {
	return t.vals[key]
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
