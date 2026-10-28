package dkim2

import (
	"strings"
)

// Domains as -08 compares them: the relaxed domain match (§7.2), address
// domains mapped to A-labels (§18), and the From mailbox §11 checks.

// domainOf returns the domain of an email address or RFC 5321 path: the text
// between the last "@" and any closing ">", lowercased, with one trailing dot
// removed and every U-label mapped to an A-label (§18).  A domain literal
// ("[192.0.2.1]") is returned as it is, with literal set.  An address with no
// "@" (the null path "<>") has no domain.
func domainOf(addr string) (domain string, literal bool) {
	at := strings.LastIndexByte(addr, '@')
	if at < 0 {
		return "", false
	}
	d := addr[at+1:]
	if gt := strings.IndexByte(d, '>'); gt >= 0 {
		d = d[:gt]
	}
	d = strings.ToLower(trimFWS(d))
	if strings.HasPrefix(d, "[") {
		return d, true
	}
	return toALabel(strings.TrimSuffix(d, ".")), false
}

// toALabel maps a domain to its A-label form: every label is lowercased, and
// a label holding anything but ASCII becomes "xn--" followed by its RFC 3492
// Punycode.  No other IDNA (UTS 46) mapping is applied.
func toALabel(domain string) string {
	labels := strings.Split(domain, ".")
	for i, l := range labels {
		if isASCII(l) {
			labels[i] = lowerName(l)
		} else {
			labels[i] = "xn--" + punycodeEncode(strings.ToLower(l))
		}
	}
	return strings.Join(labels, ".")
}

// relaxedMatch is the §7.2 relaxed domain match, Parameter1 p1 against
// Parameter2 p2, without regard to case: p1 matches when it equals p2, or
// does once leftmost labels are removed from p1 (and only from p1).  An empty
// domain or a domain literal never matches.
func relaxedMatch(p1, p2 string) bool {
	p1 = strings.TrimSuffix(strings.ToLower(p1), ".")
	p2 = strings.TrimSuffix(strings.ToLower(p2), ".")
	if p1 == "" || p2 == "" || strings.HasPrefix(p1, "[") || strings.HasPrefix(p2, "[") {
		return false
	}
	for {
		if p1 == p2 {
			return true
		}
		dot := strings.IndexByte(p1, '.')
		if dot < 0 {
			return false
		}
		p1 = p1[dot+1:]
	}
}

// addrMatches reports whether some address in addrs has a domain that
// relaxed-matches d as Parameter1 (§7.2 item 1 runs over every rt= address).
func addrMatches(addrs []string, d string) bool {
	for _, a := range addrs {
		if dom, lit := domainOf(a); !lit && relaxedMatch(dom, d) {
			return true
		}
	}
	return false
}

// fromMailbox returns the addr-spec of a From field value that holds exactly
// one mailbox -- "Name <a@b>" or "a@b", comments allowed, folding already
// undone or not -- and false for anything else: a list of mailboxes, a group,
// or no address at all.  It is deliberately lenient about the display name
// (RFC 2047 encoded words, odd characters): only the addr-spec matters.
func fromMailbox(v string) (string, bool) {
	// Comments become a space; quoted strings and domain literals are kept,
	// and nothing inside them counts as a special.
	var clean []byte
	type special struct {
		c   byte
		pos int
	}
	var specials []special
	depth := 0
	inQuote, inLit := false, false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '\r' || c == '\n':
			continue
		case depth > 0:
			switch c {
			case '\\':
				i++
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					clean = append(clean, ' ')
				}
			}
			continue
		case inQuote:
			clean = append(clean, c)
			if c == '\\' && i+1 < len(v) {
				i++
				clean = append(clean, v[i])
			} else if c == '"' {
				inQuote = false
			}
			continue
		case inLit:
			clean = append(clean, c)
			if c == ']' {
				inLit = false
			}
			continue
		}
		switch c {
		case '(':
			depth++
			continue
		case '"':
			inQuote = true
		case '[':
			inLit = true
		case '<', '>', ',', ':', ';':
			specials = append(specials, special{c, len(clean)})
		}
		clean = append(clean, c)
	}
	if depth > 0 || inQuote || inLit {
		return "", false
	}
	addr := string(clean)
	lt, gt := -1, -1
	for _, s := range specials {
		switch {
		case s.c == '<' && lt < 0:
			lt = s.pos
		case s.c == '>' && lt >= 0 && gt < 0:
			gt = s.pos
		case s.c == ':' && lt >= 0 && gt < 0:
			// an obsolete route inside the angle brackets
		default:
			return "", false // a list, a group, or stray brackets
		}
	}
	if lt >= 0 {
		if gt < 0 || strings.TrimSpace(addr[gt+1:]) != "" {
			return "", false
		}
		addr = addr[lt+1 : gt]
		if c := strings.LastIndexByte(addr, ':'); c >= 0 {
			addr = addr[c+1:]
		}
	}
	addr = strings.TrimSpace(addr)
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 || strings.ContainsAny(addr[at+1:], " \t") {
		return "", false
	}
	if !strings.HasPrefix(addr, "\"") && strings.ContainsAny(addr[:at], " \t") {
		return "", false
	}
	return addr, true
}

// fromAuthentic reports whether From fields froms are Authentic for signing
// domain d (§11): exactly one From field, holding exactly one mailbox, whose
// domain is not a literal and relaxed-matches d (as an A-label, §18).
func fromAuthentic(froms []Header, d string) bool {
	if len(froms) != 1 {
		return false
	}
	addr, ok := fromMailbox(froms[0].Value)
	if !ok {
		return false
	}
	dom, lit := domainOf(addr)
	return !lit && relaxedMatch(dom, toALabel(d))
}

// fromFields returns the From fields among headers.
func fromFields(headers []Header) []Header {
	var out []Header
	for _, h := range headers {
		if lowerName(h.Name) == "from" {
			out = append(out, h)
		}
	}
	return out
}

// RFC 3492 Punycode parameters.
const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
)

func pcAdapt(delta, numPoints int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}

func pcDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

// punycodeEncode is the RFC 3492 §6.3 encoding of one label (without the
// "xn--" prefix).
func punycodeEncode(label string) string {
	runes := []rune(label)
	var out []byte
	for _, r := range runes {
		if r < 0x80 {
			out = append(out, byte(r))
		}
	}
	b := len(out)
	h := b
	if b > 0 {
		out = append(out, '-')
	}
	n, delta, bias := pcInitialN, 0, pcInitialBias
	for h < len(runes) {
		m := int(^uint(0) >> 1)
		for _, r := range runes {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range runes {
			if int(r) < n {
				delta++
			}
			if int(r) != n {
				continue
			}
			q := delta
			for k := pcBase; ; k += pcBase {
				t := k - bias
				if t < pcTMin {
					t = pcTMin
				} else if t > pcTMax {
					t = pcTMax
				}
				if q < t {
					break
				}
				out = append(out, pcDigit(t+(q-t)%(pcBase-t)))
				q = (q - t) / (pcBase - t)
			}
			out = append(out, pcDigit(q))
			bias = pcAdapt(delta, h+1, h == b)
			delta = 0
			h++
		}
		delta++
		n++
	}
	return string(out)
}
