package dkim2

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// MessageInstance is a parsed or constructed Message-Instance header.
type MessageInstance struct {
	Version int
	Hashes  []HashSet
	Recipe  *Recipe // nil if no r= tag
}

// HashSet is one spec-05 §7.3 hash-set: alg:header-hash:body-hash.
type HashSet struct {
	Alg        string // lowercased
	HeaderHash string // base64, FWS already stripped
	BodyHash   string // base64, FWS already stripped
}

func parseHashSets(h string) []HashSet {
	var out []HashSet
	for _, item := range strings.Split(h, ",") {
		parts := strings.Split(strings.TrimSpace(item), ":")
		if len(parts) != 3 {
			continue
		}
		out = append(out, HashSet{
			Alg:        strings.ToLower(strings.TrimSpace(parts[0])),
			HeaderHash: strings.TrimSpace(parts[1]),
			BodyHash:   strings.TrimSpace(parts[2]),
		})
	}
	return out
}

// hashSetsEqual reports whether two hash-set lists cover the same content:
// same set of algorithms, each with matching header/body hash values.
func hashSetsEqual(a, b []HashSet) bool {
	if len(a) != len(b) {
		return false
	}
	am := make(map[string][2]string, len(a))
	for _, hs := range a {
		am[hs.Alg] = [2]string{hs.HeaderHash, hs.BodyHash}
	}
	for _, hs := range b {
		v, ok := am[hs.Alg]
		if !ok || v[0] != hs.HeaderHash || v[1] != hs.BodyHash {
			return false
		}
	}
	return true
}

// verifyMIHashes checks every implemented hash-set in mi against freshly
// computed hashes of headers/body. All implemented hash-sets MUST match;
// unimplemented algorithms are skipped per §3.4. Fails closed with the
// spec-05 message when none of the hash-sets name an implemented algorithm.
func verifyMIHashes(mi *MessageInstance, headers []Header, body []byte) error {
	usable := 0
	for _, hs := range mi.Hashes {
		if _, ok := HashAlg(hs.Alg); !ok {
			continue // §3.4: skip unimplemented algorithms
		}
		usable++

		gotH, err := hashHeaders(headers, hs.Alg)
		if err != nil {
			return err
		}
		wantH, err := base64.StdEncoding.DecodeString(hs.HeaderHash)
		if err != nil || !bytes.Equal(gotH, wantH) {
			return fmt.Errorf("m=%d: %s header hash mismatch", mi.Version, hs.Alg)
		}

		gotB, err := hashBody(bytes.NewReader(body), hs.Alg)
		if err != nil {
			return err
		}
		wantB, err := base64.StdEncoding.DecodeString(hs.BodyHash)
		if err != nil || !bytes.Equal(gotB, wantB) {
			return fmt.Errorf("m=%d: %s body hash mismatch", mi.Version, hs.Alg)
		}
	}
	if usable == 0 {
		return fmt.Errorf("Message-Instance m=%d no supported hash algorithm", mi.Version)
	}
	return nil
}

// parseMI parses a Message-Instance header (with or without the field name prefix).
func parseMI(raw string) (*MessageInstance, error) {
	value := raw
	if colon := strings.IndexByte(raw, ':'); colon >= 0 {
		name := strings.TrimSpace(raw[:colon])
		// Only strip as field-name prefix when it looks like a header name
		// (no '=' or ';' means it's not part of "sha256:..." or a tag value)
		if !strings.ContainsAny(name, "=;") {
			value = raw[colon+1:]
		}
	}
	tvl := parseTagValueList(value)

	mStr := tvl.get("m")
	if mStr == "" {
		return nil, fmt.Errorf("missing m= tag")
	}
	m, err := strconv.Atoi(mStr)
	if err != nil {
		return nil, fmt.Errorf("invalid m= tag: %w", err)
	}

	h := stripB64WSP(tvl.get("h"))
	hashes := parseHashSets(h)
	if len(hashes) == 0 {
		return nil, fmt.Errorf("invalid h= tag: %q", h)
	}
	mi := &MessageInstance{Version: m, Hashes: hashes}

	if rB64 := stripB64WSP(tvl.get("r")); rB64 != "" {
		rJSON, err := base64.StdEncoding.DecodeString(rB64)
		if err != nil {
			return nil, fmt.Errorf("invalid r= tag: %w", err)
		}
		recipe, err := parseRecipe(rJSON)
		if err != nil {
			return nil, fmt.Errorf("invalid recipe JSON: %w", err)
		}
		mi.Recipe = recipe
	}
	return mi, nil
}

// String returns the complete Message-Instance header value (with field name,
// without trailing CRLF). Format matches Python output exactly.
func (mi *MessageInstance) String() string {
	parts := make([]string, len(mi.Hashes))
	for i, hs := range mi.Hashes {
		parts[i] = hs.Alg + ":" + hs.HeaderHash + ":" + hs.BodyHash
	}
	s := fmt.Sprintf("Message-Instance: m=%d; h=%s;", mi.Version, strings.Join(parts, ","))
	if mi.Recipe != nil {
		rJSON, _ := encodeRecipe(mi.Recipe)
		s += " r=" + base64.StdEncoding.EncodeToString(rJSON) + ";"
	}
	return s
}
