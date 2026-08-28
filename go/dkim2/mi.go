package dkim2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// HashSet is one spec-06 §7.3 hash-set: alg:header-hash:body-hash.
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

// implementedAlgs returns the algorithms in hashes that this build implements
// (per §3.4, i.e. resolve via HashAlg), in the order they appear.
func implementedAlgs(hashes []HashSet) []string {
	var algs []string
	for _, hs := range hashes {
		if _, ok := HashAlg(hs.Alg); ok {
			algs = append(algs, hs.Alg)
		}
	}
	return algs
}

// verifyMIHashesPrecomputed checks every implemented hash-set in mi against
// a freshly computed header hash (per algorithm; headers is an in-memory
// slice, so recomputing per algorithm is cheap) and the already-computed
// bodyHashes (one streaming pass over the body — see hashBodyMulti — must
// have produced an entry for every algorithm implementedAlgs(mi.Hashes)
// names). All implemented hash-sets MUST match; unimplemented algorithms are
// skipped per §3.4. Fails closed with the spec-06 message when none of the
// hash-sets name an implemented algorithm.
func verifyMIHashesPrecomputed(mi *MessageInstance, headers []Header, bodyHashes map[string][]byte) error {
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

		gotB := bodyHashes[hs.Alg]
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

// verifyMIHashes is the buffered-body convenience form of
// verifyMIHashesPrecomputed, for callers (Undo) that already hold the whole
// body in memory. It still hashes the body in a single streaming pass across
// all implemented algorithms (hashBodyMulti), it just reads that pass from a
// bytes.Reader over the already-buffered body rather than from a live stream.
func verifyMIHashes(mi *MessageInstance, headers []Header, body []byte) error {
	bodyHashes, err := hashBodyMulti(bytes.NewReader(body), implementedAlgs(mi.Hashes))
	if err != nil {
		return err
	}
	return verifyMIHashesPrecomputed(mi, headers, bodyHashes)
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

	// spec-06 §7.3: an algorithm MUST NOT be present more than once.
	seen := map[string]bool{}
	for _, hs := range hashes {
		if seen[hs.Alg] {
			return nil, fmt.Errorf("PERMERROR Message-Instance m=%d has a duplicate hash algorithm", m)
		}
		seen[hs.Alg] = true
	}

	mi := &MessageInstance{Version: m, Hashes: hashes}

	if rB64 := stripB64WSP(tvl.get("r")); rB64 != "" {
		rJSON, err := base64.StdEncoding.DecodeString(rB64)
		if err != nil {
			// §11.2: a bad base64 r= value is a syntax error -- distinct
			// from, and reported before, a post-decode JSON parse failure
			// (below): the payload never even reached JSON parsing.
			return nil, fmt.Errorf("PERMERROR Message-Instance m=%d syntax error", m)
		}
		recipe, err := parseRecipe(rJSON)
		if err != nil {
			// spec-06 §11.2: "errors in a JSON object specifying Recipes
			// should be called out specifically" -- a malformed r= payload
			// is reported distinctly from a generic syntax error. This
			// covers actual JSON syntax/type errors; other parseRecipe
			// failures (e.g. the §5.1 null-header-Recipe rejection) already
			// carry their own specific message and are left as-is.
			var syntaxErr *json.SyntaxError
			var typeErr *json.UnmarshalTypeError
			if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) {
				return nil, fmt.Errorf("PERMERROR Message-Instance m=%d contains invalid JSON", m)
			}
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
