package dkim2

import (
	"bytes"
	"encoding/base64"
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

// HashSet is one §9.3 hash-set: alg:header-hash:body-hash.
type HashSet struct {
	Alg        string // as written: hash names are case sensitive (§9.3)
	HeaderHash string // base64, FWS already stripped
	BodyHash   string // base64, FWS already stripped
	// Group is the hash-all ("," list) the set belongs to, counting the
	// "|"-separated groups of h= from 0 (-08 §9.3).  Signers write one.
	Group int
}

// validBase64String reports whether a value, its FWS already stripped, is a
// non-empty base64string: padded base64 that decodes.
func validBase64String(v string) bool {
	if v == "" {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(v)
	return err == nil
}

// splitGroups splits an h= or s= value (FWS still present) into its "|"
// groups of ","-separated members (-08 §9.3, §10.9).  FWS may surround
// either separator; an empty member -- a leading, trailing or doubled "|"
// or "," -- is a syntax error (contract D2).
func splitGroups(v string) ([][]string, bool) {
	var groups [][]string
	for _, g := range strings.Split(v, "|") {
		var members []string
		for _, m := range strings.Split(g, ",") {
			if trimFWS(m) == "" {
				return nil, false
			}
			members = append(members, m)
		}
		groups = append(groups, members)
	}
	return groups, true
}

// parseHashSets parses an h= value (FWS still present): "|" groups of ","
// lists of hash-sets.  Each hash-set is exactly name:header-hash:body-hash,
// both digests non-empty padded base64, whatever the name; FWS is allowed
// around the name and the colons and inside the digests, but not inside
// the name ("sha 256" is a syntax error, never "sha256").
func parseHashSets(h string) ([]HashSet, error) {
	groups, ok := splitGroups(h)
	if !ok {
		return nil, fmt.Errorf("empty member in h=")
	}
	var out []HashSet
	for g, items := range groups {
		for _, item := range items {
			parts := strings.Split(item, ":")
			if len(parts) != 3 {
				return nil, fmt.Errorf("bad hash-set %q", item)
			}
			name := trimFWS(parts[0])
			hh, bh := stripB64WSP(parts[1]), stripB64WSP(parts[2])
			if !validToken(name) || !validBase64String(hh) || !validBase64String(bh) {
				return nil, fmt.Errorf("bad hash-set %q", item)
			}
			out = append(out, HashSet{Alg: name, HeaderHash: hh, BodyHash: bh, Group: g})
		}
	}
	return out, nil
}

// hashSetsEqual reports whether two hash-set lists cover the same content:
// same set of algorithms, each with matching header/body hash values, in
// the same groups.
func hashSetsEqual(a, b []HashSet) bool {
	if len(a) != len(b) {
		return false
	}
	am := make(map[string]HashSet, len(a))
	for _, hs := range a {
		am[hs.Alg] = hs
	}
	for _, hs := range b {
		if v, ok := am[hs.Alg]; !ok || v != hs {
			return false
		}
	}
	return true
}

// implementedAlgs returns the algorithms in hashes that this build implements
// (per §3.5, i.e. resolve via HashAlg), in the order they appear.
func implementedAlgs(hashes []HashSet) []string {
	var algs []string
	for _, hs := range hashes {
		if _, ok := HashAlg(hs.Alg); ok {
			algs = append(algs, hs.Alg)
		}
	}
	return algs
}

// verifyMIHashesPrecomputed checks mi's h= against a freshly computed header
// hash (per algorithm; headers is an in-memory slice, so recomputing per
// algorithm is cheap) and the already-computed bodyHashes (one streaming
// pass over the body — see hashBodyStream — must have produced an entry for
// every algorithm implementedAlgs(mi.Hashes) names), combining the
// hash-sets' results as -08 §14.7 says (checkMIHashes).
func verifyMIHashesPrecomputed(mi *MessageInstance, headers []Header, bodyHashes map[string][]byte) error {
	return checkMIHashes(mi, headerHasher(headers), bodyHashes)
}

// headerHasher hashes headers on demand, per algorithm.
func headerHasher(headers []Header) func(alg string) ([]byte, error) {
	return func(alg string) ([]byte, error) { return hashHeaders(headers, alg) }
}

// checkMIHashes is verifyMIHashesPrecomputed with the header hash supplied
// per algorithm by headerHash -- the planned chain walk (plan.go) has it
// already, for an instance it never rebuilds.
func checkMIHashes(mi *MessageInstance, headerHash func(string) ([]byte, error), bodyHashes map[string][]byte) error {
	return combineHashSets(mi, headerHash, bodyHashes, true)
}

// hashResultError is one of §14.7's results for a Message-Instance: "FAIL:
// Message-Instance m=<x> header hash <alg> mismatch" (or body hash), "...
// no group of hashes passed", or "PERMERROR: ... algorithm <alg> unknown".
type hashResultError struct{ text string }

func (e *hashResultError) Error() string { return e.text }

// verifyMIHeaderHashes is verifyMIHashesPrecomputed for a message with no
// body — the returned original in a DSN's text/rfc822-headers part (§16.4):
// a hash-set passes when its header hash matches.
func verifyMIHeaderHashes(mi *MessageInstance, headers []Header) error {
	return checkMIHeaderHashes(mi, headerHasher(headers))
}

// checkMIHeaderHashes is verifyMIHeaderHashes with the header hash supplied
// per algorithm by headerHash.
func checkMIHeaderHashes(mi *MessageInstance, headerHash func(string) ([]byte, error)) error {
	return combineHashSets(mi, headerHash, nil, false)
}

// Intermediate results (-08 §14.6, §14.7), in the order the combining rules
// test for them after PASS.
const (
	resPass = iota
	resTemperror
	resFail
	resPermerror
)

// combineHashSets is -08 §14.7 (contract D4).  Each hash-set, in h= order,
// is PASS when its header hash and (withBody) its body hash match, FAIL
// when either does not -- the header reported before the body -- and
// PERMERROR "algorithm <alg> unknown" when this build does not implement
// its algorithm.  A "," group passes when every set does, fails when any
// set fails, else is PERMERROR; the "|" groups pass when any does, fail
// when any fails, else are PERMERROR.  Every set is checked, so the result
// does not depend on the order of evaluation.
func combineHashSets(mi *MessageInstance, headerHash func(string) ([]byte, error),
	bodyHashes map[string][]byte, withBody bool) error {
	results := make([]itemResult, len(mi.Hashes))
	for i, hs := range mi.Hashes {
		r := &results[i]
		r.group = hs.Group
		if _, ok := HashAlg(hs.Alg); !ok {
			r.state, r.err = resPermerror, &hashResultError{
				fmt.Sprintf("PERMERROR: Message-Instance m=%d algorithm %s unknown", mi.Version, hs.Alg)}
			continue
		}
		gotH, err := headerHash(hs.Alg)
		if err != nil {
			return err
		}
		if wantH, err := base64.StdEncoding.DecodeString(hs.HeaderHash); err != nil || !bytes.Equal(gotH, wantH) {
			r.state, r.err = resFail, &hashResultError{
				fmt.Sprintf("FAIL: Message-Instance m=%d header hash %s mismatch", mi.Version, hs.Alg)}
			continue
		}
		if withBody {
			if wantB, err := base64.StdEncoding.DecodeString(hs.BodyHash); err != nil || !bytes.Equal(bodyHashes[hs.Alg], wantB) {
				r.state, r.err = resFail, &hashResultError{
					fmt.Sprintf("FAIL: Message-Instance m=%d body hash %s mismatch", mi.Version, hs.Alg)}
			}
		}
	}
	return combineResults(results, &hashResultError{
		fmt.Sprintf("FAIL: Message-Instance m=%d no group of hashes passed", mi.Version)})
}

// itemResult is one hash-set's or signature's intermediate result, its
// error text when not PASS, and its group.
type itemResult struct {
	state int
	err   error
	group int
}

// combineResults combines intermediate results, in h= or s= order, as -08
// §14.6/§14.7 do (contract D3/D4): an all-group passes when every item does;
// else it is TEMPERROR when every item that did not pass is TEMPERROR; else
// FAIL when any is; else PERMERROR.  The any-groups pass when any group
// does; else TEMPERROR, FAIL, PERMERROR in that order.  (Hash-sets are never
// TEMPERROR.)  The error reported: with one group, the first item whose own
// result is the group's; with more, noGroup for FAIL, else the first item
// with the result.  nil for a PASS.
func combineResults(items []itemResult, noGroup error) error {
	nGroups := 0
	for _, it := range items {
		nGroups = max(nGroups, it.group+1)
	}
	groupState := make([]int, nGroups)
	for g := range groupState {
		all, allTemp, anyFail := true, true, false
		for _, it := range items {
			if it.group != g || it.state == resPass {
				continue
			}
			all = false
			allTemp = allTemp && it.state == resTemperror
			anyFail = anyFail || it.state == resFail
		}
		switch {
		case all:
			groupState[g] = resPass
		case allTemp:
			groupState[g] = resTemperror
		case anyFail:
			groupState[g] = resFail
		default:
			groupState[g] = resPermerror
		}
	}
	result := resPermerror
	for _, want := range []int{resPass, resTemperror, resFail} {
		found := false
		for _, s := range groupState {
			found = found || s == want
		}
		if found {
			result = want
			break
		}
	}
	if result == resPass {
		return nil
	}
	if nGroups > 1 && result == resFail {
		return noGroup
	}
	for _, it := range items {
		if it.state == result {
			return it.err
		}
	}
	return noGroup // not reached: some item has the groups' result
}

// verifyMIHashes is the buffered-body convenience form of
// verifyMIHashesPrecomputed, for callers (Undo) that already hold the whole
// body in memory. It still hashes the body in a single streaming pass across
// all implemented algorithms (hashBodyStream), handed the whole body as one
// slice rather than read from a live stream.
func verifyMIHashes(mi *MessageInstance, headers []Header, body []byte) error {
	bodyHashes, err := hashBodyStream(bytes.NewReader(body), implementedAlgs(mi.Hashes))
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
		return nil, fmt.Errorf("PERMERROR: Message-Instance m= tag=m missing")
	}
	m, err := strconv.Atoi(mStr)
	if err != nil {
		return nil, fmt.Errorf("PERMERROR: Message-Instance m=%s syntax error", strings.TrimSpace(mStr))
	}

	// §8, §9: tag names are case insignificant and each kind appears once;
	// "h=..; H=.." or "m=1; M=1" is a syntax error, never first/last-wins.
	if tvl.duplicate != "" {
		return nil, fmt.Errorf("PERMERROR: Message-Instance m=%d syntax error", m)
	}

	// §8: a fragment that is not a well-formed tag=value, or an h= that is
	// not a list of whole hash-sets (§9.3), is a syntax error.
	if tvl.syntaxErr {
		return nil, fmt.Errorf("PERMERROR: Message-Instance m=%d syntax error", m)
	}
	if !tvl.has("h") {
		return nil, fmt.Errorf("PERMERROR: Message-Instance m=%d tag=h missing", m)
	}
	hashes, err := parseHashSets(tvl.get("h"))
	if err != nil {
		return nil, fmt.Errorf("PERMERROR: Message-Instance m=%d syntax error", m)
	}

	// §9.3: an algorithm MUST NOT be present more than once.
	seen := map[string]bool{}
	for _, hs := range hashes {
		if seen[hs.Alg] {
			return nil, fmt.Errorf("PERMERROR: Message-Instance m=%d has a duplicate hash algorithm", m)
		}
		seen[hs.Alg] = true
	}

	mi := &MessageInstance{Version: m, Hashes: hashes}

	if rB64 := stripB64WSP(tvl.get("r")); rB64 != "" {
		rJSON, err := base64.StdEncoding.DecodeString(rB64)
		if err != nil {
			// §14.2: a bad base64 r= value is a syntax error -- distinct
			// from, and reported before, a post-decode JSON parse failure
			// (below): the payload never even reached JSON parsing.
			return nil, fmt.Errorf("PERMERROR: Message-Instance m=%d syntax error", m)
		}
		recipe, err := parseRecipe(rJSON)
		if err != nil {
			// §14.2: "errors in a JSON object specifying Recipes SHOULD be
			// called out specifically" -- a bad r= payload is reported
			// distinctly from a generic syntax error.  A step the schema
			// or §5.1/§5.2 rejects is "Recipe <path> is invalid"; anything
			// wrong with the document as a whole is "contains invalid
			// JSON" (contract D6), as is a step that does not fit the
			// message, which only the chain walk can find.
			var se *recipeStepError
			if errors.As(err, &se) {
				return nil, &malformedRecipeError{m: m, path: se.path}
			}
			return nil, &malformedRecipeError{m: m}
		}
		mi.Recipe = recipe
	}
	return mi, nil
}

// String returns the complete Message-Instance header value (with field name,
// without trailing CRLF). Format matches Python output exactly.
func (mi *MessageInstance) String() string {
	var h strings.Builder
	for i, hs := range mi.Hashes {
		switch {
		case i == 0:
		case hs.Group != mi.Hashes[i-1].Group:
			h.WriteByte('|')
		default:
			h.WriteByte(',')
		}
		h.WriteString(hs.Alg + ":" + hs.HeaderHash + ":" + hs.BodyHash)
	}
	s := fmt.Sprintf("Message-Instance: m=%d; h=%s;", mi.Version, h.String())
	if mi.Recipe != nil {
		rJSON, _ := encodeRecipe(mi.Recipe)
		s += " r=" + base64.StdEncoding.EncodeToString(rJSON) + ";"
	}
	return s
}
