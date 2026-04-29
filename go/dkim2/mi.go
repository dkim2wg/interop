package dkim2

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// MessageInstance is a parsed or constructed Message-Instance header.
type MessageInstance struct {
	Version    int
	HeaderHash []byte
	BodyHash   []byte
	Recipe     *Recipe // nil if no r= tag
}

// parseMI parses a Message-Instance header (with or without the field name prefix).
func parseMI(raw string) (*MessageInstance, error) {
	colon := strings.IndexByte(raw, ':')
	if colon < 0 {
		return nil, fmt.Errorf("invalid Message-Instance: no colon")
	}
	tvl := parseTagValueList(raw[colon+1:])

	mStr := tvl.get("m")
	if mStr == "" {
		return nil, fmt.Errorf("missing m= tag")
	}
	m, err := strconv.Atoi(mStr)
	if err != nil {
		return nil, fmt.Errorf("invalid m= tag: %w", err)
	}

	h := tvl.get("h")
	parts := strings.SplitN(h, ":", 3)
	if len(parts) != 3 || parts[0] != "sha256" {
		return nil, fmt.Errorf("invalid h= tag: %q", h)
	}
	hHash, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid header hash in h=: %w", err)
	}
	bHash, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid body hash in h=: %w", err)
	}

	mi := &MessageInstance{Version: m, HeaderHash: hHash, BodyHash: bHash}

	if rB64 := tvl.get("r"); rB64 != "" {
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
	hB64 := base64.StdEncoding.EncodeToString(mi.HeaderHash)
	bB64 := base64.StdEncoding.EncodeToString(mi.BodyHash)
	s := fmt.Sprintf("Message-Instance: m=%d; h=sha256:%s:%s;", mi.Version, hB64, bB64)
	if mi.Recipe != nil {
		rJSON, _ := encodeRecipe(mi.Recipe)
		s += " r=" + base64.StdEncoding.EncodeToString(rJSON) + ";"
	}
	return s
}
