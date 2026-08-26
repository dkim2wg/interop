package dkim2

// Conformance runner for the Turscar dkim2tests vectors (Steve Atkins),
// checked out as the git submodule at <repo>/dkim2tests. Each vector's signed
// message is verified and the accept/reject decision compared to the vector's
// ExpectedState ("pass" == accept, else reject).
//
// The vectors target spec-02, but the tag rules (case-insensitive identifiers,
// any order, single occurrence, FWS) and the >=1024-bit key requirement (§3.2)
// are unchanged in spec-05, so they apply directly. A tiny hand-rolled reader
// pulls the few fields we need so the test needs no external TOML dependency.

import (
	"bytes"
	"crypto"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Upstream vectors we knowingly diverge from, with the reason (not gated).
var turscarKnownDivergence = map[string]string{
	// Steve's signer emitted an EMPTY s= signature value here (the .signed
	// file ends "...s = rsa2048:rsa-sha256:" with no bytes) — its own signature
	// insertion tripped over the header whitespace this test exercises. With no
	// signature present, ExpectedState "pass" is unachievable.
	"tags_whitespace": "upstream vector has an empty s= signature value",
}

var reScalar = regexp.MustCompile(`(?m)^([A-Za-z]+)\s*=\s*'([^']*)'`)
var reListItem = regexp.MustCompile(`'([^']*)'`)

type turscarVector struct {
	name     string
	expected string
	signed   []byte
	mailFrom string
	rcptTo   []string
	dns      map[string]string // "sel._domainkey.domain" -> DKIM1 TXT
}

func parseTurscarTOML(t *testing.T, dir, tomlName string) turscarVector {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(dir, tomlName))
	if err != nil {
		t.Fatalf("read %s: %v", tomlName, err)
	}
	v := turscarVector{dns: map[string]string{}}
	scalars := map[string]string{}
	for _, m := range reScalar.FindAllStringSubmatch(string(text), -1) {
		scalars[m[1]] = m[2]
	}
	v.expected = scalars["ExpectedState"]
	v.mailFrom = scalars["MailFrom"]
	v.name = scalars["Name"]
	if v.name == "" {
		v.name = strings.TrimSuffix(tomlName, ".toml")
	}

	lines := strings.Split(string(text), "\n")
	inDNS := false
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "[") {
			inDNS = trimmed == "[DNS]"
			continue
		}
		if strings.HasPrefix(trimmed, "RcptTo") {
			for _, it := range reListItem.FindAllStringSubmatch(trimmed, -1) {
				v.rcptTo = append(v.rcptTo, it[1])
			}
		}
		if inDNS {
			// 'sel._domainkey.domain' = 'v=DKIM1; ...'
			q := reListItem.FindAllStringSubmatch(trimmed, -1)
			if len(q) == 2 {
				v.dns[q[0][1]] = q[1][1]
			}
		}
	}

	sf := scalars["SignedFile"]
	signed, err := os.ReadFile(filepath.Join(dir, sf))
	if err != nil {
		t.Fatalf("read signed file %s: %v", sf, err)
	}
	v.signed = signed
	return v
}

// mapKeyFetcher serves keys from a per-vector "host -> TXT" map.
type mapKeyFetcher struct{ dns map[string]string }

func (f *mapKeyFetcher) FetchPublicKey(selector, domain string) (crypto.PublicKey, string, error) {
	txt, ok := f.dns[selector+"._domainkey."+domain]
	if !ok {
		return nil, "", os.ErrNotExist
	}
	return parseDKIM1TXT(txt)
}

func TestTurscarConformance(t *testing.T) {
	dir := filepath.Join("..", "..", "dkim2tests", "tests")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("dkim2tests submodule not checked out (git submodule update --init): %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	gated, skipped := 0, 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		v := parseTurscarTOML(t, dir, e.Name())
		if why, known := turscarKnownDivergence[v.name]; known {
			t.Logf("SKIP %s: %s", v.name, why)
			skipped++
			continue
		}
		gated++
		results, err := VerifyFull(bytes.NewReader(v.signed), &mapKeyFetcher{v.dns},
			VerifyOptions{MailFrom: v.mailFrom, RcptTo: v.rcptTo, SkipTimestampCheck: true})
		accept := err == nil && len(results) > 0
		var detail string
		for _, r := range results {
			if r.Error != nil {
				accept = false
				detail = r.Error.Error()
			}
		}
		if err != nil {
			detail = err.Error()
		}
		wantAccept := v.expected == "pass"
		if accept != wantAccept {
			t.Errorf("%s: expected=%s got accept=%v (%s)", v.name, v.expected, accept, detail)
		}
	}
	t.Logf("%d gated vectors agree on accept/reject; %d skipped", gated, skipped)
}
