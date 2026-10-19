package dkim2

import (
	"bufio"
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/iotest"
)

// The planned chain walk (plan.go) must give exactly the verdicts the undo
// walk (undo.go) gives.  These tests compare the two: per instance (header
// hash, body hash, whether the body is still checked, which Recipe fails)
// and as whole VerifyFull verdict strings, on hand-built chains and on every
// captured message in the corpus.

// planLevel is one version of a hand-built message, oldest first.  recipe is
// the r= JSON of this level's Message-Instance ("" for none): it undoes this
// level into the one below.
type planLevel struct {
	hdr    string // header fields, each ending CRLF; no blank line
	body   string // raw body bytes as sent
	recipe string
}

// buildPlanChain writes the top level's content under one unsigned
// Message-Instance per level, each hashed over its own level's content.
func buildPlanChain(t *testing.T, levels []planLevel) []byte {
	t.Helper()
	var b bytes.Buffer
	for k, lv := range levels {
		hs, _, err := parseHeaders(strings.NewReader(lv.hdr + "\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		hh, err := hashHeaders(hs, "sha256")
		if err != nil {
			t.Fatal(err)
		}
		bh, err := hashBodyMulti(strings.NewReader(lv.body), []string{"sha256"})
		if err != nil {
			bh = map[string][]byte{"sha256": make([]byte, 32)} // a line too long to hash
		}
		fmt.Fprintf(&b, "Message-Instance: m=%d; h=sha256:%s:%s;", k+1,
			base64.StdEncoding.EncodeToString(hh), base64.StdEncoding.EncodeToString(bh["sha256"]))
		if lv.recipe != "" {
			fmt.Fprintf(&b, " r=%s;", base64.StdEncoding.EncodeToString([]byte(lv.recipe)))
		}
		b.WriteString("\r\n")
	}
	top := levels[len(levels)-1]
	b.WriteString(top.hdr + "\r\n" + top.body)
	return b.Bytes()
}

// splitMessage returns a message's header fields and its raw body bytes,
// as the planned walk sees them.
func splitMessage(t *testing.T, msg []byte) ([]Header, []byte) {
	t.Helper()
	br := bufio.NewReader(bytes.NewReader(msg))
	headers, err := readHeaderFields(br)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(br)
	if err != nil {
		t.Fatal(err)
	}
	return headers, body
}

// undoState rebuilds msg down to target with the undo walk and returns the
// rebuilt content headers and body, whether the body is past a null body
// Recipe, and the walk's error.
func undoState(t *testing.T, msg []byte, target int) ([]Header, []byte, bool, error) {
	t.Helper()
	headers, bodyReader, err := parseHeaders(bytes.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(bodyReader)
	var mis []undoMI
	var content []Header
	highest := 0
	for _, h := range headers {
		switch strings.ToLower(h.Name) {
		case "message-instance":
			mi, err := parseMI(h.Raw)
			if err != nil {
				t.Fatal(err)
			}
			mis = append(mis, undoMI{mi.Version, h.Raw, mi})
			if mi.Version > highest {
				highest = mi.Version
			}
		case "dkim2-signature":
		default:
			content = append(content, h)
		}
	}
	return rebuildTo(mis, highest, target, content, body, true)
}

// comparePlan feeds msg's body to a chain plan in the given chunks and
// checks every instance against the undo walk.  It returns false when the
// message falls back to the undo walk (no plan).
func comparePlan(t *testing.T, name string, msg []byte, chunks func([]byte) [][]byte) bool {
	t.Helper()
	headers, body := splitMessage(t, msg)
	p := newChainPlan(headers)
	if p == nil {
		return false
	}
	for _, c := range chunks(body) {
		if n, err := p.Write(c); err != nil || n != len(c) {
			t.Fatalf("%s: plan write: %d, %v", name, n, err)
		}
	}
	p.close()

	// The first Recipe (walking down) that fails stops the walk.
	stop := 0
	for v := p.top; v >= 2; v-- {
		if p.recipeFails(v) {
			stop = v
			break
		}
	}
	for target := p.top - 1; target >= 1; target-- {
		content, rebuilt, gone, err := undoState(t, msg, target)
		if stop > target {
			want := (&malformedRecipeError{m: stop}).Error()
			if err == nil || err.Error() != want {
				t.Errorf("%s: target %d: undo walk error %v, plan says %q", name, target, err, want)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: target %d: undo walk fails (%v), plan does not", name, target, err)
			continue
		}
		in := p.inst[target]
		if gone != in.bodyGone {
			t.Errorf("%s: target %d: body gone undo=%v plan=%v", name, target, gone, in.bodyGone)
			continue
		}
		for _, alg := range []string{"sha256", "sha512"} {
			want, _ := hashHeaders(content, alg)
			if got := p.headerHash(in, alg); !bytes.Equal(got, want) {
				t.Errorf("%s: target %d: %s header hash differs", name, target, alg)
			}
		}
		if gone || p.tooLong { // past a null body Recipe, or Verify fails first
			continue
		}
		for _, alg := range implementedAlgs(in.mi.Hashes) {
			want, werr := hashBodyMulti(bytes.NewReader(rebuilt), []string{alg})
			if werr != nil {
				if !in.body.tooLong {
					t.Errorf("%s: target %d: undo body hash fails (%v), plan does not", name, target, werr)
				}
				continue
			}
			if got := in.body.sums[alg]; !bytes.Equal(got, want[alg]) {
				t.Errorf("%s: target %d: %s body hash differs", name, target, alg)
			}
		}
	}
	return true
}

func oneChunk(b []byte) [][]byte { return [][]byte{b} }

func byteChunks(b []byte) [][]byte {
	out := make([][]byte, len(b))
	for i := range b {
		out[i] = b[i : i+1]
	}
	return out
}

// cyclingChunks cuts b into pieces of 1, 2, ... 97 bytes, over and over.
func cyclingChunks(b []byte) [][]byte {
	var out [][]byte
	for i, n := 0, 1; i < len(b); n = n%97 + 1 {
		j := min(i+n, len(b))
		out = append(out, b[i:j])
		i = j
	}
	return out
}

// verdict renders a VerifyFull outcome for comparison.
func verdict(results []VerifyResult, err error) string {
	var b strings.Builder
	for _, r := range results {
		fmt.Fprintf(&b, "i=%d d=%s err=%v\n", r.Sequence, r.Domain, r.Error)
	}
	if err != nil {
		fmt.Fprintf(&b, "ERROR %v\n", err)
	}
	return b.String()
}

// compareVerdicts runs VerifyFull both ways (the planned walk reading the
// message through r) and requires the same verdict; it returns it.
func compareVerdicts(t *testing.T, name string, msg []byte, r io.Reader, f KeyFetcher, opt VerifyOptions) string {
	t.Helper()
	ref := opt
	ref.UndoWalk = true
	want := verdict(VerifyFull(bytes.NewReader(msg), f, ref))
	got := verdict(VerifyFull(r, f, opt))
	if got != want {
		t.Errorf("%s: verdict differs\nundo walk:\n%s\nplanned walk:\n%s", name, want, got)
	}
	return got
}

const planHdr = "From: a@example.com\r\nTo: b@example.com\r\nSubject: hello\r\n"

type planCase struct {
	name   string
	levels []planLevel
	want   string // substring of the verdict; "" = passes
	m01    bool   // write m=1 as m=01
	noPlan bool   // structurally bad: parseMI rejects it, so Verify does and there is no plan
}

func planCases() []planCase {
	big := strings.Repeat("x", 1<<20)
	mixed := strings.Repeat("lf line\n\nnext\r\n", 6000) // 18000 lines, > normFlush
	h := planHdr
	return []planCase{
		{name: "no recipe", levels: []planLevel{
			{h, "a\r\nb\r\n", ""}, {h, "a\r\nb\r\n", ""}}},
		{name: "footer append", levels: []planLevel{
			{h, "line1\r\nline2\r\n", ""},
			{h, "line1\r\nline2\r\n-- \r\nfooter\r\n", `{"b":[{"c":[1,2]}]}`}}},
		{name: "mime wrap", levels: []planLevel{
			{h, "hello\r\nworld\r\n", ""},
			{h, "--x\r\nContent-Type: text/plain\r\n\r\nhello\r\nworld\r\n--x--\r\n", `{"b":[{"c":[4,5]}]}`}}},
		{name: "literals around copies", levels: []planLevel{
			{h, "A\r\nb\r\nC\r\nd\r\nE\r\n", ""},
			{h, "b\r\nd\r\n", `{"b":[{"d":["A"]},{"c":[1,1]},{"d":["C"]},{"c":[2,2]},{"u":["RQ=="]}]}`}}},
		{name: "three levels copying a literal", levels: []planLevel{
			{h, "X\r\n", ""},
			{h, "X\r\nb\r\n", `{"b":[{"c":[1,1]}]}`},
			{h, "b\r\nc\r\n", `{"b":[{"d":["X"]},{"c":[1,1]}]}`}}},
		{name: "three levels sharing a body", levels: []planLevel{
			{h, "a\r\n", ""},
			{h, "a\r\nf\r\n", `{"b":[{"c":[1,1]}]}`},
			{h, "a\r\nf\r\n", `{"h":{"subject":[{"c":[1,1]}]}}`},
			{h, "a\r\nf\r\ng\r\n", `{"b":[{"c":[1,2]}]}`}}},
		{name: "trailing blank lines and blank literals at the end", levels: []planLevel{
			{h, "a\r\n\r\n\r\n", ""},
			{h, "a\r\nfoot\r\n\r\n", `{"b":[{"c":[1,1]},{"d":["",""]}]}`}}},
		{name: "blank run across a body line and a literal", levels: []planLevel{
			{h, "a\r\n\r\n\r\nz\r\n", ""},
			{h, "a\r\n\r\nb\r\n", `{"b":[{"c":[1,2]},{"d":["","z"]}]}`}}},
		{name: "copy into trailing blank lines", levels: []planLevel{
			{h, "a\r\n\r\nq\r\n", ""},
			{h, "a\r\n\r\n\r\n", `{"b":[{"c":[1,2]},{"d":["q"]}]}`}}},
		{name: "copy past end", want: "PERMERROR: Message-Instance m=2 contains invalid JSON", levels: []planLevel{
			{h, "a\r\nb\r\n", ""},
			{h, "a\r\n", `{"b":[{"c":[1,3]}]}`}}},
		{name: "copy past end of a rebuilt body", want: "PERMERROR: Message-Instance m=2 contains invalid JSON", levels: []planLevel{
			{h, "a\r\nb\r\n", ""},
			{h, "a\r\n", `{"b":[{"c":[1,2]}]}`},
			{h, "a\r\nb\r\n", `{"b":[{"c":[1,1]}]}`}}},
		{name: "out of order copies", noPlan: true, want: "PERMERROR: Message-Instance m=2 contains invalid JSON", levels: []planLevel{
			{h, "b\r\na\r\n", ""},
			{h, "a\r\nb\r\n", `{"b":[{"c":[2,2]},{"c":[1,1]}]}`}}},
		{name: "overlapping copies", noPlan: true, want: "PERMERROR: Message-Instance m=2 contains invalid JSON", levels: []planLevel{
			{h, "a\r\nb\r\nb\r\nc\r\n", ""},
			{h, "a\r\nb\r\nc\r\n", `{"b":[{"c":[1,2]},{"c":[2,3]}]}`}}},
		{name: "null body recipe", levels: []planLevel{
			{h, "whatever\r\n", ""},
			{strings.Replace(h, "hello", "[l] hello", 1), "new\r\n", `{"h":{"subject":[{"d":["hello"]}]},"b":null}`}}},
		{name: "null body recipe, header mismatch below", want: "FAIL: Message-Instance m=1 header hash sha256 mismatch", levels: []planLevel{
			{strings.Replace(h, "hello", "other", 1), "whatever\r\n", ""},
			{strings.Replace(h, "hello", "[l] hello", 1), "new\r\n", `{"h":{"subject":[{"d":["hello"]}]},"b":null}`}}},
		{name: "header recipes checked below a null body recipe", want: "PERMERROR: Message-Instance m=2 contains invalid JSON", levels: []planLevel{
			{h, "a\r\n", ""},
			{h, "b\r\n", `{"h":{"subject":[{"c":[1,2]}]},"b":[{"c":[1,5]}]}`},
			{h, "c\r\n", `{"b":null}`}}},
		{name: "unterminated last line", levels: []planLevel{
			{h, "a\r\n", ""},
			{h, "a\r\nb", `{"b":[{"c":[1,1]}]}`}}},
		{name: "copy of an unterminated last line", levels: []planLevel{
			{h, "x\r\nb\r\n", ""},
			{h, "a\r\nb", `{"b":[{"d":["x"]},{"c":[2,2]}]}`}}},
		{name: "empty body", levels: []planLevel{
			{h, "x\r\n", ""},
			{h, "", `{"b":[{"d":["x"]}]}`}}},
		{name: "empty recipe", levels: []planLevel{
			{h, "", ""},
			{h, "foot\r\n", `{"b":[]}`}}},
		{name: "empty recipe then copy of the blank line", levels: []planLevel{
			{h, "\r\n", ""},
			{h, "", `{"b":[{"c":[1,1]}]}`},
			{h, "foot\r\n", `{"b":[]}`}}},
		{name: "copy from an empty body", want: "PERMERROR: Message-Instance m=2 contains invalid JSON", levels: []planLevel{
			{h, "\r\n", ""},
			{h, "", `{"b":[{"c":[1,1]}]}`}}},
		{name: "only blank lines", levels: []planLevel{
			{h, "\r\n", ""},
			{h, "\r\n\r\n\r\n", `{"b":[{"c":[1,3]}]}`}}},
		{name: "lone CR in a line", levels: []planLevel{
			{h, "a\rb\r\n", ""},
			{h, "a\rb\r\nc\r\r\n\r\r\n", `{"b":[{"c":[1,1]}]}`}}},
		{name: "bare LF", levels: []planLevel{
			{h, "b\n", ""},
			{h, "a\nb\n\n", `{"b":[{"c":[2,2]}]}`}}},
		{name: "body hash mismatch", want: "FAIL: Message-Instance m=1 body hash sha256 mismatch", levels: []planLevel{
			{h, "a\r\nX\r\n", ""},
			{h, "a\r\nb\r\n", `{"b":[{"c":[1,1]},{"d":["Y"]}]}`}}},
		{name: "subject tag removed", levels: []planLevel{
			{h, "a\r\n", ""},
			{strings.Replace(h, "hello", "[list] hello", 1), "a\r\n", `{"h":{"subject":[{"d":["hello"]}]}}`}}},
		{name: "fields removed", levels: []planLevel{
			{h, "a\r\n", ""},
			{h + "List-Id: <l.example.com>\r\nList-Post: <mailto:l@example.com>\r\n", "a\r\n", `{"h":{"list-id":[],"list-post":[]}}`}}},
		{name: "repeated fields with copies and literals", levels: []planLevel{
			{h + "Comments: c1\r\nComments: c2\r\nComments: c3\r\n", "a\r\n", ""},
			{h + "Comments: c1\r\nComments: X\r\nComments: c3\r\n", "a\r\n", `{"h":{"comments":[{"c":[1,1]},{"d":["c2"]},{"c":[3,3]}]}}`}}},
		{name: "a field added", levels: []planLevel{
			{h + "Keywords: k\r\n", "a\r\n", ""},
			{h, "a\r\n", `{"h":{"keywords":[{"d":["k"]}]}}`}}},
		{name: "three header levels", levels: []planLevel{
			{h + "Comments: one\r\n", "a\r\n", ""},
			{strings.Replace(h, "hello", "[a] hello", 1) + "Comments: one\r\nComments: two\r\n", "a\r\n",
				`{"h":{"subject":[{"d":["hello"]}],"comments":[{"c":[2,2]}]}}`},
			{strings.Replace(h, "hello", "[b] [a] hello", 1) + "Comments: two\r\n", "a\r\n",
				`{"h":{"subject":[{"d":["[a] hello"]}],"comments":[{"c":[1,1]},{"d":["one"]}]}}`}}},
		{name: "folded values", levels: []planLevel{
			{"From: a@example.com\r\nSubject: a\r\n long\r\n\tsubject\r\nTo: x@example.com,\r\n y@example.com\r\n", "a\r\n", ""},
			{"From: a@example.com\r\nSubject: [l] a\r\n long\r\nTo: x@example.com,\r\n y@example.com\r\n", "a\r\n",
				`{"h":{"subject":[{"d":["a long\tsubject"]}],"to":[{"c":[1,1]}]}}`}}},
		{name: "mixed-case names", levels: []planLevel{
			{"FROM: a@example.com\r\nsubject: hello\r\nSUBJECT: two\r\n", "a\r\n", ""},
			{"FROM: a@example.com\r\nSubject: [l] hello\r\nSUBJECT: two\r\n", "a\r\n", `{"h":{"subject":[{"c":[1,1]},{"d":["hello"]}]}}`}}},
		{name: "mixed-case recipe keys", levels: []planLevel{
			{h + "Keywords: k\r\n", "a\r\n", ""},
			{strings.Replace(h, "hello", "[l] hello", 1), "a\r\n", `{"h":{"Subject":[{"d":["hello"]}],"KEYWORDS":[{"d":["k"]}]}}`}}},
		{name: "skipped fields with recipes", levels: []planLevel{
			{h + "Received: from a\r\nX-Foo: bar\r\n", "a\r\n", ""},
			{"Received: from b\r\n" + h + "Received: from a\r\nX-Other: 1\r\n", "a\r\n",
				`{"h":{"received":[{"c":[1,1]}],"x-foo":[{"d":["bar"]}],"x-other":[]}}`}}},
		{name: "skipped field copy past end", want: "PERMERROR: Message-Instance m=2 contains invalid JSON", levels: []planLevel{
			{h, "a\r\n", ""},
			{h + "Received: from a\r\n", "a\r\n", `{"h":{"received":[{"c":[1,2]}]}}`}}},
		{name: "header copy past end", want: "PERMERROR: Message-Instance m=2 contains invalid JSON", levels: []planLevel{
			{h, "a\r\n", ""},
			{h, "a\r\n", `{"h":{"subject":[{"c":[1,2]}]}}`}}},
		{name: "header copy of a missing field", want: "PERMERROR: Message-Instance m=2 contains invalid JSON", levels: []planLevel{
			{h, "a\r\n", ""},
			{h, "a\r\n", `{"h":{"keywords":[{"c":[1,1]}]}}`}}},
		{name: "header copies out of order", noPlan: true, want: "PERMERROR: Message-Instance m=2 contains invalid JSON", levels: []planLevel{
			{h, "a\r\n", ""},
			{h + "Comments: 1\r\nComments: 2\r\n", "a\r\n", `{"h":{"comments":[{"c":[2,2]},{"c":[1,1]}]}}`}}},
		{name: "first bad name in key order", want: "PERMERROR: Message-Instance m=2 contains invalid JSON", levels: []planLevel{
			{h, "a\r\n", ""},
			{h, "a\r\n", `{"h":{"to":[{"c":[1,3]}],"keywords":[{"c":[1,1]}],"subject":[{"c":[2,2]}]}}`}}},
		{name: "body error before header error", want: "PERMERROR: Message-Instance m=2 contains invalid JSON", levels: []planLevel{
			{h, "a\r\n", ""},
			{h, "a\r\n", `{"h":{"subject":[{"c":[1,2]}]},"b":[{"c":[1,9]}]}`}}},
		{name: "upper error wins over lower", want: "PERMERROR: Message-Instance m=3 contains invalid JSON", levels: []planLevel{
			{h, "a\r\n", ""},
			{h, "a\r\n", `{"h":{"subject":[{"c":[1,2]}]}}`},
			{h, "a\r\n", `{"b":[{"c":[1,4]}]}`}}},
		{name: "hash mismatch above a recipe error", want: "FAIL: Message-Instance m=2 header hash sha256 mismatch", levels: []planLevel{
			{h, "a\r\n", ""},
			{strings.Replace(h, "hello", "zz", 1), "a\r\n", `{"h":{"subject":[{"c":[1,2]}]}}`},
			{h, "a\r\n", `{"b":[{"c":[1,1]}]}`}}},
		{name: "message-instance named by a header recipe", levels: []planLevel{
			{h, "a\r\n", ""},
			{h, "a\r\n", `{"h":{"message-instance":[{"d":["m=7; h=sha256:AA==:AA=="]}]}}`}}},
		{name: "message-instance copied by a header recipe", want: "PERMERROR: Message-Instance m=2 contains invalid JSON", levels: []planLevel{
			{h, "a\r\n", ""},
			{h, "a\r\n", `{"h":{"message-instance":[{"c":[1,1]}]}}`}}},
		{name: "m=01", m01: true, levels: []planLevel{
			{h, "a\r\n", ""},
			{h, "a\r\nfoot\r\n", `{"b":[{"c":[1,1]}]}`}}},
		{name: "literal line too long to hash", want: "token too long", levels: []planLevel{
			{h, big + "\r\n", ""},
			{h, "a\r\n", `{"b":[{"d":["` + big + `"]}]}`}}},
		{name: "body line too long to hash", want: "body hash: bufio.Scanner: token too long", levels: []planLevel{
			{h, "a\r\n", ""},
			{h, "a\r\n" + big + "\r\n", `{"b":[{"c":[1,1]}]}`}}},
		{name: "body line just short enough", levels: []planLevel{
			{h, "a\r\n", ""},
			{h, "a\r\n" + big[:1<<20-2] + "\r\n", `{"b":[{"c":[1,1]}]}`}}},
		{name: "mixed endings past the rewrite buffer", levels: []planLevel{
			{h, mixed, ""},
			{h, "head\n" + mixed + "\n\r\nfoot\r\r\n", `{"b":[{"c":[2,18001]}]}`}}},
	}
}

func (c planCase) message(t *testing.T) []byte {
	msg := buildPlanChain(t, c.levels)
	if c.m01 {
		msg = bytes.Replace(msg, []byte("Message-Instance: m=1;"), []byte("Message-Instance: m=01;"), 1)
	}
	return msg
}

// TestPlanParityUnit compares the two walks on hand-built chains, the body
// fed whole, in every two-piece split and one byte at a time.
func TestPlanParityUnit(t *testing.T) {
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	opt := VerifyOptions{SkipTimestampCheck: true, Outbound: true}
	for _, c := range planCases() {
		t.Run(c.name, func(t *testing.T) {
			msg := c.message(t)
			got := compareVerdicts(t, c.name, msg, bytes.NewReader(msg), f, opt)
			// An unsigned top that matches leaves no results at all.
			if c.want == "" && got != "" {
				t.Errorf("want a pass, got:\n%s", got)
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Errorf("want %q, got:\n%s", c.want, got)
			}
			if planned := comparePlan(t, c.name, msg, oneChunk); planned == c.noPlan {
				t.Fatalf("planned=%v, want %v", planned, !c.noPlan)
			}
			compareVerdicts(t, c.name+" one byte", msg, iotest.OneByteReader(bytes.NewReader(msg)), f, opt)
			if c.noPlan {
				return
			}
			_, body := splitMessage(t, msg)
			if len(body) > 4096 {
				comparePlan(t, c.name+" cycling", msg, cyclingChunks)
				return
			}
			comparePlan(t, c.name+" one byte", msg, byteChunks)
			for i := 0; i <= len(body); i++ {
				comparePlan(t, fmt.Sprintf("%s split %d", c.name, i), msg, func(b []byte) [][]byte {
					return [][]byte{b[:i], b[i:]}
				})
			}
		})
	}
}

// TestPlanFallsBack: a message the plan cannot model exactly goes to the
// undo walk, with the same verdict.
func TestPlanFallsBack(t *testing.T) {
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	opt := VerifyOptions{SkipTimestampCheck: true, Outbound: true}
	base := planCases()[1].levels // footer append
	for _, tc := range []struct {
		name string
		msg  []byte
	}{
		{"case-colliding recipe keys", buildPlanChain(t, []planLevel{base[0],
			{planHdr, base[1].body, `{"h":{"subject":[{"c":[1,1]}],"Subject":[{"c":[1,2]}]}}`}})},
		{"MI gap", bytes.Replace(buildPlanChain(t, []planLevel{base[0], base[1], base[1]}),
			[]byte("m=2;"), []byte("m=4;"), 1)},
		{"duplicate MI", bytes.Replace(buildPlanChain(t, []planLevel{base[0], base[1], base[1]}),
			[]byte("m=2;"), []byte("m=3;"), 1)},
	} {
		headers, _ := splitMessage(t, tc.msg)
		if newChainPlan(headers) != nil {
			t.Errorf("%s: planned, want the undo walk", tc.name)
		}
		if tc.name == "case-colliding recipe keys" {
			continue // the undo walk itself picks a key at random
		}
		compareVerdicts(t, tc.name, tc.msg, iotest.OneByteReader(bytes.NewReader(tc.msg)), f, opt)
	}
}

// TestPlanTooLongThreshold pins the line length at which the body hash
// fails to the one hashBodyMulti fails at.
func TestPlanTooLongThreshold(t *testing.T) {
	for _, n := range []int{maxCanonLine - 3, maxCanonLine - 2, maxCanonLine - 1, maxCanonLine} {
		body := "a\r\n" + strings.Repeat("y", n) + "\r\nz\r\n"
		_, want := hashBodyMulti(strings.NewReader(body), []string{"sha256"})
		msg := buildPlanChain(t, []planLevel{{planHdr, "a\r\n", ""}, {planHdr, body, `{"b":[{"c":[1,1]}]}`}})
		headers, raw := splitMessage(t, msg)
		p := newChainPlan(headers)
		p.Write(raw)
		p.close()
		_, got := p.topHashes([]string{"sha256"})
		if (got == nil) != (want == nil) {
			t.Errorf("line of %d: plan error %v, hashBodyMulti error %v", n, got, want)
		}
	}
}

// fileKeys answers key lookups from dns.json-shaped files, read once.
type fileKeys map[string][][]string

func loadFileKeys(t *testing.T, paths ...string) fileKeys {
	t.Helper()
	k := fileKeys{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var db map[string]map[string][][2]string
		if err := json.Unmarshal(data, &db); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		for dom, recs := range db {
			for sel, rrs := range recs {
				name := sel + "." + dom
				if _, seen := k[name]; seen {
					continue // the first file wins
				}
				k[name] = [][]string{}
				for _, rr := range rrs {
					if strings.EqualFold(rr[0], "txt") {
						k[name] = append(k[name], []string{rr[1]})
					}
				}
			}
		}
	}
	return k
}

func (k fileKeys) FetchPublicKey(selector, domain string) (crypto.PublicKey, string, error) {
	name := selector + "._domainkey." + domain
	rrs, ok := k[name]
	if !ok {
		return nil, "", fmt.Errorf("%w: %s", ErrKeyNotFound, name)
	}
	return keyFromTXTRecords(rrs, name)
}

// corpusDir is the captured list-mail corpus: $DKIM2_CORPUS, else the
// corpus/results directory at the top of the repository.
func corpusDir() string {
	if d := os.Getenv("DKIM2_CORPUS"); d != "" {
		return d
	}
	return "../../corpus/results"
}

// TestPlanParityCorpus compares the two walks on every captured message,
// fed in uneven chunks, and on copies with one body byte changed and with
// the Subject changed.
func TestPlanParityCorpus(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(corpusDir(), "capture", "*.eml"))
	expected, _ := filepath.Glob("../../perl/tests/expected/*.eml")
	files = append(files, expected...)
	if len(files) == 0 {
		t.Skip("no corpus")
	}
	if testing.Short() {
		t.Skip("corpus parity is slow")
	}
	keys := loadFileKeys(t, "../../dns.json", filepath.Join(corpusDir(), "dns-live.json"))
	opt := VerifyOptions{SkipTimestampCheck: true}
	planned, fellBack, mutants := 0, 0, 0
	verdicts := map[string]int{}
	for _, path := range files {
		msg, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(path)
		variants := map[string][]byte{name: msg}
		_, body := splitMessage(t, msg)
		if len(body) > 0 {
			i := len(msg) - len(body) + len(body)/2
			if msg[i] == '\n' || msg[i] == '\r' {
				i--
			}
			m := bytes.Clone(msg)
			m[i] ^= 0x01
			if m[i] == '\n' || m[i] == '\r' {
				m[i] = 'Q'
			}
			variants[name+" body byte"] = m
		}
		if s := subjectRe(msg); s >= 0 {
			m := append(bytes.Clone(msg[:s]), []byte("Subject: changed ")...)
			variants[name+" subject"] = append(m, msg[s+len("Subject: "):]...)
		}
		for vname, v := range variants {
			if vname != name {
				mutants++
			}
			got := compareVerdicts(t, vname, v, iotest.OneByteReader(bytes.NewReader(v)), keys, opt)
			kind := strings.TrimPrefix(vname, name)
			if kind == "" {
				kind = " unmodified"
			}
			verdicts[kind[1:]+": "+outcome(got)]++
			if comparePlan(t, vname, v, cyclingChunks) {
				planned++
			} else {
				fellBack++
			}
		}
	}
	t.Logf("corpus: %d messages + %d mutants; %d planned, %d fell back to the undo walk",
		len(files), mutants, planned, fellBack)
	var vs []string
	for v, n := range verdicts {
		vs = append(vs, fmt.Sprintf("%5d %s", n, v))
	}
	sort.Strings(vs)
	t.Logf("verdicts:\n%s", strings.Join(vs, "\n"))
}

// subjectRe finds the start of the first Subject field in msg's header.
func subjectRe(msg []byte) int {
	end := bytes.Index(msg, []byte("\r\n\r\n"))
	if end < 0 {
		end = len(msg)
	}
	for i := 0; i < end; {
		if bytes.HasPrefix(msg[i:], []byte("Subject: ")) {
			return i
		}
		j := bytes.IndexByte(msg[i:end], '\n')
		if j < 0 {
			break
		}
		i += j + 1
	}
	return -1
}

// outcome sums a verdict up: "pass", or its first failure with the
// per-message detail (numbers, domains) cut away.
func outcome(v string) string {
	for _, line := range strings.Split(strings.TrimSpace(v), "\n") {
		if line == "" || strings.HasSuffix(line, "err=<nil>") {
			continue
		}
		if _, rest, ok := strings.Cut(line, " err="); ok {
			line = rest
		}
		if i := strings.LastIndex(line, ": "); i >= 0 {
			line = line[i+2:]
		}
		return line
	}
	return "pass"
}
