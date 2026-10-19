package dkim2

import (
	"bufio"
	"bytes"
	"fmt"
	"hash"
	"io"
	"math"
	"sort"
	"strings"
)

// The planned chain walk.  VerifyFull must check every lower
// Message-Instance against the version of the message its Recipes rebuild.
// The undo walk (undo.go) does that literally, rebuilding each previous
// message in turn.  The plan reaches the same verdicts, with the same
// errors, without rebuilding anything:
//
//   - Body: each instance's body is a list of segments, each a run of lines
//     of the received body or of the literal lines the body Recipes carry.
//     The top instance is the whole received body; walking down, an
//     instance's list is its parent's list composed with the parent's body
//     Recipe.  An instance with no body Recipe shares its parent's list, so
//     identical bodies share one set of digests.  Then ONE pass over the
//     received body, which may arrive in chunks cut anywhere (Write), feeds
//     each line to the digest of every list that holds it.
//   - Headers: the fields are split once; per field name and per instance
//     the plan keeps the list of values (received or literal), numbered
//     bottom-up as Recipes number them.  A value is canonicalized at most
//     once, and only when its name is in the header hash.
//
// The plan reproduces the undo walk's quirks too: a copy range is checked
// against all of the body it copies from, trailing blank lines included; a
// Recipe that rebuilds an empty body rebuilds one blank line; a header
// Recipe naming message-instance or dkim2-signature acts on the content
// fields, of which there are none by those names.  What it cannot model
// exactly it declines (newChainPlan returns nil) and VerifyFull falls back
// to the undo walk.

// maxCanonLine is the longest canonical body line, its CRLF included, that
// writeCanonicalBody's line scanner takes; a longer one fails the body
// hash with bufio.ErrTooLong.
const maxCanonLine = 1024 * 1024

var crlf = []byte("\r\n")

// chainPlan is the planned walk for one message.  It is an io.Writer for
// the raw body bytes (anything after the blank line that ends the header);
// close it at the end of the body.
type chainPlan struct {
	top     int
	inst    []*planInstance // by m= (1..top); nil below a Recipe that fails
	lits    []string        // literal body lines; LIT segments index them from 1
	vals    []hdrValue      // every header value, received or literal
	hdrSums map[hdrSumKey][]byte
	lists   []*bodyList // distinct body lists to hash

	// The pass over the body.
	n       int // body lines seen so far
	next    int // the line at which some list's segment begins or ends
	active  []*bodyAcc
	part    []byte // a line not yet ended by LF
	tooLong bool   // a body line too long to hash: Verify fails "body hash"
	closed  bool
}

type planInstance struct {
	mi        *MessageInstance
	hdr       map[string][]int // lowercased field name -> value indices, bottom-up
	hdrID     int              // instances with the same hdr share an id
	body      *bodyList        // nil when bodyGone
	bodyGone  bool             // below a null body Recipe: header hash only
	recipeBad bool             // undoing this instance's Recipe fails
	topEnd    int              // highest "c" end its body Recipe takes from the received body
}

type hdrValue struct {
	h     Header
	canon string
	done  bool
}

type hdrSumKey struct {
	id  int
	alg string
}

// bodySeg is lines from..to (1-based, inclusive) of the received body, or
// with lit set of the plan's literal table.
type bodySeg struct {
	lit      bool
	from, to int
}

func (s bodySeg) len() int { return s.to - s.from + 1 }

type bodyList struct {
	segs    []bodySeg
	lines   int  // its length; -1 for the received body, known only at the end
	tooLong bool // holds a literal line too long to hash
	accs    map[string]*bodyAcc
	sums    map[string][]byte
	seg     int // the pass's cursor into segs
}

func (l *bodyList) add(s bodySeg) {
	if n := len(l.segs); n > 0 && l.segs[n-1].lit == s.lit && l.segs[n-1].to+1 == s.from {
		l.segs[n-1].to = s.to
		return
	}
	l.segs = append(l.segs, s)
}

// bodyAcc is one body digest, canonicalizing as writeCanonicalBody does:
// a run of blank lines is held back until a non-blank line follows it, so
// trailing blank lines are dropped, and an empty result hashes as one CRLF.
type bodyAcc struct {
	h       hash.Hash
	pending int
	wrote   bool
}

func (a *bodyAcc) flush() {
	for ; a.pending > 0; a.pending-- {
		a.h.Write(crlf)
	}
}

func (a *bodyAcc) line(text []byte) {
	if len(text) == 0 {
		a.pending++
		return
	}
	a.flush()
	a.h.Write(text)
	a.h.Write(crlf)
	a.wrote = true
}

// span hashes whole non-blank lines, each already ending CRLF.
func (a *bodyAcc) span(b []byte) {
	a.flush()
	a.h.Write(b)
	a.wrote = true
}

func (a *bodyAcc) sum() []byte {
	if !a.wrote {
		a.h.Write(crlf)
	}
	return a.h.Sum(nil)
}

// newChainPlan plans the walk down the chain in headers.  It returns nil when
// the message is one to leave to the undo walk: a Message-Instance that does
// not parse, m= values other than exactly 1..N, a field name or Recipe key
// whose lowercasing differs between the ASCII and Unicode forms the undo
// walk mixes, or two Recipe keys for one name (the undo walk picks one at
// random).
func newChainPlan(headers []Header) *chainPlan {
	mis := map[int]*MessageInstance{}
	var content []Header
	for _, h := range headers {
		switch strings.ToLower(h.Name) {
		case "message-instance":
			mi, err := parseMI(h.Raw)
			if err != nil || mis[mi.Version] != nil {
				return nil
			}
			mis[mi.Version] = mi
		case "dkim2-signature":
		default:
			if lowerName(h.Name) != strings.ToLower(h.Name) {
				return nil
			}
			content = append(content, h)
		}
	}
	top := len(mis)
	if top == 0 {
		return nil
	}
	for v := 1; v <= top; v++ {
		if mis[v] == nil {
			return nil
		}
		if r := mis[v].Recipe; r != nil {
			seen := map[string]bool{}
			for k := range r.Headers {
				lk := lowerName(k)
				if seen[lk] || strings.ToLower(lk) != lk {
					return nil
				}
				seen[lk] = true
			}
		}
	}

	p := &chainPlan{top: top, inst: make([]*planInstance, top+1), hdrSums: map[hdrSumKey][]byte{}}
	in := &planInstance{mi: mis[top], hdr: map[string][]int{},
		body: &bodyList{segs: []bodySeg{{false, 1, math.MaxInt}}, lines: -1}}
	for i := len(content) - 1; i >= 0; i-- {
		k := lowerName(content[i].Name)
		p.vals = append(p.vals, hdrValue{h: content[i]})
		in.hdr[k] = append(in.hdr[k], len(p.vals)-1)
	}
	p.inst[top] = in

	// Walk down: undoing instance v's Recipe gives instance v-1.
	ids := 0
	for v := top; v >= 2; v-- {
		cur := p.inst[v]
		prev := &planInstance{mi: mis[v-1], hdr: cur.hdr, hdrID: cur.hdrID,
			body: cur.body, bodyGone: cur.bodyGone}
		if r := cur.mi.Recipe; r != nil {
			if r.BodyNull {
				prev.bodyGone, prev.body = true, nil
			}
			if r.Headers != nil {
				ids++
				prev.hdrID = ids
				prev.hdr, cur.recipeBad = p.undoHeaders(cur.hdr, r.Headers)
			}
			if !cur.recipeBad && r.Body != nil && !prev.bodyGone {
				prev.body, cur.topEnd, cur.recipeBad = p.compose(cur.body, r.Body)
			}
		}
		if cur.recipeBad {
			break // nothing below is ever checked
		}
		p.inst[v-1] = prev
	}

	// One digest per algorithm per distinct body list.
	for v := 1; v <= top; v++ {
		in := p.inst[v]
		if in == nil || in.body == nil {
			continue
		}
		l := in.body
		if l.accs == nil {
			l.accs = map[string]*bodyAcc{}
			p.lists = append(p.lists, l)
		}
		for _, alg := range implementedAlgs(in.mi.Hashes) {
			if l.accs[alg] == nil {
				newHash, _ := HashAlg(alg)
				l.accs[alg] = &bodyAcc{h: newHash()}
			}
		}
	}
	p.advance(1)
	return p
}

// undoHeaders applies one header Recipe to the per-name value lists hdr,
// as undoHeaderRecipes does; bad reports a step that breaks the §5.1 rules
// against the values present.  Unchanged names keep their lists.
func (p *chainPlan) undoHeaders(hdr map[string][]int, recipes map[string][]RecipeStep) (out map[string][]int, bad bool) {
	out = make(map[string][]int, len(hdr)+len(recipes))
	for k, v := range hdr {
		out[k] = v
	}
	for name, steps := range recipes {
		k := lowerName(name)
		vals := hdr[k]
		if validateRecipeSteps(steps, len(vals)) != nil {
			return nil, true
		}
		var list []int
		for _, s := range steps {
			if s.Copy != nil {
				list = append(list, vals[s.Copy[0]-1:s.Copy[1]]...)
				continue
			}
			lits, _ := s.literals() // validated above
			for _, val := range lits {
				p.vals = append(p.vals, hdrValue{h: Header{Name: k, Value: val, Raw: k + ": " + val + "\r\n"}})
				list = append(list, len(p.vals)-1)
			}
		}
		out[k] = list
	}
	return out, false
}

// compose returns the body list a body Recipe rebuilds from parent, as
// undoBodyRecipe would, and the highest line it copies from the received
// body when parent is that body (whose length is only known at the end).
func (p *chainPlan) compose(parent *bodyList, steps []RecipeStep) (out *bodyList, topEnd int, bad bool) {
	if validateRecipeSteps(steps, parent.lines) != nil {
		return nil, 0, true
	}
	out = &bodyList{}
	pi, pstart := 0, 1 // parent.segs[pi] starts at parent line pstart
	for _, s := range steps {
		if s.Copy == nil {
			lits, _ := s.literals() // validated above
			for _, v := range lits {
				p.lits = append(p.lits, v)
				out.add(bodySeg{true, len(p.lits), len(p.lits)})
				out.tooLong = out.tooLong || len(v)+2 > maxCanonLine
			}
			continue
		}
		a, b := s.Copy[0], s.Copy[1]
		if parent.lines < 0 {
			topEnd = b // copies ascend
		}
		for a <= b {
			seg := parent.segs[pi]
			pend := pstart + seg.len() - 1
			if a > pend {
				pstart = pend + 1
				pi++
				continue
			}
			hi := min(b, pend)
			piece := bodySeg{seg.lit, seg.from + a - pstart, seg.from + hi - pstart}
			out.add(piece)
			if piece.lit && parent.tooLong {
				for i := piece.from; i <= piece.to; i++ {
					out.tooLong = out.tooLong || len(p.lits[i-1])+2 > maxCanonLine
				}
			}
			a = hi + 1
		}
	}
	if len(out.segs) == 0 {
		// undoBodyRecipe writes an empty result as one CRLF: one blank line.
		p.lits = append(p.lits, "")
		out.add(bodySeg{true, len(p.lits), len(p.lits)})
	}
	for _, s := range out.segs {
		out.lines += s.len()
	}
	return out, topEnd, false
}

// advance prepares for body line ln, at which some list's segment begins
// or ends: literal segments now due are hashed, and the lists holding line
// ln become the active ones.
func (p *chainPlan) advance(ln int) {
	p.next = math.MaxInt
	p.active = p.active[:0]
	for _, l := range p.lists {
		for l.seg < len(l.segs) {
			s := l.segs[l.seg]
			if s.lit {
				p.emitLits(l, s)
			} else if s.to >= ln {
				break
			}
			l.seg++
		}
		if l.seg == len(l.segs) {
			continue
		}
		s := l.segs[l.seg]
		if s.from > ln {
			p.next = min(p.next, s.from)
			continue
		}
		for _, a := range l.accs {
			p.active = append(p.active, a)
		}
		if s.to < math.MaxInt {
			p.next = min(p.next, s.to+1)
		}
	}
}

func (p *chainPlan) emitLits(l *bodyList, s bodySeg) {
	for i := s.from; i <= s.to; i++ {
		for _, a := range l.accs {
			a.line([]byte(p.lits[i-1]))
		}
	}
}

// trimCRs strips the CRs before a line's LF (or the end of the body), as
// readBody does.
func trimCRs(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == '\r' {
		b = b[:len(b)-1]
	}
	return b
}

// line takes one body line, its ending already stripped.
func (p *chainPlan) line(text []byte) {
	if len(text)+2 > maxCanonLine {
		p.tooLong = true
		return
	}
	ln := p.n + 1
	if ln == p.next {
		p.advance(ln)
	}
	for _, a := range p.active {
		a.line(text)
	}
	p.n = ln
}

func (p *chainPlan) spanOut(b []byte) {
	for _, a := range p.active {
		a.span(b)
	}
}

// Write takes the next piece of the raw body.  Lines are split as readBody
// splits them.  A run of ordinary lines ("text CRLF") between two segment
// boundaries goes to each digest in one write.  It never fails.
func (p *chainPlan) Write(b []byte) (int, error) {
	n := len(b)
	if p.tooLong {
		return n, nil
	}
	if len(p.part) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			p.part = append(p.part, b...)
			p.tooLong = len(trimCRs(p.part))+2 > maxCanonLine
			return n, nil
		}
		p.part = append(p.part, b[:i]...)
		p.line(trimCRs(p.part))
		p.part = p.part[:0]
		b = b[i+1:]
	}
	span, pos := -1, 0
	for !p.tooLong {
		i := bytes.IndexByte(b[pos:], '\n')
		if i < 0 {
			break
		}
		raw := b[pos : pos+i]
		text := trimCRs(raw)
		ln := p.n + 1
		switch {
		case len(text)+2 > maxCanonLine:
			p.tooLong = true
			continue
		case ln == p.next:
			if span >= 0 {
				p.spanOut(b[span:pos])
				span = -1
			}
			p.advance(ln)
		}
		if len(text) > 0 && len(raw) == len(text)+1 {
			if span < 0 {
				span = pos
			}
		} else {
			if span >= 0 {
				p.spanOut(b[span:pos])
				span = -1
			}
			for _, a := range p.active {
				a.line(text)
			}
		}
		p.n = ln
		pos += i + 1
	}
	if p.tooLong {
		p.part = nil
		return n, nil
	}
	if span >= 0 {
		p.spanOut(b[span:pos])
	}
	p.part = append(p.part, b[pos:]...)
	p.tooLong = len(trimCRs(p.part))+2 > maxCanonLine
	return n, nil
}

// close ends the body: an unterminated last line is a line, the literal
// lines still due are hashed, and every digest is finished.
func (p *chainPlan) close() {
	if p.closed {
		return
	}
	p.closed = true
	if !p.tooLong && len(p.part) > 0 {
		p.line(trimCRs(p.part))
	}
	p.part = nil
	for _, l := range p.lists {
		for ; l.seg < len(l.segs); l.seg++ {
			if s := l.segs[l.seg]; s.lit {
				p.emitLits(l, s)
			}
		}
		l.sums = make(map[string][]byte, len(l.accs))
		for alg, a := range l.accs {
			l.sums[alg] = a.sum()
		}
	}
}

// topHashes is verifyFields's bodyHashes: the received body's digests.
func (p *chainPlan) topHashes(algs []string) (map[string][]byte, error) {
	if p.tooLong {
		return nil, bufio.ErrTooLong
	}
	sums := p.inst[p.top].body.sums
	out := make(map[string][]byte, len(algs))
	for _, alg := range algs {
		out[alg] = sums[alg]
	}
	return out, nil
}

// recipeFails reports whether undoing instance v's Recipe fails: at plan
// time, or a copy past the end of the received body.
func (p *chainPlan) recipeFails(v int) bool {
	in := p.inst[v]
	return in.recipeBad || in.topEnd > p.n
}

func (p *chainPlan) canon(i int) string {
	v := &p.vals[i]
	if !v.done {
		v.canon, v.done = canonicalizeHeader(v.h), true
	}
	return v.canon
}

// headerHash is hashHeaders over instance in's fields.
func (p *chainPlan) headerHash(in *planInstance, alg string) []byte {
	key := hdrSumKey{in.hdrID, alg}
	if s, ok := p.hdrSums[key]; ok {
		return s
	}
	var names []string
	for k, v := range in.hdr {
		if len(v) > 0 && !shouldExcludeHeader(k) {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	newHash, _ := HashAlg(alg)
	h := newHash()
	for _, k := range names {
		for _, i := range in.hdr[k] {
			io.WriteString(h, p.canon(i))
			h.Write(crlf)
		}
	}
	s := h.Sum(nil)
	p.hdrSums[key] = s
	return s
}

// check is the undo walk's hash check of instance t, word for word.
func (p *chainPlan) check(t int) error {
	in := p.inst[t]
	hh := func(alg string) ([]byte, error) { return p.headerHash(in, alg), nil }
	if in.bodyGone {
		if err := checkMIHeaderHashes(in.mi, hh); err != nil {
			return fmt.Errorf("hash mismatch after reconstruction (target v=%d, body not checked below a null body Recipe): %w", t, err)
		}
		return nil
	}
	if in.body.tooLong {
		return fmt.Errorf("hash mismatch after reconstruction (target v=%d): %w", t, bufio.ErrTooLong)
	}
	if err := checkMIHashes(in.mi, hh, in.body.sums); err != nil {
		return fmt.Errorf("hash mismatch after reconstruction (target v=%d): %w", t, err)
	}
	return nil
}

// walk checks the instances below the top in the undo walk's order --
// undo instance t+1's Recipe, then check instance t -- stopping at the
// first failure, and reports it as VerifyFull's undo walk does.
func (p *chainPlan) walk(results []VerifyResult) ([]VerifyResult, error) {
	for t := p.top - 1; t >= 1; t-- {
		if p.recipeFails(t + 1) {
			return results, &malformedRecipeError{m: t + 1}
		}
		if err := p.check(t); err != nil {
			return append(results, VerifyResult{
				Domain: fmt.Sprintf("MI-chain v=%d", t),
				Error:  fmt.Errorf("MI chain validation failed: %w", err),
			}), nil
		}
	}
	return results, nil
}
