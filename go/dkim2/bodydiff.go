package dkim2

// Capped Myers body diff (docs/superpowers/specs/2026-10-09-capped-myers-
// body-diff-design.md, "Exact pseudocode (normative for every port)"). Every
// implementation runs the same algorithm with the same tie-breaks, so they all
// emit identical body recipes; vectors/body-diff.json pins the output.

const (
	// MaxRecipeLiterals is the most literal lines a body recipe may carry.
	MaxRecipeLiterals = 1000
	// MaxDiffWork bounds the Myers search: one unit per diagonal visited and
	// one per snake comparison.
	MaxDiffWork = 4_000_000
)

type bodyDiffKind int

const (
	bodyDiffOK bodyDiffKind = iota
	bodyDiffIdentical
	bodyDiffTooBig
)

// bodyDiffStep is one item of the flat recipe: a copy of current lines
// From..To (1-based, inclusive), or (Lit) one literal previous-body line.
type bodyDiffStep struct {
	From, To int
	Lit      bool
	Line     string
}

// bodyDiff computes the flat recipe that rebuilds prev from cur, carrying at
// most maxLiterals literal lines. It reports bodyDiffIdentical when the two
// are equal and bodyDiffTooBig when the cap or MaxDiffWork is exceeded.
func bodyDiff(cur, prev []string, maxLiterals int) ([]bodyDiffStep, bodyDiffKind) {
	C, P := len(cur), len(prev)
	pre := 0
	for pre < C && pre < P && cur[pre] == prev[pre] {
		pre++
	}
	if pre == C && pre == P {
		return nil, bodyDiffIdentical
	}
	suf := 0
	for suf < C-pre && suf < P-pre && cur[C-1-suf] == prev[P-1-suf] {
		suf++
	}
	a := cur[pre : C-suf]
	b := prev[pre : P-suf]

	// Intern lines; equal lines get equal ids.
	ids := make(map[string]int32, len(a)+len(b))
	intern := func(s string) int32 {
		if id, ok := ids[s]; ok {
			return id
		}
		id := int32(len(ids))
		ids[s] = id
		return id
	}
	aid := make([]int32, len(a))
	for i, s := range a {
		aid[i] = intern(s)
	}
	bid := make([]int32, len(b))
	for i, s := range b {
		bid[i] = intern(s)
	}
	cntA := make([]int, len(ids))
	cntB := make([]int, len(ids))
	for _, id := range aid {
		cntA[id]++
	}
	for _, id := range bid {
		cntB[id]++
	}

	var A, B []int32
	var ai, bj []int
	for i, id := range aid {
		if cntB[id] > 0 {
			A = append(A, id)
			ai = append(ai, i)
		}
	}
	for j, id := range bid {
		if cntA[id] > 0 {
			B = append(B, id)
			bj = append(bj, j)
		}
	}
	N, M := len(A), len(B)
	u := len(b) - M

	floor := u
	for id := range cntA {
		if cntA[id] > 0 && cntB[id] > cntA[id] {
			floor += cntB[id] - cntA[id]
		}
	}
	if floor > maxLiterals {
		return nil, bodyDiffTooBig
	}

	match := make([]int, M)
	for y := range match {
		match[y] = -1
	}
	if N > 0 && M > 0 {
		dmax := N - M + 2*(maxLiterals-u)
		if dmax > N+M {
			dmax = N + M
		}
		if dmax < 0 {
			return nil, bodyDiffTooBig
		}
		off := dmax + 1
		V := make([]int, 2*dmax+3)
		// trace[d] holds V[k] for k in [-d-1, d+1] as it stood before
		// round d, at index k+d+1.
		var trace [][]int32
		work := 0
		D := -1
	search:
		for d := 0; d <= dmax; d++ {
			snap := make([]int32, 2*d+3)
			for k := -d - 1; k <= d+1; k++ {
				snap[k+d+1] = int32(V[k+off])
			}
			trace = append(trace, snap)
			for k := -d; k <= d; k += 2 {
				var x int
				if k == -d || (k != d && V[k-1+off] < V[k+1+off]) {
					x = V[k+1+off] // down
				} else {
					x = V[k-1+off] + 1 // right
				}
				y := x - k
				for x < N && y < M && A[x] == B[y] {
					x++
					y++
					work++
				}
				V[k+off] = x
				work++
				if work > MaxDiffWork {
					return nil, bodyDiffTooBig
				}
				if x == N && y == M {
					D = d
					break search
				}
			}
		}
		if D < 0 {
			return nil, bodyDiffTooBig
		}
		x, y := N, M
		for d := D; d >= 1; d-- {
			T := trace[d]
			t := func(k int) int { return int(T[k+d+1]) }
			k := x - y
			down := k == -d || (k != d && t(k-1) < t(k+1))
			var pk int
			if down {
				pk = k + 1
			} else {
				pk = k - 1
			}
			px := t(pk)
			py := px - pk
			sx := px + 1
			if down {
				sx = px
			}
			for x > sx {
				x--
				y--
				match[y] = x
			}
			x, y = px, py
		}
		for x > 0 {
			x--
			y--
			match[y] = x
		}
	}

	// srcMid[j] = index into a for middle previous line j, or -1.
	srcMid := make([]int, len(b))
	for j := range srcMid {
		srcMid[j] = -1
	}
	for y, x := range match {
		if x >= 0 {
			srcMid[bj[y]] = ai[x]
		}
	}

	var recipe []bodyDiffStep
	literals := 0
	for j := 0; j < P; j++ {
		var i int
		switch {
		case j < pre:
			i = j
		case j >= P-suf:
			i = j - P + C
		default:
			i = srcMid[j-pre]
			if i >= 0 {
				i += pre
			}
		}
		if i < 0 {
			recipe = append(recipe, bodyDiffStep{Lit: true, Line: prev[j]})
			literals++
			continue
		}
		if n := len(recipe); n > 0 && !recipe[n-1].Lit && recipe[n-1].To == i {
			recipe[n-1].To = i + 1
		} else {
			recipe = append(recipe, bodyDiffStep{From: i + 1, To: i + 1})
		}
	}
	if literals > maxLiterals {
		return nil, bodyDiffTooBig
	}
	return recipe, bodyDiffOK
}
