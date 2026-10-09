# Capped Myers body diff — design

Date: 2026-10-09. Prompted by the external Perl review (docs/reviews/2026-10-08-perl-spec-06.md, R2).

## Problem

Body recipes reconstruct the previous body from the current one: copy ranges
(1-based, inclusive, ascending, into the current body) plus literal lines (from
the previous body). Every generator today has unbounded worst-case cost:

| Impl | Generator | Algorithm | Worst case |
|---|---|---|---|
| Perl (production) | `MessageInstance::_best_body_diff` | Algorithm::Diff LCS, twice | quadratic in matching pairs (`a,b,a,b` vs `b,a,b,a`: 4000 lines = 3.7 s) |
| Mailman (production fallback) | `compute_body_recipe` | difflib `autojunk=False` | quadratic or worse |
| Python (tests/fixtures) | `build_body_recipe` | difflib | quadratic or worse |
| C (tests) | `dkim2_gen_body_recipe` | greedy longest-run scan | O(N·M·L) |
| Go (tests) | `diffLines` | greedy hash match | linear, poor quality (one `c` per line) |

## Rule

- A body recipe may carry at most **1000 literal lines** (`MAX_RECIPE_LITERALS`)
  by default; every implementation lets the caller configure the cap.
  This counts lines the recipe outputs as literals, not input lines.
- Over the cap (or over the work budget below) the diff reports TOO_BIG and the
  caller falls back:
  - a caller that can rewrite the body (Perl `UseEpilogue`/`EpilogueThreshold`)
    stores the old body in the MIME epilogue;
  - every other caller (header-only signers, Perl's default `calculate`,
    Mailman's egress, the C/Python/Go generators) emits the **null body
    recipe** (`"b": null`, body unrecoverable).

## Algorithm (identical in every language, so all produce identical recipes)

Input: `cur[0..C)`, `prev[0..P)` (lines, already split by the implementation's
existing splitter), `max_literals` (default 1000).

1. If `cur == prev`: IDENTICAL (no recipe).
2. Trim: `pre` = common prefix length; `suf` = common suffix length of what is
   left (never overlapping `pre`). Middle: `a = cur[pre..C-suf)` (n lines),
   `b = prev[pre..P-suf)` (m lines).
3. If `m == 0`: no literals — recipe is the trimmed copies only.
   If `n == 0`: all `m` middle lines are literals.
4. Intern lines to integer ids. Discard lines that cannot be in the LCS:
   `a` lines whose id never occurs in `b` (pure deletions), `b` lines whose id
   never occurs in `a` (certain literals). Keep index maps back to `a`/`b`.
   `u` = number of discarded `b` lines. Every discarded `b` line is a
   literal, and so is each extra copy of a line `b` holds more often than
   `a`: if `u + sum(max(0, cnt_b - cnt_a))` over lines `a` also holds exceeds
   `max_literals`, TOO_BIG (the `floor` check in the pseudocode).
5. Myers greedy forward search (O(ND), Myers 1986) over the reduced
   sequences `a'` (n'), `b'` (m'), storing V for each d for backtracking.
   - literals = m − LCS, and D = n' + m' − 2·LCS', so the literal cap gives an
     exact edit bound: `Dmax = n' − m' + 2·(max_literals − u)`. If `Dmax < 0`
     (more `b'` lines than budget allows even with every `a'` matched), TOO_BIG.
     Stop with TOO_BIG when `d > Dmax`.
   - Work budget: count one unit per diagonal visited and one per snake
     comparison; TOO_BIG when the count exceeds `MAX_DIFF_WORK = 4_000_000`.
     This bounds CPU and trace memory when n' ≫ m' makes Dmax loose.
   - Tie-break (fixed, so outputs match across languages): at diagonal k on
     round d, move down (take `b'[y]`, a literal) when `k == -d` or
     (`k != d` and `V[k-1] < V[k+1]`); otherwise move right (skip `a'[x]`).
6. Backtrack to the edit script, map reduced indices back to `a`/`b`, then to
   whole-body indices. Emit, in previous-body order: copy ranges for matched
   runs (merged when adjacent in both bodies) and literal lines for unmatched
   previous lines, prefixed/suffixed by the trimmed copies. Adjacent copy
   ranges are merged; literal runs follow each implementation's existing
   `d`/`b` grouping.

The recipe it produces has minimal literal lines (Myers yields an LCS).

### Exact pseudocode (normative for every port)

Lines compare as exact byte strings. Indices are 0-based except in the output.

```
body_diff(cur[C], prev[P], L):            # L = max literal lines
  pre = 0; while pre < C and pre < P and cur[pre] == prev[pre]: pre++
  if pre == C and pre == P: return IDENTICAL
  suf = 0; while suf < C-pre and suf < P-pre and cur[C-1-suf] == prev[P-1-suf]: suf++
  a = cur[pre .. C-suf)        b = prev[pre .. P-suf)
  cnt_a[line], cnt_b[line] = occurrence counts in a, b
  A, ai = ids/indices of the a lines with cnt_b[line] > 0, in order
  B, bj = ids/indices of the b lines with cnt_a[line] > 0, in order
          (id = any interning where equal lines get equal ids)
  N = |A|; M = |B|; u = |b| - M
  floor = u + sum over distinct lines with cnt_a > 0 of max(0, cnt_b - cnt_a)
  if floor > L: return TOO_BIG
  match[0..M) = none
  if N > 0 and M > 0:
    dmax = N - M + 2*(L - u); if dmax > N + M: dmax = N + M
    if dmax < 0: return TOO_BIG
    V[k] for k in [-dmax-1, dmax+1], all 0
    trace = []; work = 0
    for d in 0 .. dmax:
      trace[d] = copy of V            # (only k in [-d-1, d+1] is ever read)
      for k in -d, -d+2, .., d:
        if k == -d or (k != d and V[k-1] < V[k+1]): x = V[k+1]      # down
        else:                                       x = V[k-1] + 1  # right
        y = x - k
        while x < N and y < M and A[x] == B[y]: x++; y++; work++
        V[k] = x
        work++; if work > MAX_DIFF_WORK (4000000): return TOO_BIG
        if x == N and y == M: goto FOUND(d)
    return TOO_BIG
  FOUND(D):  (x, y) = (N, M)
    for d in D down to 1:
      T = trace[d]; k = x - y
      down = (k == -d or (k != d and T[k-1] < T[k+1]))
      pk = down ? k+1 : k-1;  px = T[pk];  py = px - pk
      (sx, sy) = down ? (px, py+1) : (px+1, py)
      while x > sx: x--; y--; match[y] = x
      (x, y) = (px, py)
    while x > 0: x--; y--; match[y] = x
  src[j] for previous-body line j (0-based, whole body):
    j < pre        -> j
    j >= P - suf   -> j - P + C
    otherwise      -> pre + ai[match[y]] if j == pre + bj[y] has a match, else none
  recipe = []; literals = 0
  for j in 0 .. P-1:
    i = src[j]
    if i is none: append literal prev[j]; literals++
    elif last step is a copy [f,t] and t == i: extend it to [f, i+1]
    else: append copy [i+1, i+1]
  if literals > L: return TOO_BIG          # cannot happen; belt and braces
  return recipe
```

Points of difference from textbook Myers, all deliberate:
- Points off the grid (x > N or y > M) are kept in V, not clamped; the snake
  guard and the exact `x == N and y == M` test make that safe, and it keeps
  the tie-breaking identical everywhere.
- `work` counts one per snake step and one per diagonal visited, and is
  checked after each diagonal.
- Literal runs are then grouped into the implementation's `d`/`b` literal
  steps exactly as before; the vectors compare the flat list above.

## Per-implementation changes

- **Perl** `MessageInstance.pm`: replace `_body_recipe_linediff`,
  `_body_recipe_flat`, `_recipe_for_region`, `_recipe_cost` and the
  Algorithm::Diff dependency with `_myers_body_recipe`. `calculate`:
  default → TOO_BIG gives the null recipe, cap `MaxRecipeLiterals` (default
  1000; dkim2-milter `--max-recipe-literals`, DKIM2Sign `max_recipe_literals`);
  `EpilogueThreshold => N` is the cap on the epilogue path, as given, and goes
  to the epilogue on TOO_BIG; `UseEpilogue` unchanged. A header-only signer
  signs over its own null only with `allow_null_body_recipe`. Drop Algorithm::Diff from Makefile.PL/README/CLAUDE.md/POD.
- **Mailman** `message_instance.py`: replace the difflib fallback in
  `compute_body_recipe`; TOO_BIG → `NULL_BODY_RECIPE`. Develop on `dkim2`,
  backport to `dkim2-3.3.10` and `dkim2-3.3.8`, re-export patches.
- **Python** `dkim2sign.py`, **C** `dkim2_recipe.c`, **Go** `recipe.go`:
  replace the generator; TOO_BIG → null body recipe (`"b": null`; C sets
  `*impossible`; Go sets `Recipe.BodyNull`).
- Line splitting stays as each implementation has it today.

## Shared vectors

`vectors/body-diff.json`: cases `{name, cur:[lines], prev:[lines],
max_literals?, expect: "identical" | "too_big" | [steps]}` where a step is
`[from,to]` or a literal string. Generated by the Perl reference
(`util/build-body-diff-vectors.pl`) and checked by every implementation's test
suite, including: identical, prefix-only change, N removed + M added at the
front, the `a,b,a,b`/`b,a,b,a` case (must be fast and small), exactly 1000
literals (ok), 1001 literals (too_big), the line-count floor, and a pair
either side of where the work budget runs out (a one-literal Recipe exists
for both, so only the work count separates them). Large timing cases live
in each implementation's own tests.

## Performance target

The review's `a,b` probe at 4000 lines and a 100k-line body with edits at
both ends each finish in well under 100 ms in Perl.
