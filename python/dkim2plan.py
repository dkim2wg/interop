#!/usr/bin/env python3
"""
DKIM2 planned chain walk - draft-ietf-dkim-dkim2-spec-06

The verifier checks every Message-Instance in the chain: the top one against
the message, then each lower one against the message as the Recipes above it
say it was.  The undo walk (dkim2undo) rebuilds each previous message to do
that.  This module works out the same hashes without rebuilding anything:

  * BodyPlan describes every instance's body as a list of segments --
    (BODY, from, to), a run of lines of the current body, or (LIT, from, to),
    a run of entries in one shared table of Recipe literal lines (0-based,
    half-open).  The top instance is [(BODY, 0, END)]; each body Recipe
    composes the list above it into the one below.  BodyPass then makes one
    forward pass over the current body (in chunks cut anywhere), feeding each
    span of lines to the digests of every distinct list that holds it.

  * HeaderPlan splits the header fields once and keeps, per instance and per
    field name, the bottom-up tuple of fields (received or literal) that
    name has.  Unchanged names share their tuple and its canonical text.

plan_chain() makes the decisions the undo walk makes, in the same order, and
records where a Recipe cannot be applied.  A copy range is checked against
the body it applies to: at plan time for a rebuilt body (its length is
known), at the end of the body for the current one.  Where the plan could
not reproduce the undo walk exactly (a header Recipe naming
message-instance, a key the undo walk would not group back under its own
name, an r= that is not a JSON object) plan_chain() returns None and the
caller uses the undo walk.
"""

import hashlib
import sys

from dkim2sign import (
    _header_name,
    _should_exclude_header,
    canonicalize_header_field,
    _extract_tag,
    HASH_ALGS,
)
from dkim2undo import MalformedRecipe, compile_steps, decode_recipes

BODY, LIT = 0, 1
END = sys.maxsize          # "to the end of the current body"
_CRLF = b"\r\n"
_HASHERS = {"sha256": hashlib.sha256, "sha512": hashlib.sha512}
assert set(_HASHERS) == set(HASH_ALGS)


def mi_hash_algs(mi_hdr: str) -> set[str]:
    """Implemented hash algorithms named in a Message-Instance h= tag."""
    colon = mi_hdr.find(":")
    h = _extract_tag(mi_hdr[colon + 1:], "h")
    algs = set()
    for item in (h or "").split(","):
        parts = "".join(item.split()).split(":")
        if len(parts) == 3 and parts[0].lower() in _HASHERS:
            algs.add(parts[0].lower())
    return algs


def recipe_actions(recipes):
    """What undoing a decoded r= object does, decided as the walk decides it.

    Returns (null_h, h, null_b, b): null_h if "h" is present and null (a
    syntax error, nothing applied); h the header Recipes to apply (a
    non-empty object) or None; null_b if "b" is present and null; b the body
    Recipe to apply (a non-empty array) or None.  An empty or falsy "b" is
    an unchanged body, as is a "b" that is not an array (the content check
    has already reported that one as malformed).
    """
    null_h = "h" in recipes and recipes["h"] is None
    h = recipes.get("h")
    if not (h and isinstance(h, dict) and len(h) > 0):
        h = None
    null_b = "b" in recipes and recipes["b"] is None
    b = recipes.get("b")
    if null_b or not (b and isinstance(b, list)):
        b = None
    return null_h, h, null_b, b


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------

def _plain_key(name: str) -> bool:
    """True if a literal field written under this (lowercased) Recipe key is
    grouped back under the same name -- no colon, no surrounding space -- and
    it is not message-instance (undoing which would change the instances the
    lower levels see)."""
    raw = name.encode("utf-8", errors="surrogateescape") + b":"
    return (name != "message-instance"
            and _header_name(raw).decode("utf-8", errors="surrogateescape") == name)


class HeaderPlan:
    """Per-instance header fields as name -> bottom-up tuple of field ids."""

    def __init__(self, content_headers: list[bytes]):
        self.fields = list(content_headers)  # received, then literal fields
        self._canon: dict[int, bytes] = {}
        self._blocks: dict[int, tuple] = {}  # id(tuple) -> (tuple, bytes)
        self._digests: dict[tuple, tuple] = {}
        top: dict[str, list[int]] = {}
        for i, hdr in enumerate(content_headers):
            name = _header_name(hdr).decode("utf-8", errors="surrogateescape")
            top.setdefault(name, []).append(i)
        self.top = {n: tuple(reversed(ids)) for n, ids in top.items()}

    def _apply(self, ids: tuple, name: str, steps) -> tuple:
        out: list[int] = []
        prefix = name.encode("utf-8", errors="surrogateescape") + b":"
        for item in compile_steps(steps, len(ids)):
            if item[0] == "c":
                out.extend(ids[item[1] - 1:item[2]])
            else:
                for val in item[1]:
                    out.append(len(self.fields))
                    self.fields.append(prefix + val)
        return tuple(out)

    def undo(self, state: dict, h_recipes: dict) -> dict:
        """The previous instance's state; MalformedRecipe as the undo walk.

        A name present now takes the first key that lowercases to it (an
        empty or falsy Recipe removes it); a name absent now takes the first
        such key whose Recipe is not empty."""
        new = dict(state)
        done: set[str] = set()
        for key in h_recipes:
            name = key.lower()
            if name in done:
                continue
            steps = h_recipes[key]
            if state.get(name):
                done.add(name)
                new[name] = self._apply(state[name], name, steps) if steps else ()
            elif steps:
                done.add(name)
                new[name] = self._apply((), name, steps)
        return new

    def plain_keys(self, h_recipes: dict) -> bool:
        return all(_plain_key(k.lower()) for k in h_recipes)

    def _block(self, ids: tuple) -> bytes:
        hit = self._blocks.get(id(ids))
        if hit is not None:
            return hit[1]
        parts = []
        for i in ids:
            c = self._canon.get(i)
            if c is None:
                c = self._canon[i] = canonicalize_header_field(self.fields[i]) + _CRLF
            parts.append(c)
        data = b"".join(parts)
        self._blocks[id(ids)] = (ids, data)   # keep ids alive: ids are reused
        return data

    def digest(self, state: dict, alg: str) -> bytes:
        """Header hash of one instance (spec-06 §6.2): names in byte order,
        each name's fields bottom-up; skip-listed names are not hashed."""
        key = (id(state), alg)
        hit = self._digests.get(key)
        if hit is not None:
            return hit[1]
        h = _HASHERS[alg]()
        for bname, name in sorted(
                (n.encode("utf-8", errors="surrogateescape"), n) for n in state):
            if state[name] and not _should_exclude_header(bname):
                h.update(self._block(state[name]))
        d = h.digest()
        self._digests[key] = (state, d)
        return d


# ---------------------------------------------------------------------------
# Body
# ---------------------------------------------------------------------------

def _push(out: list, seg: tuple) -> None:
    """Append a segment, merging it into the previous one if they abut."""
    if out:
        last = out[-1]
        if last[0] == seg[0] and last[2] == seg[1]:
            out[-1] = (seg[0], last[1], seg[2])
            return
    out.append(seg)


class BodyPlan:
    """Segment lists for each instance's body and the literal-line table."""

    def __init__(self):
        self.lits: list[bytes] = []
        self.top = [(BODY, 0, END)]
        self.deferred: dict[int, int] = {}   # version -> last "c" end vs top
        self.wanted: dict[int, tuple] = {}   # id(list) -> (list, algs)
        self.nlines: int | None = None       # current body, once known
        self._digests: dict[int, dict] = {}

    def want(self, segs: list, algs) -> None:
        hit = self.wanted.get(id(segs))
        if hit is None:
            self.wanted[id(segs)] = (segs, set(algs))
        else:
            hit[1].update(algs)

    def compose(self, parent: list, steps, version: int) -> list:
        """The previous instance's list: `steps` (a body Recipe) resolved
        against `parent`.  MalformedRecipe for a bad Recipe, or a copy range
        past the end of a rebuilt body; a range against the current body is
        checked when its length is known (body_error)."""
        compiled = compile_steps(steps, None)
        last_end = max((it[2] for it in compiled if it[0] == "c"), default=0)
        if parent is self.top:
            self.deferred[version] = last_end
        else:
            # A rebuilt body always has a line: every Recipe step emits one.
            if last_end > sum(s[2] - s[1] for s in parent):
                raise MalformedRecipe(
                    f'"c" range ends at {last_end}, past the rebuilt body')
        out: list[tuple] = []
        k = 0       # parent segment holding position `base`
        base = 0    # parent position where segment k starts
        for item in compiled:
            if item[0] == "c":
                pos, end = item[1] - 1, item[2]
                while k < len(parent) and base + parent[k][2] - parent[k][1] <= pos:
                    base += parent[k][2] - parent[k][1]
                    k += 1
                while pos < end:
                    kind, a, b = parent[k]
                    stop = min(end - base, b - a)
                    _push(out, (kind, a + pos - base, a + stop))
                    pos = base + stop
                    if stop == b - a:
                        base += b - a
                        k += 1
            else:
                i = len(self.lits)
                self.lits.extend(item[1])
                _push(out, (LIT, i, len(self.lits)))
        return out

    def body_error(self, version: int) -> bool:
        """True if the body Recipe at `version` copies past the current body."""
        return self.deferred.get(version, 0) > self.nlines

    def digest(self, segs: list, alg: str) -> bytes:
        return self._digests[id(segs)][alg]


class _Acc:
    """One distinct segment list being hashed: §6.1 trailing blank lines are
    held back as a count, emitted only when a non-blank line follows."""
    __slots__ = ("segs", "k", "hashes", "pending", "emitted")

    def __init__(self, segs, algs):
        self.segs = segs
        self.k = 0
        self.hashes = [_HASHERS[a]() for a in sorted(algs)]
        self.pending = 0
        self.emitted = False

    def update(self, data) -> None:
        for h in self.hashes:
            h.update(data)

    def lines(self, data, nlines: int, tail: int) -> None:
        """Complete CRLF lines `data`, the last `tail` of them blank."""
        if tail == nlines:
            self.pending += nlines
            return
        if self.pending:
            self.update(_CRLF * self.pending)
        self.update(data)
        self.pending = tail
        self.emitted = True

    def literals(self, lits) -> None:
        for line in lits:
            if not line:
                self.pending += 1
                continue
            if self.pending:
                self.update(_CRLF * self.pending)
                self.pending = 0
            self.update(line + _CRLF)
            self.emitted = True


def _trailing_crlfs(buf, lo: int, hi: int) -> int:
    """How many CRLF pairs end buf[lo:hi] (galloping, not per line)."""
    k, step = 0, 1
    while step:
        start = hi - 2 * (k + step)
        if start >= lo and buf[start:hi - 2 * k] == _CRLF * step:
            k += step
            step *= 2
        else:
            step //= 2
    return k


class BodyPass:
    """One forward pass over the current body, CRLF-normalised, in chunks.

    Only a partial line is kept between chunks.  Within a chunk, line
    offsets are found only where some list's segment starts or ends, and
    each span between them is hashed as one slice."""

    def __init__(self, plan: BodyPlan):
        self.plan = plan
        self.accs = [_Acc(segs, algs) for segs, algs in plan.wanted.values()]
        self.partial = b""
        self.line0 = 0

    def feed(self, data: bytes) -> None:
        start = 0
        if self.partial:
            nl = data.find(b"\n")
            if nl < 0:
                self.partial += data
                return
            joined = self.partial + data[:nl + 1]
            self.partial = b""
            self._chunk(joined, 0, len(joined))
            start = nl + 1
        last = data.rfind(b"\n", start)
        if last < 0:
            self.partial = data[start:]
            return
        self._chunk(data, start, last + 1)
        self.partial = data[last + 1:]

    def _chunk(self, buf: bytes, lo: int, hi: int) -> None:
        n = buf.count(b"\n", lo, hi)
        first, past = self.line0, self.line0 + n
        offsets = {first: lo, past: hi}
        mv = memoryview(buf)
        shapes: dict[tuple, int] = {}

        def offset(line):
            pos = offsets.get(line)
            if pos is not None:
                return pos
            near = max(l for l in offsets if l < line)
            pos, need = offsets[near], line - near
            if need <= 16:
                for _ in range(need):
                    pos = buf.find(b"\n", pos) + 1
            else:
                # Smallest p with `need` newlines in buf[pos:p]; each probe
                # counts only the half still in question.
                a, b, have = pos, hi, 0
                while a < b:
                    mid = (a + b) // 2
                    c = buf.count(b"\n", a, mid)
                    if have + c >= need:
                        b = mid
                    else:
                        have += c + (buf[mid] == 10)
                        a = mid + 1
                pos = a
            offsets[line] = pos
            return pos

        for acc in self.accs:
            segs = acc.segs
            while acc.k < len(segs):
                kind, a, b = segs[acc.k]
                if kind == LIT:
                    acc.literals(self.plan.lits[a:b])
                    acc.k += 1
                    continue
                if a >= past:
                    break
                s, e = max(a, first), min(b, past)
                o0, o1 = offset(s), offset(e)
                tail = shapes.get((o0, o1))
                if tail is None:
                    tail = shapes[(o0, o1)] = _trailing_crlfs(buf, o0, o1)
                if tail * 2 == o1 - o0:
                    acc.lines(None, e - s, e - s)
                else:
                    acc.lines(mv[o0:o1 - 2 * (tail - 1)], e - s, tail - 1)
                if b <= past:
                    acc.k += 1
                else:
                    break
        self.line0 = past

    def close(self) -> None:
        """End of body: an unterminated last line is a line; finish every
        list (a body segment still open is past the end, and only a list
        below a failing range check holds one) and record the digests."""
        if self.partial:
            line = self.partial + _CRLF
            self.partial = b""
            self._chunk(line, 0, len(line))
        self.plan.nlines = self.line0
        for acc in self.accs:
            for kind, a, b in acc.segs[acc.k:]:
                if kind == LIT:
                    acc.literals(self.plan.lits[a:b])
            if not acc.emitted:
                acc.update(_CRLF)
            self.plan._digests[id(acc.segs)] = {
                h.name: h.digest() for h in acc.hashes}


# ---------------------------------------------------------------------------
# The chain
# ---------------------------------------------------------------------------

class ChainPlan:
    """Every instance's (header state, body list or None), and the versions
    whose Recipes cannot be applied."""

    def __init__(self, content_headers):
        self.headers = HeaderPlan(content_headers)
        self.body = BodyPlan()
        self.state: dict[int, tuple] = {}
        self.bad: set[int] = set()

    def recipe_error(self, version: int) -> bool:
        return version in self.bad or self.body.body_error(version)


def plan_chain(content_headers: list[bytes], mi_by_version: dict,
               versions: list[int], extra_algs=()) -> ChainPlan | None:
    """Plan the walk down `versions` (descending), deciding as the undo walk
    does; None if this message needs the undo walk itself."""
    plan = ChainPlan(content_headers)
    hstate, segs = plan.headers.top, plan.body.top
    for version in versions:
        mi_hdr = mi_by_version[version]
        plan.state[version] = (hstate, segs)
        if segs is not None:
            plan.body.want(segs, mi_hash_algs(mi_hdr) | set(extra_algs))
        if version == versions[-1]:
            break
        try:
            recipes = decode_recipes(mi_hdr)
        except (ValueError, TypeError):
            recipes = None
        if recipes is None:
            continue
        if not isinstance(recipes, dict):
            return None
        _, h, null_b, b = recipe_actions(recipes)
        if h is not None:
            if not plan.headers.plain_keys(h):
                return None
            try:
                hstate = plan.headers.undo(hstate, h)
            except MalformedRecipe:
                plan.bad.add(version)
                break
        if null_b:
            segs = None
        elif b is not None and segs is not None:
            try:
                segs = plan.body.compose(segs, b, version)
            except MalformedRecipe:
                plan.bad.add(version)
                break
    return plan
