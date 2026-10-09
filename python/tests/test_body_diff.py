"""Capped Myers body diff (dkim2sign.body_diff / build_body_recipe).

Normative algorithm: docs/superpowers/specs/2026-10-09-capped-myers-body-
diff-design.md.  Every implementation must reproduce vectors/body-diff.json
exactly; over the 1000-literal cap or the work budget the generator emits
the null body Recipe ("b": null).
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dkim2sign import (  # noqa: E402
    BODY_DIFF_IDENTICAL, BODY_DIFF_TOO_BIG, MAX_RECIPE_LITERALS, b64json,
    body_diff, build_body_recipe, build_recipes, compute_body_hash,
)
from dkim2undo import Unrecoverable, decode_recipes, reconstruct_body  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "..", "..", "vectors", "body-diff.json")

with open(VECTORS) as f:
    CASES = json.load(f)["cases"]


def _enc(lines):
    return [s.encode("utf-8") for s in lines]


def _flat_to_json(flat):
    return [item if isinstance(item, list) else item.decode("utf-8") for item in flat]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_shared_vector(case):
    got = body_diff(_enc(case["cur"]), _enc(case["prev"]),
                    case.get("max_literals", MAX_RECIPE_LITERALS))
    expect = case["expect"]
    if expect == "identical":
        assert got is BODY_DIFF_IDENTICAL
    elif expect == "too_big":
        assert got is BODY_DIFF_TOO_BIG
    else:
        assert isinstance(got, list), got
        assert _flat_to_json(got) == expect


@pytest.mark.parametrize("case", [c for c in CASES if isinstance(c["expect"], list)],
                         ids=lambda c: c["name"])
def test_shared_vector_round_trips_through_undo(case):
    cur = b"".join(l + b"\r\n" for l in _enc(case["cur"]))
    prev = b"".join(l + b"\r\n" for l in _enc(case["prev"]))
    steps = build_body_recipe(prev, cur)
    assert compute_body_hash(reconstruct_body(cur, steps)) == compute_body_hash(prev)


def test_alternating_4000_is_small():
    cur = [b"a", b"b"] * 2000
    prev = [b"b", b"a"] * 2000
    got = body_diff(cur, prev)
    assert isinstance(got, list)
    assert sum(1 for s in got if not isinstance(s, list)) <= 1


def test_reversed_halves_are_too_big():
    # 30000 x then 30000 y vs the reverse: needs 30000 literals, so the
    # literal bound (Dmax = 2000) stops the search after ~2M work units.
    cur = [b"x"] * 30000 + [b"y"] * 30000
    prev = [b"y"] * 30000 + [b"x"] * 30000
    got = body_diff(cur, prev)
    assert got is BODY_DIFF_TOO_BIG


def test_work_budget_gives_too_big():
    # n' >> m' makes Dmax loose (~100000), so only MAX_DIFF_WORK stops it:
    # the cheapest script skips ~98000 cur lines.
    cur = [b"a", b"b"] * 50000
    prev = [b"b"] * 1000 + [b"a"] * 1000
    got = body_diff(cur, prev)
    assert got is BODY_DIFF_TOO_BIG
    # It is the budget, not the literal cap, that refused it: the same shape
    # at a size the budget allows needs no literals at all.
    small = body_diff([b"a", b"b"] * 500, [b"b"] * 10 + [b"a"] * 10)
    assert isinstance(small, list)
    assert all(isinstance(s, list) for s in small)


def test_literal_cap_boundary():
    cur = [b"keep"]
    ok = body_diff(cur, cur + [b"p%d" % i for i in range(1000)])
    assert isinstance(ok, list)
    assert sum(1 for s in ok if not isinstance(s, list)) == 1000
    assert body_diff(cur, cur + [b"p%d" % i for i in range(1001)]) is BODY_DIFF_TOO_BIG


def _body(lines):
    return b"".join(l + b"\r\n" for l in lines)


def test_over_cap_build_recipes_emits_null_body_recipe():
    hdrs = [b"Subject: s\r\n"]
    prev = _body([b"old %d" % i for i in range(1001)])
    cur = _body([b"new"])
    assert build_body_recipe(prev, cur) is None
    recipes = build_recipes(hdrs, prev, hdrs, cur)
    assert "b" in recipes and recipes["b"] is None
    assert '"b":null' in json.dumps(recipes, separators=(",", ":"))
    # The undo side reads it back as the null body Recipe.
    decoded = decode_recipes(f"v=2; r={b64json(recipes)}")
    assert "b" in decoded and decoded["b"] is None


def test_generated_null_body_recipe_is_unrecoverable_on_undo():
    from dkim2undo import undo_message_instance
    hdrs = [b"Subject: s\r\n"]
    prev = _body([b"old %d" % i for i in range(1001)])
    cur = _body([b"new"])
    r = b64json(build_recipes(hdrs, prev, hdrs, cur))
    msg = (b"Message-Instance: m=2; h=sha256:AAA:BBB; r=" + r.encode() + b"\r\n"
           b"Message-Instance: m=1; h=sha256:CCC:DDD;\r\n"
           b"Subject: s\r\n\r\n" + cur)
    with pytest.raises(Unrecoverable):
        undo_message_instance(msg)


def test_body_recipe_for_same_lines_different_octets_copies_everything():
    # Line endings differ, so the body hashes differ but the lines do not.
    prev, cur = b"a\nb\n", b"a\r\nb\r\n"
    steps = build_body_recipe(prev, cur)
    assert steps == [{"c": [1, 2]}]
    assert compute_body_hash(reconstruct_body(cur, steps)) == compute_body_hash(prev)


def test_configurable_cap_through_build_recipes():
    hdrs = [b"Subject: s\r\n"]
    prev = _body([b"keep", b"o1", b"o2", b"o3"])
    cur = _body([b"keep"])
    assert build_recipes(hdrs, prev, hdrs, cur, max_literals=2) == {"b": None}
    assert build_recipes(hdrs, prev, hdrs, cur, max_literals=3) == {
        "b": [{"c": [1, 1]}, {"d": ["o1", "o2", "o3"]}]}
    assert build_body_recipe(prev, cur, max_literals=2) is None
