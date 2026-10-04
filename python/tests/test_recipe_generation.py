"""Recipe generation (dkim2sign.build_recipes and friends).

Producer rules, spec-06 §5 plus the extension proposed to the WG:

  * a literal whose octets include a byte >= 0x80 is emitted as a "b" item
    (base64 of the raw octets), never as "d" -- and never via Python's
    surrogateescape, which would put \\udcXX escapes in the JSON;
  * pure-ASCII literals stay "d"; consecutive literals of one kind coalesce;
  * a "c" range never goes backwards: a header instance that is still
    present but now in a different position is written out literally.
"""

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from twohop import two_hop, verify  # noqa: E402
from dkim2sign import (  # noqa: E402
    b64json, build_body_recipe, build_header_recipe, build_recipes,
    compute_body_hash, compute_header_hash, parse_message, recipe_literal_steps,
)
from dkim2undo import compile_steps, reconstruct_body, reconstruct_headers  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def b64_of(octets: bytes) -> str:
    return base64.b64encode(octets).decode()


def test_8bit_literals_become_b_items_and_ascii_stays_d():
    steps = recipe_literal_steps([b"a", b"b", b"caf\xe9", b"\xb1\xa4", b"z"])
    assert steps == [{"d": ["a", "b"]}, {"b": ["Y2Fm6Q==", "saQ="]}, {"d": ["z"]}]


def test_literal_with_cr_or_lf_is_refused():
    for bad in (b"a\r\nb", b"a\nb", b"a\r"):
        try:
            recipe_literal_steps([bad])
        except ValueError:
            continue
        raise AssertionError(f"{bad!r} was accepted as a Recipe literal")


def test_emitted_json_carries_no_surrogate_escapes():
    recipe = build_recipes([b"Subject: caf\xe9"], b"\xb1\xa4\r\n",
                           [b"Subject: cafe"], b"replaced\r\n")
    text = json.dumps(recipe)
    assert "\\udc" not in text, text
    assert recipe == {"h": {"subject": [{"b": ["IGNhZuk="]}]},
                      "b": [{"b": ["saQ="]}]}
    # And the signer's own encoding of it is plain ASCII base64 of plain JSON.
    assert b"\\udc" not in base64.b64decode(b64json(recipe))


def _hash_after_undo(prev_headers, prev_body, cur_headers, cur_body):
    recipe = build_recipes(prev_headers, prev_body, cur_headers, cur_body)
    headers = reconstruct_headers(cur_headers, recipe["h"]) if "h" in recipe else cur_headers
    body = reconstruct_body(cur_body, recipe["b"]) if "b" in recipe else cur_body
    return recipe, compute_header_hash(headers), compute_body_hash(body)


def test_reordered_duplicate_headers_never_yield_a_descending_range():
    prev = [b"Received: a", b"X-Loop: 1",
            b"List-Id: one", b"List-Id: two", b"List-Id: three", b"Subject: s"]
    cur = [b"Received: b", b"X-Loop: 2",
           b"List-Id: three", b"List-Id: two", b"List-Id: one", b"Subject: s"]
    recipe, hh, bh = _hash_after_undo(prev, b"x\r\n", cur, b"x\r\n")
    steps = recipe["h"]["list-id"]
    # Every "c" ascends past the one before it (compile_steps raises if not).
    compile_steps(steps, 3)
    starts = [s["c"][0] for s in steps if "c" in s]
    ends = [s["c"][1] for s in steps if "c" in s]
    assert all(starts[i] > ends[i - 1] for i in range(1, len(starts))), steps
    # At least one instance had to be written out literally, and it still
    # undoes to the previous header hash.
    assert any("d" in s for s in steps), steps
    assert hh == compute_header_hash(prev)
    assert bh == compute_body_hash(b"x\r\n")
    # Hash-excluded fields (Received, X-*) are never described.
    assert set(recipe["h"]) == {"list-id"}


def test_body_recipe_copies_runs_and_writes_the_rest():
    prev = b"l1\r\ncaf\xe9\r\nl3\r\nl4\r\n"
    cur = b"l1\r\nX\r\nl3\r\nl4\r\nfooter\r\n"
    steps = build_body_recipe(prev, cur)
    assert steps == [{"c": [1, 1]}, {"b": ["Y2Fm6Q=="]}, {"c": [3, 4]}]
    assert compute_body_hash(reconstruct_body(cur, steps)) == compute_body_hash(prev)


def test_header_recipe_for_a_removed_field_is_all_literals():
    assert build_header_recipe([b"Subject: a", b"Subject: \xe9"], []) == \
        [{"b": ["IOk="]}, {"d": [" a"]}]


def test_added_field_gets_an_empty_recipe_and_unchanged_fields_none():
    recipe = build_recipes([b"Subject: s", b"To: t"], b"x\r\n",
                           [b"List-Id: l", b"Subject: s", b"To: t"], b"x\r\n")
    assert recipe == {"h": {"list-id": []}}


def test_nothing_relevant_changed_means_no_recipe():
    assert build_recipes([b"Subject: s"], b"x\r\n",
                         [b"Received: r", b"Subject: s"], b"x\r\n\r\n") is None


def test_generated_recipe_verifies_end_to_end():
    original = (
        b"From: sender@test1.dkim2.com\r\n"
        b"To: list@test2.dkim2.com\r\n"
        b"Subject: \xb1\xa4 original\r\n"
        b"Keywords: b\r\n"
        b"Keywords: a\r\n"
        b"Date: Fri, 24 Jul 2026 12:00:00 +0000\r\n"
        b"Message-ID: <gen@test1.dkim2.com>\r\n"
        b"\r\n"
        b"caf\xe9\r\n"
        b"plain\r\n"
        b"\xb1\xa4\r\n"
    )
    captured = {}

    def modify(headers, body):
        new = []
        for h in headers:
            if h.lower().startswith(b"subject:"):
                new.append(b"Subject: [list] " + h.split(b":", 1)[1].strip())
            elif h.lower().startswith(b"keywords:"):
                continue
            else:
                new.append(h)
        new = [b"Keywords: a", b"Keywords: b", b"List-Id: <list.test2.dkim2.com>"] + new
        new_body = b"cafe\r\nplain\r\n-- \r\nfooter\r\n"
        captured["recipe"] = build_recipes(headers, body, new, new_body)
        return new, new_body

    # two_hop takes the Recipe up front, so run modify once to build it.
    headers, body = parse_message(original)
    modify(headers, body)
    recipe = captured["recipe"]
    assert "\\udc" not in json.dumps(recipe)
    assert recipe["h"]["subject"] == [{"b": [b64_of(b" \xb1\xa4 original")]}]
    assert recipe["b"][-1] == {"b": [b64_of(b"\xb1\xa4")]}
    result = verify(two_hop(original, modify, recipe=recipe))
    assert result.ok, result.errors


def test_generator_reproduces_the_hand_written_multihop_recipes():
    # generate_multihop.py's fixtures were written by hand before there was
    # a generator; the generator must agree with them where they describe
    # signed header fields (the dup-headers fixtures describe
    # Authentication-Results, which §4 excludes and §5.1 says SHOULD NOT be
    # described, so the generator leaves those out by design).
    raw = open(os.path.join(HERE, "emails", "simple.eml"), "rb").read()
    headers, body = parse_message(raw)

    added = [b"Received: from test1.dkim2.com by relay.example.com",
             b"List-Unsubscribe: <mailto:unsub@relay.example.com>"] + headers
    assert build_recipes(headers, body, added, body) == {"h": {"list-unsubscribe": []}}

    footer = body.rstrip(b"\r\n") + b"\r\n\r\n-- \r\nSent via relay.example.com\r\n"
    assert build_recipes(headers, body, headers, footer) == {"b": [{"c": [1, 1]}]}

    replaced = [b"Subject: [MODIFIED] Simple test message"
                if h.lower().startswith(b"subject:") else h for h in headers]
    assert build_recipes(headers, body, replaced, body) == \
        {"h": {"subject": [{"d": [" Simple test message"]}]}}


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
