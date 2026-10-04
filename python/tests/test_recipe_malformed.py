"""A Recipe that is valid JSON but cannot be applied is a PERMERROR.

spec-06 §5.1/§5.2 already require each "c" start to exceed every preceding
"c" end, and the schema requires two integers >= 1; the verifier used to
apply whatever it was given (an out-of-range "c" silently copied nothing).
The extension proposed to the WG makes every such fault, plus a "b" item
that is not base64 or decodes to CR/LF, a malformed Recipe:

    PERMERROR Message-Instance m=<x> has a malformed Recipe

distinct from "syntax error" (bad base64 r=) and "contains invalid JSON".
Each case here goes through dkim2verify.verify_message on a complete,
validly-signed two-hop message, so the only thing wrong with it is the
Recipe -- and the result must be a not-ok result, never an exception.
"""

import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from twohop import two_hop, verify  # noqa: E402
from dkim2undo import undo_message_instance  # noqa: E402

ORIGINAL = (
    b"From: sender@test1.dkim2.com\r\n"
    b"To: list@test2.dkim2.com\r\n"
    b"Subject: one\r\n"
    b"Date: Fri, 24 Jul 2026 12:00:00 +0000\r\n"
    b"Message-ID: <malformed@test1.dkim2.com>\r\n"
    b"\r\n"
    b"line 1\r\n"
    b"line 2\r\n"
    b"line 3\r\n"
)

WANT = "PERMERROR Message-Instance m=2 has a malformed Recipe"


def _footer(headers, body):
    """Three original lines kept, a two-line footer added (five lines now):
    {"b": [{"c": [1, 3]}]} is the one correct body Recipe, and the header
    fields are untouched."""
    return headers, body + b"-- \r\nfooter\r\n"


def _dup_subjects(headers, body):
    """Two Subject fields added above the original, so the current message
    has three instances and {"c": [1, 1]} is the correct header Recipe."""
    return [b"Subject: three", b"Subject: two"] + headers, body


def test_baseline_valid_recipe_verifies():
    # Proves the harness: the same message with the correct Recipe passes,
    # so the rejections below are down to the Recipe alone.
    assert verify(two_hop(ORIGINAL, _footer, recipe={"b": [{"c": [1, 3]}]})).ok
    assert verify(two_hop(ORIGINAL, _dup_subjects,
                          recipe={"h": {"subject": [{"c": [1, 1]}]}})).ok


def _b(octets: bytes) -> str:
    return base64.b64encode(octets).decode()


# (name, modify, recipe dict, detectable from the JSON alone?)
# The last flag is False only for faults that need the message to see:
# simple (non-full-chain) verification cannot know how many lines exist.
CASES = [
    ("descending c ranges", _footer,
     {"b": [{"c": [2, 2]}, {"c": [1, 1]}]}, True),
    ("overlapping c ranges", _footer,
     {"b": [{"c": [1, 2]}, {"c": [2, 3]}]}, True),
    ("adjacent c ranges that touch", _footer,
     {"b": [{"c": [1, 2]}, {"c": [2, 2]}]}, True),
    ("c start 0", _footer,
     {"b": [{"c": [0, 1]}]}, True),
    ("c end before start", _footer,
     {"b": [{"c": [3, 1]}]}, True),
    ("c end beyond the line count", _footer,
     {"b": [{"c": [1, 6]}]}, False),
    ("c start beyond the line count", _footer,
     {"b": [{"c": [6, 6]}]}, False),
    ("c bounds as strings", _footer,
     {"b": [{"c": ["1", "3"]}]}, True),
    ("c bound 1.5", _footer,
     {"b": [{"c": [1, 1.5]}]}, True),
    ("c bound true", _footer,
     {"b": [{"c": [True, 3]}]}, True),
    ("c with three bounds", _footer,
     {"b": [{"c": [1, 2, 3]}]}, True),
    ("c with one bound", _footer,
     {"b": [{"c": [1]}]}, True),
    ("invalid base64 in b", _footer,
     {"b": [{"b": ["!!!!"]}, {"c": [2, 3]}]}, True),
    ("unpadded base64 in b", _footer,
     {"b": [{"b": ["bGluZSAx"[:-1]]}, {"c": [2, 3]}]}, True),
    ("CRLF inside a decoded b item", _footer,
     {"b": [{"b": [_b(b"line 1\r\nline 2")]}, {"c": [3, 3]}]}, True),
    ("LF inside a decoded b item", _footer,
     {"b": [{"b": [_b(b"line 1\nline 2")]}, {"c": [3, 3]}]}, True),
    ("CR inside a decoded b item", _footer,
     {"b": [{"b": [_b(b"line 1\r")]}, {"c": [2, 3]}]}, True),
    ("CRLF inside a d item", _footer,
     {"b": [{"d": ["line 1\r\nline 2"]}, {"c": [3, 3]}]}, True),
    ("b item that is not a string", _footer,
     {"b": [{"b": [1]}, {"c": [2, 3]}]}, True),
    ("empty d array", _footer,
     {"b": [{"d": []}, {"c": [1, 3]}]}, True),
    ("empty b array", _footer,
     {"b": [{"b": []}, {"c": [1, 3]}]}, True),
    ("empty d array in a header recipe", _dup_subjects,
     {"h": {"subject": [{"c": [1, 1]}, {"d": []}]}}, True),
    ("step with two keys", _footer,
     {"b": [{"c": [1, 3], "d": ["x"]}]}, True),
    ("unknown step type", _footer,
     {"b": [{"z": True}, {"c": [1, 3]}]}, True),
    ("bare array step", _footer,
     {"b": [[1, 3]]}, True),
    ("bare string step", _footer,
     {"b": ["line 1", {"c": [2, 3]}]}, True),
    ("header c ranges descending", _dup_subjects,
     {"h": {"subject": [{"c": [2, 2]}, {"c": [1, 1]}]}}, True),
    ("header c end beyond the instance count", _dup_subjects,
     {"h": {"subject": [{"c": [1, 4]}]}}, False),
    ("header steps not an array", _dup_subjects,
     {"h": {"subject": {"c": [1, 1]}}}, True),
    ("h not an object", _dup_subjects,
     {"h": [{"c": [1, 1]}]}, True),
    ("neither h nor b", _footer,
     {"x": []}, True),
]


@pytest.mark.parametrize("name,modify,recipe,structural", CASES,
                         ids=[c[0] for c in CASES])
def test_malformed_recipe_rejected_full_chain(name, modify, recipe, structural):
    msg = two_hop(ORIGINAL, modify, recipe_json=json.dumps(recipe).encode())
    result = verify(msg, full_chain=True)
    assert not result.ok, name
    assert WANT in result.errors, (name, result.errors)
    # Named once, however many code paths noticed it.
    assert result.errors.count(WANT) == 1, (name, result.errors)
    # It is a format fault in a DKIM2 header field (§11.2), not a signature
    # or hash failure.
    assert result.status == "permerror", (name, result.status, result.errors)


@pytest.mark.parametrize("name,modify,recipe,structural",
                         [c for c in CASES if c[3]],
                         ids=[c[0] for c in CASES if c[3]])
def test_malformed_recipe_rejected_without_full_chain(name, modify, recipe, structural):
    # Simple mode never applies the Recipe, but everything decidable from
    # the JSON alone is still checked on the top instance.
    msg = two_hop(ORIGINAL, modify, recipe_json=json.dumps(recipe).encode())
    result = verify(msg, full_chain=False)
    assert not result.ok, name
    assert WANT in result.errors, (name, result.errors)


def test_malformed_recipe_is_not_reported_as_invalid_json():
    msg = two_hop(ORIGINAL, _footer,
                  recipe_json=json.dumps({"b": [{"c": [2, 2]}, {"c": [1, 1]}]}).encode())
    result = verify(msg)
    assert not any("invalid JSON" in e or "syntax error" in e for e in result.errors), \
        result.errors


def test_undo_cli_path_refuses_a_malformed_recipe():
    msg = two_hop(ORIGINAL, _footer, recipe_json=b'{"b": [{"c": [1, 6]}]}')
    with pytest.raises(ValueError) as exc:
        undo_message_instance(msg)
    assert "exceeds" in str(exc.value), exc.value


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
