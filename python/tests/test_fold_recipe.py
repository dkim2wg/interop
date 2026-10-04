"""Folding whitespace inside an r= Recipe value (spec-06 §2.12).

A list manager's Message-Instance m=2 carries a base64 r= value several
hundred characters long, which it folds with CRLF+HTAB to stay within RFC 5322
line length.  FWS inside a tag value "MUST be ignored when the value is used".

Regression: the verifier passed the r= value to a strict base64 decoder with
the fold whitespace still inside it, so every list-produced m=2 was rejected
as a "syntax error" (found 2026-10-04 replaying real Mailman and Sympa output,
util/charset-corpus.sh; the hand-written fixtures' recipes were short enough
never to fold).
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2verify import verify_message  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DNS = os.path.join(ROOT, "dns.json")
FIXTURE = os.path.join(HERE, "expected", "multihop-body-footer.eml")


def _fold_recipe(signed: bytes, every: int, ws: bytes) -> bytes:
    """Insert a CRLF+ws fold every `every` characters inside each r= value."""
    def fold_r(m):
        val = m.group(2)
        chunks = [val[i:i + every] for i in range(0, len(val), every)]
        return m.group(1) + (b"\r\n" + ws).join(chunks)
    head, sep, body = signed.partition(b"\r\n\r\n")
    head = re.sub(rb"(r=)([A-Za-z0-9+/=]+)", fold_r, head)
    return head + sep + body


def _verify(msg: bytes):
    with open(DNS) as fh:
        dns_data = json.load(fh)
    return verify_message(msg, dns_data, full_chain=True, skip_timestamp_check=True)


def test_fixture_has_a_recipe_and_verifies_unfolded():
    raw = open(FIXTURE, "rb").read()
    assert b"r=" in raw
    result = _verify(raw)
    assert result.ok, result.errors


def test_recipe_folded_with_tab_verifies():
    raw = open(FIXTURE, "rb").read()
    folded = _fold_recipe(raw, 10, b"\t")
    assert folded != raw
    result = _verify(folded)
    assert result.ok, f"tab-folded r= broke verification: {result.errors}"


def test_recipe_folded_with_space_verifies():
    raw = open(FIXTURE, "rb").read()
    folded = _fold_recipe(raw, 12, b" ")
    result = _verify(folded)
    assert result.ok, f"space-folded r= broke verification: {result.errors}"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
