"""The "b" Recipe step: literals carried as base64 of their raw octets.

Extension to spec-06 §5 proposed to the WG.  A "d" item is JSON text, so a
header value or body line in Latin-1 or EUC-KR -- not valid UTF-8 -- has no
"d" representation (a Perl producer that wrote the raw octets anyway made
the whole r= payload "invalid JSON", see test_recipe_not_utf8.py).  A "b"
item is {"b": ["<base64>"]}: the decoded octets are applied exactly as a
"d" string would be, name + colon prepended / CRLF appended.

The Recipe here is written by hand so the test pins the wire format, not
whatever the generator happens to emit.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from twohop import two_hop, verify, hop1  # noqa: E402

# The original carries an EUC-KR Subject value and a Latin-1 body line.
ORIGINAL = (
    b"From: sender@test1.dkim2.com\r\n"
    b"To: list@test2.dkim2.com\r\n"
    b"Subject: \xb1\xa4\r\n"
    b"Date: Fri, 24 Jul 2026 12:00:00 +0000\r\n"
    b"Message-ID: <b-step@test1.dkim2.com>\r\n"
    b"\r\n"
    b"caf\xe9\r\n"
    b"second line\r\n"
)


def _list_rewrites(headers, body):
    """The intermediary rewrites the Subject and the first body line to ASCII
    and appends a footer, so both 8-bit literals must come back via "b"."""
    headers = [b"Subject: [list] rewritten" if h.lower().startswith(b"subject:") else h
               for h in headers]
    body = b"cafe\r\nsecond line\r\n-- \r\nlist footer\r\n"
    return headers, body


# b" \xb1\xa4" (the value after the colon, leading space included) and b"caf\xe9".
RECIPE = {
    "h": {"subject": [{"b": ["ILGk"]}]},
    "b": [{"b": ["Y2Fm6Q=="]}, {"c": [2, 2]}],
}


def test_original_with_8bit_octets_signs_and_verifies():
    result = verify(hop1(ORIGINAL))
    assert result.ok, result.errors


def test_b_steps_round_trip_through_full_chain_verify():
    msg = two_hop(ORIGINAL, _list_rewrites, recipe=RECIPE)
    result = verify(msg, full_chain=True)
    assert result.ok, result.errors


def test_b_step_header_value_without_leading_space_is_hash_equivalent():
    # §6.2 canonicalisation drops WSP after the colon, so a producer that
    # strips the leading space from the value gets the same header hash.
    recipe = {"h": {"subject": [{"b": ["saQ="]}]},
              "b": [{"b": ["Y2Fm6Q=="]}, {"c": [2, 2]}]}
    result = verify(two_hop(ORIGINAL, _list_rewrites, recipe=recipe))
    assert result.ok, result.errors


def test_d_and_b_steps_mix_in_one_list():
    def modify(headers, body):
        return headers, b"-- \r\nfooter\r\n"
    original = ORIGINAL.replace(b"caf\xe9\r\nsecond line\r\n",
                                b"plain\r\ncaf\xe9\r\n\xb1\xa4\r\nplain again\r\n")
    recipe = {"b": [{"d": ["plain"]}, {"b": ["Y2Fm6Q==", "saQ="]}, {"d": ["plain again"]}]}
    result = verify(two_hop(original, modify, recipe=recipe))
    assert result.ok, result.errors


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
