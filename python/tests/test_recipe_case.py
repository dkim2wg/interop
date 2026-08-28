#!/usr/bin/env python3
"""Recipe header keys are always emitted lowercase (canonical form).

spec-06 §5.1: header field names in the JSON Recipes MUST be lower case
(matching against the message stays case-insensitive). We lowercase the
recipe (h) keys on output regardless of the case the caller supplied.
"""
import base64
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dkim2sign  # noqa: E402


def recipe_h_keys(mi_value: str):
    r = re.search(r"r=([A-Za-z0-9+/=]+)", mi_value).group(1)
    return list(json.loads(base64.b64decode(r))["h"].keys())


def test_mixed_case_recipe_keys_lowercased():
    mi = dkim2sign.build_message_instance(
        [b"From: a@b.com"], b"body\r\n", version=2,
        recipe={"h": {"List-ID": [], "Reply-To": [], "X-Weird-CASE": []}})
    keys = recipe_h_keys(mi)
    assert keys == ["list-id", "reply-to", "x-weird-case"], keys


if __name__ == "__main__":
    test_mixed_case_recipe_keys_lowercased()
    print("ok: recipe header keys lowercased")
