"""An r= payload whose JSON is not valid UTF-8 is a PERMERROR, not a crash.

Found 2026-10-04: the Perl producer (Sympa, dkim2-milter) writes Recipe
literals as raw octets, so a Latin-1 or EUC-KR header or body line makes the
base64-decoded JSON undecodable as UTF-8.  json.loads() then raised
UnicodeDecodeError -- a ValueError, but not a JSONDecodeError -- and the
verifier died with a traceback instead of reporting §11.2's "contains invalid
JSON".
"""

import base64
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


def _with_recipe_bytes(raw: bytes, payload: bytes) -> bytes:
    head, sep, body = raw.partition(b"\r\n\r\n")
    head = re.sub(rb"(r=)[A-Za-z0-9+/=]+", lambda m: m.group(1) + base64.b64encode(payload), head, count=1)
    return head + sep + body


def test_non_utf8_recipe_is_reported_not_raised():
    raw = open(FIXTURE, "rb").read()
    msg = _with_recipe_bytes(raw, b'{"b":[{"d":["caf\xe9 au lait"]}]}')
    with open(DNS) as fh:
        dns = json.load(fh)
    result = verify_message(msg, dns, full_chain=True, skip_timestamp_check=True)
    assert not result.ok
    assert any("contains invalid JSON" in e for e in result.errors), result.errors


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
