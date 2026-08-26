"""Folding whitespace inside DKIM2 tag values (spec-05 §2.12).

FWS may appear inside a base64 string and around the colons of an s= item, and
"MUST be ignored when the value is used".

Regression: the verifier used to split an s= item on ':' before stripping FWS,
so a fold landing between the selector colon and the algorithm token left
CRLF+TAB glued to the algorithm name and the comparison against the key type
failed.  Folded output from a conformant signer must verify.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2sign import sign_message  # noqa: E402
from dkim2verify import verify_message  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
KEY = os.path.join(ROOT, "keys", "sel1._domainkey.test1.dkim2.com.pem")
DNS = os.path.join(ROOT, "dns.json")

BASE = (
    b"From: sender@test1.dkim2.com\r\n"
    b"To: rcpt@test2.dkim2.com\r\n"
    b"Subject: folding test\r\n"
    b"Date: Fri, 24 Jul 2026 12:00:00 +0000\r\n"
    b"Message-ID: <fold@test1.dkim2.com>\r\n"
    b"\r\n"
    b"Hello folding world.\r\n"
)

# Each entry inserts one CRLF+TAB fold at a different point in the signed
# headers.  "s_selector" is the case that used to fail.
FOLD_POINTS = {
    "mf_base64": (r"(mf=)([A-Za-z0-9+/=]{6})", r"\1\2\r\n\t"),
    "rt_base64": (r"(rt=)([A-Za-z0-9+/=]{6})", r"\1\2\r\n\t"),
    "s_selector": (r"(s=[A-Za-z0-9_-]+:)", r"\1\r\n\t"),
    "s_algorithm": (r"(:rsa-sha256:)", r"\1\r\n\t"),
    "h_hashes": (r"(h=sha256:)([A-Za-z0-9+/=]{6})", r"\1\2\r\n\t"),
}


def _refold(signed: bytes, pattern: str, repl: str) -> bytes:
    """Insert a fold into the DKIM2-Signature / Message-Instance headers only."""
    head, sep, body = signed.decode().partition("\r\n\r\n")
    out = []
    for h in head.split("\r\n"):
        name = h.split(":", 1)[0].lower()
        if name in ("dkim2-signature", "message-instance"):
            out.append(re.sub(pattern, repl, h))
        else:
            out.append(h)
    return ("\r\n".join(out) + sep + body).encode()


def _sign() -> bytes:
    return sign_message(BASE, "sel1", "test1.dkim2.com", KEY,
                        mailfrom="<sender@test1.dkim2.com>",
                        rcptto=["<rcpt@test2.dkim2.com>"],
                        timestamp=1740000000)


def _verify(msg: bytes):
    with open(DNS) as fh:
        dns_data = json.load(fh)
    return verify_message(msg, dns_data, skip_timestamp_check=True)


def test_unfolded_baseline_verifies():
    result = _verify(_sign())
    assert result.ok, f"unfolded message failed to verify: {result.errors}"


def test_every_fold_point_verifies():
    signed = _sign()
    for name, (pattern, repl) in FOLD_POINTS.items():
        folded = _refold(signed, pattern, repl)
        assert folded != signed, f"{name}: fold was not actually inserted"
        result = _verify(folded)
        assert result.ok, f"fold in {name} broke verification: {result.errors}"


def test_all_folds_at_once_verify():
    signed = _sign()
    for pattern, repl in FOLD_POINTS.values():
        signed = _refold(signed, pattern, repl)
    result = _verify(signed)
    assert result.ok, f"fully folded message failed to verify: {result.errors}"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok - {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL - {name}: {e}")
    sys.exit(1 if failures else 0)
