"""A hop that changes nothing adds no Message-Instance (spec-05 §9.1/§9.2.5).

Regression: on a transparent re-sign the signer used to emit a fresh
Message-Instance carrying hashes identical to the one below it and no recipe at
all.  A recipe-less instance is legal to *receive* — it asserts no change, and
verifiers must accept one — but there is no reason to produce it.  An unmodified
hop signs against the existing top instance and reuses its m=.
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
DNS = os.path.join(ROOT, "dns.json")
KEY1 = os.path.join(ROOT, "keys", "sel1._domainkey.test1.dkim2.com.pem")
KEY2 = os.path.join(ROOT, "keys", "sel1._domainkey.test2.dkim2.com.pem")

BASE = (
    b"From: sender@test1.dkim2.com\r\n"
    b"To: rcpt@test2.dkim2.com\r\n"
    b"Subject: mi reuse test\r\n"
    b"Date: Fri, 24 Jul 2026 12:00:00 +0000\r\n"
    b"Message-ID: <reuse@test1.dkim2.com>\r\n"
    b"\r\n"
    b"Hello unchanged world.\r\n"
)


def _verify(msg: bytes):
    with open(DNS) as fh:
        dns_data = json.load(fh)
    return verify_message(msg, dns_data, skip_timestamp_check=True)


def _hop1() -> bytes:
    return sign_message(BASE, "sel1", "test1.dkim2.com", KEY1,
                        mailfrom="<sender@test1.dkim2.com>",
                        rcptto=["<rcpt@test2.dkim2.com>"],
                        timestamp=1740000000)


def _resign_unchanged(msg: bytes) -> bytes:
    """Second hop that relays the message byte-for-byte unchanged."""
    return sign_message(msg, "sel1", "test2.dkim2.com", KEY2,
                        mailfrom="<sender@test2.dkim2.com>",
                        rcptto=["<final@test3.dkim2.com>"],
                        timestamp=1740000100)


def _headers(msg: bytes, name: str) -> list[str]:
    head = msg.decode().partition("\r\n\r\n")[0]
    # Unfold so a folded header is still one logical entry.
    logical: list[str] = []
    for line in head.split("\r\n"):
        if line[:1] in (" ", "\t") and logical:
            logical[-1] += " " + line.lstrip()
        else:
            logical.append(line)
    return [h for h in logical if h.lower().startswith(name.lower() + ":")]


def test_unchanged_hop_adds_no_message_instance():
    resigned = _resign_unchanged(_hop1())
    mis = _headers(resigned, "Message-Instance")
    assert len(mis) == 1, (
        f"expected the single m=1 instance to be reused, got {len(mis)}: {mis}"
    )


def test_unchanged_hop_signature_points_at_reused_instance():
    resigned = _resign_unchanged(_hop1())
    sigs = _headers(resigned, "DKIM2-Signature")
    assert len(sigs) == 2, f"expected two signatures, got {len(sigs)}"
    by_seq = {int(re.search(r"i=(\d+)", s).group(1)):
              int(re.search(r"m=(\d+)", s).group(1)) for s in sigs}
    assert by_seq == {1: 1, 2: 1}, (
        f"both signatures should reference instance m=1, got {by_seq}"
    )


def test_unchanged_hop_still_verifies():
    result = _verify(_resign_unchanged(_hop1()))
    assert result.ok, f"reused-instance chain failed to verify: {result.errors}"


def test_recipe_less_instance_from_upstream_is_accepted():
    # An upstream that does emit a Recipe-less instance must still verify: the
    # instance asserts no change, which is legal.
    signed = _hop1()
    mi = _headers(signed, "Message-Instance")[0]
    grafted = (mi.replace("m=1;", "m=2;") + "\r\n").encode() + signed
    # Re-sign over the grafted chain so a signature covers m=2.
    resigned = _resign_unchanged(grafted)
    assert len(_headers(resigned, "Message-Instance")) == 2, \
        "fixture should carry the recipe-less m=2 instance"
    result = _verify(resigned)
    assert result.ok, f"recipe-less instance was rejected: {result.errors}"


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
