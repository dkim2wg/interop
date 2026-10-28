"""Contract C9: on a message with more than one fault the PRIMARY error (the
first in result.errors, whose state is the result) is the first in C9's
order: §14.2 structure (steps a..h), each Message-Instance's content by
ascending m=, the §14.7 chain walk, each DKIM2-Signature's content by
ascending i=, then §14.3, §14.4, §14.5, §14.6, §14.8.

Fixtures are the multi-* vectors from util/build-negative-vectors.py, each
carrying two faults; util/negative-vectors.sh pins the same texts for every
verifier.
"""
import base64
import json
import re
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
import dkim2verify  # noqa: E402

sys.path.insert(0, HERE)
from util_fixtures import bnv  # noqa: E402

with open(os.path.join(ROOT, "dns.json")) as _fh:
    DNS = json.load(_fh)

HDR1 = "FAIL: Message-Instance m=1 header hash sha256 mismatch"
JSON2 = "PERMERROR: Message-Instance m=2 contains invalid JSON"
EXPECT = {
    "multi-from-tampered": HDR1,
    "multi-header-and-body-tampered": HDR1,
    "multi-expired-custody": "FAIL: DKIM2-Signature i=1 signature expired",
    "multi-custody-bad-signature":
        "FAIL: DKIM2-Signature i=1 MAIL FROM and d= do not match",
    "multi-bad-signature-header-hash": HDR1,
    "multi-tamper-two-instances":
        "FAIL: Message-Instance m=2 header hash sha256 mismatch",
    "multi-expired-recipe-json": JSON2,
    # -08 (contract D6): the out-of-order step is named.
    "multi-expired-recipe-order": "PERMERROR: Message-Instance m=2 Recipe b[1] is invalid",
    "multi-expired-recipe-past-end": JSON2,
    "multi-tamper-recipe-past-end":
        "FAIL: Message-Instance m=2 body hash sha256 mismatch",
    "multi-signature-gap-recipe-json": "PERMERROR: DKIM2-Signature i=1 missing",
    "multi-instance-gap-signature-gap": "PERMERROR: Message-Instance m=1 missing",
    "multi-instance-gap-unsigned": "PERMERROR: Message-Instance m=1 missing",
    "multi-instance-no-m-signature-twice":
        "PERMERROR: Message-Instance m= tag=m missing",
    "multi-instance-twice-signature-no-i":
        "PERMERROR: Message-Instance m=1 appears more than once",
    "multi-instance-twice-junk-signature":
        "PERMERROR: Message-Instance m=1 appears more than once",
    "multi-instance-twice-lowest":
        "PERMERROR: Message-Instance m=1 appears more than once",
    "multi-signature-twice-lowest":
        "PERMERROR: DKIM2-Signature i=1 appears more than once",
    "multi-instance-syntax-dup-alg": "PERMERROR: Message-Instance m=1 syntax error",
    "multi-instance-syntax-dup-selector":
        "PERMERROR: Message-Instance m=1 syntax error",
    "multi-instance-dup-alg-recipe":
        "PERMERROR: Message-Instance m=2 has a duplicate hash algorithm",
    "multi-header-sha512-body-sha256":
        "FAIL: Message-Instance m=1 header hash sha512 mismatch",
    "multi-expired-nd": "FAIL: DKIM2-Signature i=1 signature expired",
    "multi-expired-header-hash": HDR1,
    "multi-custody-header-hash": HDR1,
    "multi-body-hash-no-key": "FAIL: Message-Instance m=1 body hash sha256 mismatch",
}


def test_every_multi_vector_is_covered():
    assert {n[:-4] for n in bnv.FIXTURES if n.startswith("multi-")} == set(EXPECT)


class _CountingKeys:
    """A dns.json key source that records every name prefetched and every
    name actually looked up (used)."""

    def __init__(self):
        self.prefetched = []
        self.names = []

    def prefetch(self, names):
        self.prefetched.extend(names)

    def txt_records(self, name):
        self.names.append(name)
        sel, _, domain = name.partition("._domainkey.")
        recs = DNS.get(domain, {}).get(f"{sel}._domainkey")
        if not recs:
            raise KeyError(name)
        return [v if isinstance(v, str) else "".join(v)
                for t, v in recs if t.lower() == "txt"]


@pytest.mark.parametrize("walk", ["plan", "undo"])
@pytest.mark.parametrize("name", sorted(EXPECT))
def test_primary_error(name, walk):
    msg = bnv.FIXTURES[name + ".eml"]()
    keys = _CountingKeys()
    r = dkim2verify.verify_message(
        msg, keys, full_chain=True, walk=walk,
        skip_timestamp_check=not name.startswith("multi-expired-"))
    want = EXPECT[name]
    assert r.message == want, r.errors
    assert r.errors[0] == want
    assert r.status == ("fail" if want.startswith("FAIL:") else "permerror")
    # Instances that fail (structure, content or walk) are the verdict: no
    # public key is used, and no key error reported.
    if "Message-Instance" in want or "DKIM2-Signature i=1 missing" in want \
            or "appears more than once" in want:
        assert keys.names == [], keys.names
        assert not any("public key" in e for e in r.errors), r.errors


def test_unsigned_instances_are_still_walked():
    # Outbound (allow_unsigned_mi) with no signature: the instances are
    # walked, and one that does not match the message is the result.
    msg = bnv.build_multi_header_sha512_body_sha256()
    headers, body = dkim2verify.parse_message(msg)
    unsigned = b"".join(h + b"\r\n" for h in headers
                        if not h.lower().startswith(b"dkim2-signature:"))
    r = dkim2verify.verify_message(unsigned + b"\r\n" + body, DNS,
                                   full_chain=True, allow_unsigned_mi=True)
    assert r.message == "FAIL: Message-Instance m=1 header hash sha512 mismatch"


def test_more_fields_than_the_chain_length():
    msg = bnv.build_positive_control()
    head, sep, body = msg.partition(b"\r\n\r\n")
    mi = b"Message-Instance: m=1; h=sha256:AAAA:BBBB"
    sig = b"DKIM2-Signature: i=1; m=1"
    for extra, want in ((mi, "Message-Instance"), (sig, "DKIM2-Signature")):
        r = dkim2verify.verify_message(
            b"\r\n".join([extra] * 33) + b"\r\n" + head + sep + body, DNS,
            full_chain=True, skip_timestamp_check=True)
        assert r.message == f"PERMERROR: more than 32 {want} fields"


# --- malformed input never escapes as an exception --------------------------

def _replace_tag(msg: bytes, field: bytes, old: bytes, new: bytes) -> bytes:
    head, sep, body = msg.partition(b"\r\n\r\n")
    start = head.index(field)
    at = head.index(old, start)
    return head[:at] + new + head[at + len(old):] + sep + body


@pytest.mark.parametrize("field,old", [
    (b"DKIM2-Signature:", b"i=1;"), (b"DKIM2-Signature:", b"m=1;"),
    (b"Message-Instance:", b"m=1;"),
])
def test_chain_number_of_5000_digits(field, old):
    huge = b"9" * 5000
    msg = _replace_tag(bnv.build_positive_control(), field, old,
                       old[:2] + huge + b";")
    r = dkim2verify.verify_message(msg, DNS, full_chain=True,
                                   skip_timestamp_check=True)
    assert r.status == "permerror"
    assert r.message.endswith(
        f"={huge.decode()} exceeds the maximum chain number of 100"), r.message[-60:]


def test_timestamp_of_5000_digits_is_from_the_future():
    msg = bnv.build_positive_control()
    t = re.search(rb"t=(\d+);", msg).group(1)
    msg = msg.replace(b"t=" + t + b";", b"t=" + b"9" * 5000 + b";", 1)
    r = dkim2verify.verify_message(msg, DNS, full_chain=True)
    assert r.message == "FAIL: DKIM2-Signature i=1 signature is from the future"
    msg = msg.replace(b"t=" + b"9" * 5000, b"t=" + b"0" * 5000 + b"1", 1)
    r = dkim2verify.verify_message(msg, DNS, full_chain=True)
    assert r.message == "FAIL: DKIM2-Signature i=1 signature expired"


def test_deeply_nested_recipe_is_invalid_json():
    deep = base64.b64encode(b"[" * 200000 + b"]" * 200000).decode()
    msg = bnv.build_positive_control()
    head, sep, body = msg.partition(b"\r\n\r\n")
    head = head.replace(b"Message-Instance: m=1;",
                        f"Message-Instance: m=1; r={deep};".encode(), 1)
    for walk in ("plan", "undo"):
        r = dkim2verify.verify_message(head + sep + body, DNS, full_chain=True,
                                       walk=walk, skip_timestamp_check=True)
        assert r.message == "PERMERROR: Message-Instance m=1 contains invalid JSON"


# --- prefetch fan-out --------------------------------------------------------

def test_prefetch_is_capped_top_signature_first():
    sigs = [f"DKIM2-Signature: i={i}; m=1; d=d{i}.example; "
            f"s=a:rsa-sha256:AA,b:ed25519-sha256:AA,c:x-unknown:AA,a:rsa-sha256:AA"
            for i in range(1, 6)]
    names = dkim2verify._key_names(sigs)
    assert len(names) == dkim2verify.PREFETCH_MAX == 8
    assert names[:4] == ["a._domainkey.d5.example", "b._domainkey.d5.example",
                         "a._domainkey.d4.example", "b._domainkey.d4.example"]
    assert names[-1] == "b._domainkey.d2.example"
