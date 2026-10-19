"""Every DKIM2-Signature i= and m=, and every Message-Instance m=, is a chain
number: 1*DIGIT in ASCII (int() alone would take "0_1", " 1" or full-width
digits), at most three digits naming 1..MAX_CHAIN_NUMBER (100), so "01" and
"001" are 1; and no more than MAX_CHAIN_LENGTH (32). Anything else is a
PERMERROR: found before any gap/contiguity check walks 1..max.

Fixtures are the negative vectors from util/build-negative-vectors.py:
genuinely signed chains whose second hop carries the out-of-range number.
"""
import json
import os
import re
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
import dkim2sign  # noqa: E402
import dkim2verify  # noqa: E402

sys.path.insert(0, HERE)
from util_fixtures import bnv  # noqa: E402  (From Authentic for test1)

with open(os.path.join(ROOT, "dns.json")) as _fh:
    DNS = json.load(_fh)
KEY = os.path.join(ROOT, "keys", "sel1._domainkey.test3.dkim2.com.pem")

LEN = "exceeds the maximum chain length of 32"
NUM = "exceeds the maximum chain number of 100"
# Patterns (re.search) for the error each case gives.
CASES = {
    "signature-i-33": (bnv.build_signature_i_33,
                       rf"^PERMERROR: DKIM2-Signature i=33 {LEN}$"),
    "signature-i-101": (bnv.build_signature_i_101,
                        rf"^PERMERROR: DKIM2-Signature i=101 {NUM}$"),
    "signature-i-huge": (bnv.build_signature_i_huge,
                         rf"^PERMERROR: DKIM2-Signature i=\d+ {NUM}$"),
    "signature-m-huge": (bnv.build_signature_m_huge,
                         rf"^PERMERROR: DKIM2-Signature i=\d+ m=\d+ {NUM}$"),
    "signature-m-malformed": (bnv.build_signature_m_malformed,
                              r"^PERMERROR: DKIM2-Signature i=\d+ syntax error$"),
    "instance-m-huge": (bnv.build_instance_m_huge,
                        rf"^PERMERROR: Message-Instance m=\d+ {NUM}$"),
    "instance-m-malformed": (bnv.build_instance_m_malformed,
                             r"^PERMERROR: Message-Instance m=\S* syntax error$"),
}


def test_max_chain_length_is_32():
    assert dkim2sign.MAX_CHAIN_LENGTH == 32
    assert dkim2sign.MAX_CHAIN_NUMBER == 100


def _mal(v):
    return f"PERMERROR: Message-Instance m={v.strip()} syntax error"


@pytest.mark.parametrize("v,want", [
    ("1", None), ("9", None), ("32", None), ("01", None), ("001", None),
    ("032", None),
    ("33", f"PERMERROR: Message-Instance m=33 {LEN}"),
    ("100", f"PERMERROR: Message-Instance m=100 {LEN}"),
    ("101", f"PERMERROR: Message-Instance m=101 {NUM}"),
    ("0001", f"PERMERROR: Message-Instance m=0001 {NUM}"),
    ("4294967297", f"PERMERROR: Message-Instance m=4294967297 {NUM}"),
    ("99999999999999999999",
     f"PERMERROR: Message-Instance m=99999999999999999999 {NUM}"),
] + [(v, _mal(v)) for v in ("", "0", "000", "abc", "1x", "4294967297x", "0_1",
                            "\uff11", "+1", "-1", "\u00b9")] + [
    (None, None),
])
def test_chain_number_error(v, want):
    assert dkim2sign.chain_number_error("Message-Instance", "m", v) == want


def test_chain_number_error_i():
    assert (dkim2sign.chain_number_error("DKIM2-Signature", "i", "abc")
            == "PERMERROR: DKIM2-Signature i=abc syntax error")
    assert (dkim2sign.chain_number_error("DKIM2-Signature", "m", "200", "2")
            == f"PERMERROR: DKIM2-Signature i=2 m=200 {NUM}")


def test_instance_m_huge_alone():
    # Message-Instance m= out of range with the signature's m= in range.
    msg = bnv.build_positive_null_body().replace(
        b"Message-Instance: m=1;", b"Message-Instance: m=99999999999999999999;", 1)
    r = dkim2verify.verify_message(msg, DNS, full_chain=True,
                                   skip_timestamp_check=True)
    assert r.status == "permerror"
    assert r.message == f"PERMERROR: Message-Instance m=99999999999999999999 {NUM}"


@pytest.mark.parametrize("name", sorted(CASES))
def test_verifier_permerror(name):
    build, want = CASES[name]
    r = dkim2verify.verify_message(build(), DNS, full_chain=True,
                                   skip_timestamp_check=True)
    assert not r.ok
    assert r.status == "permerror"
    assert re.search(want, r.message), r.message


@pytest.mark.parametrize("name", sorted(CASES))
@pytest.mark.parametrize("skip_gate", [False, True])
def test_signer_refuses(name, skip_gate):
    # The signer's own parser refuses too, even with the gate bypassed: it
    # would otherwise compute i= or m= one above the out-of-range value.
    build, want = CASES[name]
    with pytest.raises(dkim2sign.SigningRefused,
                       match=want.replace("^", "").replace("$", "")):
        dkim2sign.sign_message(
            build(), "sel1", "test3.dkim2.com", KEY,
            mailfrom="<list@test3.dkim2.com>",
            rcptto=["<subscriber@test4.dkim2.com>"], dns_data=DNS,
            skip_timestamp_check=True, skip_upstream_check=skip_gate)


def _signed_sample():
    return bnv.build_positive_null_body()


SIG_M = "PERMERROR: DKIM2-Signature i=1 syntax error"


@pytest.mark.parametrize("field,old,new,want", [
    ("sig", b"; m=1;", b"; m=abc;", SIG_M),
    ("sig", b"; m=1;", b"; m=4294967297x;", SIG_M),
    ("sig", b"; m=1;", "; m=\uff11;".encode(), SIG_M),
    ("sig", b"; m=1;", b"; m=0_1;", SIG_M),
    ("sig", b"; m=1;", b"; m=0;", SIG_M),
    ("mi", b"Message-Instance: m=1;", b"Message-Instance: m=0_1;", _mal("0_1")),
    ("mi", b"Message-Instance: m=1;", "Message-Instance: m=\uff11;".encode(),
     _mal("\uff11")),
    ("mi", b"Message-Instance: m=1;", b"Message-Instance: m=4294967297x;",
     _mal("4294967297x")),
])
def test_malformed_numbers_are_permerror_not_a_crash(field, old, new, want):
    msg = _signed_sample()
    if field == "sig":
        # the i=1 signature (first DKIM2-Signature with i=1)
        j = msg.index(old, msg.index(b"i=1;"))
        msg = msg[:j] + new + msg[j + len(old):]
    else:
        assert old in msg
        msg = msg.replace(old, new, 1)
    r = dkim2verify.verify_message(msg, DNS, full_chain=True,
                                   skip_timestamp_check=True)
    assert r.status == "permerror"
    assert r.message == want
    for skip_gate in (False, True):
        with pytest.raises(dkim2sign.SigningRefused, match=re.escape(want)):
            dkim2sign.sign_message(
                msg, "sel1", "test3.dkim2.com", KEY,
                mailfrom="<list@test3.dkim2.com>",
                rcptto=["<subscriber@test4.dkim2.com>"], dns_data=DNS,
                skip_timestamp_check=True, skip_upstream_check=skip_gate)
