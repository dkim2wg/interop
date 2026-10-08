"""Every DKIM2-Signature i= and m=, and every Message-Instance m=, is bounded
by MAX_CHAIN_LENGTH (32): a larger value, or one longer than two digits, is a
PERMERROR found before any gap/contiguity check walks 1..max.

Fixtures are the negative vectors from util/build-negative-vectors.py:
genuinely signed chains whose second hop carries the out-of-range number.
"""
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
import dkim2sign  # noqa: E402
import dkim2verify  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "bnv", os.path.join(ROOT, "util", "build-negative-vectors.py"))
bnv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bnv)

with open(os.path.join(ROOT, "dns.json")) as _fh:
    DNS = json.load(_fh)
KEY = os.path.join(ROOT, "keys", "sel1._domainkey.test3.dkim2.com.pem")

RANGE = "exceeds the maximum chain length of 32"
CASES = {
    "signature-i-33": (bnv.build_signature_i_33,
                       f"PERMERROR DKIM2-Signature i= {RANGE}"),
    "signature-i-huge": (bnv.build_signature_i_huge,
                         f"PERMERROR DKIM2-Signature i= {RANGE}"),
    "signature-m-huge": (bnv.build_signature_m_huge,
                         f"PERMERROR DKIM2-Signature m= {RANGE}"),
    "instance-m-huge": (bnv.build_instance_m_huge, RANGE),
}


def test_max_chain_length_is_32():
    assert dkim2sign.MAX_CHAIN_LENGTH == 32


@pytest.mark.parametrize("v,ok", [
    ("1", True), ("9", True), ("32", True), ("01", True),
    ("33", False), ("99", False), ("001", False), ("4294967297", False),
    ("99999999999999999999", False),
])
def test_chain_number_in_range(v, ok):
    assert dkim2sign.chain_number_in_range(v) is ok


def test_instance_m_huge_alone():
    # Message-Instance m= out of range with the signature's m= in range.
    msg = bnv.build_positive_null_body().replace(
        b"Message-Instance: m=1;", b"Message-Instance: m=99999999999999999999;", 1)
    r = dkim2verify.verify_message(msg, DNS, full_chain=True,
                                   skip_timestamp_check=True)
    assert r.status == "permerror"
    assert r.message == f"PERMERROR Message-Instance m= {RANGE}"


@pytest.mark.parametrize("name", sorted(CASES))
def test_verifier_permerror(name):
    build, want = CASES[name]
    r = dkim2verify.verify_message(build(), DNS, full_chain=True,
                                   skip_timestamp_check=True)
    assert not r.ok
    assert r.status == "permerror"
    assert want in r.message


@pytest.mark.parametrize("name", sorted(CASES))
@pytest.mark.parametrize("skip_gate", [False, True])
def test_signer_refuses(name, skip_gate):
    # The signer's own parser refuses too, even with the gate bypassed: it
    # would otherwise compute i= or m= one above the out-of-range value.
    build, _ = CASES[name]
    with pytest.raises(dkim2sign.SigningRefused, match=RANGE):
        dkim2sign.sign_message(
            build(), "sel1", "test3.dkim2.com", KEY,
            mailfrom="<list@test3.dkim2.com>",
            rcptto=["<subscriber@test4.dkim2.com>"], dns_data=DNS,
            skip_timestamp_check=True, skip_upstream_check=skip_gate)
