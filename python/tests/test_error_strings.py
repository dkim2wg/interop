"""Task 3.4: canonical spec-04 verifier error strings.

Each test asserts the exact byte-for-byte canonical error message per the
current->target mapping in .superpowers/sdd/task-3.4-brief.md.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2verify import (  # noqa: E402
    verify_dkim2_signature,
    _chain_custody_errors,
    _classify_status,
)


def _sig(value):
    return "DKIM2-Signature: " + value


def _b64(s):
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


# --- _chain_custody_errors ---

def test_nd_adjacency_mismatch_canonical():
    sigs = [
        _sig("i=1; m=1; t=1; d=fwd.example; nd=mx.dest.example; s=s:rsa-sha256:AAAA"),
        _sig("i=2; m=2; t=1; d=other.example; mf=PA==; rt=PA==; s=s:rsa-sha256:AAAA"),
    ]
    errs = _chain_custody_errors(sigs)
    assert "DKIM2-Signature i=1 MAIL nd= does not match" in errs, errs


def test_custody_break_canonical():
    sigs = [
        _sig(f"i=1; m=1; t=1; d=fwd.example; rt={_b64('<rcpt@dest.example>')}; "
             "s=s:rsa-sha256:AAAA"),
        _sig(f"i=2; m=2; t=1; d=dest.example; mf={_b64('<mallory@evil.example>')}; "
             f"rt={_b64('<x@y.example>')}; s=s:rsa-sha256:AAAA"),
    ]
    errs = _chain_custody_errors(sigs)
    assert "DKIM2-Signature i=2 MAIL FROM <mallory@evil.example> did not match" in errs, errs


def test_missing_mf_canonical():
    sigs = [
        _sig("i=1; m=1; t=1; d=fwd.example; rt=PA==; s=s:rsa-sha256:AAAA"),
        _sig("i=2; m=2; t=1; d=dest.example; rt=PA==; s=s:rsa-sha256:AAAA"),
    ]
    errs = _chain_custody_errors(sigs)
    assert "DKIM2-Signature i=2 MAIL FROM <> did not match" in errs, errs


def test_missing_rt_canonical():
    sigs = [
        _sig("i=1; m=1; t=1; d=fwd.example; s=s:rsa-sha256:AAAA"),
        _sig("i=2; m=2; t=1; d=dest.example; mf=PA==; s=s:rsa-sha256:AAAA"),
    ]
    errs = _chain_custody_errors(sigs)
    assert "DKIM2-Signature i=1 RCPT TO <> did not match" in errs, errs


# --- verify_dkim2_signature: required-tag / chain-tag checks ---

def test_missing_required_tag_reports_first_missing_i():
    # i= missing, everything else present
    errs = verify_dkim2_signature(
        _sig("m=2; t=1; d=fwd.example; nd=x.example; s=sel:rsa-sha256:AAAA"),
        [], [], {})
    assert "DKIM2-Signature i=None tag=i missing" in errs, errs


def test_missing_required_tag_reports_first_missing_t():
    errs = verify_dkim2_signature(
        _sig("i=2; m=2; d=fwd.example; nd=x.example; s=sel:rsa-sha256:AAAA"),
        [], [], {})
    assert "DKIM2-Signature i=2 tag=t missing" in errs, errs


def test_missing_required_tag_order_i_before_s():
    # both i= and s= missing -> i= reported first (order i,m,t,d,s)
    errs = verify_dkim2_signature(
        _sig("m=2; t=1; d=fwd.example; nd=x.example"),
        [], [], {})
    assert "DKIM2-Signature i=None tag=i missing" in errs, errs


def test_nd_with_mf_rt_unexpected_canonical():
    errs = verify_dkim2_signature(
        _sig("i=2; m=2; t=1; d=fwd.example; nd=mx.dest.example; "
             "mf=PA==; rt=PA==; s=sel:rsa-sha256:AAAA"),
        [], [], {})
    assert "DKIM2-Signature i=2 tag=nd was unexpected" in errs, errs


def test_missing_chain_tags_canonical():
    errs = verify_dkim2_signature(
        _sig("i=2; m=2; t=1; d=fwd.example; s=sel:rsa-sha256:AAAA"),
        [], [], {})
    assert "DKIM2-Signature i=2 tag=mf missing" in errs, errs


# --- _classify_status ---

def test_custody_break_classifies_as_fail():
    assert _classify_status(
        ["DKIM2-Signature i=2 MAIL FROM <mallory@evil.example> did not match"]
    ) == 'fail'


def test_missing_mf_classifies_as_fail():
    assert _classify_status(
        ["DKIM2-Signature i=2 MAIL FROM <> did not match"]
    ) == 'fail'


def test_missing_rt_classifies_as_fail():
    assert _classify_status(
        ["DKIM2-Signature i=1 RCPT TO <> did not match"]
    ) == 'fail'


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("python error string tests OK")
