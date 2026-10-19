"""draft -07 verifier error strings (§14.2-§14.8, contract C4/C6).

Each test asserts the exact text, in the form "<STATE>: <text>".
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


# --- _chain_custody_errors (C4) ---

def test_nd_adjacency_mismatch_canonical():
    sigs = [
        _sig("i=1; m=1; t=1; d=fwd.example; nd=mx.dest.example; s=s:rsa-sha256:AAAA"),
        _sig(f"i=2; m=2; t=1; d=other.example; mf={_b64('<a@other.example>')}; "
             "rt=PA==; s=s:rsa-sha256:AAAA"),
    ]
    assert _chain_custody_errors(sigs) == [
        "PERMERROR: DKIM2-Signature i=1 nd= does not match"]


def test_custody_break_canonical():
    sigs = [
        _sig(f"i=1; m=1; t=1; d=fwd.example; mf={_b64('<a@fwd.example>')}; "
             f"rt={_b64('<rcpt@dest.example>')}; s=s:rsa-sha256:AAAA"),
        _sig(f"i=2; m=2; t=1; d=evil.example; mf={_b64('<mallory@evil.example>')}; "
             f"rt={_b64('<x@y.example>')}; s=s:rsa-sha256:AAAA"),
    ]
    assert _chain_custody_errors(sigs) == [
        "PERMERROR: DKIM2-Signature i=2 mf= does not match the rt= of i=1"]


def test_null_mf_d_mismatch_canonical():
    sigs = [
        _sig(f"i=1; m=1; t=1; d=fwd.example; mf={_b64('<a@fwd.example>')}; "
             f"rt={_b64('<rcpt@dest.example>')}; s=s:rsa-sha256:AAAA"),
        _sig(f"i=2; m=2; t=1; d=evil.example; mf={_b64('<>')}; "
             f"rt={_b64('<x@y.example>')}; s=s:rsa-sha256:AAAA"),
    ]
    assert _chain_custody_errors(sigs) == [
        "PERMERROR: DKIM2-Signature i=2 d= does not match the rt= of i=1"]


def test_mf_vs_d_canonical():
    sigs = [_sig(f"i=1; m=1; t=1; d=fwd.example; mf={_b64('<a@b.example>')}; "
                 f"rt={_b64('<rcpt@dest.example>')}; s=s:rsa-sha256:AAAA")]
    assert _chain_custody_errors(sigs) == [
        "PERMERROR: DKIM2-Signature i=1 MAIL FROM and d= do not match"]


def test_mf_vs_d_skipped_for_null_mf():
    sigs = [_sig(f"i=1; m=1; t=1; d=fwd.example; mf={_b64('<>')}; "
                 f"rt={_b64('<rcpt@dest.example>')}; s=s:rsa-sha256:AAAA")]
    assert _chain_custody_errors(sigs) == []


# --- verify_dkim2_signature: required-tag / chain-tag checks ---

def test_missing_required_tag_reports_first_missing_i():
    # i= missing, everything else present
    errs = verify_dkim2_signature(
        _sig("m=2; t=1; d=fwd.example; nd=x.example; s=sel:rsa-sha256:AAAA"),
        [], [], {})
    assert errs == ["PERMERROR: DKIM2-Signature i= tag=i missing"], errs


def test_missing_required_tag_reports_first_missing_t():
    errs = verify_dkim2_signature(
        _sig("i=2; m=2; d=fwd.example; nd=x.example; s=sel:rsa-sha256:AAAA"),
        [], [], {})
    assert errs == ["PERMERROR: DKIM2-Signature i=2 tag=t missing"], errs


def test_missing_required_tag_order_i_before_s():
    # both i= and s= missing -> i= reported first (order i,m,t,d,s)
    errs = verify_dkim2_signature(
        _sig("m=2; t=1; d=fwd.example; nd=x.example"),
        [], [], {})
    assert errs == ["PERMERROR: DKIM2-Signature i= tag=i missing"], errs


def test_nd_with_mf_unexpected_canonical():
    errs = verify_dkim2_signature(
        _sig("i=2; m=2; t=1; d=fwd.example; nd=mx.dest.example; "
             "mf=PA==; rt=PA==; s=sel:rsa-sha256:AAAA"),
        [], [], {})
    assert errs == ["PERMERROR: DKIM2-Signature i=2 tag=mf was unexpected"], errs


def test_nd_with_rt_unexpected_canonical():
    errs = verify_dkim2_signature(
        _sig("i=2; m=2; t=1; d=fwd.example; nd=mx.dest.example; "
             "rt=PA==; s=sel:rsa-sha256:AAAA"),
        [], [], {})
    assert errs == ["PERMERROR: DKIM2-Signature i=2 tag=rt was unexpected"], errs


def test_missing_chain_tags_canonical():
    errs = verify_dkim2_signature(
        _sig("i=2; m=2; t=1; d=fwd.example; s=sel:rsa-sha256:AAAA"),
        [], [], {})
    assert errs == ["PERMERROR: DKIM2-Signature i=2 tag=mf missing"], errs


def test_missing_rt_canonical():
    errs = verify_dkim2_signature(
        _sig("i=2; m=2; t=1; d=fwd.example; mf=PA==; s=sel:rsa-sha256:AAAA"),
        [], [], {})
    assert errs == ["PERMERROR: DKIM2-Signature i=2 tag=rt missing"], errs


def test_duplicate_tag_is_syntax_error():
    errs = verify_dkim2_signature(
        _sig("i=2; m=2; t=1; d=fwd.example; D=x; nd=x.example; "
             "s=sel:rsa-sha256:AAAA"), [], [], {})
    assert errs == ["PERMERROR: DKIM2-Signature i=2 syntax error"], errs


# --- _classify_status: the state the first error names ---

def test_custody_break_classifies_as_permerror():
    assert _classify_status(
        ["PERMERROR: DKIM2-Signature i=2 mf= does not match the rt= of i=1"]
    ) == 'permerror'


def test_fail_and_temperror_classify_by_prefix():
    assert _classify_status(
        ["FAIL: Message-Instance m=1 body hash sha256 mismatch"]) == 'fail'
    assert _classify_status(
        ["TEMPERROR: DKIM2-Signature i=1 public key s could not be fetched"]
    ) == 'temperror'
    assert _classify_status([]) == 'pass'


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("python error string tests OK")
