import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2verify import verify_dkim2_signature, _chain_custody_errors  # noqa: E402
from dkim2sign import build_dkim2_signature  # noqa: E402


def _sig(value):
    return "DKIM2-Signature: " + value


# --- required-tag rule (draft-03 §8) ---

def test_nd_excludes_mf_rt():
    errs = verify_dkim2_signature(
        _sig("i=2; m=2; t=1; d=fwd.example; nd=mx.dest.example; "
             "mf=PA==; rt=PA==; s=sel:rsa-sha256:AAAA"),
        [], [], {})
    assert any("was unexpected" in e for e in errs), errs


def test_missing_chain_tags():
    errs = verify_dkim2_signature(
        _sig("i=2; m=2; t=1; d=fwd.example; s=sel:rsa-sha256:AAAA"),
        [], [], {})
    assert any("tag=mf missing" in e for e in errs), errs


def test_missing_t_tag():
    errs = verify_dkim2_signature(
        _sig("i=2; m=2; d=fwd.example; nd=x.example; s=sel:rsa-sha256:AAAA"),
        [], [], {})
    assert any("tag=t missing" in e for e in errs), errs


# --- Chain of Custody (draft-03 §11.4) ---

def test_chain_nd_match():
    sigs = [
        _sig("i=1; m=1; t=1; d=fwd.example; nd=mx.dest.example; s=s:rsa-sha256:AAAA"),
        _sig("i=2; m=2; t=1; d=mx.dest.example; mf=PA==; rt=PA==; s=s:rsa-sha256:AAAA"),
    ]
    assert _chain_custody_errors(sigs) == []


def test_chain_nd_mismatch():
    sigs = [
        _sig("i=1; m=1; t=1; d=fwd.example; nd=mx.dest.example; s=s:rsa-sha256:AAAA"),
        _sig("i=2; m=2; t=1; d=other.example; mf=PA==; rt=PA==; s=s:rsa-sha256:AAAA"),
    ]
    errs = _chain_custody_errors(sigs)
    assert any("nd= does not match" in e for e in errs), errs


# --- signer emit (draft-03 §9.3) ---

def test_emit_nd():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.generate()
    hdr = build_dkim2_signature(
        [], [], "Message-Instance: m=1; h=sha256:AAA:BBB;",
        "fwd.example", "sel", key, "ed25519-sha256",
        seq=1, mi_version=1, timestamp=1, next_domain="mx.dest.example")
    assert "nd=mx.dest.example" in hdr
    assert "mf=" not in hdr and "rt=" not in hdr


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("python nd= tests OK")
