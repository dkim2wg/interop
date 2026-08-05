import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2verify import _flag_enforcement_errors, _sig_flags  # noqa: E402
from dkim2sign import build_dkim2_signature  # noqa: E402


def _sig(value):
    return "DKIM2-Signature: " + value


# --- parsing / recognition ---

def test_feedhere_parsed():
    flags = _sig_flags(_sig("i=1; m=1; t=1; d=x; mf=PA==; rt=PA==; "
                            "f=feedback,feedhere; s=s:rsa-sha256:AAAA"))
    assert flags == ["feedback", "feedhere"]


# --- donotmodify enforcement (draft-03 §11.8) ---

def test_donotmodify_violation():
    mi = ["Message-Instance: m=1; h=sha256:AAA:BBB;",
          "Message-Instance: m=2; h=sha256:CCC:DDD;"]  # body+header changed
    sigs = [_sig("i=1; m=1; t=1; d=x; mf=PA==; rt=PA==; "
                 "f=donotmodify; s=s:rsa-sha256:AAAA")]
    errs = _flag_enforcement_errors(sigs, mi)
    assert any("donotmodify" in e for e in errs), errs


def test_donotmodify_ok_when_unchanged():
    mi = ["Message-Instance: m=1; h=sha256:AAA:BBB;",
          "Message-Instance: m=2; h=sha256:AAA:BBB;"]  # unchanged
    sigs = [_sig("i=1; m=1; t=1; d=x; mf=PA==; rt=PA==; "
                 "f=donotmodify; s=s:rsa-sha256:AAAA")]
    assert _flag_enforcement_errors(sigs, mi) == []


def test_donotexplode_violation():
    mi = ["Message-Instance: m=1; h=sha256:AAA:BBB;"]
    sigs = [
        _sig("i=1; m=1; t=1; d=x; mf=PA==; rt=PA==; f=donotexplode; s=s:rsa-sha256:AAAA"),
        _sig("i=2; m=1; t=1; d=y; mf=PA==; rt=PA==; f=exploded; s=s:rsa-sha256:AAAA"),
    ]
    errs = _flag_enforcement_errors(sigs, mi)
    assert any("exploded" in e for e in errs), errs


def test_feedhere_not_enforced():
    # feedhere/feedback carry no enforcement even if the message changed.
    mi = ["Message-Instance: m=1; h=sha256:AAA:BBB;",
          "Message-Instance: m=2; h=sha256:CCC:DDD;"]
    sigs = [_sig("i=1; m=1; t=1; d=x; mf=PA==; rt=PA==; "
                 "f=feedhere,feedback; s=s:rsa-sha256:AAAA")]
    assert _flag_enforcement_errors(sigs, mi) == []


# --- emit (draft-03 §8.10) ---

def test_emit_flags():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.generate()
    hdr = build_dkim2_signature(
        [], [], "Message-Instance: m=1; h=sha256:AAA:BBB;",
        "ex.example", "sel", key, "ed25519-sha256",
        mailfrom="a@x.example", rcptto=["b@y.example"],
        seq=1, mi_version=1, timestamp=1, flags=["donotmodify", "feedhere"])
    assert "f=donotmodify,feedhere" in hdr


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("python flags tests OK")
