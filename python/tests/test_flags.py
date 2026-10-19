import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import dkim2verify  # noqa: E402
from dkim2verify import _sig_flags  # noqa: E402
from dkim2sign import build_dkim2_signature  # noqa: E402


def _sig(value):
    return "DKIM2-Signature: " + value


# --- parsing / recognition ---

def test_flags_parsed():
    flags = _sig_flags(_sig("i=1; m=1; t=1; d=x; mf=PA==; rt=PA==; "
                            "f=feedback,feedhere; s=s:rsa-sha256:AAAA"))
    assert flags == ["feedback", "feedhere"]


def test_no_flag_enforcement_left():
    # -07 removed donotmodify/donotexplode (old §11.8); nothing enforces f=.
    assert not hasattr(dkim2verify, "_flag_enforcement_errors")


# --- emit (-07 §10.10, §12.5) ---

def _emit(seq=1, flags=None, rcptto=("b@y.example",), **kw):
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.generate()
    return build_dkim2_signature(
        [], [], "Message-Instance: m=1; h=sha256:AAA:BBB;",
        "ex.example", "sel", key, "ed25519-sha256",
        mailfrom="a@x.example", rcptto=list(rcptto),
        seq=seq, mi_version=1, timestamp=1, flags=flags, **kw)


def test_emit_flags():
    assert "f=donotmodify,feedhere" in _emit(flags=["donotmodify", "feedhere"])


def test_exploded_never_at_i1():
    assert "; f=" not in _emit(exploded=True)
    assert "; f=" not in _emit(rcptto=("b@y.example", "c@y.example"))
    assert "f=feedhere;" in _emit(flags=["exploded", "feedhere"])


def test_exploded_above_i1():
    assert "f=exploded;" in _emit(seq=2, exploded=True)
    assert "f=exploded;" in _emit(seq=2, rcptto=("b@y.example", "c@y.example"))
    assert "; f=" not in _emit(seq=2)
    assert "f=feedhere,exploded;" in _emit(seq=2, flags=["feedhere"],
                                           exploded=True)
    assert "f=exploded;" in _emit(seq=2, flags=["exploded"], exploded=True)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("python flags tests OK")
