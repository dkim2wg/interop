"""draft -08 contract tests (docs/superpowers/specs/2026-10-28-dkim2-spec-08-design.md).

Each section names the contract item it pins.  Keys and DNS for
example.com, example.org, ... come from spec07_env (generated for the test
suite only); the s=/h= layouts are built by hand where a test needs one the
signer never writes.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import spec07_env as E  # noqa: E402
from spec07_env import add_mi, message, replace_header, sign, verify  # noqa: E402

WALKS = ("plan", "undo")


def _hop1(frm="A <a@example.com>", rt=("list@lists.example.org",), **kw):
    raw = kw.pop("raw", None) or message(frm)
    return sign(raw, kw.pop("d", "example.com"),
                kw.pop("mailfrom", "a@example.com"), list(rt), **kw)


def _to_list(msg, **kw):
    return sign(msg, "example.org", kw.pop("mailfrom", "list@lists.example.org"),
                kw.pop("rcptto", ["b@example.net"]), **kw)


def _bad_recipe(recipe_json: bytes) -> bytes:
    """A list hop over an unsigned m=2 carrying exactly these Recipe bytes
    (the signer gate would refuse it, so it is not run)."""
    msg = add_mi(_hop1(), recipe_json=recipe_json)
    return _to_list(msg, skip_upstream_check=True)


def _pass(msg, **kw):
    for walk in WALKS:
        r = verify(msg, walk=walk, **kw)
        assert r.ok and r.status == "pass", (walk, r.errors)


def _fails_with(msg, error, status="permerror", **kw):
    for walk in WALKS:
        r = verify(msg, walk=walk, **kw)
        assert not r.ok, (walk, r.message)
        assert r.errors[0] == error, (walk, r.errors)
        assert r.status == status, (walk, r.status, r.errors)


# --- D10: tag names and JSON keys are strictly lowercase ----------------------

def test_d10_uppercase_mi_tag_is_unknown():
    signed = _hop1()
    # "M=1" alone: m= is missing (structure, C9 step b).
    _fails_with(signed.replace(b"Message-Instance: m=1;", b"Message-Instance: M=1;"),
                "PERMERROR: Message-Instance m= tag=m missing")
    # "H=": h= is missing.
    _fails_with(signed.replace(b"; h=sha256:", b"; H=sha256:"),
                "PERMERROR: Message-Instance m=1 tag=h missing")


def test_d10_uppercase_sig_tag_is_unknown():
    signed = _hop1()
    _fails_with(signed.replace(b"; d=example.com;", b"; D=example.com;"),
                "PERMERROR: DKIM2-Signature i=1 tag=d missing")


def test_d10_uppercase_twin_is_not_a_duplicate():
    signed = _hop1()
    # "m=1; ... M=2": M is an unknown tag, ignored, so not a duplicate (a
    # syntax error would be §14.2).  Added after signing, it changes the
    # signed input, so the result is the §14.6 signature FAIL.
    raw = signed.replace(b"Message-Instance: m=1;", b"Message-Instance: m=1; M=2;")
    r = verify(raw)
    assert r.errors[0] == "FAIL: DKIM2-Signature i=1 selector sel incorrect signature", r.errors


def test_d10_uppercase_json_key_is_invalid_json():
    for rj in (b'{"H":{"subject":[{"c":[1,1]}]}}',
               b'{"h":{"Subject":[{"c":[1,1]}]}}',
               b'{"h":{"subject":[{"C":[1,1]}]}}'):
        msg = _bad_recipe(rj)
        _fails_with(msg, "PERMERROR: Message-Instance m=2 contains invalid JSON")


def test_d10_duplicate_keys_compared_exactly():
    # Two keys equal but for case are two keys -- and the uppercase one is
    # invalid on its own, so it is still invalid JSON.
    msg = _bad_recipe(b'{"h":{"subject":[],"Subject":[]}}')
    _fails_with(msg, "PERMERROR: Message-Instance m=2 contains invalid JSON")
