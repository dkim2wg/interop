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


# --- D6: "Recipe <path> is invalid" ---------------------------------------------

INVALID_JSON_2 = "PERMERROR: Message-Instance m=2 contains invalid JSON"


def _step_invalid(path):
    return f"PERMERROR: Message-Instance m=2 Recipe {path} is invalid"


@pytest.mark.parametrize("rj", [
    b'{"b":[{"c":[1.5,2]}]}',             # a fraction, anywhere
    b'{"b":[{"c":[1,2]}],"x":1e0}',        # an exponent, even 1e0, even unused
    b'{"b":[{"c":[1,2]}],"x":[1.0]}',
    b'{"b":[{"c":[1,NaN]}]}',              # not JSON at all
    b'[]',                                  # not an object
    b'{}',                                  # neither h nor b
    b'{"x":1}',
    b'{"h":{}}',                            # h not a non-empty object
    b'{"h":null}',
    b'{"h":[]}',
    b'{"b":{}}',                            # b not an array or null
    b'{"b":"x"}',
    b'{"b":[{"x":1}],"h":[]}',             # whole-document before any step
    b'{"b":[{"c":[1,1]}],"b":null}',       # duplicate key
])
def test_d6_whole_document_is_invalid_json(rj):
    _fails_with(_bad_recipe(rj), INVALID_JSON_2)


@pytest.mark.parametrize("rj,path", [
    (b'{"b":[{"c":[1,1]},5]}', "b[1]"),                       # not an object
    (b'{"b":[{}]}', "b[0]"),                                  # no key
    (b'{"b":[{"c":[1,1],"d":["x"]}]}', "b[0]"),               # two keys
    (b'{"b":[{"b":["x"]}]}', "b[0]"),                         # the old -06 step
    (b'{"b":[{"c":[1]}]}', "b[0]"),                           # not two integers
    (b'{"b":[{"c":[1,2,3]}]}', "b[0]"),
    (b'{"b":[{"c":[true,1]}]}', "b[0]"),
    (b'{"b":[{"c":["1",1]}]}', "b[0]"),
    (b'{"b":[{"c":[0,1]}]}', "b[0]"),                         # start < 1
    (b'{"b":[{"c":[2,1]}]}', "b[0]"),                         # start > end
    (b'{"b":[{"d":[]}]}', "b[0]"),                            # empty
    (b'{"b":[{"u":[]}]}', "b[0]"),
    (b'{"b":[{"d":[1]}]}', "b[0]"),                           # not a string
    (b'{"b":[{"d":"x"}]}', "b[0]"),
    (b'{"b":[{"d":["a\\rb"]}]}', "b[0]"),                     # CR or LF
    (b'{"b":[{"d":["a\\nb"]}]}', "b[0]"),
    (b'{"b":[{"u":["DQ=="]}]}', "b[0]"),                      # decodes to CR
    (b'{"b":[{"u":["QR=="]}]}', "b[0]"),                      # non-canonical
    (b'{"b":[{"u":["QQ"]}]}', "b[0]"),
    (b'{"b":[{"d":["\\ud800"]}]}', "b[0]"),                   # lone surrogate
    (b'{"b":[{"c":[2,2]},{"c":[1,1]}]}', "b[1]"),             # out of order
    (b'{"b":[{"c":[1,2]},{"c":[2,3]}]}', "b[1]"),             # overlap
    (b'{"h":{"subject":"x"}}', "h.subject"),                  # not an array
    (b'{"h":{"subject":[{"c":[1,1]},{"x":1}]}}', "h.subject[1]"),
    (b'{"h":{"x y":[{"z":1}]}}', "h.x\\x20y[0]"),             # escaped octets
    (b'{"h":{"caf\xc3\xa9":[{"z":1}]}}', "h.caf\\xC3\\xA9[0]"),
    (b'{"h":{"a\\\\b":[{"z":1}]}}', "h.a\\b[0]"),             # backslash is 0x5C
])
def test_d6_one_bad_step_names_its_path(rj, path):
    _fails_with(_bad_recipe(rj), _step_invalid(path))


def test_d6_first_bad_step_b_then_h_in_byte_order():
    _fails_with(_bad_recipe(b'{"h":{"subject":[{"x":1}]},"b":[{"c":[1,1]},{"x":1}]}'),
                _step_invalid("b[1]"))
    _fails_with(_bad_recipe(b'{"h":{"to":[{"x":1}],"subject":[{"x":1}]}}'),
                _step_invalid("h.subject[0]"))
    _fails_with(_bad_recipe(b'{"h":{"subject":[{"x":1}],"Subject":[]}}'),
                INVALID_JSON_2)


def test_d6_copy_past_the_end_is_still_invalid_json():
    # Found only when the Recipe is applied (the chain walk), as in -07.
    _fails_with(_bad_recipe(b'{"b":[{"c":[1,9]}]}'), INVALID_JSON_2)


# --- D5: timestamps, Chain of Custody and From Authentic are FAIL ----------------

def test_d5_expired_and_future_are_fail():
    import time
    old = _hop1(timestamp=int(time.time()) - 30 * 86400)
    _fails_with(old, "FAIL: DKIM2-Signature i=1 signature expired", "fail",
                skip_timestamp_check=False)
    new = _hop1(timestamp=int(time.time()) + 3 * 86400)
    _fails_with(new, "FAIL: DKIM2-Signature i=1 signature is from the future", "fail",
                skip_timestamp_check=False)


def test_d5_custody_is_fail():
    # i=1 mf= not under d=
    msg = sign(message(), "example.com", "a@example.org", ["r@example.net"],
               skip_upstream_check=True)
    _fails_with(msg, "FAIL: DKIM2-Signature i=1 MAIL FROM and d= do not match", "fail")
    # the envelope against the top signature
    good = _hop1()
    _fails_with(good, "FAIL: DKIM2-Signature i=1 MAIL FROM <x@example.com> did not match",
                "fail", mail_from="<x@example.com>")
    _fails_with(good, "FAIL: DKIM2-Signature i=1 RCPT TO <x@example.net> did not match",
                "fail", rcpt_to=["<x@example.net>"])
    # i=2's mf= is not one of i=1's rt=
    hop2 = sign(_hop1(), "example.org", "list@example.org", ["b@example.net"],
                skip_upstream_check=True)
    _fails_with(hop2, "FAIL: DKIM2-Signature i=2 mf= does not match the rt= of i=1", "fail")


def test_d5_from_not_authentic_is_fail():
    msg = sign(message("A <a@other.net>"), "example.com", "a@example.com",
               ["r@example.net"], skip_upstream_check=True, skip_from_check=True)
    _fails_with(msg, "FAIL: DKIM2-Signature i=1 matching From is not authentic", "fail")
