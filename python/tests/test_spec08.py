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
    # A lone surrogate escape is not a Unicode string: the document does not
    # parse as text (as Perl's decoder sees it), wherever the string is.
    b'{"b":[{"d":["\\ud800"]}]}',
    b'{"b":[{"c":[1,1]}],"x":["\\udc80"]}',
    b'{"b":[{"c":[1,1]}],"\\udc80":1}',
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


# --- hand-built s= and h= layouts (test1.dkim2.com keys from dns.json) ----------

import copy  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import time  # noqa: E402

import dkim2verify  # noqa: E402
from dkim2sign import (  # noqa: E402
    b64, compute_body_hash, compute_header_hash, compute_signature,
    load_private_key, parse_message,
)

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
T1 = "test1.dkim2.com"
T1DNS = json.load(open(os.path.join(REPO, "dns.json")))
BASE = (b"From: a@test1.dkim2.com\r\nTo: b@example.com\r\nSubject: s08\r\n"
        b"\r\nHello\r\n")


def _h(layout: str) -> str:
    """An h= value from a layout like "sha256:H:B|sha512:H:BAD": H and B are
    the right header and body hashes, BAD a wrong (but base64) one."""
    headers, body = parse_message(BASE)

    def one(m):
        alg, hh, bh = m.group(1), m.group(2), m.group(3)
        good = alg in ("sha256", "sha512")
        hv = b64(compute_header_hash(headers, alg)) if good and hh == "H" else (
            "AAAA" if hh in ("H", "BAD") else hh)
        bv = b64(compute_body_hash(body, alg)) if good and bh == "B" else (
            "AAAA" if bh in ("B", "BAD") else bh)
        return f"{alg}:{hv}:{bv}"
    return re.sub(r"([^\s:,|]+):([^\s:,|]*):([^\s:,|]*)", one, layout)


def make(s_layout: str, h_layout: str = "sha256:H:B", t=None, dns_sel=None):
    """A one-hop message whose s= is `s_layout`: items "sel:alg:VALUE" joined
    by "," and "|" (with any FWS written in the layout).  VALUE "SIGN:<key>"
    is a real signature with that test1 key over the signed form."""
    t = str(int(time.time())) if t is None else t
    mi = f"Message-Instance: m=1; h={_h(h_layout)};"
    mf, rt = b64(b"<a@test1.dkim2.com>"), b64(b"<b@example.com>")
    pre = f"DKIM2-Signature: i=1; m=1; t={t}; d={T1}; mf={mf}; rt={rt}; s="
    item = re.compile(r"([^\s:,|]+)(\s*:\s*)([^\s:,|]+)(\s*:)(SIGN:[\w-]+|[^,|;]*)")
    incomplete = pre + item.sub(lambda m: m.group(1) + m.group(2) + m.group(3)
                                + m.group(4), s_layout) + ";"

    def signed(m):
        v = m.group(5)
        if v.startswith("SIGN:"):
            key, kalg = load_private_key(
                os.path.join(REPO, "keys", f"{v[5:]}._domainkey.{T1}.pem"))
            v = b64(compute_signature([mi], [], incomplete, key, kalg))
        return m.group(1) + m.group(2) + m.group(3) + m.group(4) + v
    sig = pre + item.sub(signed, s_layout) + ";"
    return (mi + "\r\n" + sig + "\r\n").encode() + BASE


def v8(raw, dns=None, **kw):
    kw.setdefault("skip_timestamp_check", True)
    out = []
    for walk in WALKS:
        r = dkim2verify.verify_message(raw, T1DNS if dns is None else dns,
                                       full_chain=True, walk=walk, **kw)
        out.append((r.ok, r.status, r.errors[:1]))
    assert out[0] == out[1], out
    return dkim2verify.verify_message(raw, T1DNS if dns is None else dns, **kw)


def ok(raw, **kw):
    r = v8(raw, **kw)
    assert r.ok and r.status == "pass", r.errors


def err(raw, text, **kw):
    r = v8(raw, **kw)
    assert not r.ok and r.errors[0] == text, r.errors
    assert r.status == text.split(":", 1)[0].lower(), (r.status, r.errors)


def _dns_with(records, sel):
    d = copy.deepcopy(T1DNS)
    d[T1][f"{sel}._domainkey"] = records
    return d


@pytest.fixture
def lookups(monkeypatch):
    calls = []
    real = dkim2verify.lookup_public_key

    def counting(domain, selector, dns_data):
        calls.append(selector)
        return real(domain, selector, dns_data)
    monkeypatch.setattr(dkim2verify, "lookup_public_key", counting)
    return calls


S1 = "sel1:rsa-sha256:SIGN:sel1"
S2 = "sel2:rsa-sha256:SIGN:sel2"
ED = "ed25519:ed25519-sha256:SIGN:ed25519"
SIG1 = "DKIM2-Signature i=1"
MI1 = "Message-Instance m=1"


def test_harness_baseline():
    ok(make(S1))
    ok(make(f"{S1},{ED}"))


# --- D2: "|" groups of "," lists in s= and h= -----------------------------------

@pytest.mark.parametrize("layout", [
    f"{S1}|{S2}", f"{S1} | {S2}", f"{S1}\r\n\t|\r\n\t{S2}", f"{S1},{S2}|{ED}",
    f"{S1} ,\r\n {S2}",
])
def test_d2_groups_and_fws_parse(layout):
    ok(make(layout))


@pytest.mark.parametrize("layout", [
    f"|{S1}", f"{S1}|", f"{S1}||{S2}", f",{S1}", f"{S1},", f"{S1},,{S2}",
    f"{S1}|,{S2}", f"{S1} | ",
])
def test_d2_empty_member_is_syntax_error(layout):
    err(make(layout), f"PERMERROR: {SIG1} syntax error")


@pytest.mark.parametrize("layout", [
    "|sha256:H:B", "sha256:H:B|", "sha256:H:B||sha512:H:B", "sha256:H:B,",
    "sha256:H:B,,sha512:H:B",
])
def test_d2_empty_hash_member_is_syntax_error(layout):
    err(make(S1, layout), f"PERMERROR: {MI1} syntax error")


def test_d2_duplicates_across_the_whole_tag():
    err(make(f"{S1}|{S1}"), f"PERMERROR: {SIG1} has a duplicate selector")
    err(make(S1, "sha256:H:B|sha256:H:B"),
        f"PERMERROR: {MI1} has a duplicate hash algorithm")


def test_d2_same_algorithm_many_selectors_allowed():
    # -08 dropped "has more selectors than allowed".
    ok(make(f"{S1},{S2},sel3:rsa-sha256:SIGN:sel3"))


def test_d2_fold_never_inside_a_name():
    err(make("sel1:rsa-\r\n\tsha256:SIGN:sel1"), f"PERMERROR: {SIG1} syntax error")
    err(make(S1, "sha\r\n\t256:H:B"), f"PERMERROR: {MI1} syntax error")


# --- D3: combining signature results -------------------------------------------

BADSIG = "sel2:rsa-sha256:SIGN:sel1"         # sel1's signature under sel2: FAIL
UNK = "x:mldsa44:AAAA"                        # D8: mldsa44 is not implemented


def test_d3_unknown_algorithm_alone_is_permerror_no_key(lookups):
    err(make(UNK), f"PERMERROR: {SIG1} selector x algorithm unknown")
    assert lookups == []


@pytest.mark.parametrize("alg", ["mldsa44", "mldsa44-ed25519-sha512", "RSA-SHA256",
                                 "future-alg"])
def test_d8_unimplemented_algorithms(alg, lookups):
    err(make(f"{S1},x:{alg}:AAAA"), f"PERMERROR: {SIG1} selector x algorithm unknown")
    ok(make(f"{S1}|x:{alg}:AAAA"))
    assert "x" not in lookups


def test_d3_unknown_joined_by_comma_vs_bar():
    err(make(f"{S1},{UNK}"), f"PERMERROR: {SIG1} selector x algorithm unknown")
    ok(make(f"{S1}|{UNK}"))
    ok(make(f"{UNK}|{S1}"))


def test_d3_one_group_fail_string_is_first_fail():
    err(make(f"{S1},{BADSIG}"), f"FAIL: {SIG1} selector sel2 incorrect signature")
    err(make(f"{BADSIG},{S1}"), f"FAIL: {SIG1} selector sel2 incorrect signature")
    # FAIL beats PERMERROR in a group, so the FAIL is reported though the
    # unknown item comes first.
    err(make(f"{UNK},{BADSIG}"), f"FAIL: {SIG1} selector sel2 incorrect signature")


def test_d3_many_groups_fail_is_no_group_passed():
    err(make(f"{BADSIG}|{UNK}"), f"FAIL: {SIG1} no group of signatures passed")
    err(make(f"{S1},{BADSIG}|sel3:rsa-sha256:SIGN:sel1"),
        f"FAIL: {SIG1} no group of signatures passed")
    ok(make(f"{BADSIG}|{S1}"))


def test_d3_many_groups_permerror_is_first_permerror():
    err(make(f"{UNK}|y:future:AAAA"), f"PERMERROR: {SIG1} selector x algorithm unknown")
    err(make(f"nokey:rsa-sha256:SIGN:sel1|{UNK}"),
        f"PERMERROR: {SIG1} public key nokey does not exist")


def test_d3_key_errors_are_items():
    # An absent key is that item's PERMERROR (-07 skipped it).
    err(make(f"{S1},nokey:rsa-sha256:SIGN:sel1"),
        f"PERMERROR: {SIG1} public key nokey does not exist")
    ok(make(f"{S1}|nokey:rsa-sha256:SIGN:sel1"))
    # A revoked key in another group does not stop a pass.
    dns = _dns_with([["txt", "v=DKIM1; k=rsa; p="]], "sel2")
    ok(make(f"{S1}|{S2}"), dns=dns)
    err(make(f"{S1},{S2}"), f"PERMERROR: {SIG1} public key sel2 has been revoked", dns=dns)


@pytest.fixture
def tempfail(monkeypatch):
    real = dkim2verify.lookup_public_key

    def lookup(domain, selector, dns_data):
        if selector == "sel2":
            raise dkim2verify.DNSTempError("sel2")
        return real(domain, selector, dns_data)
    monkeypatch.setattr(dkim2verify, "lookup_public_key", lookup)


def test_d3_temperror_rules(tempfail):
    t = f"TEMPERROR: {SIG1} public key sel2 could not be fetched"
    err(make(f"{S1},{S2}"), t)                   # every non-PASS is TEMPERROR
    err(make(f"{S2},{BADSIG.replace('sel2', 'sel3')}"),
        f"FAIL: {SIG1} selector sel3 incorrect signature")  # a FAIL is not
    err(make(f"{S2}|{UNK}"), t)                  # any group TEMPERROR
    ok(make(f"{S2}|{S1}"))


def test_d3_every_item_is_verified(lookups):
    ok(make(f"{S1}|{S2}|{ED}"))
    assert sorted(set(lookups)) == ["ed25519", "sel1", "sel2"]


def test_d3_limit_of_8_items(lookups):
    items = [S1, S2, "sel3:rsa-sha256:SIGN:sel3", ED,
             "dkim2test:rsa-sha256:SIGN:dkim2test", "rsa1024:rsa-sha256:SIGN:rsa1024"]
    ok(make(",".join(items) + "|a:x:AAAA,b:x:AAAA"))
    lookups.clear()
    err(make(",".join(items) + "|a:x:AAAA,b:x:AAAA,c:x:AAAA"),
        f"PERMERROR: {SIG1} has more than 8 signatures")
    assert lookups == []
    # after the duplicate-selector check
    err(make(",".join(items + [S1]) + "|a:x:AAAA,b:x:AAAA"),
        f"PERMERROR: {SIG1} has a duplicate selector")


@pytest.mark.parametrize("val", ["", "@@@@", "AA AA!"])
def test_d3_unknown_algorithm_value_must_be_base64(val):
    err(make(f"{S1}|x:future:{val}"), f"PERMERROR: {SIG1} syntax error")


@pytest.mark.parametrize("val", ["", "@@@@"])
def test_d3_unknown_hash_values_must_be_base64(val):
    err(make(S1, f"sha256:H:B|x-hash:{val}:AAAA"), f"PERMERROR: {MI1} syntax error")
    err(make(S1, f"sha256:H:B|x-hash:AAAA:{val}"), f"PERMERROR: {MI1} syntax error")


def test_d3_amended_c9_key_error_above_bad_signature_below():
    # i=1 has a bad signature, i=2's key is missing: §14.5 and §14.6 are one
    # step per signature now, so the i=1 FAIL is primary.
    hop1 = _hop1()
    bad1 = hop1.replace(b"s=sel:ed25519-sha256:", b"s=sel:ed25519-sha256:A", 1)
    bad1 = re.sub(rb"(s=sel:ed25519-sha256:)A(.)", lambda m: m.group(1) + (
        b"B" if m.group(2) != b"B" else b"C"), bad1, count=1)
    two = sign(bad1, "example.org", "list@lists.example.org", ["b@example.net"],
               skip_upstream_check=True)
    dns = dict(E.DNS)
    del dns["example.org"]
    r = dkim2verify.verify_message(two, dns, full_chain=True, skip_timestamp_check=True)
    assert r.errors[0] == "FAIL: DKIM2-Signature i=1 selector sel incorrect signature", r.errors
    assert any("i=2 public key sel does not exist" in e for e in r.errors), r.errors


# --- D4: combining hash results ------------------------------------------------

def test_d4_unknown_hash_alone_is_permerror():
    err(make(S1, "x-hash:AAAA:AAAA"), f"PERMERROR: {MI1} algorithm x-hash unknown")
    err(make(S1, "SHA256:H:B"), f"PERMERROR: {MI1} algorithm SHA256 unknown")


def test_d4_unknown_hash_joined_by_comma_vs_bar():
    err(make(S1, "sha256:H:B,x-hash:AAAA:AAAA"), f"PERMERROR: {MI1} algorithm x-hash unknown")
    ok(make(S1, "sha256:H:B|x-hash:AAAA:AAAA"))
    ok(make(S1, "x-hash:AAAA:AAAA|sha256:H:B"))


def test_d4_one_group_strings():
    err(make(S1, "sha256:H:BAD"), f"FAIL: {MI1} body hash sha256 mismatch")
    err(make(S1, "sha256:BAD:BAD"), f"FAIL: {MI1} header hash sha256 mismatch")
    # in h= order, each set header before body (replaces C9's "every
    # header hash before any body hash")
    err(make(S1, "sha256:H:BAD,sha512:BAD:B"), f"FAIL: {MI1} body hash sha256 mismatch")
    err(make(S1, "sha512:BAD:B,sha256:H:BAD"), f"FAIL: {MI1} header hash sha512 mismatch")
    err(make(S1, "x-hash:AAAA:AAAA,sha256:H:BAD"), f"FAIL: {MI1} body hash sha256 mismatch")


def test_d4_many_groups():
    err(make(S1, "sha256:H:BAD|sha512:BAD:B"), f"FAIL: {MI1} no group of hashes passed")
    err(make(S1, "sha256:H:BAD|x-hash:AAAA:AAAA"), f"FAIL: {MI1} no group of hashes passed")
    err(make(S1, "x-hash:AAAA:AAAA|y-hash:AAAA:AAAA"),
        f"PERMERROR: {MI1} algorithm x-hash unknown")
    ok(make(S1, "sha256:H:BAD|sha512:H:B"))


# --- D7: malformed keys --------------------------------------------------------

def _short_rsa_p():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.RSAPublicNumbers(65537, (1 << 1022) | 0x1234567).public_key()
    return b64(key.public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.SubjectPublicKeyInfo))


ED_P = [v for t, v in T1DNS[T1]["ed25519._domainkey"] if t == "txt"][0].split("p=")[1]
ED_SPKI = b64(bytes.fromhex("302a300506032b6570032100") + __import__("base64").b64decode(ED_P))


@pytest.mark.parametrize("sel,item,rec", [
    ("sel1", S1, f"v=DKIM1; k=rsa; p={_short_rsa_p()}"),        # 1023 bits
    ("sel1", S1, "v=DKIM1; k=rsa; p=AAAA"),                      # not a key
    ("sel1", S1, f"v=DKIM1; k=rsa; p={ED_SPKI}"),                # not RSA
    ("ed25519", ED, f"v=DKIM1; k=ed25519; p={b64(bytes(31))}"),  # 31 octets
    ("ed25519", ED, f"v=DKIM1; k=ed25519; p={b64(bytes(33))}"),  # 33 octets
    ("ed25519", ED, f"v=DKIM1; k=ed25519; p={ED_SPKI}"),         # DER SPKI
])
def test_d7_malformed_key(sel, item, rec):
    err(make(item), f"PERMERROR: {SIG1} public key {sel} is malformed",
        dns=_dns_with([["txt", rec]], sel))


def test_d7_non_base64_p_is_still_syntax_error():
    err(make(S1), f"PERMERROR: {SIG1} public key sel1 has a syntax error",
        dns=_dns_with([["txt", "v=DKIM1; k=rsa; p=!!!!"]], "sel1"))


def test_d7_rsa_1024_verifies():
    ok(make("rsa1024:rsa-sha256:SIGN:rsa1024"))


# --- D9: fully_verified ----------------------------------------------------------

from util_fixtures import bnv  # noqa: E402


def _fv(raw, dns=None, **kw):
    kw.setdefault("skip_timestamp_check", True)
    out = set()
    for walk in WALKS:
        r = dkim2verify.verify_message(raw, T1DNS if dns is None else dns,
                                       full_chain=True, walk=walk, **kw)
        out.add((r.status, r.fully_verified))
    assert len(out) == 1, out
    return out.pop()


def test_d9_plain_pass_is_fully_verified():
    assert _fv(make(S1)) == ("pass", True)
    assert _fv(bnv.build_positive_bottom_recipe()) == ("pass", True)


def test_d9_null_body_recipe_is_pass_but_not_fully_verified():
    assert _fv(bnv.build_positive_null_body()) == ("pass", False)
    assert _fv(bnv.build_positive_null_below()) == ("pass", False)


def test_d9_non_pass_is_not_fully_verified():
    assert _fv(make(f"{S1},{BADSIG}"))[1] is False
    assert _fv(make(UNK))[1] is False


def test_d9_headers_only_is_not_fully_verified():
    r = dkim2verify.verify_message(make(S1), T1DNS, headers_only=True,
                                   skip_timestamp_check=True)
    assert r.ok and r.fully_verified is False


def test_d9_unsigned_top_instance_is_not_fully_verified():
    raw = make(S1)
    head, sep, body = raw.partition(b"\r\n\r\n")
    r = dkim2verify.verify_message(raw, T1DNS, full_chain=True, allow_unsigned_mi=True,
                                   skip_timestamp_check=True)
    assert r.ok and r.fully_verified is True
    # outbound mode over an instance no signature covers yet
    msg = add_mi(_hop1(), replace_header(b"Subject", b"x"))
    r = verify(msg, allow_unsigned_mi=True)
    assert r.ok and r.fully_verified is False


# --- D11: a DSN's d= relaxed-matches the reported message's top rt= -------------

def _wrap_dsn(embedded):
    import test_spec07
    return test_spec07._wrap_dsn(embedded)


def test_d11_propagated_dsn_d_must_match_top_rt():
    import dkim2dsn
    # i=1 (example.com) sent to list@lists.example.org; the list (example.org)
    # forwarded it.  After the list's hop is taken off, the top rt= is
    # lists.example.org, which example.org relaxed-matches.
    dsn = _wrap_dsn(_to_list(_hop1()))
    out = dkim2dsn.propagate(dsn, forwarder_domain="example.org",
                             keyfile=E.keyfile("example.org"), selector="sel",
                             domain="example.org", skip_authentication=True)
    assert out["raw"]
    # example.net matches no rt= domain: no DSN.
    with pytest.raises(ValueError, match="rt="):
        dkim2dsn.propagate(dsn, forwarder_domain="example.org",
                           keyfile=E.keyfile("example.net"), selector="sel",
                           domain="example.net", skip_authentication=True)
    # lists.example.org itself is fine too.
    dkim2dsn.propagate(dsn, forwarder_domain="example.org",
                       keyfile=E.keyfile("lists.example.org"), selector="sel",
                       domain="lists.example.org", skip_authentication=True)
