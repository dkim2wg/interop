"""Header-history walk past a null body Recipe (spec-06 §5).

A null body Recipe means the previous *body* cannot be recreated; header
Recipes are mandatory, so the header history below the null is still undone
and checked (header hash only -- the body hash is not checked below it).
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
from dkim2verify import verify_message  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "build_negative_vectors", os.path.join(ROOT, "util", "build-negative-vectors.py"))
bnv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bnv)


def _verify(msg):
    with open(os.path.join(ROOT, "dns.json")) as fh:
        dns = json.load(fh)
    return verify_message(msg, dns, full_chain=True, skip_timestamp_check=True)


def test_null_at_m2_over_signed_m1_passes():
    r = _verify(bnv.build_positive_null_body())
    assert r.ok, r.errors


def test_null_at_m3_over_normal_m2_passes():
    r = _verify(bnv.build_positive_null_body_over_recipe())
    assert r.ok, r.errors


def test_forged_history_below_null_fails_on_m1_header_hash():
    r = _verify(bnv.build_null_body_forged_history())
    assert not r.ok
    assert any("v=1" in e and "header hash mismatch" in e for e in r.errors), r.errors
    assert not any("body hash" in e for e in r.errors), r.errors


def test_header_recipe_not_applying_below_null_fails():
    def bad(*a):
        r = bnv._null_body_recipe(*a)
        r["h"] = {"subject": [{"c": [90, 99]}]}  # no such lines in m=1's Subject
        return r
    headers, body = bnv.load_base()
    msg = bnv._null_body_chain([
        (headers, body),
        (bnv._subject_prefixed(headers, b"list"), body + b"rewritten\r\n", bad),
    ])
    r = _verify(msg)
    assert not r.ok, r.errors


def _chain3_null_in_middle(forge):
    headers, body = bnv.load_base()
    h2 = bnv._subject_prefixed(headers, b"list")
    if forge:
        h2 = bnv._to_changed(h2)
    h3 = bnv._subject_prefixed(h2, b"fwd")
    b2 = body + b"rewritten\r\n"
    return bnv._null_body_chain([
        (headers, body),
        (h2, b2, bnv._forged_recipe if forge else bnv._null_body_recipe),
        (h3, b2, bnv._footer_recipe),  # ordinary: header Recipe only
    ])


def test_null_below_ordinary_instance_passes():
    r = _verify(_chain3_null_in_middle(False))
    assert r.ok, r.errors


def test_forged_history_below_null_below_ordinary_fails():
    r = _verify(_chain3_null_in_middle(True))
    assert not r.ok
    assert any("v=1" in e and "header hash mismatch" in e for e in r.errors), r.errors


def test_header_recipe_not_applying_below_null_error_text():
    def bad(*a):
        r = bnv._null_body_recipe(*a)
        r["h"] = {"subject": [{"c": [90, 99]}]}
        return r
    headers, body = bnv.load_base()
    r = _verify(bnv._null_body_chain([
        (headers, body),
        (bnv._subject_prefixed(headers, b"list"), body + b"rewritten\r\n", bad),
    ]))
    assert not r.ok
    from dkim2verify import _malformed_recipe_error
    assert _malformed_recipe_error(2) in r.errors, r.errors
    assert not any("signature" in e.lower() and "verif" in e.lower()
                   for e in r.errors), r.errors


def _empty_body(forge):
    headers, _ = bnv.load_base()
    h2 = bnv._subject_prefixed(headers, b"list")
    if forge:
        h2 = bnv._to_changed(h2)
    return bnv._null_body_chain([
        (headers, b""),
        (h2, b"", bnv._forged_recipe if forge else bnv._footer_recipe),
    ])


def test_empty_body_header_only_recipe_passes():
    r = _verify(_empty_body(False))
    assert r.ok, r.errors


def test_empty_body_hidden_to_change_fails():
    r = _verify(_empty_body(True))
    assert not r.ok
    assert any("v=1" in e and "header hash mismatch" in e for e in r.errors), r.errors


def test_pass_message_notes_unchecked_body():
    r = _verify(bnv.build_positive_null_body())
    assert "body not checked below m=2" in r.message, r.message
    assert "body not checked" not in _verify(bnv.build_positive_bottom_recipe()).message
