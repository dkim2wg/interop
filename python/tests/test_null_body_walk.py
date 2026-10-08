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
