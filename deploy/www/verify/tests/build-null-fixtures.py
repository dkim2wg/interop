#!/usr/bin/env python3
"""Build re-signed null-body-Recipe fixtures for null-body.test.mjs.
Usage: build-null-fixtures.py <outdir>.  Reuses the chain builder in
util/build-negative-vectors.py (imported, not modified)."""
import importlib.util, os, sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), *[".."] * 4))
spec = importlib.util.spec_from_file_location(
    "bnv", os.path.join(REPO, "util", "build-negative-vectors.py"))
bnv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bnv)
ds = bnv.ds
chain, nullr, forged, plain = bnv._null_body_chain, bnv._null_body_recipe, bnv._forged_recipe, bnv._footer_recipe
sub, tochg = bnv._subject_prefixed, bnv._to_changed


def custom(mutate):
    def f(*a):
        r = plain(*a) or {}
        mutate(r)
        return r
    return f


def null_below_ordinary(forge):
    h, b = bnv.load_base()
    h2 = sub(h, b"list")
    if forge:
        h2 = tochg(h2)
    # m=3 ordinary: header-only Recipe, body unchanged
    return chain([(h, b), (h2, b + b"rewritten\r\n", forged if forge else nullr),
                  (sub(h2, b"fwd"), b + b"rewritten\r\n", plain)])


def empty_body(null, forge):
    h, _ = bnv.load_base()
    h2 = sub(h, b"list")
    if forge:
        h2 = tochg(h2)
    def forged_plain(*a):
        r = plain(*a) or {}
        r["h"] = {k: v for k, v in r.get("h", {}).items() if k.lower() != "to"}
        return r
    rec = (forged if forge else nullr) if null else (forged_plain if forge else plain)
    return chain([(h, b""), (h2, b"", rec)])


def bad_body_below_null(bad_b):
    h, b = bnv.load_base()
    h2 = sub(h, b"fwd")
    h3 = sub(h2, b"list")
    def m2(*a):
        r = plain(*a) or {}
        r["b"] = bad_b
        return r
    return chain([(h, b), (h2, b + b"x\r\n", m2), (h3, b + b"y\r\n", nullr)])


def bad_header_below_null():
    h, b = bnv.load_base()
    h2 = sub(h, b"fwd")
    h3 = sub(h2, b"list")
    def m2(*a):
        r = plain(*a) or {}
        r["h"] = dict(r.get("h", {}), subject=[{"c": [5, 9]}])
        return r
    return chain([(h, b), (h2, b + b"x\r\n", m2), (h3, b + b"y\r\n", nullr)])


FIX = {
    "null-below-ordinary.eml": lambda: null_below_ordinary(False),
    "null-below-ordinary-forged.eml": lambda: null_below_ordinary(True),
    "empty-body-null.eml": lambda: empty_body(True, False),
    "empty-body-null-forged.eml": lambda: empty_body(True, True),
    "empty-body-plain.eml": lambda: empty_body(False, False),
    "empty-body-plain-forged.eml": lambda: empty_body(False, True),
    "bad-body-int-below-null.eml": lambda: bad_body_below_null(5),
    "bad-body-steps-below-null.eml": lambda: bad_body_below_null([{"c": [3, 1]}]),
    "bad-header-below-null.eml": bad_header_below_null,
}

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
for name, fn in FIX.items():
    open(os.path.join(out, name), "wb").write(fn())
