"""The shared fixture builders in util/, loaded for this suite.

util/build-negative-vectors.py (bnv) and util/build-signer-gate-fixtures.py
(fx) have hyphens in their names, so they are loaded by path.  Both build
their chains from perl/tests/emails/brong-orig.eml, whose From
(brong@test1.dkim2.com) is Authentic for i=1 (-07 §11).
"""
import importlib.util
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(ROOT, "util", filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bnv = _load("bnv", "build-negative-vectors.py")
fx = _load("build_signer_gate_fixtures", "build-signer-gate-fixtures.py")
