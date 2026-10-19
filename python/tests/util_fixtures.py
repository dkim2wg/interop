"""The shared fixture builders in util/, loaded for this suite.

util/build-negative-vectors.py (bnv) and util/build-signer-gate-fixtures.py
(fx) build their chains from perl/tests/emails/brong-orig.eml, whose From is
brong@fastmailteam.com while i=1 signs as test1.dkim2.com.  Under -07 §11
that From is not Authentic, so every chain built from it is a PERMERROR.
This suite points the builders at tests/emails/brong-orig.eml instead: the
same message with From: brong@test1.dkim2.com.
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
bnv.SRC = os.path.join(HERE, "emails", "brong-orig.eml")
fx = _load("build_signer_gate_fixtures", "build-signer-gate-fixtures.py")
fx.bnv.SRC = bnv.SRC
