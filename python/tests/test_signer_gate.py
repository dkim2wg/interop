"""Signer gate: sign_message() verifies an existing DKIM2 chain first.

Fixtures come from util/build-signer-gate-fixtures.py (messages as they arrive
at the next hop, test3.dkim2.com, which is about to sign).
"""
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
import dkim2sign  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "build_signer_gate_fixtures",
    os.path.join(ROOT, "util", "build-signer-gate-fixtures.py"))
fx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fx)

KEY = os.path.join(ROOT, "keys", "sel1._domainkey.test3.dkim2.com.pem")
with open(os.path.join(ROOT, "dns.json")) as _fh:
    DNS = json.load(_fh)


def _sign(msg, **kw):
    kw.setdefault("dns_data", DNS)
    kw.setdefault("skip_timestamp_check", True)
    return dkim2sign.sign_message(
        msg, "sel1", "test3.dkim2.com", KEY, mailfrom="<list@test3.dkim2.com>",
        rcptto=["<subscriber@test4.dkim2.com>"], **kw)


def _top_i(out):
    first = out.split(b"\r\n", 1)[0].decode()
    assert first.startswith("DKIM2-Signature:"), first
    return int(first.split("i=")[1].split(";")[0])


def test_fresh_signs_without_any_dns():
    out = dkim2sign.sign_message(
        fx.build_fresh(), "sel1", "test3.dkim2.com", KEY,
        mailfrom="<list@test3.dkim2.com>", rcptto=["<s@test4.dkim2.com>"])
    assert _top_i(out) == 1


def test_valid_chain_signs():
    assert _top_i(_sign(fx.build_valid_chain())) == 2


def test_broken_signature_refused():
    with pytest.raises(dkim2sign.SigningRefused, match="upstream DKIM2 chain"):
        _sign(fx.build_broken_signature())


def test_broken_mi_chain_refused():
    with pytest.raises(dkim2sign.SigningRefused):
        _sign(fx.build_broken_mi_chain())


def test_null_top_refused_by_default():
    with pytest.raises(dkim2sign.SigningRefused, match="null body Recipe"):
        _sign(fx.build_null_top())


def test_null_top_signed_with_option():
    assert _top_i(_sign(fx.build_null_top(), allow_null_body_recipe=True)) == 2


def test_forged_null_top_refused_even_with_option():
    with pytest.raises(dkim2sign.SigningRefused):
        _sign(fx.build_null_top_forged(), allow_null_body_recipe=True)


def test_old_timestamps_refused_unless_ignored():
    with pytest.raises(dkim2sign.SigningRefused):
        _sign(fx.build_valid_chain(), skip_timestamp_check=False)


def test_chain_without_key_source_refused(monkeypatch):
    monkeypatch.delenv("DKIM2_DNS_JSON", raising=False)
    with pytest.raises(dkim2sign.SigningRefused, match="no DNS data"):
        _sign(fx.build_valid_chain(), dns_data=None)


def test_dns_json_env_honoured(monkeypatch):
    monkeypatch.setenv("DKIM2_DNS_JSON", os.path.join(ROOT, "dns.json"))
    assert _top_i(_sign(fx.build_valid_chain(), dns_data=None)) == 2


def test_mi_only_signs_without_keys(monkeypatch):
    monkeypatch.delenv("DKIM2_DNS_JSON", raising=False)
    out = dkim2sign.sign_message(
        fx.build_mi_only(), "sel1", "test3.dkim2.com", KEY,
        mailfrom="<list@test3.dkim2.com>", rcptto=["<s@test4.dkim2.com>"])
    assert _top_i(out) == 1


def test_mi_only_broken_refused_for_the_chain_not_the_signature():
    with pytest.raises(dkim2sign.SigningRefused) as e:
        _sign(fx.build_mi_only_broken())
    assert "no DKIM2-Signature" not in str(e.value)


def test_mi_only_null_refused_then_signed_with_option():
    with pytest.raises(dkim2sign.SigningRefused, match="null body Recipe"):
        _sign(fx.build_mi_only_null())
    assert _top_i(_sign(fx.build_mi_only_null(), allow_null_body_recipe=True)) == 1
