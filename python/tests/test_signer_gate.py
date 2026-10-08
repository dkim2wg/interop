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


def test_null_top_refusal_says_unsigned():
    # i=1 covers only m=1; the null m=2 is unsigned, so it is refused.
    with pytest.raises(dkim2sign.SigningRefused,
                       match="unsigned top Message-Instance m=2 has a null body Recipe"):
        _sign(fx.build_null_top())


def test_signed_null_top_signs_without_option():
    # The list domain signed its null m=2 (i=2, m=2): a forwarder extends it.
    out = _sign(fx.build_null_top_signed())
    assert _top_i(out) == 3
    first = out.split(b"\r\n", 1)[0].decode()
    assert " m=2;" in first          # unchanged: no new Message-Instance
    assert _top_i(_sign(fx.build_null_top_signed(),
                        allow_null_body_recipe=True)) == 3


def test_null_below_unsigned_top_refused_then_signed_with_option():
    # Unsigned null m=2 under an unsigned ordinary m=3; i=1 covers only m=1.
    # The null is not the top, but nothing covers it: refused like null-top.
    with pytest.raises(dkim2sign.SigningRefused,
                       match="unsigned Message-Instance m=2 has a null body Recipe"):
        _sign(fx.build_null_below_unsigned_top())
    assert _top_i(_sign(fx.build_null_below_unsigned_top(),
                        allow_null_body_recipe=True)) == 2


def test_null_below_signed_signs_without_option():
    # The null m=2 is covered by a valid i=2/m=2; only an ordinary m=3 is
    # unsigned on top of it.
    out = _sign(fx.build_null_below_signed())
    assert _top_i(out) == 3
    assert _top_i(_sign(fx.build_null_below_signed(),
                        allow_null_body_recipe=True)) == 3


@pytest.mark.parametrize("name", sorted(fx.FAKE_COVER))
@pytest.mark.parametrize("allow", [False, True])
def test_fake_coverage_signature_refused(name, allow):
    # null-top plus a DKIM2-Signature naming m=2 that cannot be keyed (no i=,
    # i=0, i=abc, the real i=1 signature with m rewritten, unparseable): it
    # is not coverage, and the chain itself is a PERMERROR, so the signer
    # refuses with or without the option -- and never with a traceback.
    msg = fx._fake_cover(fx.FAKE_COVER[name])
    with pytest.raises(dkim2sign.SigningRefused, match="not signing"):
        _sign(msg, allow_null_body_recipe=allow)


@pytest.mark.parametrize("ival", ["", "0", "abc", "-1", "\u0661"])
def test_verifier_permerror_on_unkeyable_signature(ival):
    import dkim2verify
    msg = (f"DKIM2-Signature: i={ival}; m=2; d=evil.example\r\n").encode() \
        + fx.build_null_top_signed()
    r = dkim2verify.verify_message(msg, DNS, full_chain=True,
                                   skip_timestamp_check=True)
    assert r.status == "permerror"
    assert "malformed i= tag" in r.message


def test_verifier_permerror_on_signature_without_i():
    import dkim2verify
    msg = b"DKIM2-Signature: m=2; d=evil.example\r\n" + fx.build_null_top_signed()
    r = dkim2verify.verify_message(msg, DNS, full_chain=True,
                                   skip_timestamp_check=True)
    assert r.status == "permerror"
    assert "missing or malformed i= tag" in r.message


def test_get_seq_from_sig_never_raises():
    assert dkim2sign._get_seq_from_sig("DKIM2-Signature: i=abc; m=1") == 0
    assert dkim2sign._get_seq_from_sig("DKIM2-Signature: m=1") == 0
    assert dkim2sign._get_seq_from_sig("DKIM2-Signature: i = 7 ; m=1") == 7


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


def _nd_top_chain(nd):
    """test1's i=1 signature carrying nd=<nd>, as it arrives at test3."""
    import gate_env  # noqa: F401
    eml = (b"From: sender@test1.dkim2.com\r\nTo: rcpt@test3.dkim2.com\r\n"
           b"Subject: hello\r\n\r\nbody line\r\n")
    headers, body = dkim2sign.parse_message(eml)
    mi1 = dkim2sign.build_message_instance(headers, body, version=1)
    key1, alg1 = dkim2sign.load_private_key(os.path.join(
        ROOT, "keys", "ed25519._domainkey.test1.dkim2.com.pem"))
    sig1 = dkim2sign.build_dkim2_signature(
        [], [], mi1, "test1.dkim2.com", "ed25519", key1, alg1,
        seq=1, mi_version=1, timestamp=1740000000, next_domain=nd)
    return (sig1.encode() + b"\r\n" + mi1.encode() + b"\r\n"
            + b"\r\n".join(headers) + b"\r\n\r\n" + body)


def test_nd_naming_us_is_signed():
    out = _sign(_nd_top_chain("TEST3.dkim2.com"), allow_null_body_recipe=True)
    assert _top_i(out) == 2


def test_nd_naming_another_domain_is_refused():
    with pytest.raises(dkim2sign.SigningRefused,
                       match="top signature nd=test2.dkim2.com names another domain"):
        _sign(_nd_top_chain("test2.dkim2.com"))
