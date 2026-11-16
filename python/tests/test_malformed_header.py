"""A line in the header section that is not a header field (CVE-2026-129847,
reported against Mail::DKIM2 0.34): no colon, WSP or nothing before the
colon, or a first line that starts with WSP (a continuation of nothing).

Python never dropped such a line -- it hashed it as a field of its own --
so the attack failed closed here, but as a header hash mismatch, not the
fault itself.  Every verifier now says "PERMERROR: malformed header field"
for a message with any DKIM2 field, before anything else (the chain's
structure included); a message with none is still "none".  The signer
refuses such a message.

Fixtures are the negative vectors from util/build-negative-vectors.py: a
genuinely signed message with one such line added afterwards.
"""
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
import dkim2sign  # noqa: E402
import dkim2verify  # noqa: E402

sys.path.insert(0, HERE)
from util_fixtures import bnv  # noqa: E402

with open(os.path.join(ROOT, "dns.json")) as _fh:
    DNS = json.load(_fh)
KEY = os.path.join(ROOT, "keys", "sel1._domainkey.test1.dkim2.com.pem")
WANT = "PERMERROR: malformed header field"

BUILDERS = {
    "no-colon": bnv.build_malformed_header_no_colon,
    "wsp-in-name": bnv.build_malformed_header_wsp_in_name,
    "empty-name": bnv.build_malformed_header_empty_name,
    "leading-wsp": bnv.build_malformed_header_leading_wsp,
    # Two faults: m=2 missing (C9 step f) as well; this one is first.
    "instance-gap": bnv.build_multi_malformed_header_instance_gap,
}

PLAIN = (b"From: brong@test1.dkim2.com\r\nTo: x@example.com\r\n"
         b"Subject: hi\r\n\r\nbody\r\n")


@pytest.mark.parametrize("field,bad", [
    (b"Subject: x", False),
    (b"Subject : x", False),
    (b"Subject:", False),
    (b"Subject\r\n : x", True),           # a fold before the colon
    (b"Subject: x\r\n\tmore", False),
    (b"NoColonHere", True),
    (b"Sub ject: x", True),
    (b":Empty: x", True),
    (b" Subject: evil", True),             # first line, starts with SP
    (b"\tSubject: evil", True),            # ... or HTAB
])
def test_malformed_header_field(field, bad):
    assert dkim2sign.malformed_header_field(field) is bad


def test_parse_message_keeps_a_leading_continuation_line():
    headers, _ = dkim2sign.parse_message(b" Subject: evil\r\n" + PLAIN)
    assert headers[0] == b" Subject: evil"
    assert dkim2sign.malformed_header(headers)
    assert not dkim2sign.malformed_header(dkim2sign.parse_message(PLAIN)[0])


def test_parse_message_joins_many_folds():
    """parse_message() joins a field's lines once (it was quadratic in the
    folds); the fields it gives are unchanged.  Output pinned, not time."""
    n = 20000
    raw = b"X-Long: a" + b"\r\n \tb" * n + b"\r\nSubject: x\r\n\r\nbody\r\n"
    headers, body = dkim2sign.parse_message(raw)
    assert headers == [b"X-Long: a" + b"\r\n \tb" * n, b"Subject: x"]
    assert body == b"body\r\n"
    assert not dkim2sign.malformed_header(headers)


@pytest.mark.parametrize("name", sorted(BUILDERS))
@pytest.mark.parametrize("kw", [
    {},                                              # simple
    {"full_chain": True},                            # planned walk (streaming)
    {"full_chain": True, "walk": "undo"},            # undo walk
    {"headers_only": True},
])
def test_verifier_permerror_first(name, kw):
    msg = BUILDERS[name]()
    r = dkim2verify.verify_message(msg, DNS, skip_timestamp_check=True, **kw)
    assert r.status == "permerror"
    assert r.errors[0] == WANT


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_message_verifier_byte_at_a_time(name):
    """The incremental verifier, fed one byte at a time, splits the header
    block itself: it sees the line too."""
    msg = BUILDERS[name]()
    v = dkim2verify.MessageVerifier(DNS, full_chain=True,
                                    skip_timestamp_check=True)
    for i in range(len(msg)):
        v.feed(msg[i:i + 1])
    r = v.close()
    assert r.status == "permerror"
    assert r.errors[0] == WANT


def test_no_dkim2_field_is_still_none():
    for line in (b"NoColonHere\r\n", b" Subject: evil\r\n"):
        r = dkim2verify.verify_message(line + PLAIN, DNS, full_chain=True)
        assert r.status == "none"


def test_cli_reports_it(tmp_path, capsys):
    p = tmp_path / "m.eml"
    p.write_bytes(BUILDERS["no-colon"]())
    sys.argv = ["dkim2verify.py", str(p), "--dns-json",
                os.path.join(ROOT, "dns.json"), "--full-chain",
                "--skip-timestamp-check"]
    with pytest.raises(SystemExit) as e:
        dkim2verify.main()
    assert e.value.code != 0
    assert WANT in capsys.readouterr().out


@pytest.mark.parametrize("line,first", [
    (b"NoColonHere\r\n", False), (b"Sub ject: x\r\n", False),
    (b":Empty: x\r\n", False), (b" Subject: evil\r\n", True),
])
def test_signer_refuses(line, first):
    """Refused whether or not the message already has a chain, and even
    with the upstream gate bypassed."""
    for msg in (bnv._with_header_line(PLAIN, line, first),
                bnv._with_header_line(bnv.build_positive_control(), line, first)):
        for skip in (False, True):
            with pytest.raises(dkim2sign.SigningRefused) as e:
                dkim2sign.sign_message(
                    msg, "sel1", "test1.dkim2.com", KEY,
                    mailfrom="brong@test1.dkim2.com", rcptto=["x@example.com"],
                    dns_data=DNS, skip_timestamp_check=True,
                    skip_upstream_check=skip)
            assert str(e.value) == "not signing: malformed header field"


def test_signer_signs_a_well_formed_message():
    out = dkim2sign.sign_message(
        PLAIN, "sel1", "test1.dkim2.com", KEY,
        mailfrom="brong@test1.dkim2.com", rcptto=["x@example.com"],
        dns_data=DNS)
    assert out.startswith(b"DKIM2-Signature:")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
