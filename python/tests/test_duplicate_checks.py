import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2verify import _check_signature_duplicates  # noqa: E402


def test_clean_signature_list_has_no_errors():
    items = [("sel1", "rsa-sha256", "AAA"), ("sel2", "ed25519-sha256", "BBB")]
    assert _check_signature_duplicates(items, "1") == []


def test_duplicate_selector_is_permerror():
    # spec-06 §8.9: a Selector MUST NOT be present more than once
    items = [("sel1", "rsa-sha256", "AAA"), ("sel1", "ed25519-sha256", "BBB")]
    errs = _check_signature_duplicates(items, "3")
    assert errs == ["PERMERROR DKIM2-Signature i=3 has a duplicate selector"]


def test_duplicate_selector_is_case_insensitive():
    # Selector is a Domain (§3.5); DNS names are case-insensitive
    items = [("Sel1", "rsa-sha256", "AAA"), ("sel1", "ed25519-sha256", "BBB")]
    assert "has a duplicate selector" in _check_signature_duplicates(items, "1")[0]


def test_same_algorithm_twice_with_distinct_selectors_is_allowed():
    # spec-06 §8.9: one additional signature using the same algorithm MAY be
    # present provided a different Selector is used
    items = [("sel1", "rsa-sha256", "AAA"), ("sel2", "rsa-sha256", "BBB")]
    assert _check_signature_duplicates(items, "1") == []


def test_same_algorithm_three_times_has_excess_selectors():
    items = [("sel1", "rsa-sha256", "AAA"), ("sel2", "rsa-sha256", "BBB"),
             ("sel3", "rsa-sha256", "CCC")]
    errs = _check_signature_duplicates(items, "2")
    assert errs == ["PERMERROR DKIM2-Signature i=2 has more selectors than allowed"]


def test_duplicate_selector_and_excess_selector_are_independent():
    # two sigs sharing an algorithm AND a selector is a duplicate-selector
    # error but NOT an excess-selector error (the count is 2, not 3+)
    items = [("sel1", "rsa-sha256", "AAA"), ("sel1", "rsa-sha256", "BBB")]
    errs = _check_signature_duplicates(items, "1")
    assert any("duplicate selector" in e for e in errs)
    assert not any("more selectors than allowed" in e for e in errs)


def test_duplicate_mi_version_is_permerror_inbound_and_outbound():
    import json
    import dkim2verify
    import dkim2sign
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))
    dns = json.load(open(os.path.join(root, "dns.json")))
    eml = (b"From: a@test1.dkim2.com\r\nTo: b@test2.dkim2.com\r\n"
           b"Subject: x\r\n\r\nbody\r\n")
    headers, body = dkim2sign.parse_message(eml)
    mi1 = dkim2sign.build_message_instance(headers, body, version=1)
    raw = (mi1.encode() + b"\r\n" + mi1.encode() + b"\r\n"
           + b"\r\n".join(headers) + b"\r\n\r\n" + body)
    for allow in (False, True):
        r = dkim2verify.verify_message(raw, dns, allow_unsigned_mi=allow,
                                       skip_timestamp_check=True)
        assert r.status == 'permerror', (allow, r)
        assert 'duplicate Message-Instance m=1' in r.message, r.message


def test_malformed_mi_m_is_clean_permerror():
    import json
    import dkim2verify
    here = os.path.dirname(os.path.abspath(__file__))
    dns = json.load(open(os.path.join(os.path.dirname(os.path.dirname(here)), "dns.json")))
    for bad in ("abc", "", "1x", "-1"):
        raw = (f"Message-Instance: m={bad}; h=sha256:AA:BB\r\n"
               "From: a@test1.dkim2.com\r\n\r\nbody\r\n").encode()
        for allow in (False, True):
            r = dkim2verify.verify_message(raw, dns, allow_unsigned_mi=allow)
            assert r.status == 'permerror', (bad, allow, r)
            assert 'malformed m= tag' in r.message, r.message
