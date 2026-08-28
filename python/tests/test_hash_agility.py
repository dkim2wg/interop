import base64
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2sign import HASH_ALGS, compute_body_hash, compute_header_hash  # noqa: E402
from dkim2verify import parse_hash_sets, verify_message_instance  # noqa: E402


def test_registry_has_both_algorithms():
    # spec-06 §3: Verifiers MUST implement all four algorithms
    assert set(HASH_ALGS) == {"sha256", "sha512"}


def test_parse_multiple_hash_sets():
    sets = parse_hash_sets("sha256:AAA:BBB,sha512:CCC:DDD")
    assert sets == [("sha256", "AAA", "BBB"), ("sha512", "CCC", "DDD")]


def test_parse_hash_name_is_case_insensitive():
    # RFC 5234 quoted strings are case-insensitive
    assert parse_hash_sets("SHA256:AAA:BBB")[0][0] == "sha256"


def test_body_hash_sha512_differs_and_is_64_bytes():
    b = b"Hello\r\n"
    assert len(compute_body_hash(b, "sha512")) == 64
    assert len(compute_body_hash(b, "sha256")) == 32
    assert compute_body_hash(b, "sha512") != compute_body_hash(b, "sha256")


def test_sha512_body_hash_matches_hashlib():
    # canonical body for "Hello\r\n" is unchanged (one trailing CRLF)
    assert compute_body_hash(b"Hello\r\n", "sha512") == hashlib.sha512(b"Hello\r\n").digest()


def _mi(h_tag):
    return f"Message-Instance: m=1; h={h_tag};"


def test_unknown_algorithm_alone_fails_closed(monkeypatch):
    # §3.4 says ignore unimplemented algorithms, but an MI with no implemented
    # hash-set cannot be verified and MUST NOT be left at pass.
    errs = verify_message_instance(_mi("x-whirlpool:AAA:BBB"), [b"From: a@b\r\n"], b"x\r\n")
    assert any("no supported hash algorithm" in e for e in errs)


def test_duplicate_algorithm_is_permerror():
    errs = verify_message_instance(_mi("sha256:AAA:BBB,sha256:CCC:DDD"),
                                   [b"From: a@b\r\n"], b"x\r\n")
    assert any("has a duplicate hash algorithm" in e for e in errs)


def test_duplicate_algorithm_detected_case_insensitively():
    errs = verify_message_instance(_mi("sha256:AAA:BBB,SHA256:CCC:DDD"),
                                   [b"From: a@b\r\n"], b"x\r\n")
    assert any("has a duplicate hash algorithm" in e for e in errs)


# --- Review round 1 findings -------------------------------------------------

def test_malformed_base64_hash_value_is_permerror_not_crash():
    # §11.2: verifiers MUST meticulously validate format and values. A
    # hostile/corrupt h= value must not raise an uncaught exception.
    headers = [b"From: a@b\r\n"]
    body = b"x\r\n"
    errs = verify_message_instance(_mi("sha256:!!!notb64!!!:AAAA"), headers, body)
    assert any("PERMERROR" in e and "not valid base64" in e and "sha256" in e
               for e in errs)


def test_mixed_hash_sets_sha512_wrong_fails_and_names_sha512():
    headers = [b"From: a@b\r\n"]
    body = b"x\r\n"
    h256 = base64.b64encode(compute_header_hash(headers, "sha256")).decode()
    b256 = base64.b64encode(compute_body_hash(body, "sha256")).decode()
    h_tag = f"sha256:{h256}:{b256},sha512:AAAA:AAAA"
    errs = verify_message_instance(_mi(h_tag), headers, body)
    assert errs
    assert any("sha512" in e and "mismatch" in e for e in errs)
    assert not any("sha256" in e and "mismatch" in e for e in errs)


def test_mixed_hash_sets_sha256_wrong_fails_and_names_sha256():
    # Mirror case: correct sha512, wrong sha256 — confirms the all-must-pass
    # loop over hash-sets is not short-circuiting on the first algorithm.
    headers = [b"From: a@b\r\n"]
    body = b"x\r\n"
    h512 = base64.b64encode(compute_header_hash(headers, "sha512")).decode()
    b512 = base64.b64encode(compute_body_hash(body, "sha512")).decode()
    h_tag = f"sha256:AAAA:AAAA,sha512:{h512}:{b512}"
    errs = verify_message_instance(_mi(h_tag), headers, body)
    assert errs
    assert any("sha256" in e and "mismatch" in e for e in errs)
    assert not any("sha512" in e and "mismatch" in e for e in errs)
