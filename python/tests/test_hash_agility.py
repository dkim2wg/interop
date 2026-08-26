import base64
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2sign import HASH_ALGS, compute_body_hash  # noqa: E402
from dkim2verify import parse_hash_sets, verify_message_instance  # noqa: E402


def test_registry_has_both_algorithms():
    # spec-05 §3: Verifiers MUST implement all four algorithms
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
