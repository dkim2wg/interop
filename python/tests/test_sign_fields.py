"""BodyHasher and sign_fields(): signing without ever holding the whole
message -- the header fields, a body hash made as the body arrived, and the
verdict of a verifier that was fed the same pieces."""
import os
import random
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import dkim2sign  # noqa: E402
import dkim2verify  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(HERE))
DNS = dkim2verify.load_dns_json(os.path.join(ROOT, "dns.json"))
KEY1 = os.path.join(ROOT, "keys", "sel1._domainkey.test1.dkim2.com.pem")
KEY2 = os.path.join(ROOT, "keys", "sel1._domainkey.test2.dkim2.com.pem")
T = 1740000000

HEAD = (b"From: Alice <alice@test1.dkim2.com>\r\nTo: list@test2.dkim2.com\r\n"
        b"Subject: streaming\r\n")
BODY = b"line one\r\nline two\r\n\r\nlast line\r\n"
MESSAGE = HEAD + b"\r\n" + BODY


def pieces(data, rng, most=7):
    out, i = [], 0
    while i < len(data):
        n = rng.randint(1, most)
        out.append(data[i:i + n])
        i += n
    return out


BODIES = [
    b"", b"\r\n", b"\r\n\r\n\r\n", b"x", b"x\r\n", b"x\r\n\r\n\r\n", b"x\r\n\r\ny",
    b"x\r\n\r\n\r\ny\r\n\r\n", b"bare\nlf\n\n", b"bare\rcr\r\r", b"mixed\r\n\n\r\r\n",
    b"ends in cr\r", b"\r", b"\r\r\n", b"a\r\n" * 500, BODY,
]


@pytest.mark.parametrize("body", BODIES, ids=range(len(BODIES)))
def test_body_hasher_is_compute_body_hash(body):
    rng = random.Random(len(body))
    for alg in ("sha256", "sha512"):
        want = dkim2sign.compute_body_hash(body, alg)
        whole = dkim2sign.BodyHasher([alg])
        whole.feed(body)
        assert whole.digest(alg) == want
        for _ in range(20):
            h = dkim2sign.BodyHasher([alg])
            for piece in pieces(body, rng):
                h.feed(piece)
            assert h.digest(alg) == want, body


def test_body_hasher_several_algorithms_and_digest_twice():
    h = dkim2sign.BodyHasher(["sha256", "sha512"])
    h.feed(BODY[:10])
    early = h.digest()
    h.feed(BODY[10:])
    assert early == dkim2sign.compute_body_hash(BODY[:10])
    assert h.digests() == {alg: dkim2sign.compute_body_hash(BODY, alg)
                           for alg in ("sha256", "sha512")}
    assert h.digest() == h.digest()


def hashes(body, algs=("sha256",)):
    h = dkim2sign.BodyHasher(algs)
    h.feed(body)
    return h.digests()


def test_sign_fields_gives_what_sign_message_prepends():
    headers, _body = dkim2sign.parse_message(MESSAGE)
    whole = dkim2sign.sign_message(MESSAGE, "sel1", "test1.dkim2.com", KEY1,
                                   mailfrom="<alice@test1.dkim2.com>",
                                   rcptto=["<list@test2.dkim2.com>"], timestamp=T)
    fields = dkim2sign.sign_fields(headers, hashes(BODY), "sel1", "test1.dkim2.com", KEY1,
                                   mailfrom="<alice@test1.dkim2.com>",
                                   rcptto=["<list@test2.dkim2.com>"], timestamp=T)
    assert [f.split(":", 1)[0] for f in fields] == ["DKIM2-Signature", "Message-Instance"]
    assert b"".join(f.encode() + b"\r\n" for f in fields) + MESSAGE == whole


def signed_once():
    return dkim2sign.sign_message(MESSAGE, "sel1", "test1.dkim2.com", KEY1,
                                  mailfrom="<alice@test1.dkim2.com>",
                                  rcptto=["<list@test2.dkim2.com>"], timestamp=T)


def streamed_verdict(message, rng):
    v = dkim2verify.MessageVerifier(DNS, full_chain=True, skip_timestamp_check=True,
                                    allow_unsigned_mi=True)
    for piece in pieces(message, rng, most=40):
        v.feed(piece)
    return v.close()


def test_second_hop_from_pieces_verifies():
    """The message is seen once, in pieces: a verifier and a body hasher are
    fed as it arrives, and the signature is made from the header fields."""
    first = signed_once()
    headers, body = dkim2sign.parse_message(first)
    verdict = streamed_verdict(first, random.Random(1))
    assert verdict.ok, verdict.message

    fields = dkim2sign.sign_fields(headers, hashes(body), "sel1", "test2.dkim2.com", KEY2,
                                   mailfrom="<list-bounces@test2.dkim2.com>",
                                   rcptto=["<sub@example.net>"], timestamp=T,
                                   upstream=verdict, exploded=True)
    # nothing changed, so it signs over the instance that is there
    assert [f.split(":", 1)[0] for f in fields] == ["DKIM2-Signature"]
    assert "f=exploded" in fields[0]
    second = b"".join(f.encode() + b"\r\n" for f in fields) + first
    result = dkim2verify.verify_message(second, DNS, full_chain=True, skip_timestamp_check=True)
    assert result.ok, result.message
    assert second == dkim2sign.sign_message(
        first, "sel1", "test2.dkim2.com", KEY2, mailfrom="<list-bounces@test2.dkim2.com>",
        rcptto=["<sub@example.net>"], timestamp=T, exploded=True, dns_data=DNS,
        skip_timestamp_check=True)


def test_a_chain_nobody_verified_is_not_extended():
    headers, body = dkim2sign.parse_message(signed_once())
    with pytest.raises(dkim2sign.SigningRefused, match="has not been verified"):
        dkim2sign.sign_fields(headers, hashes(body), "sel1", "test2.dkim2.com", KEY2,
                              mailfrom="<list-bounces@test2.dkim2.com>",
                              rcptto=["<sub@example.net>"], timestamp=T)


def test_a_failing_verdict_is_refused():
    first = signed_once()
    tampered = first.replace(b"line two", b"line 2")
    headers, body = dkim2sign.parse_message(tampered)
    verdict = streamed_verdict(tampered, random.Random(2))
    assert not verdict.ok
    with pytest.raises(dkim2sign.SigningRefused, match="upstream DKIM2 chain result=fail"):
        dkim2sign.sign_fields(headers, hashes(body), "sel1", "test2.dkim2.com", KEY2,
                              mailfrom="<list-bounces@test2.dkim2.com>",
                              rcptto=["<sub@example.net>"], timestamp=T, upstream=verdict)


def test_from_check_still_applies():
    headers, _body = dkim2sign.parse_message(MESSAGE)
    with pytest.raises(dkim2sign.SigningRefused, match="not Authentic for d=test2.dkim2.com"):
        dkim2sign.sign_fields(headers, hashes(BODY), "sel1", "test2.dkim2.com", KEY2,
                              mailfrom="<x@test2.dkim2.com>", rcptto=["<y@example.net>"])


def test_instance_from_hashes_is_build_message_instance():
    headers, _body = dkim2sign.parse_message(MESSAGE)
    for algs in (["sha256"], ["sha512"], ["sha256", "sha512"]):
        assert (dkim2sign.build_message_instance_from_hashes(headers, hashes(BODY, algs), version=3)
                == dkim2sign.build_message_instance(headers, BODY, version=3, algs=algs))
