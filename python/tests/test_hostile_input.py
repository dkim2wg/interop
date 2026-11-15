"""Hostile input a sender can produce cheaply: none of it may cost the
verifier more than the message is worth.

Each case here was found by an adversarial review (2026-11-14) of the
verifier as a milter runs it: fed the header fields, then the body in
pieces, with keys looked up in the DNS.
"""
import base64
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
import dkim2dns  # noqa: E402
import dkim2domain  # noqa: E402
import dkim2sign  # noqa: E402
import dkim2verify  # noqa: E402
from test_plan_corpus import compare  # noqa: E402

DNS = dkim2verify.load_dns_json(os.path.join(ROOT, "dns.json"))
KEY1 = os.path.join(ROOT, "keys", "sel1._domainkey.test1.dkim2.com.pem")
HEAD = [b"From: Alice <alice@test1.dkim2.com>", b"To: list@test2.dkim2.com",
        b"Subject: hostile"]
BODY = b"".join(b"line %d\r\n" % i for i in range(40))


def with_recipe(recipe, body=BODY):
    """A message whose m=2 carries `recipe` over a signed m=1.  The hashes
    of m=2 are right; what the Recipe rebuilds is the Recipe's business."""
    raw = b"\r\n".join(HEAD) + b"\r\n\r\n" + body
    first = dkim2sign.sign_message(raw, "sel1", "test1.dkim2.com", KEY1,
                                   mailfrom="<alice@test1.dkim2.com>",
                                   rcptto=["<list@test2.dkim2.com>"], timestamp=1740000000)
    headers, body = dkim2sign.parse_message(first)
    mi2 = dkim2sign.build_message_instance(headers, body, version=2, recipe=recipe)
    return mi2.encode() + b"\r\n" + first


def streamed(raw, size=4096):
    v = dkim2verify.MessageVerifier(DNS, full_chain=True, skip_timestamp_check=True,
                                    allow_unsigned_mi=True)
    for i in range(0, len(raw), size):
        v.feed(raw[i:i + size])
    return v, v.close()


@pytest.mark.parametrize("recipe", [
    {"h": {"message-instance": []}},
    {"h": {"message-instance": [{"d": ["m=1; h=sha256:AAAA:AAAA;"]}]}},
    {"h": {"message-instance": [{"c": [1, 1]}]}},
    {"h": {"dkim2-signature": []}},
    {"h": {"dkim2-signature": [{"d": ["i=1; m=1"]}], "subject": [{"d": ["hostile"]}]}},
], ids=["mi-remove", "mi-literal", "mi-copy", "sig-remove", "sig-literal"])
def test_recipe_naming_dkim2_fields_keeps_the_plan(recipe):
    """Such a Recipe used to send the message to the undo walk, which keeps
    the body and rebuilds it at every level."""
    raw = with_recipe(recipe)
    compare(raw, DNS)                      # the plan and the undo walk agree
    v, _result = streamed(raw)
    assert v._pass is not None             # planned: hashed as it arrived
    assert len(v._body) == 0               # and no body kept


@pytest.mark.parametrize("steps", [
    [{"c": [1, 2 ** 63]}],
    [{"c": [1, 5]}, {"c": [2 ** 63, 2 ** 63 + 1]}],
    [{"c": [2 ** 64, 2 ** 65]}],
    [{"c": [1, 10 ** 30]}],
], ids=["to-2^63", "second-range", "above-2^64", "ten-to-the-30"])
def test_copy_range_past_any_body_is_a_verdict_not_an_exception(steps):
    raw = with_recipe({"b": steps})
    ref = compare(raw, DNS)
    assert not ref.ok
    _v, result = streamed(raw)
    assert result.status == ref.status and not result.ok


def test_many_single_line_copies():
    """Thousands of one-line copy steps: each used to scan every offset
    already found.  No timing here; the plan and the undo walk agree."""
    lines = 6000
    body = b"\r\n" * lines
    steps = [{"c": [i, i]} for i in range(1, lines, 2)]
    compare(with_recipe({"b": steps}, body=body), DNS)


@pytest.mark.parametrize("value", [
    b"a@" + b"(a)" * 30000 + b"b.example",
    b"a@" + b"." * 100000,
    b"a " * 50000 + b"<a@b.example>",
    b'"' + b"x" * 3000 + b'" <a@b.example>',
], ids=["comments", "dots", "words", "long-display-name"])
def test_long_from_is_not_parsed(value):
    assert len(value) > dkim2domain.MAX_FROM_LENGTH
    assert dkim2domain.from_mailbox([b"From: " + value]) == (dkim2domain.FROM_NONE, None)


def test_from_length_limit_is_octets_without_folding():
    """The same boundary in every implementation: 2048 octets, not counting
    the line breaks of folding or the white space round the value; and too
    long comes before 'a list'."""
    def long(n):
        return b'"' + b"a" * (n - 18) + b'" <a@example.com>'
    assert len(long(2048)) == dkim2domain.MAX_FROM_LENGTH
    ok = (dkim2domain.FROM_OK, "example.com")
    none = (dkim2domain.FROM_NONE, None)
    assert dkim2domain.from_mailbox([b"From:" + long(2048)]) == ok
    assert dkim2domain.from_mailbox([b"From: " + long(2048).replace(b" <", b"\r\n <") + b" \r\n"]) == ok
    assert dkim2domain.from_mailbox([b"From: " + long(2049)]) == none
    assert dkim2domain.from_mailbox([b"From: " + long(2040) + b", b@y.com"]) == none


def test_ordinary_from_is_still_parsed():
    value = b'"' + b"x" * 1500 + b'" <a@B.Example>'
    assert dkim2domain.from_mailbox([b"From: " + value]) == (dkim2domain.FROM_OK, "b.example")


class SlowResolver:
    """Answers nothing, and says each question took five seconds."""

    def __init__(self, clock):
        self.clock = clock
        self.asked = []

    def query_txt(self, name):
        self.asked.append(name)
        self.clock[0] += 5.0
        raise TimeoutError("no answer")


def test_lookups_for_one_message_stop_at_the_budget(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(dkim2dns.time, "monotonic", lambda: clock[0])
    resolver = SlowResolver(clock)
    keys = dkim2dns.LiveDNS(resolver, prefetch=False, budget=20.0).for_message()
    for n in range(256):
        with pytest.raises(dkim2dns.DNSTempError):
            keys.txt_records(f"s{n}._domainkey.d{n}.example")
    assert len(resolver.asked) == 4        # 4 x 5 s, then no more questions
    # a name already answered is still answered from memory
    with pytest.raises(dkim2dns.DNSTempError):
        keys.txt_records("s0._domainkey.d0.example")
    assert len(resolver.asked) == 4
    # the next message starts afresh
    other = dkim2dns.LiveDNS(resolver, prefetch=False, budget=20.0).for_message()
    with pytest.raises(dkim2dns.DNSTempError):
        other.txt_records("s0._domainkey.d0.example")
    assert len(resolver.asked) == 5


def test_many_signatures_many_selectors_cost_a_bounded_number_of_lookups(monkeypatch):
    """32 signatures of 8 selectors each, every one under its own domain:
    256 names in a few KB of header."""
    clock = [1000.0]
    monkeypatch.setattr(dkim2dns.time, "monotonic", lambda: clock[0])
    resolver = SlowResolver(clock)
    raw = b"\r\n".join(HEAD) + b"\r\n\r\n" + BODY
    headers, body = dkim2sign.parse_message(raw)
    mi = dkim2sign.build_message_instance(headers, body, version=1)
    mf = base64.b64encode(b"<a@test1.dkim2.com>").decode()
    sigs = []
    for i in range(1, 33):
        items = ",".join(f"s{i}x{j}:ed25519-sha256:QUJD" for j in range(8))
        sigs.append(f"DKIM2-Signature: i={i}; m=1; t=1740000000; d=d{i}.example; "
                    f"mf={mf}; rt={mf}; s={items}".encode())
    hostile = b"\r\n".join(reversed(sigs)) + b"\r\n" + mi.encode() + b"\r\n" + raw
    v = dkim2verify.MessageVerifier(dkim2dns.LiveDNS(resolver, prefetch=False),
                                    full_chain=True, skip_timestamp_check=True)
    v.feed(hostile)
    result = v.close()
    assert not result.ok
    assert len(resolver.asked) <= 4


def test_abandon_drops_lookups_not_started():
    class Future:
        cancelled = False

        def cancel(self):
            self.cancelled = True

    keys = dkim2dns.LiveDNS(SlowResolver([0.0]), prefetch=False).for_message()
    futures = [Future(), Future()]
    keys._pending = {"a": (0.0, futures[0]), "b": (0.0, futures[1])}
    keys.cancel()
    assert all(f.cancelled for f in futures) and keys._pending == {}

    v = dkim2verify.MessageVerifier(DNS, full_chain=True)
    v.abandon()                             # before any header: nothing to do
    v.feed(b"\r\n".join(HEAD) + b"\r\n\r\nbody\r\n")
    v.abandon()                             # keys from a table: nothing to cancel
