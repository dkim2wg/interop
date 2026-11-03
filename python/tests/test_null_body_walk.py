"""Header-history walk past a null body Recipe (-07 §5.2; -09 §13).

A null body Recipe means the previous *body* cannot be recreated; header
Recipes are mandatory, so the header history below the null is still undone
and checked (header hash only -- the body hash is not checked below it).

Since -09 (contract E2) a null body Recipe is a PERMERROR for every
verifier, so the walk past one only decides anything for a signer checking
its own, still unsigned, null (outbound mode).
"""
import json
import re
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
from dkim2verify import verify_message  # noqa: E402

sys.path.insert(0, HERE)
from util_fixtures import bnv  # noqa: E402  (From Authentic for test1)


NULL2 = "PERMERROR: Message-Instance m=2 has a null recipe"


def _verify(msg, **kw):
    with open(os.path.join(ROOT, "dns.json")) as fh:
        dns = json.load(fh)
    return verify_message(msg, dns, full_chain=True, skip_timestamp_check=True,
                          **kw)


def _outbound(msg, keep_i):
    """The message as a signer about to sign it sees it, had the hops above
    i=keep_i not signed yet: every DKIM2-Signature above keep_i removed,
    verified in outbound mode (allow_unsigned_mi), where an unsigned null is
    this host's own and the walk goes on past it (-09, contract E2)."""
    head, sep, body = msg.partition(b"\r\n\r\n")
    fields, cur = [], b""
    for line in head.split(b"\r\n"):
        if line[:1] in (b" ", b"\t"):
            cur += b"\r\n" + line
        else:
            if cur:
                fields.append(cur)
            cur = line
    fields.append(cur)

    def drop(f):
        if not f.lower().startswith(b"dkim2-signature:"):
            return False
        i = re.search(rb"[;\s]i=(\d+)", f.replace(b"\r\n", b"")).group(1)
        return int(i) > keep_i
    kept = [f for f in fields if not drop(f)]
    return _verify(b"\r\n".join(kept) + sep + body, allow_unsigned_mi=True)


# -09 (contract E2): a signed null body Recipe is a PERMERROR naming its
# instance, a §14.2 content check made before the walk, so it wins over a
# forged history below it.

def test_null_at_m2_over_signed_m1_is_permerror():
    r = _verify(bnv.build_positive_null_body())
    assert r.status == "permerror" and r.message == NULL2, r.errors


def test_null_at_m3_over_normal_m2_is_permerror():
    r = _verify(bnv.build_positive_null_body_over_recipe())
    assert r.message == "PERMERROR: Message-Instance m=3 has a null recipe", r.errors


def test_null_beats_forged_history_below():
    r = _verify(bnv.build_null_body_forged_history())
    assert r.message == NULL2, r.errors


# The walk past a null still matters for a signer's own unsigned null.

def test_outbound_null_at_m2_passes():
    r = _outbound(bnv.build_positive_null_body(), 1)
    assert r.ok, r.errors
    assert "body not checked below m=2" in r.message, r.message
    assert r.fully_verified     # deprecated: true exactly for a pass


def test_outbound_forged_history_below_null_fails_on_m1_header_hash():
    r = _outbound(bnv.build_null_body_forged_history(), 1)
    assert not r.ok
    assert ("FAIL: Message-Instance m=1 header hash sha256 mismatch" in r.errors), r.errors
    assert not any("body hash" in e for e in r.errors), r.errors


def test_outbound_signed_null_is_still_permerror():
    # i=2 covers the null: not this hop's own.
    r = _outbound(bnv.build_positive_null_body(), 2)
    assert r.message == NULL2, r.errors


def _bad_header_recipe_below_null():
    def bad(*a):
        r = bnv._null_body_recipe(*a)
        r["h"] = {"subject": [{"c": [90, 99]}]}  # no such lines in m=1's Subject
        return r
    headers, body = bnv.load_base()
    return bnv._null_body_chain([
        (headers, body),
        (bnv._subject_prefixed(headers, b"list"), body + b"rewritten\r\n", bad),
    ])


def test_header_recipe_not_applying_below_null_fails():
    assert _verify(_bad_header_recipe_below_null()).message == NULL2
    r = _outbound(_bad_header_recipe_below_null(), 1)
    assert not r.ok, r.errors
    from dkim2verify import _malformed_recipe_error
    assert _malformed_recipe_error(2) in r.errors, r.errors
    assert not any("signature" in e.lower() and "verif" in e.lower()
                   for e in r.errors), r.errors


def _chain3_null_in_middle(forge):
    headers, body = bnv.load_base()
    h2 = bnv._subject_prefixed(headers, b"list")
    if forge:
        h2 = bnv._to_changed(h2)
    h3 = bnv._subject_prefixed(h2, b"fwd")
    b2 = body + b"rewritten\r\n"
    return bnv._null_body_chain([
        (headers, body),
        (h2, b2, bnv._forged_recipe if forge else bnv._null_body_recipe),
        (h3, b2, bnv._footer_recipe),  # ordinary: header Recipe only
    ])


def test_null_below_ordinary_instance():
    assert _verify(_chain3_null_in_middle(False)).message == NULL2
    r = _outbound(_chain3_null_in_middle(False), 1)
    assert r.ok, r.errors


def test_outbound_forged_history_below_null_below_ordinary_fails():
    r = _outbound(_chain3_null_in_middle(True), 1)
    assert not r.ok
    assert ("FAIL: Message-Instance m=1 header hash sha256 mismatch" in r.errors), r.errors


def _empty_body(forge):
    headers, _ = bnv.load_base()
    h2 = bnv._subject_prefixed(headers, b"list")
    if forge:
        h2 = bnv._to_changed(h2)
    return bnv._null_body_chain([
        (headers, b""),
        (h2, b"", bnv._forged_recipe if forge else bnv._footer_recipe),
    ])


def test_empty_body_header_only_recipe_passes():
    r = _verify(_empty_body(False))
    assert r.ok, r.errors


def test_empty_body_hidden_to_change_fails():
    # The forged Recipe holds a null body Recipe: inbound, that is reported.
    assert _verify(_empty_body(True)).message == NULL2
    r = _outbound(_empty_body(True), 1)
    assert not r.ok
    assert ("FAIL: Message-Instance m=1 header hash sha256 mismatch" in r.errors), r.errors


def test_pass_message_does_not_mention_unchecked_body():
    assert "body not checked" not in _verify(bnv.build_positive_bottom_recipe()).message
